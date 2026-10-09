"""Private Shell-Marker ``OSC 7701`` prüfen und in Events übersetzen (Architektur 3.3).

Format (zwischen ``ESC ]`` und ``BEL``)::

    7701;ariadne;v1;<nonce>;<shell_pid>:<zähler>;<typ>;<feld>=<wert>&<feld>=<wert>

Werte sind percent-kodiert. Ein Marker gilt, wenn die Nonce stimmt und der
Zähler für diese ``shell_pid`` grösser ist als alle bisherigen. ``fg_shell``
ist nur wahr, wenn beim Lesen die Shell selbst im Vordergrund des PTY steht,
``/proc/<pid>/comm`` eine Shell ist und die PID vom Kind des Shims abstammt.
"""

from __future__ import annotations

import hmac
import os
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from ariadne._shim import procutil

__all__ = [
    "ParsedMarker",
    "Verdict",
    "MarkerValidator",
    "parse_marker",
    "percent_decode",
    "mark_event",
]

MAX_FIELDS = 40
MAX_VALUE = 4096
MAX_VARS = 16
MAX_PIDS = 256
_HEX = frozenset(b"0123456789abcdef")
_NAME_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")
_MARKS = {b"A": "A", b"B": "B", b"C": "C", b"D": "D"}


@dataclass(frozen=True)
class ParsedMarker:
    nonce: bytes
    shell_pid: int
    counter: int
    mark: str
    fields: dict[str, str]


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str | None = None  # bad_nonce | replay | malformed
    marker: ParsedMarker | None = None
    fg_shell: bool = False


def percent_decode(raw: bytes) -> bytes:
    """Dekodiert ``%XX``; ungültige Folgen bleiben wörtlich stehen."""
    if b"%" not in raw:
        return raw
    parts = raw.split(b"%")
    out = bytearray(parts[0])
    for part in parts[1:]:
        hx = part[:2]
        if len(hx) == 2 and all(c in b"0123456789abcdefABCDEF" for c in hx):
            out.append(int(hx, 16))
            out += part[2:]
        else:
            out += b"%" + part
    return bytes(out)


def _int(raw: bytes, *, signed: bool = False) -> int | None:
    if signed and raw[:1] == b"-":
        v = _int(raw[1:])
        return None if v is None else -v
    if not raw or len(raw) > 19 or not raw.isdigit():
        return None
    return int(raw)


def parse_marker(payload: bytes) -> ParsedMarker | str:
    """Zerlegt den Inhalt eines ``OSC 7701``. Gibt bei Fehlern den Grund zurück."""
    parts = payload.split(b";", 6)
    if len(parts) < 4 or parts[0] != b"7701" or parts[1] != b"ariadne" or parts[2] != b"v1":
        return "malformed"
    nonce = parts[3]
    if len(nonce) != 32 or not set(nonce) <= _HEX:
        return "bad_nonce"
    if len(parts) != 7:
        return "malformed"
    pid_raw, sep, ctr_raw = parts[4].partition(b":")
    pid, ctr = _int(pid_raw), _int(ctr_raw)
    mark = _MARKS.get(parts[5])
    if not sep or pid is None or ctr is None or pid <= 0 or mark is None:
        return "malformed"
    fields: dict[str, str] = {}
    if parts[6]:
        items = parts[6].split(b"&")
        if len(items) > MAX_FIELDS:
            return "malformed"
        for item in items:
            if not item:
                continue
            name, eq, value = item.partition(b"=")
            if not eq or not name or len(name) > 40 or not set(name) <= _NAME_CHARS:
                return "malformed"
            text = percent_decode(value).decode("utf-8", "replace")
            fields[name.decode()] = text[:MAX_VALUE]
    return ParsedMarker(nonce, pid, ctr, mark, fields)


class MarkerValidator:
    """Prüft Nonce, Wiederholung und Vordergrund. Abhängigkeiten sind austauschbar."""

    def __init__(
        self,
        nonce: str,
        child_pid: int,
        master_fd: int,
        *,
        tcgetpgrp: Callable[[int], int] = os.tcgetpgrp,
        getpgid: Callable[[int], int] = os.getpgid,
        comm: Callable[[int], str | None] = procutil.read_comm,
        descends: Callable[[int, int], bool] = procutil.descends_from,
    ) -> None:
        self._nonce = nonce.encode()
        self.child_pid = child_pid
        self.master_fd = master_fd
        self._tcgetpgrp = tcgetpgrp
        self._getpgid = getpgid
        self._comm = comm
        self._descends = descends
        self._last: OrderedDict[int, int] = OrderedDict()

    def check(self, payload: bytes) -> Verdict:
        parsed = parse_marker(payload)
        if isinstance(parsed, str):
            return Verdict(False, parsed)
        if not hmac.compare_digest(parsed.nonce, self._nonce):
            return Verdict(False, "bad_nonce")
        last = self._last.get(parsed.shell_pid)
        if last is not None and parsed.counter <= last:
            return Verdict(False, "replay")
        self._last[parsed.shell_pid] = parsed.counter
        self._last.move_to_end(parsed.shell_pid)
        while len(self._last) > MAX_PIDS:
            self._last.popitem(last=False)
        return Verdict(True, None, parsed, self.fg_shell(parsed.shell_pid))

    def fg_shell(self, pid: int) -> bool:
        try:
            if self._tcgetpgrp(self.master_fd) != self._getpgid(pid):
                return False
        except OSError:
            return False
        if self._comm(pid) not in procutil.SHELLS:
            return False
        return self._descends(pid, self.child_pid)


def mark_event(m: ParsedMarker, *, terminal_id: str, stream_off: int, fg_shell: bool) -> dict:
    """Felder für ``term.mark`` (siehe ``ariadne.events.TermMarkEv``)."""
    ev: dict = {
        "terminal_id": terminal_id,
        "stream_off": stream_off,
        "mark": m.mark,
        "counter": m.counter,
        "fg_shell": fg_shell,
        "shell_pid": m.shell_pid,
    }
    f = m.fields
    for src, dst in (("cmd", "cmd_typed"), ("cmdx", "cmd_expanded"), ("cwd", "cwd"), ("user", "user")):
        if f.get(src):
            ev[dst] = f[src]
    for src in ("exit", "shlvl"):
        if src in f:
            v = _int(f[src].encode(), signed=True)
            if v is not None:
                ev[src] = v
    if "pipestatus" in f:
        vals = [_int(x.encode(), signed=True) for x in f["pipestatus"].split(",") if x]
        if vals and all(v is not None for v in vals):
            ev["pipestatus"] = vals
    cmd_vars = {k[4:]: v for k, v in f.items() if k.startswith("var.") and len(k) > 4}
    if cmd_vars:
        ev["cmd_vars"] = dict(list(cmd_vars.items())[:MAX_VARS])
    return ev
