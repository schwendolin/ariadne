"""Terminal-Register des Daemons: Zustand pro Shim-Verbindung (Architektur 3.6, 3.7)."""

from __future__ import annotations

import bisect
import ipaddress
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, get_args

from ariadne._shim.protocol import PROTO_VERSION, ProtocolError
from ariadne.ctxrules import ContextStack
from ariadne.events import StageKind

__all__ = [
    "AckEntry",
    "Pause",
    "MarkContext",
    "Terminal",
    "parse_hello",
    "normalize_host",
    "normalize_user",
    "STAGE_KINDS",
]

STAGE_KINDS = frozenset(get_args(StageKind))
_TID_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z-]{7,63}$")
_NAME_RE = re.compile(r"^[a-z0-9_][a-z0-9_.-]{0,252}$")


@dataclass
class AckEntry:
    """Ein empfangener Rahmen. ACK geht erst, wenn alle Rahmen bis hier erledigt sind."""

    seq: int
    ready: bool = False
    need_end: int = 0  # Strom-Ende, das gespeichert sein muss
    need_gen: int = 0  # Writer-Generation, die committed sein muss


@dataclass
class Pause:
    """Aufnahme pausiert wegen Schlüsselmaterial auf dem Bildschirm (``sensitive_output``)."""

    start: int
    end: int
    deadline: float


@dataclass(frozen=True)
class MarkContext:
    """Kontext eines ``term.mark`` zum Zeitpunkt der Verarbeitung (für Mark-Hooks).

    ``stack`` und ``local`` gelten nach dem Marker, ``local_before`` davor: bei
    einem C-Marker sagt es, ob der Befehl auf Kali eingegeben wurde.
    """

    terminal_id: str
    project_id: str
    stack: tuple[dict[str, Any], ...]
    local: bool
    local_before: bool = True


@dataclass
class Terminal:
    terminal_id: str
    shell: str = "unknown"
    tty: str | None = None
    term: str | None = None
    rows: int = 0
    cols: int = 0
    tmux_pane: str | None = None
    window_id: str | None = None
    shim_version: str = "unknown"
    pid: int | None = None
    display: dict[str, str] = field(default_factory=dict)
    conn: Any = None  # asyncio.StreamWriter der aktuellen Verbindung
    stack: ContextStack = field(default_factory=ContextStack)
    bound_project_id: str | None = None
    bound_slug: str | None = None
    opened_in: set[str] = field(default_factory=set)
    recording: bool = False
    recv_end: int = 0  # bis hier angenommen (Strom-Offset)
    stored_end: int = 0  # bis hier im Journal
    max_seq: int = 0
    acked_seq: int = 0
    ack_queue: deque[AckEntry] = field(default_factory=deque)
    buffer: deque[tuple[int, bytes, AckEntry]] = field(default_factory=deque)
    buffer_bytes: int = 0
    gap_hint: str | None = None
    pause: Pause | None = None
    frame_offs: list[int] = field(default_factory=list)
    frame_times: list[tuple[int, int | None]] = field(default_factory=list)
    last_out: float = 0.0
    title_extra: str | None = None
    last_state: dict[str, Any] | None = None
    closed: bool = False

    def note_frame(self, off: int, wall: int, mono: int | None) -> None:
        self.frame_offs.append(off)
        self.frame_times.append((wall, mono))

    def time_at(self, off: int) -> tuple[int, int | None]:
        i = bisect.bisect_right(self.frame_offs, off) - 1
        if i < 0:
            return (self.frame_times[0] if self.frame_times else (0, None))
        return self.frame_times[i]

    def prune_frames(self) -> None:
        """Vergisst Zeitstempel von Rahmen, die vollständig gespeichert sind."""
        i = bisect.bisect_right(self.frame_offs, self.stored_end) - 1
        if i > 0:
            del self.frame_offs[:i]
            del self.frame_times[:i]


def _opt_str(obj: dict[str, Any], key: str, max_len: int) -> str | None:
    v = obj.get(key)
    if v is None:
        return None
    if not isinstance(v, str) or len(v) > max_len:
        raise ProtocolError(f"HELLO: Feld {key} ungültig")
    return v


def _int(obj: dict[str, Any], key: str, lo: int, hi: int, default: int = 0) -> int:
    v = obj.get(key, default)
    if v is None:
        return default
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ProtocolError(f"HELLO: Feld {key} ungültig")
    return v


def parse_hello(obj: dict[str, Any]) -> dict[str, Any]:
    """Prüft ein HELLO und gibt die übernommenen Felder zurück."""
    if obj.get("proto") != PROTO_VERSION:
        raise ProtocolError("falsche Protokollversion")
    tid = obj.get("terminal_id")
    if not isinstance(tid, str) or not _TID_RE.match(tid):
        raise ProtocolError("HELLO: terminal_id ungültig")
    display: dict[str, str] = {}
    raw_display = obj.get("display") or {}
    if isinstance(raw_display, dict):
        for k in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
            v = raw_display.get(k)
            if isinstance(v, str) and 0 < len(v) <= 512:
                display[k] = v
    resume = obj.get("resume_from_seq")
    if resume is not None and (not isinstance(resume, int) or isinstance(resume, bool) or resume < 0):
        raise ProtocolError("HELLO: resume_from_seq ungültig")
    return {
        "terminal_id": tid,
        "tty": _opt_str(obj, "tty", 128),
        "shell": _opt_str(obj, "shell", 256) or "unknown",
        "term": _opt_str(obj, "term", 64),
        "rows": _int(obj, "rows", 0, 1000),
        "cols": _int(obj, "cols", 0, 1000),
        "tmux_pane": _opt_str(obj, "tmux_pane", 64),
        "window_id": _opt_str(obj, "window_id", 64),
        "shim_version": _opt_str(obj, "shim_version", 64) or "unknown",
        "pid": _int(obj, "pid", 0, 1 << 30) or None,
        "display": display,
        "resume_from_seq": resume,
    }


def normalize_host(value: str) -> str:
    """Eingegebene Host-Kennung: ``ip:default/<ip>`` oder ``name:<name>``. Nie aufgelöst."""
    v = value.strip()
    if v.startswith("ip:default/"):
        v = v[len("ip:default/"):]
    elif v.startswith("name:"):
        v = v[len("name:"):]
    if not v or len(v) > 253:
        raise ValueError("Host leer oder zu lang")
    try:
        return f"ip:default/{ipaddress.ip_address(v)}"
    except ValueError:
        pass
    name = v.lower().rstrip(".")
    if not _NAME_RE.match(name):
        raise ValueError("ungültiger Host (erlaubt: IP oder Name aus a-z 0-9 . _ -)")
    return f"name:{name}"


def normalize_user(value: str) -> str:
    v = value.strip()
    if not v or len(v) > 64 or any(ord(c) < 0x21 or ord(c) == 0x7F or 0x80 <= ord(c) <= 0x9F for c in v):
        raise ValueError("ungültiger Benutzer")
    return v
