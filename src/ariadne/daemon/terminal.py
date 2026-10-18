"""Terminal-Register des Daemons: Zustand pro Shim-Verbindung (Architektur 3.6, 3.7)."""

from __future__ import annotations

import bisect
import ipaddress
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, get_args

from ariadne._shim.protocol import ACCEPTED_PROTOS, ProtocolError
from ariadne.ctxrules import ContextStack, context_argv
from ariadne.events import GapReason, StageKind

__all__ = [
    "AckEntry",
    "Pause",
    "MarkContext",
    "Terminal",
    "parse_hello",
    "parse_stack",
    "normalize_host",
    "normalize_user",
    "apply_stack_event",
    "merge_auto_hosts",
    "STAGE_KINDS",
    "MAX_FRAME_TIMES",
]

STAGE_KINDS = frozenset(get_args(StageKind))
GAP_REASONS = frozenset(get_args(GapReason))
_TID_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z-]{7,63}$")
_NAME_RE = re.compile(r"^[a-z0-9_][a-z0-9_.-]{0,252}$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_STAGE_SOURCES = frozenset({"auto", "hotkey", "webui", "cli", "suggestion"})
MAX_FRAME_TIMES = 4096  # Zeitindex der Rahmen für eigene Events des Daemons


@dataclass
class AckEntry:
    """Ein empfangener Rahmen. ACK geht erst, wenn alle Rahmen bis hier erledigt sind."""

    seq: int
    ready: bool = False
    need_end: int = 0  # Strom-Ende, das gespeichert sein muss
    need_gen: int = 0  # Writer-Generation, die committed sein muss


@dataclass
class Pause:
    """Aufnahme pausiert wegen Schlüsselmaterial auf dem Bildschirm (``sensitive_output``).

    ``since_mono``/``since_wall``: Zeitpunkt der Anmeldung (CLOCK_MONOTONIC bzw. Wanduhr).
    Die Pause gilt nur für Gelesenes danach und endet nur an einem Prompt-Marker, den der
    Shim danach gelesen hat: Wiederholte Rahmen aus seinem Ring (nach einem Neustart des
    Daemons) beenden sie nicht und fallen nicht in die Lücke.
    """

    start: int
    end: int
    deadline: float
    since_mono: int = 0
    since_wall: int = 0

    def covers(self, mono: int | None, wall: int | None = None) -> bool:
        """Gilt die Pause für etwas, das der Shim zu dieser Zeit gelesen hat?"""
        if isinstance(mono, int) and 0 < mono and self.since_mono:
            return mono >= self.since_mono
        if isinstance(wall, int) and 0 < wall and self.since_wall:
            return wall >= self.since_wall
        return True  # ohne Shim-Zeit (Protokoll v1): wie bisher


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
    proto: int = 1
    display: dict[str, str] = field(default_factory=dict)
    conn: Any = None  # asyncio.StreamWriter der aktuellen Verbindung
    stack: ContextStack = field(default_factory=ContextStack)
    bound_project_id: str | None = None
    bound_slug: str | None = None
    opened_in: set[str] = field(default_factory=set)
    recording: bool = False
    pending_open: bool = False  # Aufnahme an, term.open folgt beim ersten Offset (E95)
    recv_end: int = 0  # bis hier angenommen (Strom-Offset)
    stored_end: int = 0  # bis hier im Journal
    shim_off: int = 0  # höchster bekannter Offset des Shims (Rahmen, Anfragen)
    max_seq: int = 0
    acked_seq: int = 0
    ack_queue: deque[AckEntry] = field(default_factory=deque)
    seen_seq: int = 0
    gap_hint: str | None = None
    pause: Pause | None = None  # Schlüsselmaterial (sensitive_output), bis zum nächsten Prompt
    pause_until_ns: int | None = None  # Pause des Nutzers (E22), Wanduhr
    pause_mono_until: int | None = None  # dieselbe Frist auf der monotonen Uhr des Daemons
    pause_source: str = "hotkey"
    # Stromposition des letzten Prompts der Kali-Shell (Marker A/D, fg_shell) bei lokalem Stapel:
    # danach war das Terminal sicher wieder in Kali (rückwirkendes ``set``, Befund F2)
    local_prompt_off: int = -1
    # Web-Pausen (monotone Uhr: Beginn, Ende) für das Budget «30 Minuten pro Stunde» (Befund F9)
    web_pauses: list[list[int]] = field(default_factory=list)
    mux: bool = False  # Multiplexer-Client im Vordergrund (nur Anzeige)
    last_mono: int | None = None  # monotone Shim-Zeit des letzten Rahmens (time_suspect)
    frame_offs: list[int] = field(default_factory=list)
    frame_times: list[tuple[int, int | None, int]] = field(default_factory=list)  # Shim-Wand, Mono, Empfang
    title_extra: str | None = None
    last_state: dict[str, Any] | None = None
    closed: bool = False
    ctx_version: int = 0  # zählt Kontext-Entscheide; der Shim übernimmt STATE.stack nur dann
    ends: dict[str, int] = field(default_factory=dict)  # Stromende pro Projekt bei Aufnahme-Ende
    dup_end: int = -1  # Journal-Ende beim Öffnen: davor Gespeichertes nicht noch einmal schreiben
    dup_keys: set[tuple[Any, ...]] = field(default_factory=set)  # Events genau an dup_end

    def note_frame(self, off: int, wall: int, mono: int | None, recv: int = 0) -> None:
        if self.frame_offs and off < self.frame_offs[-1]:
            return
        self.frame_offs.append(off)
        self.frame_times.append((wall, mono, recv or time.time_ns()))
        if len(self.frame_offs) > MAX_FRAME_TIMES:
            del self.frame_offs[: MAX_FRAME_TIMES // 2]
            del self.frame_times[: MAX_FRAME_TIMES // 2]

    def time_at(self, off: int) -> tuple[int, int | None, int] | None:
        """Shim-Wanduhr, Shim-Monotonic und Empfangszeit des Rahmens mit ``off`` (oder ``None``)."""
        i = bisect.bisect_right(self.frame_offs, off) - 1
        if i < 0:
            return self.frame_times[0] if self.frame_times else None
        return self.frame_times[i]

    def prune_frames(self) -> None:
        """Vergisst Zeitstempel von Rahmen, die vollständig gespeichert sind."""
        i = bisect.bisect_right(self.frame_offs, self.stored_end) - 1
        if i > 0:
            del self.frame_offs[:i]
            del self.frame_times[:i]

    def note_off(self, off: int | None) -> None:
        if isinstance(off, int) and not isinstance(off, bool) and off > self.shim_off:
            self.shim_off = off


def apply_stack_event(stack: ContextStack, kind: str, header: dict[str, Any]) -> ContextStack:
    """Wirkung eines gespeicherten oder gehaltenen Events auf den Stapel (wie im Shim)."""
    off = header.get("stream_off")
    off = off if isinstance(off, int) else 0
    if kind == "term.mark":
        mark = header.get("mark")
        if mark == "C":
            cmd = header.get("cmd_expanded") or header.get("cmd_typed") or ""
            if isinstance(cmd, str) and cmd:
                stack.on_command_start(context_argv(cmd), off)
        elif mark == "D" and header.get("fg_shell"):
            stack.on_command_end(header.get("exit"), off)
    elif kind == "term.ctx_snapshot" and isinstance(header.get("stack"), list | tuple):
        return merge_auto_hosts(stack, ContextStack.from_snapshot(header["stack"]))
    return stack


def merge_auto_hosts(old: ContextStack, new: ContextStack) -> ContextStack:
    """Automatische Hosts (``host_source="auto"``, E23) aus ``old`` in ``new`` übernehmen.

    Schnappschüsse im Journal und vom Shim tragen den Auto-Host nicht; ohne diese
    Übernahme verschwände er bei jedem Schnappschuss bis zum nächsten Durchgang.
    """
    for st in old.stages:
        if st.host_source == "auto" and st.host:
            new.set_auto_host(st.opened_at, st.host)
    return new


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


def parse_stack(data: Any) -> list[dict[str, Any]] | None:
    """Kontext-Stapel vom Shim (HELLO, ``req.ctx.sync``) prüfen; ``None`` bei Fehlern."""
    if not isinstance(data, list) or not data or len(data) > 64:
        return None
    out: list[dict[str, Any]] = []
    for d in data:
        if not isinstance(d, dict) or d.get("kind") not in STAGE_KINDS:
            return None
        st: dict[str, Any] = {"kind": d["kind"]}
        for key in ("host", "user", "candidate"):
            v = d.get(key)
            if isinstance(v, str) and 0 < len(v) <= 255:
                st[key] = v
        off = d.get("opened_at")
        st["opened_at"] = off if isinstance(off, int) and not isinstance(off, bool) and off >= 0 else 0
        st["state"] = "suspended" if d.get("state") == "suspended" else "active"
        st["source"] = d["source"] if d.get("source") in _STAGE_SOURCES else "auto"
        if d.get("host_source") == "auto" and "host" in st:
            st["host_source"] = "auto"
        out.append(st)
    if out[0]["kind"] != "local":
        return None
    return out


def parse_hello(obj: dict[str, Any]) -> dict[str, Any]:
    """Prüft ein HELLO und gibt die übernommenen Felder zurück."""
    proto = obj.get("proto")
    if type(proto) is not int or proto not in ACCEPTED_PROTOS:
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
    bound = obj.get("bound_project_id")
    if bound is not None and (not isinstance(bound, str) or not _TID_RE.match(bound)):
        bound = None
    slug = obj.get("bound_slug")
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        slug = None
    hint = obj.get("gap_hint")
    pause = obj.get("pause_until_ns") if proto >= 2 else None
    if pause is not None and (type(pause) is not int or not 0 < pause < 1 << 63):
        pause = None
    return {
        "proto": proto,
        "gap_hint": hint if isinstance(hint, str) and hint in GAP_REASONS else None,
        "stack": parse_stack(obj.get("stack")),
        "bound_project_id": bound,
        "bound_slug": slug if bound else None,
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
        "pause_until_ns": pause,
        "mux": obj.get("mux") is True,
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
