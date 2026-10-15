"""Vorlauf ohne Projekt (E95, Vertrag v0.1-Bedienung 4.4): nur im Arbeitsspeicher des Daemons.

Im Zustand ``preroll`` und ``locked`` nimmt der Daemon die Rahmen der Shims an,
bestätigt sie sofort und hält sie hier pro Terminal: Inhalt, Empfangszeit, Bindung
zum Zeitpunkt der Annahme und den Stapel am Anfang des gehaltenen Fensters.

Grenzen: Fenster (``preroll_minutes``), Bytes pro Terminal und Bytes gesamt.
Verdrängt wird immer der älteste Eintrag (pro Terminal bzw. gesamt), damit jeder
Puffer zusammenhängend bleibt. Inhalte gehen nie auf die Platte und nie in Logs;
verworfene Inhalte werden nach bestem Bemühen mit Nullen überschrieben.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from ariadne.ctxrules import ContextStack
from ariadne.daemon.terminal import apply_stack_event

__all__ = ["Held", "TermPreroll", "PrerollStore", "ENTRY_OVERHEAD"]

ENTRY_OVERHEAD = 256  # geschätzte Verwaltungskosten pro Eintrag (Header, Objekte)


@dataclass
class Held:
    """Ein gehaltener Eintrag: ``out`` (Ausgabe), ``input`` (Eingabe) oder ``event`` (term.*)."""

    kind: str
    stream_off: int
    recv_ns: int  # Empfangszeit im Daemon (Wanduhr), wird als ts_utc_ns übernommen
    mono: int  # Zeitschlüssel für das Fenster (monotone Uhr)
    bound: str | None  # Projektbindung des Terminals bei der Annahme
    data: bytearray | None = None
    fields: dict[str, Any] = field(default_factory=dict)  # Rahmenfelder bzw. Event-Header
    size: int = 0  # gezählte Bytes (bleibt nach wipe() gleich)
    nbytes: int = 0  # Nutzbytes (Ausgabe oder Eingabe)
    keep: bool = False  # Ausfallpuffer (Daemon neu gestartet, Projekt aktiv): kein Zeitfenster

    def __post_init__(self) -> None:
        self.nbytes = len(self.data) if self.data is not None else 0
        self.size = ENTRY_OVERHEAD + self.nbytes

    @property
    def end(self) -> int:
        if self.kind == "out" and self.data is not None:
            return self.stream_off + len(self.data)
        if self.kind == "event" and self.fields.get("kind") == "term.gap":
            return self.stream_off + int(self.fields.get("bytes_lost", 0) or 0)
        return self.stream_off

    def wipe(self) -> None:
        if self.data is not None:
            self.data[:] = bytes(len(self.data))
            self.data = None


@dataclass
class TermPreroll:
    """Gehaltenes Fenster eines Terminals."""

    terminal_id: str
    start_stack: ContextStack
    entries: deque[Held] = field(default_factory=deque)
    bytes: int = 0
    dropped_bytes: int = 0  # verdrängte Ausgabe-Bytes (Fenster und Grenzen)

    @property
    def outage(self) -> bool:
        """Enthält Rahmen aus dem Ausfallpuffer (nach einem Neustart bei aktivem Projekt)."""
        return any(e.keep for e in self.entries)

    def oldest_mono(self) -> int | None:
        return self.entries[0].mono if self.entries else None

    def pop_oldest(self) -> Held:
        e = self.entries.popleft()
        self.bytes -= e.size
        if e.kind == "out":
            self.dropped_bytes += e.nbytes
        elif e.kind == "event":
            self.start_stack = apply_stack_event(self.start_stack, str(e.fields.get("kind")), e.fields)
        e.wipe()
        return e

    def wipe(self) -> None:
        for e in self.entries:
            e.wipe()
        self.entries.clear()
        self.bytes = 0


class PrerollStore:
    def __init__(self, *, window_s: int, terminal_bytes: int, total_bytes: int,
                 clock: Callable[[], int], keep_s: int | None = None,
                 wall_clock: Callable[[], int] | None = None) -> None:
        self.window_s = window_s
        self.keep_s = keep_s  # Fenster für den Ausfallpuffer (``None``: ohne Zeitgrenze)
        self._wall = wall_clock  # Empfangszeit gegen die Wanduhr: Suspend zählt mit
        self.terminal_bytes = terminal_bytes
        self.total_bytes = total_bytes
        self._clock = clock  # monotone Uhr in ns
        self.bufs: dict[str, TermPreroll] = {}
        self.bytes = 0

    @property
    def enabled(self) -> bool:
        return self.window_s > 0

    def add(self, terminal_id: str, entry: Held, stack_before: ContextStack) -> None:
        """Hält ``entry``. ``stack_before`` ist der Stapel vor diesem Eintrag (Fensteranfang)."""
        if not self.enabled and not entry.keep:
            entry.wipe()
            return
        buf = self.bufs.get(terminal_id)
        if buf is None:
            buf = TermPreroll(terminal_id, ContextStack.from_snapshot(stack_before.snapshot()))
            self.bufs[terminal_id] = buf
        buf.entries.append(entry)
        buf.bytes += entry.size
        self.bytes += entry.size
        while buf.entries and buf.bytes > self.terminal_bytes:
            self.bytes -= buf.pop_oldest().size
        while self.bytes > self.total_bytes:
            oldest = min((b for b in self.bufs.values() if b.entries), key=lambda b: b.oldest_mono() or 0,
                         default=None)
            if oldest is None:
                break
            self.bytes -= oldest.pop_oldest().size
        self.expire()

    def expire(self) -> None:
        """Verdrängt alles, was älter als das Fenster ist (Ausfallpuffer: ``keep_s``)."""
        now = self._clock()
        wall = self._wall() if self._wall is not None else None
        win = self.window_s * 1_000_000_000
        keep = self.keep_s * 1_000_000_000 if self.keep_s is not None else None
        for tid, buf in list(self.bufs.items()):
            while buf.entries:
                e = buf.entries[0]
                span = keep if e.keep else win
                # CLOCK_MONOTONIC steht während Suspend still; die Wanduhr der Annahme nicht.
                if span is None or (e.mono >= now - span and (wall is None or e.recv_ns >= wall - span)):
                    break
                self.bytes -= buf.pop_oldest().size
            if not buf.entries:
                buf.wipe()
                del self.bufs[tid]

    def seconds(self, terminal_id: str | None = None) -> int:
        """Länge des gehaltenen Fensters in Sekunden (aufgerundet), gesamt oder pro Terminal."""
        now = self._clock()
        bufs = [self.bufs[terminal_id]] if terminal_id in self.bufs else (
            [] if terminal_id is not None else list(self.bufs.values()))
        oldest = [b.oldest_mono() for b in bufs if b.entries]
        if not oldest:
            return 0
        return max(0, math.ceil((now - min(x for x in oldest if x is not None)) / 1e9))

    def info(self) -> dict[str, int]:
        self.expire()
        return {"terminals": sum(1 for b in self.bufs.values() if b.entries), "seconds": self.seconds(),
                "bytes": sum(len(e.data) for b in self.bufs.values() for e in b.entries
                             if e.data is not None),
                "window_s": self.window_s}

    def take(self, terminal_id: str) -> TermPreroll | None:
        buf = self.bufs.pop(terminal_id, None)
        if buf is not None:
            self.bytes -= buf.bytes
        return buf

    def terminals(self) -> Iterator[str]:
        return iter(list(self.bufs))

    def discard(self, terminal_id: str | None = None) -> None:
        for tid in [terminal_id] if terminal_id is not None else list(self.bufs):
            buf = self.bufs.pop(tid, None)
            if buf is not None:
                self.bytes -= buf.bytes
                buf.wipe()
