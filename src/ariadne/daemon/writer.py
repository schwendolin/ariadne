"""Writer des Daemons (Architektur 5.4, Vertrag v0.1-Bedienung 4.6): bündelt, schreibt, bestätigt.

Ein Commit alle 200 ms oder ab 256 KiB. Reihenfolge pro Commit:

1. Aufeinanderfolgende Ausgabe-Rahmen eines Terminals werden zu einem ``term.out``
   zusammengefasst (lückenlos, gleiche Herkunft, höchstens 256 KiB und
   :data:`ariadne.events.MAX_TIX` Einträge im Zeitindex, nie über ein anderes
   Event desselben Terminals hinweg). Der Zeitindex wandert mit: Ein Rahmen, der
   bei Byte ``n`` beginnt, ergibt den Eintrag ``(n, (mono_i - mono_0) // 1000)``,
   seine eigenen Einträge werden um ``n`` und diese Zeit verschoben. Rahmen mit
   unplausibler Zeit (``time_suspect``) bleiben eigene Zeilen.
2. ``append_many`` in einer Transaktion.
3. ACK an die Shims (nur für vollständig gespeicherte Rahmen).
4. Commit- und Mark-Hooks, ausserhalb der Transaktion. Fehler dort stoppen
   den Daemon nie.

Seit E72 schwärzt der Writer nichts mehr: Das Journal speichert alles (verschlüsselt),
eigene Secrets ersetzt der Redaktor erst an den Ausgängen (``Redactor.redact_for_exit``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ariadne import events
from ariadne.daemon.terminal import MarkContext, Terminal
from ariadne.store.api import AppendItem, EventRecord

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon

__all__ = ["Writer", "OutChunk", "MERGE_MAX", "merge_tix"]

log = logging.getLogger("ariadne.daemon")

MERGE_MAX = 256 * 1024
DT_MAX = (1 << 31) - 1  # µs; grössere Abstände werden nicht zusammengefasst


@dataclass
class OutChunk:
    """Ein angenommener Ausgabe-Rahmen mit Shim-Zeit und Zeitindex."""

    t: Terminal
    off: int
    data: bytes
    wall: int
    mono: int | None = None
    tix: tuple[tuple[int, int], ...] = ()
    recv: int = 0
    origin: str = "shim"
    suspect: bool = False


@dataclass
class _Event:
    item: AppendItem
    t: Terminal | None
    mark_ctx: MarkContext | None


def _dt_us(a_wall: int, a_mono: int | None, b_wall: int, b_mono: int | None) -> int | None:
    """Abstand von Rahmen a zu Rahmen b in µs (monotone Uhr, ohne sie die Wanduhr)."""
    if a_mono is not None and b_mono is not None:
        d = b_mono - a_mono
    elif a_mono is None and b_mono is None:
        d = b_wall - a_wall
    else:
        return None
    return d // 1000 if 0 <= d // 1000 <= DT_MAX else None


def merge_tix(base: list[tuple[int, int]], length: int, dt0: int,
              tix: tuple[tuple[int, int], ...]) -> list[tuple[int, int]]:
    """Zeitindex eines angehängten Rahmens (ab Byte ``length``, Zeit ``dt0``) anfügen."""
    out = list(base)
    last = out[-1][1] if out else 0
    if dt0 != last:
        out.append((length, dt0))
    for rel, dt in tix:
        out.append((length + rel, dt0 + dt))
    return out


@dataclass
class _Merge:
    first: OutChunk
    buf: bytearray = field(default_factory=bytearray)
    tix: list[tuple[int, int]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.buf = bytearray(self.first.data)
        self.tix = list(self.first.tix)

    def take(self, c: OutChunk) -> bool:
        f = self.first
        if c.t is not f.t or c.origin != f.origin or c.suspect or f.suspect:
            return False
        if f.off + len(self.buf) != c.off or len(self.buf) + len(c.data) > MERGE_MAX:
            return False
        if len(self.tix) + 1 + len(c.tix) > events.MAX_TIX:
            return False
        dt0 = _dt_us(f.wall, f.mono, c.wall, c.mono)
        if dt0 is None or dt0 < (self.tix[-1][1] if self.tix else 0):
            return False
        if c.tix and dt0 + c.tix[-1][1] > DT_MAX:
            return False
        self.tix = merge_tix(self.tix, len(self.buf), dt0, c.tix)
        self.buf += c.data
        return True

    def item(self) -> AppendItem:
        f = self.first
        header: dict[str, Any] = {
            "terminal_id": f.t.terminal_id, "stream_off": f.off, "length": len(self.buf),
            "t_shim_ns": f.wall,
        }
        if f.mono is not None:
            header["mono_ns"] = f.mono
        if self.tix:
            header["tix"] = [list(x) for x in self.tix]
        if f.suspect:
            header["time_suspect"] = True
        return AppendItem("term.out", header, bytes(self.buf), origin=f.origin, terminal_id=f.t.terminal_id,
                          stream_off=f.off, ts_utc_ns=f.recv or None)


class Writer:
    def __init__(self, daemon: Daemon, *, interval: float = 0.2, max_bytes: int = 256 * 1024) -> None:
        self.d = daemon
        self.interval = interval
        self.max_bytes = max_bytes
        self.pending: list[OutChunk | _Event] = []
        self.pending_bytes = 0
        self.committed_gen = 0
        self._carry: list[AppendItem] = []
        self._carry_marks: list[MarkContext | None] = []
        self._carry_journal: Any = None

    @property
    def pending_gen(self) -> int:
        """Generation, mit der alles jetzt Eingereihte committed wird."""
        return self.committed_gen + 1

    @property
    def busy(self) -> bool:
        return bool(self.pending or self._carry)

    # ------------------------------------------------------------------ #
    def add_out(self, chunk: OutChunk) -> None:
        self.pending.append(chunk)
        self.pending_bytes += len(chunk.data)
        if self.pending_bytes >= self.max_bytes:
            self.flush_now()

    def add_event(self, item: AppendItem, t: Terminal | None = None,
                  mark_ctx: MarkContext | None = None) -> None:
        self.pending.append(_Event(item, t, mark_ctx))

    def drop_carry(self) -> None:
        if self._carry:
            log.warning("Writer: %d nicht geschriebene Events verworfen", len(self._carry))
            for it in self._carry:
                if it.kind == "term.out" and it.terminal_id is not None:
                    self._forget(it.terminal_id, int(it.stream_off or 0) + int(it.header["length"]))
        self._carry, self._carry_marks, self._carry_journal = [], [], None

    def _forget(self, terminal_id: str, end: int) -> None:
        """Verlorene Daten gelten als erledigt, damit ACKs nicht dauerhaft blockieren."""
        t = self.d.terminals.get(terminal_id)
        if t is not None:
            t.stored_end = max(t.stored_end, end)

    # ------------------------------------------------------------------ #
    def _collect(self, pending: list[OutChunk | _Event], items: list[AppendItem],
                 marks: list[MarkContext | None]) -> None:
        slots: list[AppendItem | _Merge] = []
        cur: dict[str, _Merge] = {}
        for e in pending:
            if isinstance(e, OutChunk):
                tid = e.t.terminal_id
                m = cur.get(tid)
                if m is None or not m.take(e):
                    m = _Merge(e)
                    cur[tid] = m
                    slots.append(m)
                continue
            if e.t is not None:
                cur.pop(e.t.terminal_id, None)
            elif e.item.terminal_id is not None:
                cur.pop(e.item.terminal_id, None)
            slots.append(e.item)
            if e.item.kind == "term.mark":
                marks.append(e.mark_ctx)
        items.extend(s.item() if isinstance(s, _Merge) else s for s in slots)

    def flush_now(self) -> list[EventRecord]:
        """Schreibt alles Eingereihte synchron. Gibt die neuen Records zurück."""
        project = self.d.project
        pending, self.pending, self.pending_bytes = self.pending, [], 0
        if project is None:
            if pending:
                log.warning("Writer: %d Einträge ohne offenes Projekt verworfen", len(pending))
                for e in pending:
                    if isinstance(e, OutChunk):
                        self._forget(e.t.terminal_id, e.off + len(e.data))
                self.committed_gen += 1
                self.d.advance_acks()
            return []
        journal = project.journal
        if self._carry and self._carry_journal is not journal:
            self.drop_carry()
        items: list[AppendItem] = list(self._carry)
        marks: list[MarkContext | None] = list(self._carry_marks)
        self._collect(pending, items, marks)
        if not items:
            self.committed_gen += 1
            self.d.advance_acks()
            return []
        try:
            records = journal.append_many(items)
        except Exception as exc:  # Platte voll, Datenbank gesperrt ...
            log.error("Writer: Commit fehlgeschlagen (%s), %d Events warten", type(exc).__name__, len(items))
            self._carry, self._carry_marks, self._carry_journal = items, marks, journal
            return []
        self._carry, self._carry_marks, self._carry_journal = [], [], None
        self.committed_gen += 1
        for it in items:
            if it.kind == "term.out" and it.terminal_id is not None:
                t = self.d.terminals.get(it.terminal_id)
                if t is not None:
                    t.stored_end = max(t.stored_end, int(it.stream_off or 0) + int(it.header["length"]))
                    t.prune_frames()
        self.d.advance_acks()
        self.d.run_commit_hooks(records)
        mark_records = [r for r in records if r.kind == "term.mark"]
        for rec, ctx in zip(mark_records, marks, strict=False):
            self.d.run_mark_hooks(rec, ctx)
        return records
