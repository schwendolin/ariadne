"""Writer des Daemons (Architektur 5.4): bündelt, schwärzt, schreibt, bestätigt.

Ein Commit alle 200 ms oder ab 256 KiB. Reihenfolge pro Commit:

1. ``term.out`` läuft durch den Redaktor (eigene Secrets, längenerhaltend).
   Andere Events eines Terminals geben den Rückhalt nie frei: Hält der Redaktor
   gerade den Anfang eines möglichen Secrets, warten sie hinter ihm und gehen
   an ihrer Stromposition ins Journal (das ``term.out`` wird dort geteilt). Sonst
   könnte ein Ereignis, das ein Ziel auslösen kann (``term.marker_forged``,
   ``term.osc52_blocked``) oder ein ``term.resize``, ein Secret zerteilen und
   den Anfang im Klartext schreiben. Nur REC aus, Projektwechsel, Pause und das
   Ende des Terminals geben den Rückhalt hart frei; Stille nur, was kein
   Secret beginnen kann.
2. ``append_many`` in einer Transaktion.
3. ACK an die Shims (nur für vollständig gespeicherte Rahmen).
4. Commit- und Mark-Hooks, ausserhalb der Transaktion. Fehler dort stoppen
   den Daemon nie.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ariadne.daemon.terminal import MarkContext, Terminal
from ariadne.secrets.redactor import Chunk
from ariadne.store.api import AppendItem, EventRecord

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon

__all__ = ["Writer"]

log = logging.getLogger("ariadne.daemon")


@dataclass
class _Out:
    t: Terminal
    off: int
    data: bytes


@dataclass
class _Flush:
    t: Terminal
    soft: bool = False  # Leerlauf: möglichen Secret-Anfang behalten


@dataclass
class _Event:
    item: AppendItem
    t: Terminal | None
    mark_ctx: MarkContext | None


class Writer:
    def __init__(self, daemon: Daemon, *, interval: float = 0.2, max_bytes: int = 256 * 1024) -> None:
        self.d = daemon
        self.interval = interval
        self.max_bytes = max_bytes
        self.pending: list[_Out | _Flush | _Event] = []
        self.pending_bytes = 0
        self.committed_gen = 0
        self._carry: list[AppendItem] = []
        self._carry_marks: list[MarkContext | None] = []
        self._carry_journal: Any = None
        self._deferred: dict[str, list[_Event]] = {}  # Events hinter dem Redaktor-Rückhalt

    @property
    def pending_gen(self) -> int:
        """Generation, mit der alles jetzt Eingereihte committed wird."""
        return self.committed_gen + 1

    # ------------------------------------------------------------------ #
    def add_out(self, t: Terminal, off: int, data: bytes) -> None:
        self.pending.append(_Out(t, off, data))
        self.pending_bytes += len(data)
        if self.pending_bytes >= self.max_bytes:
            self.flush_now()

    def add_event(self, item: AppendItem, t: Terminal | None = None,
                  mark_ctx: MarkContext | None = None) -> None:
        self.pending.append(_Event(item, t, mark_ctx))

    def add_flush(self, t: Terminal, *, soft: bool = False) -> None:
        self.pending.append(_Flush(t, soft))

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
    def _out_item(self, t: Terminal, chunk: Chunk) -> AppendItem:
        off, data, reds = chunk
        wall, mono, recv = t.time_at(off)
        header: dict[str, Any] = {
            "terminal_id": t.terminal_id,
            "stream_off": off,
            "length": len(data),
            "t_shim_ns": wall,
            "redactions": [r.model_dump() for r in reds],
        }
        if mono is not None:
            header["mono_ns"] = mono
        # Empfangszeit des Rahmens, nicht die Commit-Zeit (der Rückhalt kann warten)
        return AppendItem("term.out", header, data, origin="shim", terminal_id=t.terminal_id,
                          stream_off=off, ts_utc_ns=recv or None)

    @staticmethod
    def _event_off(e: _Event) -> int:
        off = e.item.stream_off
        return off if isinstance(off, int) else 0

    def _put_event(self, e: _Event, items: list[AppendItem], marks: list[MarkContext | None]) -> None:
        items.append(e.item)
        if e.item.kind == "term.mark":
            marks.append(e.mark_ctx)

    def _put_chunks(self, t: Terminal, chunks: list[Chunk], items: list[AppendItem],
                    marks: list[MarkContext | None]) -> None:
        """Ausgabe-Stücke ins Journal; wartende Events an ihrer Stromposition dazwischen."""
        q = self._deferred.get(t.terminal_id)
        for off, data, reds in chunks:
            while q:
                x = self._event_off(q[0])
                if x > off + len(data):
                    break
                if x > off:
                    cut = x - off
                    items.append(self._out_item(t, (off, data[:cut], _clip(reds, off, x))))
                    reds = _clip(reds, x, off + len(data))
                    data, off = data[cut:], x
                self._put_event(q.pop(0), items, marks)
            if data:
                items.append(self._out_item(t, (off, data, reds)))
        self._release(t, items, marks)

    def _release(self, t: Terminal, items: list[AppendItem], marks: list[MarkContext | None]) -> None:
        q = self._deferred.get(t.terminal_id)
        if not q:
            self._deferred.pop(t.terminal_id, None)
            return
        pend = self.d.redactor.pending(t.terminal_id)
        limit = pend[0] if pend is not None else None
        while q and (limit is None or self._event_off(q[0]) <= limit):
            self._put_event(q.pop(0), items, marks)
        if not q:
            self._deferred.pop(t.terminal_id, None)

    def flush_now(self) -> list[EventRecord]:
        """Schreibt alles Eingereihte synchron. Gibt die neuen Records zurück."""
        project = self.d.project
        pending, self.pending, self.pending_bytes = self.pending, [], 0
        if project is None:
            self._deferred.clear()
            if pending:
                log.warning("Writer: %d Einträge ohne offenes Projekt verworfen", len(pending))
                for e in pending:
                    if isinstance(e, _Out):
                        self._forget(e.t.terminal_id, e.off + len(e.data))
                self.committed_gen += 1
                self.d.advance_acks()
            return []
        journal = project.journal
        if self._carry and self._carry_journal is not journal:
            self.drop_carry()
        items: list[AppendItem] = list(self._carry)
        marks: list[MarkContext | None] = list(self._carry_marks)
        redactor = self.d.redactor
        for e in pending:
            if isinstance(e, _Out):
                self._put_chunks(e.t, redactor.feed(e.t.terminal_id, e.off, e.data), items, marks)
            elif isinstance(e, _Flush):
                self._put_chunks(e.t, redactor.flush(e.t.terminal_id, keep_prefix=e.soft), items, marks)
            elif e.t is None:
                self._put_event(e, items, marks)
            else:
                tid = e.t.terminal_id
                pend = redactor.pending(tid)
                if tid in self._deferred or (pend is not None and self._event_off(e) > pend[0]):
                    self._deferred.setdefault(tid, []).append(e)  # wartet hinter dem Rückhalt
                else:
                    self._put_event(e, items, marks)
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


def _clip(reds: list[Any], start: int, end: int) -> list[Any]:
    """Redaktionsvermerke auf den Bereich ``[start, end)`` beschneiden."""
    out = []
    for r in reds:
        a, b = max(r.start, start), min(r.end, end)
        if a < b:
            out.append(r.model_copy(update={"start": a, "end": b}))
    return out
