"""Writer des Daemons (Architektur 5.4): bündelt, schwärzt, schreibt, bestätigt.

Ein Commit alle 200 ms oder ab 256 KiB. Reihenfolge pro Commit:

1. ``term.out`` läuft durch den Redaktor (eigene Secrets, längenerhaltend).
   Vor jedem anderen Event eines Terminals wird dessen Rückhalt freigegeben,
   damit Journal- und Strom-Reihenfolge übereinstimmen.
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

    def add_flush(self, t: Terminal) -> None:
        self.pending.append(_Flush(t))

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
        wall, mono = t.time_at(off)
        header: dict[str, Any] = {
            "terminal_id": t.terminal_id,
            "stream_off": off,
            "length": len(data),
            "t_shim_ns": wall,
            "redactions": [r.model_dump() for r in reds],
        }
        if mono is not None:
            header["mono_ns"] = mono
        return AppendItem("term.out", header, data, origin="shim", terminal_id=t.terminal_id,
                          stream_off=off)

    def flush_now(self) -> list[EventRecord]:
        """Schreibt alles Eingereihte synchron. Gibt die neuen Records zurück."""
        project = self.d.project
        pending, self.pending, self.pending_bytes = self.pending, [], 0
        if project is None:
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
                items.extend(self._out_item(e.t, c) for c in redactor.feed(e.t.terminal_id, e.off, e.data))
            elif isinstance(e, _Flush):
                items.extend(self._out_item(e.t, c) for c in redactor.flush(e.t.terminal_id))
            else:
                if e.t is not None:
                    items.extend(self._out_item(e.t, c) for c in redactor.flush(e.t.terminal_id))
                items.append(e.item)
                if e.item.kind == "term.mark":
                    marks.append(e.mark_ctx)
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
