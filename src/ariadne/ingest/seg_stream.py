"""Strom eines Terminals in der Auswertung: Bytes -> Normalizer -> Zeilen (Architektur 5.4, 5.5).

:class:`TermStream` hält pro Terminal den Normalizer und die Ereignisse für
den Segmenter. Bytes werden erst normalisiert, wenn feststeht, dass keine
Grenze mehr davor kommt: Der Shim schickt einen Marker immer nach den Bytes
davor, aber vor allen Bytes eines späteren Lesevorgangs. Darum ist alles vor
dem Anfang eines neuen Chunks bzw. vor dem Offset eines neuen Ereignisses
sicher. Gültige Marker, Schnappschüsse und Lücken sind Grenzen des Normalizers
(Zeilenende, Zustand zurückgesetzt); Entscheide sind keine Grenzen, sie wirken
über ``raw_start`` der Zeilen.

Zeilen werden mit fortlaufender Nummer ``n`` sofort in ``unit_line``
geschrieben (noch ohne Einheit, ``unit_id = ''``) und erst nach der
Segmentierung einer Einheit zugeordnet. Nach einem Neustart setzt
:meth:`TermStream.load` an der letzten Grenze wieder auf; die gleichen Zeilen
entstehen mit den gleichen Nummern und werden idempotent überschrieben.
"""

from __future__ import annotations

import bisect
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ariadne.ingest.normalizer import Normalizer, NormLine, colmap_to_json, sgr_to_json
from ariadne.ingest.segmenter import SEG_KINDS, SegEvent, event_offset

__all__ = ["TermStream", "BOUNDARY_KINDS", "INF"]

INF = 1 << 62
BOUNDARY_KINDS = frozenset({"term.open", "term.ctx_snapshot", "term.gap", "term.close", "term.resize",
                            "term.mark"})

_UPSERT_LINE = (
    "INSERT INTO unit_line(unit_id, pos, idx, terminal_id, n, text, raw_start, raw_end, flags, sgr, colmap) "
    "VALUES ('', -1, NULL, ?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(terminal_id, n) DO UPDATE SET text = excluded.text, raw_start = excluded.raw_start, "
    "raw_end = excluded.raw_end, flags = excluded.flags, sgr = excluded.sgr, colmap = excluded.colmap"
)


@dataclass
class _Chunk:
    off: int
    data: bytes


def _is_boundary(ev: SegEvent) -> bool:
    if ev.kind not in BOUNDARY_KINDS or ev.off is None:
        return False
    if ev.kind == "term.mark":
        mark = ev.header.get("mark")
        return mark == "C" or (mark in ("A", "D") and ev.header.get("fg_shell") is True)
    return True


class TermStream:
    def __init__(self, conn: Any, terminal_id: str) -> None:
        self.conn = conn
        self.tid = terminal_id
        self.events: list[SegEvent] = []
        self.chunk_offs: list[int] = []
        self.chunk_ts: list[int] = []
        self.pending: list[_Chunk] = []
        self.bounds: list[SegEvent] = []
        self.norm: Normalizer | None = None
        self.cols = 0
        self.rows = 24
        self.stream_end = 0
        self.last_out_ns: int | None = None
        self.last_seq = 0
        self.closed = False
        self.finished = False
        self.operator_id: str | None = None
        self.next_n = 0
        self.norm_off: int | None = None
        self.norm_seq = 0
        self.norm_n = 0
        self.norm_prompt = False
        self.dirty = False  # Layout neu rechnen
        self.new_lines = False
        self.min_new_raw: int | None = None
        self.prev_rows: dict[str, dict[str, Any]] = {}
        self._replaying = False

    # ------------------------------------------------------------------ Eingang
    def add_chunk(self, seq: int, off: int, data: bytes | None, length: int, ts: int) -> None:
        """``term.out``. ``data=None`` (redigiert) zählt als Lücke."""
        self.last_seq = max(self.last_seq, seq)
        if not self._replaying:
            self.conn.execute("INSERT OR IGNORE INTO seg_chunk(terminal_id, off, len, seq, ts_utc_ns) "
                              "VALUES (?, ?, ?, ?, ?)", (self.tid, off, length, seq, ts))
            self._index_chunk(off, ts)
        self.last_out_ns = ts
        end = off + length
        if end <= self.stream_end:
            return  # schon gesehen
        if data is not None:
            if off < self.stream_end:
                data = data[self.stream_end - off :]
                off = self.stream_end
            self._ensure_norm(off)
            self._advance(off)
            self.pending.append(_Chunk(off, bytes(data)))
        else:
            self._ensure_norm(off)
            self._advance(off)
        self.stream_end = end
        self.dirty = True

    def add_event(self, ev: SegEvent) -> None:
        if ev.kind not in SEG_KINDS:
            return
        self.last_seq = max(self.last_seq, ev.seq)
        if not self._replaying:
            self.conn.execute(
                "INSERT OR IGNORE INTO seg_event(terminal_id, seq, kind, off, ts_utc_ns, operator_id, "
                "header) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self.tid, ev.seq, ev.kind, ev.off, ev.ts, ev.operator_id,
                 json.dumps(dict(ev.header), ensure_ascii=False, sort_keys=True)),
            )
            self.events.append(ev)
        if ev.kind == "term.open":
            self.operator_id = ev.operator_id or self.operator_id
            self._size(ev.header)
        if ev.kind == "term.close":
            self.closed = True
        self.dirty = True
        if not _is_boundary(ev) or ev.off is None:
            return
        self._ensure_norm(ev.off)
        assert self.norm is not None
        if ev.off < self.norm.offset:
            return  # liegt in bereits normalisierten Bytes: keine Zeilengrenze mehr
        i = len(self.bounds)
        while i and (self.bounds[i - 1].off or 0) > ev.off:
            i -= 1
        self.bounds.insert(i, ev)
        self._advance(ev.off)

    # ------------------------------------------------------------------ Normalizer
    def _size(self, h: Any) -> None:
        cols, rows = h.get("cols"), h.get("rows")
        if isinstance(cols, int) and not isinstance(cols, bool):
            self.cols = cols
        if isinstance(rows, int) and not isinstance(rows, bool) and rows > 0:
            self.rows = rows

    def _ensure_norm(self, off: int) -> None:
        if self.norm is None:
            self.norm = Normalizer(off, cols=self.cols, rows=self.rows)
            self.norm_off, self.norm_n = off, self.next_n
            self.stream_end = max(self.stream_end, off)  # Bytes vor dem Aufnahmebeginn kommen nie

    def _feed_bytes(self, stop: int) -> None:
        norm = self.norm
        assert norm is not None
        while self.pending and self.pending[0].off < stop:
            ch = self.pending[0]
            take = stop - ch.off
            if take >= len(ch.data):
                self.pending.pop(0)
                norm.feed(ch.data, ch.off)
            else:
                norm.feed(ch.data[:take], ch.off)
                self.pending[0] = _Chunk(ch.off + take, ch.data[take:])
        self._collect()

    def _advance(self, limit: int) -> None:
        """Füttert alle Bytes vor ``limit`` und wendet dabei fällige Grenzen an."""
        while True:
            nxt = self.bounds[0] if self.bounds else None
            if nxt is None or (nxt.off or 0) > limit:
                self._feed_bytes(limit)
                return
            off = nxt.off or 0
            self._feed_bytes(off)
            if off > self.stream_end and nxt.kind != "term.close":
                return  # Bytes bis zur Grenze fehlen noch
            self.bounds.pop(0)
            self._apply(nxt)

    def _apply(self, ev: SegEvent) -> None:
        norm = self.norm
        assert norm is not None and ev.off is not None
        if self.finished:
            return
        off = max(ev.off, norm.offset)
        if ev.kind == "term.resize":
            self._size(ev.header)
            norm.resize(self.cols, self.rows)
            return
        if ev.kind == "term.close":
            self._feed_bytes(INF)
            norm.finish()
            self.finished = True
            self._collect()
            return
        prompt: bool | None = False
        eol = False
        if ev.kind == "term.mark":
            mark = ev.header.get("mark")
            prompt = mark == "A"
            eol = mark == "D"
        if ev.kind == "term.open":
            self._size(ev.header)
            norm.resize(self.cols, self.rows)
        norm.boundary(off, prompt=prompt, eol_mark=eol)
        self._collect()
        self.norm_off, self.norm_seq, self.norm_n, self.norm_prompt = off, ev.seq, self.next_n, bool(prompt)

    def _collect(self) -> None:
        norm = self.norm
        if norm is None:
            return
        lines = norm.take_final()
        if lines:
            self._store(lines)

    def _store(self, lines: Iterable[NormLine]) -> None:
        rows = []
        for ln in lines:
            rows.append((self.tid, self.next_n, ln.text, ln.raw_start, ln.raw_end, ln.flags,
                         sgr_to_json(ln.sgr), colmap_to_json(ln.colmap)))
            if self.min_new_raw is None or ln.raw_start < self.min_new_raw:
                self.min_new_raw = ln.raw_start
            self.next_n += 1
        self.conn.executemany(_UPSERT_LINE, rows)
        self.new_lines = True
        self.dirty = True

    def force_feed(self) -> None:
        """Alles Empfangene normalisieren (nach langer Stille oder vor dem Schliessen)."""
        if self.norm is None:
            return
        self._advance(self.stream_end)
        self._feed_bytes(INF)

    def pending_lines(self) -> list[NormLine]:
        """Vorläufige Zeilen am Ende des Stroms (noch nicht endgültig)."""
        return self.norm.pending() if self.norm is not None and not self.finished else []

    @property
    def final_off(self) -> int:
        """Alle Zeilen, die vor diesem Offset beginnen, sind endgültig gespeichert."""
        if self.finished:
            return INF
        if self.norm is None:
            return self.stream_end
        offs = [self.norm.final_off]
        if self.pending:
            offs.append(self.pending[0].off)
        if self.bounds:
            offs.append(self.bounds[0].off or 0)
        return min(offs)

    # ------------------------------------------------------------------ Zeit
    def _index_chunk(self, off: int, ts: int) -> None:
        if not self.chunk_offs or off > self.chunk_offs[-1]:
            self.chunk_offs.append(off)
            self.chunk_ts.append(ts)

    def time_at(self, off: int) -> int | None:
        i = bisect.bisect_right(self.chunk_offs, off) - 1
        if i < 0:
            return self.chunk_ts[0] if self.chunk_ts else None
        return self.chunk_ts[i]

    # ------------------------------------------------------------------ Zustand
    def save(self) -> None:
        self.conn.execute(
            "INSERT INTO seg_term(terminal_id, operator_id, cols, rows, stream_end, last_out_ns, closed, "
            "norm_off, norm_seq, norm_n, norm_prompt, next_n) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(terminal_id) DO UPDATE SET operator_id = excluded.operator_id, "
            "cols = excluded.cols, rows = excluded.rows, stream_end = excluded.stream_end, "
            "last_out_ns = excluded.last_out_ns, closed = excluded.closed, norm_off = excluded.norm_off, "
            "norm_seq = excluded.norm_seq, "
            "norm_n = excluded.norm_n, norm_prompt = excluded.norm_prompt, next_n = excluded.next_n",
            (self.tid, self.operator_id, self.cols, self.rows, self.stream_end, self.last_out_ns,
             int(self.closed), self.norm_off, self.norm_seq, self.norm_n, int(self.norm_prompt), self.next_n),
        )

    @classmethod
    def load(cls, conn: Any, terminal_id: str, journal: Any, upto_seq: int) -> TermStream:
        """Stellt den Zustand nach einem Neustart her (setzt an der letzten Grenze auf)."""
        ts = cls(conn, terminal_id)
        row = conn.execute(
            "SELECT operator_id, cols, rows, closed, norm_off, norm_n, norm_prompt, norm_seq, last_out_ns "
            "FROM seg_term "
            "WHERE terminal_id = ?", (terminal_id,)).fetchone()
        for seq, kind, off, t, op, header in conn.execute(
                "SELECT seq, kind, off, ts_utc_ns, operator_id, header FROM seg_event WHERE terminal_id = ? "
                "ORDER BY seq", (terminal_id,)):
            ts.events.append(SegEvent(int(seq), kind, off, int(t), json.loads(header), op))
        for off, t in conn.execute("SELECT off, ts_utc_ns FROM seg_chunk WHERE terminal_id = ? ORDER BY off",
                                   (terminal_id,)):
            ts._index_chunk(int(off), int(t))
        if row is None:
            return ts
        ts.operator_id = row[0]
        ts.last_out_ns = row[8]
        norm_off, norm_n, norm_prompt, norm_seq = row[4], int(row[5]), bool(row[6]), int(row[7])
        ts.cols, ts.rows = int(row[1]), int(row[2])
        # Grösse und Ende so, wie sie an der Grenze galten
        for ev in ts.events:
            if ev.seq > norm_seq:
                break
            if ev.kind in ("term.open", "term.resize"):
                ts._size(ev.header)
            if ev.kind == "term.close":
                ts.closed = True
        if norm_off is None:
            return ts
        ts.next_n = norm_n
        ts.norm_off, ts.norm_seq, ts.norm_n, ts.norm_prompt = norm_off, norm_seq, norm_n, norm_prompt
        if ts.closed and any(e.kind == "term.close" and e.seq <= norm_seq for e in ts.events):
            ts.finished = True
        ts.norm = Normalizer(norm_off, cols=ts.cols, rows=ts.rows, prompt=norm_prompt)
        ts.stream_end = norm_off
        first = conn.execute("SELECT MIN(seq) FROM seg_chunk WHERE terminal_id = ? AND off + len > ?",
                             (terminal_id, norm_off)).fetchone()[0]
        records: list[tuple[int, Any]] = []
        if first is not None:
            for rec in journal.iter_events(int(first) - 1, kinds=["term.out"], terminal_id=terminal_id):
                if rec.seq > upto_seq:
                    break
                records.append((rec.seq, rec))
        records += [(ev.seq, ev) for ev in ts.events if norm_seq < ev.seq <= upto_seq]
        records.sort(key=lambda r: r[0])
        ts._replaying = True
        try:
            for seq, item in records:
                if isinstance(item, SegEvent):
                    ts.add_event(item)
                    continue
                off = int(item.stream_off)
                length = int(item.header.get("length", len(item.body or b"")))
                if seq < norm_seq:
                    # vor der Grenze empfangen: nur der Teil ab der Grenze ist offen
                    if item.body is not None and off + length > norm_off:
                        cut = max(0, norm_off - off)
                        ts.pending.append(_Chunk(off + cut, bytes(item.body[cut:])))
                    ts.stream_end = max(ts.stream_end, off + length)
                    continue
                ts.add_chunk(seq, off, item.body, length, item.ts_utc_ns)
        finally:
            ts._replaying = False
        ts.last_seq = max([ts.last_seq] + [e.seq for e in ts.events])
        ts.dirty = True
        return ts


def seg_event_from_record(rec: Any) -> SegEvent:
    h = dict(rec.header)
    off = event_offset(rec.kind, h)
    if off is None and rec.stream_off is not None and rec.kind.startswith("term."):
        off = int(rec.stream_off)
    return SegEvent(rec.seq, rec.kind, off, rec.ts_utc_ns, h, rec.operator_id)


__all__.append("seg_event_from_record")
