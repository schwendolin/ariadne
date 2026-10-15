"""Einheiten in ``derived.db`` schreiben und lesen (Architektur 5.4).

:func:`sync_layout` gleicht das Layout eines Terminals mit der Datenbank ab:
``cmd_block``, ``ctx_span``, ``unit`` und die Zeilen. Eine Zeile gehört zur
Einheit, in deren Bereich ihr ``raw_start`` liegt. Neue Zeilen werden direkt mit
ihrer Einheit eingefügt (im Normalfall wachsen nur die letzten Einheiten).
Ändert ein rückwirkender Entscheid Grenzen, werden die betroffenen Einheiten
neu nummeriert.

``unit_fts`` pflegt dieses Modul selbst, gebündelt pro Durchgang statt per
Trigger (ein Vielfaches schneller). Prompt-Echo-Zeilen werden nie indexiert.
"""

from __future__ import annotations

import bisect
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ariadne.ingest.normalizer import NormLine, colmap_to_json, sgr_from_json, sgr_to_json
from ariadne.ingest.seg_activity import write_activity
from ariadne.ingest.seg_stream import INF, TermStream
from ariadne.ingest.segmenter import Layout, UnitPlan
from ariadne.ingest.units import Unit, line_visible
from ariadne.parsers.api import Line

__all__ = ["SyncResult", "sync_layout", "load_unit", "save_unit", "delete_unit", "store_file_lines",
           "reindex_fts"]

_UNIT_COLS = (
    "unit_id", "kind", "terminal_id", "cmd_id", "span_id", "start_off", "end_off", "argv", "cmd_text",
    "exit_code", "cwd", "context", "path", "mime", "sniff", "blob_id", "sha256", "size", "ts_utc_ns",
    "ts_end_ns", "state", "flags", "sig", "line_count", "vis_count", "event_seq", "mono_ns", "boot_id",
)
_INSERT_LINE = ("INSERT INTO unit_line(unit_id, pos, idx, terminal_id, n, text, raw_start, raw_end, flags, "
                "sgr, colmap) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")


@dataclass
class SyncResult:
    complete: list[str] = field(default_factory=list)  # fertig und vollständig normalisiert
    removed: list[str] = field(default_factory=list)
    changed_blocks: list[str] = field(default_factory=list)


def save_unit(conn: Any, row: Mapping[str, Any]) -> None:
    cols = ", ".join(_UNIT_COLS)
    marks = ", ".join("?" for _ in _UNIT_COLS)
    updates = ", ".join(f"{c} = excluded.{c}" for c in _UNIT_COLS if c != "unit_id")
    conn.execute(f"INSERT INTO unit({cols}) VALUES ({marks}) "  # noqa: S608 - feste Spaltennamen
                 f"ON CONFLICT(unit_id) DO UPDATE SET {updates}", tuple(row.get(c) for c in _UNIT_COLS))


def delete_unit(conn: Any, unit_id: str) -> None:
    conn.execute("DELETE FROM unit WHERE unit_id = ?", (unit_id,))
    conn.execute("DELETE FROM parse_failure WHERE unit_id = ?", (unit_id,))


def _upsert(conn: Any, table: str, key: str, row: Mapping[str, Any]) -> None:
    cols = list(row)
    updates = ", ".join(f"{c} = excluded.{c}" for c in cols if c != key)
    conn.execute(f"INSERT INTO {table}({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)}) "  # noqa: S608
                 f"ON CONFLICT({key}) DO UPDATE SET {updates}", tuple(row[c] for c in cols))


# --------------------------------------------------------------------------- Volltext


def _index_stream(conn: Any, tid: str, n_from: int, n_to: int) -> None:
    conn.execute("INSERT INTO unit_fts(rowid, text) SELECT id, text FROM unit_line WHERE terminal_id = ? "
                 "AND n BETWEEN ? AND ? AND (flags & 1) = 0", (tid, n_from, n_to))


def reindex_fts(conn: Any) -> None:
    """Volltextindex vollständig neu aufbauen (ohne Prompt-Echo)."""
    conn.execute("INSERT INTO unit_fts(unit_fts) VALUES ('delete-all')")
    conn.execute("INSERT INTO unit_fts(rowid, text) SELECT id, text FROM unit_line WHERE (flags & 1) = 0")


# --------------------------------------------------------------------------- Zeilen


def _line_row(unit_id: str, pos: int, idx: int | None, tid: str | None, n: int | None,
              ln: NormLine) -> tuple[Any, ...]:
    return (unit_id, pos, idx, tid, n, ln.text, ln.raw_start, ln.raw_end, ln.flags, sgr_to_json(ln.sgr),
            colmap_to_json(ln.colmap))


def _flush_lines(conn: Any, ts: TermStream, layout: Layout, counts: dict[str, list[int]]) -> int:
    """Speichert gepufferte Zeilen mit ihrer Einheit. Gibt die bisher höchste Nummer zurück."""
    tid = layout.terminal_id
    before = ts.max_n
    buf = ts.take_lines()
    if not buf:
        return before
    replay = [(n, ln) for n, ln in buf if n <= before]
    if replay:  # nach einem Neustart neu entstanden: nur der Inhalt, Zuordnung bleibt
        conn.executemany("UPDATE unit_line SET raw_start = ?, raw_end = ?, flags = ?, sgr = ?, colmap = ? "
                         "WHERE terminal_id = ? AND n = ? AND text = ?",
                         [(ln.raw_start, ln.raw_end, ln.flags, sgr_to_json(ln.sgr), colmap_to_json(ln.colmap),
                           tid, n, ln.text) for n, ln in replay])
    new = [(n, ln) for n, ln in buf if n > before]
    if not new:
        return before
    starts = [u.start for u in layout.units]
    rows = []
    for n, ln in new:
        i = max(0, bisect.bisect_right(starts, ln.raw_start) - 1)
        uid = layout.units[i].unit_id if layout.units else ""
        c = counts.setdefault(uid, [0, 0])
        vis = line_visible(ln.flags)
        rows.append(_line_row(uid, c[0], c[1] if vis else None, tid, n, ln))
        c[0] += 1
        if vis:
            c[1] += 1
    conn.executemany(_INSERT_LINE, rows)
    _index_stream(conn, tid, new[0][0], new[-1][0])
    ts.max_n = new[-1][0]
    return before


def _renumber(conn: Any, tid: str, unit_id: str, start: int, end: int) -> tuple[int, int]:
    rows = conn.execute("SELECT id, flags FROM unit_line WHERE terminal_id = ? AND raw_start >= ? "
                        "AND raw_start < ? ORDER BY n", (tid, start, end)).fetchall()
    updates = []
    pos = idx = 0
    for line_id, flags in rows:
        vis = line_visible(int(flags))
        updates.append((unit_id, pos, idx if vis else None, line_id))
        pos += 1
        if vis:
            idx += 1
    if updates:
        conn.executemany("UPDATE unit_line SET unit_id = ?, pos = ?, idx = ? WHERE id = ?", updates)
    return pos, idx


def _unit_row(ts: TermStream, u: UnitPlan, state: str, counts: Sequence[int]) -> dict[str, Any]:
    b = u.block
    command = u.kind == "command" and b is not None
    end = u.end if u.end is not None else None
    if b is not None and command:
        t0, mono, boot = b.ts_start, b.mono_start, b.boot
    else:
        t0 = ts.time_at(u.start) or (b.ts_start if b is not None else 0)
        mono, boot = ts.mono_at(u.start)
    t1 = ts.time_at(end) if end is not None else None
    if b is not None and b.ts_end is not None and end is not None and b.end_off == end:
        t1 = b.ts_end
    seq = (b.d_seq or b.c_seq) if b is not None and u.final else ts.last_seq
    return {
        "unit_id": u.unit_id, "kind": u.kind, "terminal_id": u.terminal_id, "cmd_id": u.cmd_id,
        "span_id": u.span.span_id, "start_off": u.start, "end_off": end,
        "argv": json.dumps(list(b.argv) if command and b is not None else [], ensure_ascii=False),
        "cmd_text": b.text if command and b is not None else None,
        "exit_code": b.exit if command and b is not None else None,
        "cwd": b.cwd if b is not None else None,
        "context": json.dumps(u.span.context(), ensure_ascii=False, sort_keys=True),
        "ts_utc_ns": t0, "ts_end_ns": t1, "state": state, "flags": json.dumps(sorted(u.flags)),
        "sig": u.sig(), "line_count": counts[0], "vis_count": counts[1], "event_seq": seq,
        "mono_ns": mono, "boot_id": boot,
    }


# --------------------------------------------------------------------------- Abgleich


def _sync_rows(conn: Any, ts: TermStream, layout: Layout, res: SyncResult) -> None:
    tid = layout.terminal_id
    prev = ts.prev_rows
    seen: set[str] = set()
    for b in layout.blocks:
        row = b.row()
        key = "b:" + b.cmd_id
        seen.add(key)
        if prev.get(key) != row:
            _upsert(conn, "cmd_block", "cmd_id", row)
            prev[key] = row
            res.changed_blocks.append(b.cmd_id)
    for sp in layout.spans:
        row = sp.row()
        key = "s:" + sp.span_id
        seen.add(key)
        if prev.get(key) != row:
            _upsert(conn, "ctx_span", "span_id", row)
            prev[key] = row
    for key in [k for k in prev if k not in seen]:
        if key.startswith("b:"):
            conn.execute("DELETE FROM cmd_block WHERE cmd_id = ?", (key[2:],))
            conn.execute("DELETE FROM activity WHERE cmd_id = ?", (key[2:],))
        else:
            conn.execute("DELETE FROM ctx_span WHERE span_id = ?", (key[2:],))
        del prev[key]
    if not ts.db_checked:  # nach einem Neustart: Reste aus der Datenbank entfernen
        ids = {b.cmd_id for b in layout.blocks}
        for (cid,) in conn.execute("SELECT cmd_id FROM cmd_block WHERE terminal_id = ?", (tid,)).fetchall():
            if cid not in ids:
                conn.execute("DELETE FROM cmd_block WHERE cmd_id = ?", (cid,))
                conn.execute("DELETE FROM activity WHERE cmd_id = ?", (cid,))
        sids = {s.span_id for s in layout.spans}
        for (sid,) in conn.execute("SELECT span_id FROM ctx_span WHERE terminal_id = ?", (tid,)).fetchall():
            if sid not in sids:
                conn.execute("DELETE FROM ctx_span WHERE span_id = ?", (sid,))
        ts.db_checked = True


def sync_layout(conn: Any, ts: TermStream, layout: Layout, *, activity: Any = None) -> SyncResult:
    """Schreibt Befehle, Spannen, Einheiten und Zeilen eines Terminals.

    ``activity(block, layout)`` liefert die Zeile fürs Aktivitätsprotokoll
    (oder ``None``); sie wird nur für geänderte Befehle aufgerufen.
    """
    tid = layout.terminal_id
    res = SyncResult()
    _sync_rows(conn, ts, layout, res)
    if activity is not None:
        by_id = {b.cmd_id: b for b in layout.blocks}
        for cid in res.changed_blocks:
            row = activity(by_id[cid], layout)
            if row is not None:
                write_activity(conn, row)
    old = {
        r[0]: (r[1], r[2], int(r[3]), int(r[4]), r[5])
        for r in conn.execute("SELECT unit_id, start_off, end_off, line_count, vis_count, state FROM unit "
                              "WHERE terminal_id = ? AND kind IN ('command', 'segment')", (tid,))
    }
    counts: dict[str, list[int]] = {uid: [o[2], o[3]] for uid, o in old.items()}
    stored_max = _flush_lines(conn, ts, layout, counts)
    final_off = ts.final_off
    for u in layout.units:
        end_eff = u.end if u.end is not None else INF
        o = old.get(u.unit_id)
        o_end = None if o is None else (o[1] if o[1] is not None else INF)
        if o is not None and o_end == end_eff:
            rebuild = False
        elif o is not None and o_end is not None and o_end > end_eff:
            rebuild = True  # geschrumpft: Zeilen gehen an andere Einheiten
        else:
            lo = u.start if o is None else (o_end if o_end is not None else u.start)
            rebuild = stored_max >= 0 and conn.execute(
                "SELECT 1 FROM unit_line WHERE terminal_id = ? AND raw_start >= ? AND raw_start < ? "
                "AND n <= ? LIMIT 1", (tid, lo, end_eff, stored_max)).fetchone() is not None
        c = counts.setdefault(u.unit_id, [0, 0])
        if rebuild:
            c[:] = list(_renumber(conn, tid, u.unit_id, u.start, end_eff))
        if u.final and end_eff <= final_off:
            state = "final"
            res.complete.append(u.unit_id)
        else:
            state = "provisional" if o is not None and o[4] == "provisional" else "open"
        save_unit(conn, _unit_row(ts, u, state, c))
    keep = {u.unit_id for u in layout.units}
    for uid in old:
        if uid not in keep:
            delete_unit(conn, uid)
            res.removed.append(uid)
    return res


# --------------------------------------------------------------------------- Dateien und Laden


def store_file_lines(conn: Any, unit_id: str, lines: Sequence[NormLine]) -> tuple[int, int]:
    conn.execute("INSERT INTO unit_fts(unit_fts, rowid, text) SELECT 'delete', id, text FROM unit_line "
                 "WHERE unit_id = ? AND (flags & 1) = 0", (unit_id,))
    conn.execute("DELETE FROM unit_line WHERE unit_id = ?", (unit_id,))
    rows = []
    idx = 0
    for pos, ln in enumerate(lines):
        vis = line_visible(ln.flags)
        rows.append(_line_row(unit_id, pos, idx if vis else None, None, None, ln))
        if vis:
            idx += 1
    conn.executemany(_INSERT_LINE, rows)
    conn.execute("INSERT INTO unit_fts(rowid, text) SELECT id, text FROM unit_line WHERE unit_id = ? "
                 "AND (flags & 1) = 0", (unit_id,))
    return len(rows), idx


def _lines(conn: Any, unit_id: str) -> tuple[list[Line], list[int]]:
    lines: list[Line] = []
    flags: list[int] = []
    for text, a, b, f, sgr in conn.execute("SELECT text, raw_start, raw_end, flags, sgr FROM unit_line "
                                           "WHERE unit_id = ? ORDER BY pos", (unit_id,)):
        f = int(f)
        lines.append(Line(text, int(a), int(b), sgr_from_json(sgr), bool(f & 1), bool(f & 2), bool(f & 4)))
        flags.append(f)
    return lines, flags


def load_unit(conn: Any, unit_id: str, *, data: bytes | None = None,
              extra_lines: Iterable[NormLine] = ()) -> Unit | None:
    """Einheit aus ``derived.db`` (mit Zeilen). ``extra_lines`` hängt vorläufige Zeilen an."""
    row = conn.execute(f"SELECT {', '.join(_UNIT_COLS)} FROM unit WHERE unit_id = ?",  # noqa: S608
                       (unit_id,)).fetchone()
    if row is None:
        return None
    r = dict(zip(_UNIT_COLS, row, strict=True))
    lines, flags = _lines(conn, unit_id)
    for ln in extra_lines:
        lines.append(ln.to_line())
        flags.append(ln.flags)
    return Unit(
        unit_id=r["unit_id"], kind=r["kind"], ts_utc_ns=int(r["ts_utc_ns"] or 0),
        argv=tuple(json.loads(r["argv"] or "[]")), cmd_text=r["cmd_text"], exit_code=r["exit_code"],
        cwd=r["cwd"], context=json.loads(r["context"] or "{}"), all_lines=tuple(lines),
        all_flags=tuple(flags),
        path=r["path"], mime=r["mime"], sniff=r["sniff"], terminal_id=r["terminal_id"], cmd_id=r["cmd_id"],
        span_id=r["span_id"], start_off=r["start_off"], end_off=r["end_off"], ts_end_ns=r["ts_end_ns"],
        blob_id=r["blob_id"], sha256=r["sha256"], size=r["size"], flags=tuple(json.loads(r["flags"] or "[]")),
        state=r["state"], data=data, mono_ns=r["mono_ns"], boot_id=r["boot_id"],
    )
