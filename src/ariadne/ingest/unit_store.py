"""Einheiten in ``derived.db`` schreiben und lesen (Architektur 5.4).

:func:`sync_layout` gleicht das Layout eines Terminals mit der Datenbank ab:
``cmd_block``, ``ctx_span``, ``unit`` und die Zuordnung der Zeilen. Eine Zeile
gehört zur Einheit, in deren Bereich ihr ``raw_start`` liegt. Im Normalfall
wachsen nur die letzten Einheiten (neue Zeilen werden angehängt); ändert ein
rückwirkender Entscheid Grenzen, werden die betroffenen Einheiten neu
nummeriert.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ariadne.ingest.normalizer import NormLine, sgr_from_json
from ariadne.ingest.seg_stream import INF, TermStream
from ariadne.ingest.segmenter import Layout, UnitPlan
from ariadne.ingest.units import Unit, line_visible
from ariadne.parsers.api import Line

__all__ = ["SyncResult", "sync_layout", "load_unit", "save_unit", "delete_unit", "store_file_lines"]

_UNIT_COLS = (
    "unit_id", "kind", "terminal_id", "cmd_id", "span_id", "start_off", "end_off", "argv", "cmd_text",
    "exit_code", "cwd", "context", "path", "mime", "sniff", "blob_id", "sha256", "size", "ts_utc_ns",
    "ts_end_ns", "state", "flags", "sig", "line_count", "vis_count", "event_seq",
)


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


def _assign(conn: Any, tid: str, unit_id: str, start: int, end: int, rebuild: bool,
            counts: tuple[int, int]) -> tuple[int, int]:
    if rebuild:
        rows = conn.execute("SELECT id, flags FROM unit_line WHERE terminal_id = ? AND raw_start >= ? "
                            "AND raw_start < ? ORDER BY n", (tid, start, end)).fetchall()
        pos, idx = 0, 0
    else:
        rows = conn.execute("SELECT id, flags FROM unit_line WHERE terminal_id = ? AND unit_id = '' "
                            "AND raw_start >= ? AND raw_start < ? ORDER BY n", (tid, start, end)).fetchall()
        pos, idx = counts
    updates = []
    for line_id, flags in rows:
        vis = line_visible(int(flags))
        updates.append((unit_id, pos, idx if vis else None, line_id))
        pos += 1
        if vis:
            idx += 1
    if updates:
        conn.executemany("UPDATE unit_line SET unit_id = ?, pos = ?, idx = ? WHERE id = ?", updates)
    return pos, idx


def _unit_row(ts: TermStream, u: UnitPlan, state: str, counts: tuple[int, int]) -> dict[str, Any]:
    b = u.block
    command = u.kind == "command" and b is not None
    end = u.end if u.end is not None else None
    if b is not None and command:
        t0 = b.ts_start
    else:
        t0 = ts.time_at(u.start) or (b.ts_start if b is not None else 0)
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
    }


def sync_layout(conn: Any, ts: TermStream, layout: Layout, *, activity: Any = None) -> SyncResult:
    """Schreibt Befehle, Spannen und Einheiten eines Terminals und ordnet Zeilen zu.

    ``activity(block, layout)`` liefert die Zeile fürs Aktivitätsprotokoll
    (oder ``None``); sie wird nur für geänderte Befehle aufgerufen.
    """
    tid = layout.terminal_id
    res = SyncResult()
    prev = ts.prev_rows
    # Befehle
    seen: set[str] = set()
    for b in layout.blocks:
        row = b.row()
        key = "b:" + b.cmd_id
        seen.add(key)
        if prev.get(key) != row:
            _upsert(conn, "cmd_block", "cmd_id", row)
            prev[key] = row
            res.changed_blocks.append(b.cmd_id)
    # Spannen
    for sp in layout.spans:
        row = sp.row()
        key = "s:" + sp.span_id
        seen.add(key)
        if prev.get(key) != row:
            _upsert(conn, "ctx_span", "span_id", row)
            prev[key] = row
    for key in [k for k in prev if k[:2] in ("b:", "s:") and k not in seen]:
        if key.startswith("b:"):
            conn.execute("DELETE FROM cmd_block WHERE cmd_id = ?", (key[2:],))
            conn.execute("DELETE FROM activity WHERE cmd_id = ?", (key[2:],))
        else:
            conn.execute("DELETE FROM ctx_span WHERE span_id = ?", (key[2:],))
        del prev[key]
    if not prev.get("_loaded"):
        # nach einem Neustart: Reste aus der Datenbank entfernen
        ids = {b.cmd_id for b in layout.blocks}
        for (cid,) in conn.execute("SELECT cmd_id FROM cmd_block WHERE terminal_id = ?", (tid,)).fetchall():
            if cid not in ids:
                conn.execute("DELETE FROM cmd_block WHERE cmd_id = ?", (cid,))
                conn.execute("DELETE FROM activity WHERE cmd_id = ?", (cid,))
        sids = {s.span_id for s in layout.spans}
        for (sid,) in conn.execute("SELECT span_id FROM ctx_span WHERE terminal_id = ?", (tid,)).fetchall():
            if sid not in sids:
                conn.execute("DELETE FROM ctx_span WHERE span_id = ?", (sid,))
        prev["_loaded"] = {"v": 1}
    if activity is not None:
        by_id = {b.cmd_id: b for b in layout.blocks}
        for cid in res.changed_blocks:
            row = activity(by_id[cid], layout)
            if row is not None:
                from ariadne.ingest.seg_activity import write_activity

                write_activity(conn, row)
    # Einheiten
    old = {
        r[0]: (r[1], r[2], int(r[3]), int(r[4]), r[5])
        for r in conn.execute("SELECT unit_id, start_off, end_off, line_count, vis_count, state FROM unit "
                              "WHERE terminal_id = ? AND kind IN ('command', 'segment')", (tid,))
    }
    final_off = ts.final_off
    new_from = ts.min_new_raw
    for u in layout.units:
        end_eff = u.end if u.end is not None else INF
        o = old.get(u.unit_id)
        counts = (o[2], o[3]) if o is not None else (0, 0)
        o_end = (o[1] if o[1] is not None else INF) if o is not None else None
        if o is not None and o_end == end_eff:
            rebuild = False
            touch = new_from is not None and new_from < end_eff
        elif o is not None and o_end is not None and o_end > end_eff:
            rebuild = touch = True  # geschrumpft
        else:
            foreign = conn.execute(
                "SELECT 1 FROM unit_line WHERE terminal_id = ? AND raw_start >= ? AND raw_start < ? "
                "AND unit_id NOT IN ('', ?) LIMIT 1", (tid, u.start, end_eff, u.unit_id)).fetchone()
            rebuild = foreign is not None
            touch = True
        if touch:
            counts = _assign(conn, tid, u.unit_id, u.start, end_eff, rebuild, counts)
        complete = u.final and end_eff <= final_off
        if complete:
            state = "final"
            res.complete.append(u.unit_id)
        else:
            state = "provisional" if o is not None and o[4] == "provisional" else "open"
        save_unit(conn, _unit_row(ts, u, state, counts))
    keep = {u.unit_id for u in layout.units}
    for uid in old:
        if uid not in keep:
            delete_unit(conn, uid)
            res.removed.append(uid)
    ts.min_new_raw = None
    ts.new_lines = False
    return res


def store_file_lines(conn: Any, unit_id: str, lines: Sequence[NormLine]) -> tuple[int, int]:
    conn.execute("DELETE FROM unit_line WHERE unit_id = ?", (unit_id,))
    rows = []
    idx = 0
    for pos, ln in enumerate(lines):
        vis = line_visible(ln.flags)
        from ariadne.ingest.normalizer import colmap_to_json, sgr_to_json

        rows.append((unit_id, pos, idx if vis else None, ln.text, ln.raw_start, ln.raw_end, ln.flags,
                     sgr_to_json(ln.sgr), colmap_to_json(ln.colmap)))
        if vis:
            idx += 1
    conn.executemany("INSERT INTO unit_line(unit_id, pos, idx, terminal_id, n, text, raw_start, raw_end, flags, "
                     "sgr, colmap) VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?)", rows)
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
        cwd=r["cwd"], context=json.loads(r["context"] or "{}"), all_lines=tuple(lines), all_flags=tuple(flags),
        path=r["path"], mime=r["mime"], sniff=r["sniff"], terminal_id=r["terminal_id"], cmd_id=r["cmd_id"],
        span_id=r["span_id"], start_off=r["start_off"], end_off=r["end_off"], ts_end_ns=r["ts_end_ns"],
        blob_id=r["blob_id"], sha256=r["sha256"], size=r["size"], flags=tuple(json.loads(r["flags"] or "[]")),
        state=r["state"], data=data,
    )
