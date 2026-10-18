"""Vorläufige Zeilen offener Einheiten für Leser im Thread der Auswertung (web-api.md 18.12).

Eine offene Einheit (laufender Listener, Remote-Segment vor 10 min Stille) wertet die Pipeline
vorläufig aus, mit den Zeilen, die der Normalisierer noch nicht endgültig gespeichert hat
(:meth:`ariadne.ingest.seg_stream.TermStream.pending_lines`, :meth:`Pipeline._provisional`). In
``unit_line`` stehen sie erst später. Wer dieselben Zeilen zeigen will (Logauszug «Darum
mehrdeutig» am Kontextvorschlag, Belegansicht einer offenen Einheit), bekommt sie hier: Der
:class:`~ariadne.daemon.ingest.IngestService` bindet die Pipeline für die Dauer einer Abfrage an
den Thread der Auswertung (:func:`bound`). Nichts davon wird gespeichert; ohne gebundene Pipeline
(CLI, Tests ohne Daemon) gibt es keine vorläufigen Zeilen.

Zu den vorläufigen Zeilen des Normalisierers kommen die Bytes, die der Strom noch zurückhält (der
letzte Block wartet auf eine mögliche Grenze, :meth:`TermStream._advance`): Sie laufen durch eine
Kopie des Normalisierers, der echte bleibt unberührt. Pro Bindung und Stand des Stroms wird das nur
einmal gerechnet.

Nummerierung wie in :func:`ariadne.ingest.unit_store.load_unit` mit ``extra_lines``: ``pos`` setzt
nach den gespeicherten Zeilen fort, ``idx`` zählt nur Zeilen, die Parser sehen. So passen die
Fundstellen der vorläufigen Auswertung (``span_json.line_start``) auf diese Zeilen.
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from ariadne.ingest.normalizer import sgr_to_json
from ariadne.ingest.units import line_visible

__all__ = ["bound", "pending_rows", "line_rows", "line_count", "pos_of_idx", "visible_extra"]

_local = threading.local()
_INF = 1 << 62

Row = tuple[int, int | None, str, int, str | None, int, int]  # pos, idx, text, flags, sgr, raw_start, raw_end


@contextmanager
def bound(pipeline: Any) -> Iterator[None]:
    """Pipeline (mit ``terms``) für Abfragen in diesem Thread bereitstellen."""
    prev = getattr(_local, "pipeline", None), getattr(_local, "cache", None)
    _local.pipeline, _local.cache = pipeline, {}
    try:
        yield
    finally:
        _local.pipeline, _local.cache = prev


def _stream_lines(tid: str, ts: Any) -> list[Any]:
    """Vorläufige Zeilen eines Stroms samt zurückgehaltener Bytes (über eine Kopie normalisiert)."""
    norm = getattr(ts, "norm", None)
    if norm is None or getattr(ts, "finished", False):
        return []
    chunks = list(getattr(ts, "pending", None) or ())
    if not chunks:
        return list(ts.pending_lines())
    cache = getattr(_local, "cache", None)
    key = (tid, getattr(ts, "stream_end", None), getattr(norm, "_off", None), len(chunks))
    if isinstance(cache, dict) and key in cache:
        return list(cache[key])
    tmp = copy.deepcopy(norm)
    for ch in chunks:
        tmp.feed(ch.data, ch.off)
    lines = [*tmp.take_final(), *tmp.pending()]
    if isinstance(cache, dict):
        cache[key] = lines
    return list(lines)


def pending_rows(conn: Any, unit_id: str) -> list[Row]:
    """Vorläufige Zeilen einer nicht endgültigen Strom-Einheit, sonst ``[]``."""
    pipe = getattr(_local, "pipeline", None)
    terms = getattr(pipe, "terms", None)
    if not isinstance(terms, dict):
        return []
    row = conn.execute(
        "SELECT terminal_id, start_off, end_off, state, line_count, vis_count FROM unit WHERE unit_id = ?",
        (unit_id,),
    ).fetchone()
    if row is None or row[3] == "final" or not isinstance(row[0], str):
        return []
    ts = terms.get(row[0])
    if ts is None:
        return []
    try:
        lines = _stream_lines(row[0], ts)
    except Exception:  # noqa: BLE001 - ein Leser bricht nie die Auswertung
        return []
    start = int(row[1] or 0)
    end = int(row[2]) if row[2] is not None else _INF
    pos, idx = int(row[4] or 0), int(row[5] or 0)
    out: list[Row] = []
    for ln in lines:
        if not start <= ln.raw_start < end:
            continue
        vis = line_visible(ln.flags)
        out.append(
            (pos, idx if vis else None, ln.text, int(ln.flags), sgr_to_json(ln.sgr), ln.raw_start, ln.raw_end)
        )
        pos += 1
        if vis:
            idx += 1
    return out


def line_count(conn: Any, unit_id: str) -> int:
    """Gespeicherte und vorläufige Zeilen einer Einheit."""
    n = int(conn.execute("SELECT COUNT(*) FROM unit_line WHERE unit_id = ?", (unit_id,)).fetchone()[0])
    return n + len(pending_rows(conn, unit_id))


def line_rows(
    conn: Any, unit_id: str, start: int, count: int
) -> list[tuple[int, int | None, str, int, str | None]]:
    """Zeilen ``(pos, idx, text, flags, sgr)`` ab ``start``, gespeicherte zuerst, dann vorläufige."""
    rows = [
        tuple(r)
        for r in conn.execute(
            "SELECT pos, idx, text, flags, sgr FROM unit_line WHERE unit_id = ? AND pos >= ? "
            "ORDER BY pos LIMIT ?",
            (unit_id, start, count),
        ).fetchall()
    ]
    if len(rows) < count:
        for p in pending_rows(conn, unit_id):
            if p[0] >= start and len(rows) < count:
                rows.append(p[:5])
    return rows  # type: ignore[return-value]


def pos_of_idx(conn: Any, unit_id: str, idx: int) -> int | None:
    """Anzeige-Position zu einer Parser-Zeile (``span_json.line_start``)."""
    row = conn.execute("SELECT pos FROM unit_line WHERE unit_id = ? AND idx = ?", (unit_id, idx)).fetchone()
    if row is not None:
        return int(row[0])
    for p in pending_rows(conn, unit_id):
        if p[1] == idx:
            return p[0]
    return None


def visible_extra(conn: Any, unit_id: str) -> int:
    """Zahl der vorläufigen Zeilen, die Parser sehen (für «41 Zeilen ohne Befehlsgrenzen»)."""
    return sum(1 for r in pending_rows(conn, unit_id) if r[1] is not None)
