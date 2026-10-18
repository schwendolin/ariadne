"""Belege (``docs/web-api.md`` 11): Quellen eines Werts, Kopf einer Einheit, bereinigte Logzeilen
und «Ganzes Log» als Text.

Zeilen einer Einheit zählen nach ``unit_line.pos`` (Anzeige-Reihenfolge, 0-basiert); Fundstellen der
Parser (``Span``, gezählt in ``idx``) werden darauf umgerechnet. Logzeilen kommen ohne ANSI und OSC,
mit sichtbaren Steuerzeichen. Verdeckt (``masked``) werden immer bekannte Secrets (``secret_value``)
und eigene Secrets (Redaktor, E72), ohne ``reveal_hidden`` auch SGR-verdeckter Text, im
Präsentationsmodus zusätzlich jeder Secret-Bereich, den ein Parser gemeldet hat (Architektur 7.8).
Rohbytes gibt es über HTTP nicht.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Query
from starlette.responses import Response

from ariadne.ingest.queries import term_refs
from ariadne.store import chain
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.text import Bag, iso, render_line
from ariadne.web.api.views import (
    claim_rows,
    command_ref,
    commands_for,
    fact_view,
    level,
    loads,
    secret_values,
    stack_views,
    term_ref,
    unit_brief,
    unit_rows,
    with_secrets,
)

__all__ = [
    "add_routes",
    "fact_sources",
    "unit_detail",
    "unit_lines",
    "render_rows",
    "secret_spans",
    "LINES_MAX",
    "LOG_MAX_LINES",
    "chain_break_line",
]

CHAIN_CHECK_MAX = 5000  # so viele Ausgabe-Events einer Einheit prüft der Kopf der Belegansicht
_EV_COLS = (
    "seq, id, layer, kind, ts_utc_ns, mono_ns, boot_id, operator_id, origin, terminal_id, stream_off, "
    "header, body, salt, body_commit, prev_hash, hash"
)

LINES_MAX = 2000
LOG_MAX_LINES = 200_000
_SOURCES_MAX = 500


def _valid_unit(unit_id: str) -> bool:
    return 3 <= len(unit_id) <= 200 and unit_id.isprintable()


def _pos_map(conn: Any, unit_id: str, idxs: set[int]) -> dict[int, int]:
    if not idxs:
        return {}
    lo, hi = min(idxs), max(idxs)
    return {
        int(i): int(p)
        for i, p in conn.execute(
            "SELECT idx, pos FROM unit_line WHERE unit_id = ? AND idx BETWEEN ? AND ?", (unit_id, lo, hi)
        )
    }


def _lines_of(conn: Any, unit_id: str, span: Any) -> list[int] | None:
    if not isinstance(span, Mapping):
        return None
    a, b = span.get("line_start"), span.get("line_end")
    if not isinstance(a, int) or not isinstance(b, int):
        return None
    m = _pos_map(conn, unit_id, {a, b})
    if a not in m or b not in m:
        return None
    return [m[a], m[b]]


def _stack(conn: Any, u: Mapping[str, Any], bag: Bag) -> list[dict[str, Any]]:
    span_id = u.get("span_id")
    if isinstance(span_id, str):
        row = conn.execute("SELECT stack FROM ctx_span WHERE span_id = ?", (span_id,)).fetchone()
        if row is not None:
            return stack_views(loads(row[0], []), bag)
    ctx = loads(u.get("context"), {}) if isinstance(u.get("context"), str) else u.get("context")
    return stack_views([ctx] if isinstance(ctx, dict) else [], bag)


def _src_ip(conn: Any, cmd_id: Any) -> Any:
    if not isinstance(cmd_id, str):
        return None
    row = conn.execute("SELECT src_ip FROM activity WHERE cmd_id = ?", (cmd_id,)).fetchone()
    return row[0] if row else None


def fact_sources(conn: Any, claim_key: str, bag: Bag) -> dict[str, Any] | None:
    rows = claim_rows(conn, "claim_key = ?", (claim_key,), 1)
    if not rows:
        return None
    bag = with_secrets(bag, conn)
    srcs = conn.execute(
        "SELECT decision_id, unit_id, parser_id, trust, confidence, span_json, distrusted FROM claim_source "
        "WHERE claim_key = ? ORDER BY ts_utc_ns, journal_seq LIMIT ?",
        (claim_key, _SOURCES_MAX),
    ).fetchall()
    units = commands_for(conn, [str(s[1]) for s in srcs if s[1]])
    decisions = {
        str(r[0]): (r[1], r[2])
        for r in conn.execute(
            "SELECT id, kind, ts FROM decision WHERE id IN "
            "(SELECT decision_id FROM claim_source WHERE claim_key = ? "
            "AND decision_id IS NOT NULL)",
            (claim_key,),
        )
    }
    out: list[dict[str, Any]] = []
    for did, unit_id, parser, trust, conf, span_json, distrusted in srcs:
        u = units.get(str(unit_id)) if unit_id else None
        if u is None:
            if did and str(did) in decisions:
                kind, ts = decisions[str(did)]
                out.append({"t": "user", "decision_id": did, "kind": kind, "ts": iso(ts)})
            continue
        lines = _lines_of(conn, str(unit_id), loads(span_json, None))
        b = bag.new()
        if u.get("kind") == "file":
            item = {
                "t": "file",
                "unit_id": unit_id,
                "path": b(u.get("path")) or "",
                "sha256": u.get("sha256"),
                "lines": lines,
                "parser": parser,
                "trust": trust,
                "produced_by_cmd": u.get("cmd_id"),
            }
        else:
            flags = [f for f in loads(u.get("flags"), []) or [] if isinstance(f, str)]
            if u.get("kind") == "segment":
                flags.append("remote_reconstructed")
            item = {
                "t": "stream",
                "unit_id": unit_id,
                "terminal_id": u.get("terminal_id"),
                "cmd": command_ref(u, b, _src_ip(conn, u.get("cmd_id")))
                if u.get("kind") == "command"
                else None,
                "context": _stack(conn, u, b),
                "lines": lines,
                "parser": parser,
                "trust": trust,
                "confidence": level(conf) or "low",
                "flags": b.many(flags),
                "distrusted": bool(distrusted),
            }
        item["ctrl"] = b.ctrl
        out.append(item)
    return {"fact": fact_view(rows[0], bag), "sources": out}


def _event_ok(jconn: Any, row: Any) -> bool:
    """Ein Ausgabe-Event der Kette: Commitment, Hash und Verweis auf den Vorgänger stimmen."""
    seq, header_text, body, salt, commit = int(row[0]), row[11], row[12], row[13], row[14]
    row_prev, row_hash = bytes(row[15]), bytes(row[16])
    commit_b = bytes(commit) if commit is not None else None
    if body is not None:
        if salt is None or commit_b is None:
            return False
        try:
            if chain.body_commit(bytes(salt), bytes(body)) != commit_b:
                return False
        except ValueError:
            return False
    h = chain.event_hash(
        row_prev,
        seq=seq,
        event_id=row[1],
        layer=row[2],
        kind=row[3],
        ts_utc_ns=row[4],
        mono_ns=row[5],
        boot_id=row[6],
        operator_id=row[7],
        origin=row[8],
        terminal_id=row[9],
        stream_off=row[10],
        header_json=str(header_text).encode(),
        body_commit=commit_b,
    )
    if h != row_hash:
        return False
    if seq > 1:
        prev = jconn.execute("SELECT hash FROM event WHERE seq = ?", (seq - 1,)).fetchone()
        if prev is None or bytes(prev[0]) != row_prev:
            return False
    return True


def chain_break_line(conn: Any, journal: Any, u: Mapping[str, Any]) -> int | None:
    """Erste Zeile (``pos``) einer Einheit, ab der die Hash-Kette ihrer Ausgabe nicht stimmt (18.8),
    sonst ``None``. Geprüft werden die Ausgabe-Events des Terminals im Bereich der Einheit."""
    tid, start, end = u.get("terminal_id"), u.get("start_off"), u.get("end_off")
    jconn = getattr(journal, "conn", None)
    if not isinstance(tid, str) or not isinstance(start, int) or jconn is None:
        return None
    hi = end if isinstance(end, int) else 1 << 62
    rows = jconn.execute(
        f"SELECT {_EV_COLS} FROM event WHERE kind = 'term.out' AND terminal_id = ? "  # noqa: S608
        "AND stream_off < ? AND stream_off >= ? ORDER BY stream_off LIMIT ?",
        (tid, hi, max(0, start - (1 << 20)), CHAIN_CHECK_MAX),
    ).fetchall()
    for row in rows:
        header = loads(row[11], {}) or {}
        length = header.get("length") if isinstance(header.get("length"), int) else len(row[12] or b"")
        off = int(row[10] or 0)
        if off + int(length) <= start:
            continue
        if not _event_ok(jconn, row):
            hit = conn.execute(
                "SELECT MIN(pos) FROM unit_line WHERE unit_id = ? AND raw_end > ?", (u.get("unit_id"), off)
            ).fetchone()
            return int(hit[0]) if hit and hit[0] is not None else 0
    return None


def unit_detail(
    conn: Any, unit_id: str, chain_ok: bool, bag: Bag, journal: Any = None
) -> dict[str, Any] | None:
    rows = unit_rows(conn, "unit_id = ?", (unit_id,), 1)
    if not rows:
        return None
    bag = with_secrets(bag, conn)
    u = rows[0]
    parser = conn.execute(
        "SELECT parser_id FROM observation WHERE unit_id = ? ORDER BY obs_id LIMIT 1", (unit_id,)
    ).fetchone()
    out = unit_brief(u, bag, parser=parser[0] if parser else None) or {}
    b = bag.new()
    start, end = u.get("ts_utc_ns"), u.get("ts_end_ns")
    lines = conn.execute("SELECT COUNT(*) FROM unit_line WHERE unit_id = ?", (unit_id,)).fetchone()[0]
    out.update(
        {
            "exit": u.get("exit_code") if isinstance(u.get("exit_code"), int) else None,
            "started_at": iso(start),
            "ended_at": iso(end),
            "duration_ms": (end - start) // 1_000_000
            if isinstance(start, int) and isinstance(end, int) and end >= start
            else None,
            "src_ip": b(_src_ip(conn, u.get("cmd_id"))),
            "context": _stack(conn, u, b),
            "line_count": int(lines),
            "flags": b.many(f for f in loads(u.get("flags"), []) or [] if isinstance(f, str)),
            "chain_ok": bool(chain_ok),
            "terminal": term_ref(u.get("terminal_id"), term_refs(conn), b),
            "chain_break_line": chain_break_line(conn, journal, u) if journal is not None else None,
        }
    )
    out["ctrl"] = bool(out.get("ctrl")) or b.ctrl
    return out


def secret_spans(conn: Any, unit_id: str) -> dict[int, list[tuple[int, int]]]:
    """Secret-Bereiche, die Parser gemeldet haben (pro ``idx``; ``(0, -1)`` heisst ganze Zeile)."""
    out: dict[int, list[tuple[int, int]]] = {}
    for (span_json,) in conn.execute(
        "SELECT span_json FROM observation WHERE unit_id = ? AND is_secret = 1 "
        "UNION ALL SELECT span_json FROM mention WHERE unit_id = ? AND is_secret = 1 LIMIT 100000",
        (unit_id, unit_id),
    ):
        span = loads(span_json, None)
        if not isinstance(span, Mapping):
            continue
        a, b = span.get("line_start"), span.get("line_end")
        if not isinstance(a, int) or not isinstance(b, int) or b < a or b - a > 10000:
            continue
        cs, ce = span.get("col_start"), span.get("col_end")
        for i in range(a, b + 1):
            start = cs if i == a and isinstance(cs, int) else 0
            end = ce if i == b and isinstance(ce, int) else -1
            out.setdefault(i, []).append((start, end))
    return out


def _char_hits(text: str, redactor: Any) -> list[tuple[int, int, str]]:
    raw = text.encode("utf-8", "surrogateescape")
    out: list[tuple[int, int, str]] = []
    for h in redactor.scan(raw) if redactor is not None else []:
        a = len(raw[: h.start].decode("utf-8", "replace"))
        b = len(raw[: h.end].decode("utf-8", "replace"))
        out.append((a, max(b, a + 1), "own_secret"))
    return out


def render_rows(
    rows: list[Any],
    secrets: list[str],
    spans: dict[int, list[tuple[int, int]]],
    *,
    reveal: bool,
    redactor: Any,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for pos, idx, text, flags, sgr_json in rows:
        text = str(text)
        sgr = loads(sgr_json, []) or []
        masks: list[tuple[int, int, str]] = []
        for s in secrets:
            i = text.find(s)
            while i >= 0:
                masks.append((i, i + len(s), "secret"))
                i = text.find(s, i + len(s))
        masks.extend(_char_hits(text, redactor))
        if not reveal:
            for sp in sgr:
                if (
                    isinstance(sp, Mapping)
                    and sp.get("c")
                    and isinstance(sp.get("s"), int)
                    and isinstance(sp.get("e"), int)
                ):
                    masks.append((int(sp["s"]), int(sp["e"]), "concealed"))
        if isinstance(idx, int):
            for a, b in spans.get(idx, []):
                masks.append((a, len(text) if b < 0 else b, "secret"))
        shown, ctrl, masked, colors = render_line(text, masks, [s for s in sgr if isinstance(s, Mapping)])
        f = int(flags or 0)
        out.append(
            {
                "n": int(pos),
                "text": shown,
                "ctrl": ctrl,
                "sgr": colors,
                "prompt_echo": bool(f & 1),
                "concealed": bool(f & 2),
                "overwritten": bool(f & 4),
                "masked": masked,
            }
        )
    return out


def unit_lines(
    conn: Any, unit_id: str, start: int, count: int, *, reveal: bool, presentation: bool, redactor: Any
) -> dict[str, Any] | None:
    if conn.execute("SELECT 1 FROM unit WHERE unit_id = ?", (unit_id,)).fetchone() is None:
        return None
    total = int(conn.execute("SELECT COUNT(*) FROM unit_line WHERE unit_id = ?", (unit_id,)).fetchone()[0])
    rows = conn.execute(
        "SELECT pos, idx, text, flags, sgr FROM unit_line WHERE unit_id = ? AND pos >= ? "
        "ORDER BY pos LIMIT ?",
        (unit_id, start, count),
    ).fetchall()
    spans = secret_spans(conn, unit_id) if presentation else {}
    lines = render_rows(rows, secret_values(conn), spans, reveal=reveal, redactor=redactor)
    return {"unit_id": unit_id, "total": total, "from": start, "lines": lines}


def unit_log(conn: Any, unit_id: str, *, presentation: bool, redactor: Any) -> str | None:
    """«Ganzes Log»: bereinigte Zeilen mit sichtbaren Escapes, Secrets wie bei ``/lines`` ersetzt."""
    if conn.execute("SELECT 1 FROM unit WHERE unit_id = ?", (unit_id,)).fetchone() is None:
        return None
    rows = conn.execute(
        "SELECT pos, idx, text, flags, sgr FROM unit_line WHERE unit_id = ? ORDER BY pos LIMIT ?",
        (unit_id, LOG_MAX_LINES + 1),
    ).fetchall()
    spans = secret_spans(conn, unit_id) if presentation else {}
    lines = render_rows(rows[:LOG_MAX_LINES], secret_values(conn), spans, reveal=False, redactor=redactor)
    text = "\n".join(ln["text"] for ln in lines)
    if len(rows) > LOG_MAX_LINES:
        text += "\n[gekürzt: mehr als 200000 Zeilen]"
    return text + "\n"


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/facts/{claim_key}/sources", name="fact_sources")
    async def get_sources(pid: str, claim_key: str) -> Response:
        p = api.project(pid)
        if len(claim_key) != 64 or not all(c in "0123456789abcdef" for c in claim_key):
            raise ApiError("not_found")
        bag = api.bag()
        res = await api.query(p, lambda c: fact_sources(c, claim_key, bag))
        if res is None:
            raise ApiError("not_found")
        return await api.respond(res)

    @router.get("/p/{pid}/units/{unit_id}", name="unit")
    async def get_unit(pid: str, unit_id: str) -> Response:
        p = api.project(pid)
        if not _valid_unit(unit_id):
            raise ApiError("not_found")
        bag = api.bag()
        chain_ok = bool(p.head_ok)
        res = await api.query_journal(p, lambda c, j: unit_detail(c, unit_id, chain_ok, bag, j))
        if res is None:
            raise ApiError("not_found")
        if res.get("chain_break_line") is not None:
            res["chain_ok"] = False  # Bruchstelle in dieser Einheit, auch wenn der Kopf stimmt
        return await api.respond(res)

    @router.get("/p/{pid}/units/{unit_id}/lines", name="unit_lines")
    async def get_lines(
        pid: str,
        unit_id: str,
        start: int = Query(default=0, ge=0, le=2**40, alias="from"),  # noqa: B008
        count: int = Query(default=400, ge=1, le=LINES_MAX),  # noqa: B008
        reveal_hidden: bool = Query(default=False),
    ) -> Response:  # noqa: B008
        p = api.project(pid)
        if not _valid_unit(unit_id):
            raise ApiError("not_found")
        d = api.daemon
        presentation = bool(d.presentation)
        # Verdeckter Text nur im Profil lab und nicht im Präsentationsmodus (lieber zu viel verdecken)
        reveal = reveal_hidden and p.info.profile == "lab" and not presentation
        red = d.redactor
        res = await api.query(
            p,
            lambda c: unit_lines(
                c, unit_id, start, count, reveal=reveal, presentation=presentation, redactor=red
            ),
        )
        if res is None:
            raise ApiError("not_found")
        return await api.respond(res)

    @router.get("/p/{pid}/units/{unit_id}/log.txt", name="unit_log")
    async def get_log(pid: str, unit_id: str) -> Response:
        p = api.project(pid)
        if not _valid_unit(unit_id):
            raise ApiError("not_found")
        d = api.daemon
        presentation = bool(d.presentation)
        red = d.redactor
        text = await api.query(p, lambda c: unit_log(c, unit_id, presentation=presentation, redactor=red))
        if text is None:
            raise ApiError("not_found")
        final, _labels = await asyncio.to_thread(red.redact_for_exit, text)  # zweite Schicht, grosser Text
        name = hashlib.sha256(unit_id.encode()).hexdigest()[:12]
        return Response(
            str(final).encode("utf-8"),
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="unit-{name}.txt"'},
        )
