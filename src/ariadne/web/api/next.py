"""``GET /p/{pid}/next``: die Arbeitsliste «Als Nächstes» (``docs/web-api.md`` 9, E86, E42).

Grundlage sind die offenen Einträge aus ``v_inbox`` (wie :func:`ariadne.ingest.queries.inbox`,
hier als flache Liste mit der Zeit pro Eintrag), :func:`~ariadne.ingest.queries.group_ref` und
:func:`~ariadne.ingest.queries.quiet_summary`. «Klären» ist die Spur «entscheiden», «Bestätigen»
gibt es nur im Profil customer (Gruppen mit Sammelbestätigung, E88). Denkanstösse liefert
:func:`ariadne.rules.api.suggestions` (web-api.md 18.6).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter
from starlette.responses import Response

from ariadne.ingest import pending, queries
from ariadne.ingest.proj_build import display
from ariadne.parsers._common import canon_ip
from ariadne.rules import api as rules_api
from ariadne.web.api.common import Api
from ariadne.web.api.text import Bag, iso
from ariadne.web.api.views import (
    chunks,
    claim_rows,
    commands_for,
    conflict_rows,
    conflict_view,
    fact_view,
    loads,
    secret_values,
    term_ref,
    unit_brief,
    with_secrets,
)

__all__ = ["add_routes", "next_view"]

_VALUE_KINDS = ("decide_value", "candidate_group")
_ITEMS_MAX = 2000
EXCERPT_LINES = 4  # «Darum mehrdeutig»: höchstens so viele Zeilen (18.8)


def _off_ts(conn: Any, tid: Any, off: Any) -> int | None:
    """Zeit eines Offsets im Strom eines Terminals (aus den gespeicherten Blöcken)."""
    if not isinstance(tid, str) or not isinstance(off, int):
        return None
    row = conn.execute(
        "SELECT ts_utc_ns FROM seg_chunk WHERE terminal_id = ? AND off <= ? ORDER BY off DESC LIMIT 1",
        (tid, off),
    ).fetchone()
    if row is None:
        row = conn.execute(
            "SELECT ts_utc_ns FROM seg_chunk WHERE terminal_id = ? ORDER BY off LIMIT 1", (tid,)
        ).fetchone()
    return int(row[0]) if row and isinstance(row[0], int) else None


def _line_pos(conn: Any, unit_id: str, span_json: Any) -> int | None:
    span = loads(span_json, None)
    idx = span.get("line_start") if isinstance(span, Mapping) else None
    if not isinstance(idx, int):
        return None
    return pending.pos_of_idx(conn, unit_id, idx)


def _claim_ts(conn: Any, claim_key: Any) -> int | None:
    """Zeit der ersten Quelle eines Werts (Callback «um 16:52:31» im Grund des Kontextvorschlags)."""
    if not isinstance(claim_key, str):
        return None
    row = conn.execute("SELECT MIN(ts_utc_ns) FROM claim_source WHERE claim_key = ?", (claim_key,)).fetchone()
    return int(row[0]) if row is not None and isinstance(row[0], int) else None


def _span_lines(span_json: Any) -> int:
    """Zeilen der Fundstelle (``line_start`` bis ``line_end``), mindestens 1, höchstens EXCERPT_LINES."""
    span = loads(span_json, None)
    if not isinstance(span, Mapping):
        return 1
    a, b = span.get("line_start"), span.get("line_end")
    if isinstance(a, int) and isinstance(b, int) and b >= a:
        return max(1, min(EXCERPT_LINES, b - a + 1))
    return 1


def _callback_ip(remote: str) -> str | None:
    """IP aus ``host:port``, ``[v6]:port`` oder einer nackten Adresse (Wert einer Callback-Mention)."""
    ip = canon_ip(remote)
    if ip is not None:
        return ip
    if remote.startswith("[") and "]" in remote:
        return canon_ip(remote[1 : remote.index("]")])
    host, sep, port = remote.rpartition(":")
    return canon_ip(host) if sep and port.isdigit() else None


def _excerpt(conn: Any, tid: str, off: int, claim_key: Any, bag: Bag, redactor: Any) -> dict[str, Any] | None:
    """Logauszug zum Kontextvorschlag (18.8): beim zweiten Callback aus einer anderen Adresse in
    derselben Stufe dieser (``note: 'second_callback'``, «Darum mehrdeutig»), sonst die Zeile des
    vorgeschlagenen Callbacks (``note: 'callback'``). Nur die Zeilen der Fundstelle (höchstens
    :data:`EXCERPT_LINES`), bekannte und eigene Secrets wie in der Belegansicht verdeckt. Bei einer
    offenen Einheit (Listener läuft) kommen die Zeilen aus :mod:`ariadne.ingest.pending`."""
    from ariadne.web.api.evidence import render_rows, secret_spans

    hits: list[tuple[str, Any, Any, str]] = []
    for unit_id, span_json, ts, subject in conn.execute(
        "SELECT cs.unit_id, cs.span_json, cs.ts_utc_ns, c.subject_identifier FROM claim c "
        "JOIN claim_source cs ON cs.claim_key = c.claim_key JOIN obs_unit u ON u.unit_id = cs.unit_id "
        "WHERE c.predicate = 'access.callback' AND c.state != 'rejected' AND u.terminal_id = ? "
        "AND u.ctx_opened_at = ? ORDER BY cs.ts_utc_ns, cs.unit_id LIMIT 200",
        (tid, off),
    ):
        hits.append((str(unit_id), span_json, ts, str(subject)))
    # Weitere Meldungen des Listeners in derselben Einheit sind Mentions (nur die erste ist eine
    # Beobachtung): ein zweiter vertrauenswürdiger Callback aus einer anderen Adresse macht die Stufe
    # mehrdeutig (listener.callback, ``reason: not_first``) und gehört in den Auszug.
    for unit_id, span_json, ts, value, attrs in conn.execute(
        "SELECT m.unit_id, m.span_json, m.ts_utc_ns, m.value, m.attrs_json FROM mention m "
        "JOIN obs_unit u ON u.unit_id = m.unit_id WHERE m.value_type = 'callback' AND u.terminal_id = ? "
        "AND u.ctx_opened_at = ? ORDER BY m.ts_utc_ns, m.mention_id LIMIT 200",
        (tid, off),
    ):
        a = loads(attrs, {}) or {}
        ip = (
            _callback_ip(str(value or ""))
            if isinstance(a, Mapping) and a.get("reason") == "not_first"
            else None
        )
        if ip is not None:
            hits.append((str(unit_id), span_json, ts, f"ip:default/{ip}"))
    hits.sort(key=lambda h: (h[2] if isinstance(h[2], int) else 0, h[0]))
    pick: tuple[str, Any, Any] | None = None
    note = None
    seen: list[str] = []
    for unit_id, span_json, ts, ip in hits:
        if seen and ip not in seen:
            pick, note = (unit_id, span_json, ts), "second_callback"
            break
        if ip not in seen:
            seen.append(ip)
    if pick is None and isinstance(claim_key, str):
        row = conn.execute(
            "SELECT unit_id, span_json, ts_utc_ns FROM claim_source WHERE claim_key = ? "
            "AND unit_id IS NOT NULL ORDER BY ts_utc_ns LIMIT 1",
            (claim_key,),
        ).fetchone()
        if row is not None:
            pick, note = (str(row[0]), row[1], row[2]), "callback"
    if pick is None:
        return None
    unit_id, span_json, ts = pick
    pos = _line_pos(conn, unit_id, span_json)
    if pos is None:
        return None
    # wie im Design: genau die Zeile(n) der Fundstelle, nicht ihre Umgebung (die zeigt der Beleg)
    rows = pending.line_rows(conn, unit_id, pos, _span_lines(span_json))
    if not rows:
        return None
    spans = secret_spans(conn, unit_id) if bag.presentation else {}
    lines = render_rows(rows, secret_values(conn), spans, reveal=False, redactor=redactor)
    return {
        "unit_id": unit_id,
        "lines": [int(rows[0][0]), int(rows[-1][0])],
        "text": [ln["text"] for ln in lines],
        "ctrl": any(ln["ctrl"] for ln in lines),
        "note": note,
        "ts": iso(ts),
    }


def _brief(
    info: Any, units: Mapping[str, Mapping[str, Any]], bag: Bag, parser: Any = None
) -> dict[str, Any] | None:
    if not isinstance(info, Mapping) or not isinstance(info.get("unit_id"), str):
        return None
    row = units.get(info["unit_id"])
    merged = {**info, **(row or {})} if row else dict(info)
    return unit_brief(merged, bag, parser=parser)


def _verdicts(conn: Any, keys: list[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for part in chunks(sorted(set(keys))):
        marks = ",".join("?" * len(part))
        for key, verdict in conn.execute(
            f"SELECT key, scope_verdict FROM identifier WHERE key IN ({marks})",  # noqa: S608
            tuple(part),
        ):
            out[str(key)] = verdict
    return out


def next_view(conn: Any, profile: str, bag: Bag, redactor: Any = None) -> dict[str, Any]:
    bag = with_secrets(bag, conn)  # Titel kommen aus Befehlstexten (SEC-W1)
    refs = queries.term_refs(conn)
    rows = conn.execute(
        "SELECT item_key, kind, group_key, title, payload_json, created_ts FROM v_inbox "
        "ORDER BY created_ts, group_key, item_key LIMIT ?",
        (_ITEMS_MAX,),
    ).fetchall()
    items = [
        {
            "key": str(r[0]),
            "kind": r[1],
            "group": str(r[2]),
            "title": r[3],
            "payload": loads(r[4], {}) or {},
            "ts": r[5],
        }
        for r in rows
    ]
    claim_keys = [
        str(i["payload"].get("claim_key"))
        for i in items
        if i["kind"] in _VALUE_KINDS and isinstance(i["payload"].get("claim_key"), str)
    ]
    claims: dict[str, dict[str, Any]] = {}
    for part in chunks(claim_keys):
        for c in claim_rows(conn, f"claim_key IN ({','.join('?' * len(part))})", part, len(part)):
            claims[str(c["claim_key"])] = c
    unit_ids = [
        str((i["payload"].get("unit") or {}).get("unit_id"))
        for i in items
        if isinstance(i["payload"].get("unit"), Mapping)
    ]
    units = commands_for(conn, unit_ids)
    conflicts = {str(k["conflict_key"]): k for k in conflict_rows(conn, "state = 'open'", (), 2000)}
    merge_ids = [
        str(x)
        for i in items
        if i["kind"] == "merge_suggestion"
        for x in i["payload"].get("identifiers") or []
        if isinstance(x, str)
    ]
    verdicts = _verdicts(conn, merge_ids)
    clarify: list[dict[str, Any]] = []
    groups: dict[str, dict[str, Any]] = {}
    for it in items:
        kind, data, ts = it["kind"], it["payload"], iso(it["ts"])
        b = bag.new()
        out: dict[str, Any] | None = None
        if kind in _VALUE_KINDS:
            c = claims.get(str(data.get("claim_key")))
            if c is None:
                continue
            out = {
                "kind": "decide_value",
                "item_key": it["key"],
                "group_ref": queries.group_ref(it["group"]),
                "ts": ts,
                "fact": fact_view(c, bag),
                "reason": b(data.get("reason")) or "",
                "unit": _brief(data.get("unit"), units, bag, data.get("parser")),
            }
            if kind == "candidate_group" and profile == "customer":
                g = groups.get(it["group"])
                if g is None:
                    gb = bag.new()
                    s = data.get("summary") if isinstance(data.get("summary"), Mapping) else {}
                    g = groups[it["group"]] = {
                        "group_ref": queries.group_ref(it["group"]),
                        "title": gb.cmd(it["title"]) or "",
                        "unit": _brief(data.get("unit"), units, bag),
                        "items": [],
                        "summary": {
                            "hosts": int(s.get("hosts") or 0),
                            "services": int(s.get("services") or 0),
                            "other": int(s.get("other") or 0) + int(s.get("credentials") or 0),
                            "out_of_scope": int(s.get("out_of_scope") or 0),
                            "low_confidence": int(s.get("low_confidence") or 0),
                        },
                        "ctrl": gb.ctrl,
                    }
                out["ctrl"] = b.ctrl
                g["items"].append(out)
                continue
        elif kind == "conflict":
            k = conflicts.get(str(data.get("conflict_key")))
            if k is None:
                continue
            out = {
                "kind": "conflict",
                "item_key": it["key"],
                "ts": ts,
                "conflict": conflict_view(conn, k, bag),
            }
        elif kind == "ctx_unknown":
            unit = _brief(data.get("unit"), units, bag)
            out = {
                "kind": "ctx_unknown",
                "item_key": it["key"],
                "ts": ts,
                "terminal_id": data.get("terminal_id") if isinstance(data.get("terminal_id"), str) else None,
                "from_off": data.get("from_off") if isinstance(data.get("from_off"), int) else None,
                "stage_kind": data.get("kind") if isinstance(data.get("kind"), str) else None,
                "candidate": b(data.get("candidate")),
                "units": int(data.get("units") or data.get("values") or (1 if unit else 0)),
                "unit": unit,
                "terminal": term_ref(data.get("terminal_id"), refs, bag),
                "from_ts": iso(_off_ts(conn, data.get("terminal_id"), data.get("from_off"))),
                "excerpt": None,
            }
        elif kind == "ctx_suggestion":
            host = data.get("suggested_host")
            if not isinstance(host, str) or not isinstance(data.get("terminal_id"), str):
                continue
            out = {
                "kind": "ctx_suggestion",
                "item_key": it["key"],
                "ts": ts,
                "terminal_id": data["terminal_id"],
                "from_off": int(data.get("from_off") or 0),
                "stage_kind": data.get("kind") if isinstance(data.get("kind"), str) else None,
                "units": int(data.get("units") or 0),
                "suggested_host": b(host),
                "suggested_label": b(display(host)),
                "reason": b(data.get("reason")) or "",
                "claim_key": data.get("claim_key") if isinstance(data.get("claim_key"), str) else None,
                "terminal": term_ref(data["terminal_id"], refs, bag),
                "from_ts": iso(_off_ts(conn, data["terminal_id"], data.get("from_off"))),
                "reason_ts": iso(_claim_ts(conn, data.get("claim_key"))),
                "excerpt": _excerpt(
                    conn,
                    data["terminal_id"],
                    int(data.get("from_off") or 0),
                    data.get("claim_key"),
                    bag,
                    redactor,
                ),
            }
        elif kind == "merge_suggestion":
            idents = []
            for x in data.get("identifiers") or []:
                if isinstance(x, str):
                    idents.append({"key": b(x), "label": b(display(x)) or "", "verdict": verdicts.get(x)})
            out = {
                "kind": "merge_suggestion",
                "item_key": it["key"],
                "ts": ts,
                "identifiers": idents,
                "shared": b(data.get("shared")) or "",
                "reason": b(data.get("reason")) or "",
            }
        elif kind == "orphan_decision":
            out = {
                "kind": "orphan_decision",
                "item_key": it["key"],
                "ts": ts,
                "decision_id": data.get("decision_id"),
                "decision_kind": data.get("kind"),
                "reason": b(data.get("reason")) or "",
                "ref": b(data.get("ref")),
            }
        elif kind == "mass_find":
            unit = _brief(data.get("unit"), units, bag)
            if unit is None:
                continue
            out = {
                "kind": "mass_find",
                "item_key": it["key"],
                "ts": ts,
                "unit": unit,
                "hosts": int(data.get("hosts") or 0),
                "candidates": int(data.get("candidates") or 0),
            }
        if out is None:
            continue
        out["ordinal"] = None  # stabile Nummer («K2»), setzt die Route aus state.db (18.12)
        out["ctrl"] = b.ctrl
        clarify.append(out)
    return {
        "clarify": clarify,
        "confirm": list(groups.values()) if profile == "customer" else [],
        # Denkanstösse aus der Regel-Engine (web-api.md 18.6, Bau v0.1-Oberfläche): nur offene.
        "suggestions": rules_api.suggestions(conn, profile=profile, state="open", limit=50)[0],
        "suggestions_available": not rules_api.STUB,
        "quiet": queries.quiet_summary(conn),
        "open": len(clarify),
    }


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/next", name="next")
    async def get_next(pid: str) -> Response:
        p = api.project(pid)
        bag = api.bag()
        profile = p.info.profile
        redactor = api.daemon.redactor
        view = await api.query(p, lambda c: next_view(c, profile, bag, redactor))
        keys = [str(i["item_key"]) for i in view["clarify"]]
        if keys:
            from ariadne.web.api.ui_state import item_ordinals, state_call

            ords = await state_call(api, p, item_ordinals, keys)
            for item in view["clarify"]:
                item["ordinal"] = ords.get(str(item["item_key"]))
        return await api.respond(view)
