"""``GET /p/{pid}/next``: die Arbeitsliste «Als Nächstes» (``docs/web-api.md`` 9, E86, E42).

Grundlage sind die offenen Einträge aus ``v_inbox`` (wie :func:`ariadne.ingest.queries.inbox`,
hier als flache Liste mit der Zeit pro Eintrag), :func:`~ariadne.ingest.queries.group_ref` und
:func:`~ariadne.ingest.queries.quiet_summary`. «Klären» ist die Spur «entscheiden», «Bestätigen»
gibt es nur im Profil customer (Gruppen mit Sammelbestätigung, E88). Denkanstösse folgen später.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter
from starlette.responses import Response

from ariadne.ingest import queries
from ariadne.ingest.proj_build import display
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
    unit_brief,
)

__all__ = ["add_routes", "next_view"]

_VALUE_KINDS = ("decide_value", "candidate_group")
_ITEMS_MAX = 2000


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


def next_view(conn: Any, profile: str, bag: Bag) -> dict[str, Any]:
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
                        "title": gb(it["title"]) or "",
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
        out["ctrl"] = b.ctrl
        clarify.append(out)
    return {
        "clarify": clarify,
        "confirm": list(groups.values()) if profile == "customer" else [],
        "suggestions": [],
        "suggestions_available": False,
        "quiet": queries.quiet_summary(conn),
        "open": len(clarify),
    }


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/next", name="next")
    async def get_next(pid: str) -> Response:
        p = api.project(pid)
        bag = api.bag()
        profile = p.info.profile
        return await api.respond(await api.query(p, lambda c: next_view(c, profile, bag)))
