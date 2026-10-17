"""``GET /p/{pid}/project``, ``GET /p/{pid}/changes`` und ``GET``/``PUT /p/{pid}/ui/positions``
(``docs/web-api.md`` 6 und 7).

Positionen der Karte liegen in ``state.db`` (Tabelle ``ui_positions``), ausserhalb der Hash-Kette;
sie sind kein Entscheid. Zugriff nur in ``asyncio.to_thread`` mit eigener Verbindung (Vertrag 3.2).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, Query
from starlette.responses import Response

from ariadne.ingest.db import get_meta
from ariadne.ingest.projection import DELTA_KEEP
from ariadne.project.guardrails import InvalidTarget, LabAllowlist, parse_target
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.models import PositionsRequest
from ariadne.web.api.status import project_brief
from ariadne.web.api.text import iso
from ariadne.web.api.views import loads

__all__ = ["add_routes", "MAX_CHANGES", "POSITIONS_SQL"]

MAX_CHANGES = 5000
POSITIONS_SQL = (
    "CREATE TABLE IF NOT EXISTS ui_positions (node_id TEXT PRIMARY KEY, x REAL NOT NULL, "
    "y REAL NOT NULL, updated_ns INTEGER NOT NULL)"
)


def _scope_lists(settings: Any) -> tuple[list[str], list[str]]:
    scope = settings.get("scope") if isinstance(settings, dict) else None
    if not isinstance(scope, dict):
        return [], []

    def strs(v: Any) -> list[str]:
        return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []

    return strs(scope.get("include")), strs(scope.get("exclude"))


def _public(include: list[str]) -> bool:
    """Ziele ausserhalb der Lab-Allowlist (Standardliste, nur syntaktisch, nie DNS)."""
    allow = LabAllowlist.default()
    for raw in include:
        try:
            if not allow.allows(parse_target(raw)):
                return True
        except (InvalidTarget, ValueError):
            return True
    return False


def _project_derived(conn: Any, journal: Any) -> dict[str, Any]:
    created = None
    for rec in journal.iter_events(kinds=["system.project_created"]):
        created = rec.ts_utc_ns
        break
    row = journal.conn.execute("SELECT seq, hash FROM event ORDER BY seq DESC LIMIT 1").fetchone()
    head_seq, head_hash = (int(row[0]), bytes(row[1]).hex()) if row else (0, "")
    version = 0
    not_customer = False
    for kind, payload in conn.execute(
        "SELECT kind, payload_json FROM decision WHERE kind IN ('d.scope.update', 'd.lab.not_customer') "
        "ORDER BY seq"
    ):
        data = loads(payload, {}) or {}
        if kind == "d.scope.update" and isinstance(data.get("version"), int):
            version = max(version, int(data["version"]))
        elif kind == "d.lab.not_customer":
            not_customer = True
    started = conn.execute("SELECT MIN(ts_utc_ns) FROM seg_event WHERE kind = 'term.open'").fetchone()
    return {
        "created": created,
        "head_seq": head_seq,
        "head_hash": head_hash,
        "version": version,
        "not_customer": not_customer,
        "started": started[0] if started else None,
    }


def _changes(conn: Any, since: int) -> dict[str, Any]:
    gen_raw = get_meta(conn, "generation")
    to = int(gen_raw) if gen_raw is not None and gen_raw.isdigit() else 0
    if since > to or since < to - DELTA_KEEP:  # andere derived.db (Reparse) oder Änderungen schon gelöscht
        return {"to": to, "reset": True, "changes": []}
    rows = conn.execute(
        "SELECT generation, entity, entity_key, change FROM projection_delta WHERE generation > ? "
        "ORDER BY generation, entity, entity_key LIMIT ?",
        (since, MAX_CHANGES + 1),
    ).fetchall()
    if len(rows) > MAX_CHANGES:
        return {"to": to, "reset": True, "changes": []}
    return {
        "to": to,
        "reset": False,
        "changes": [{"generation": int(g), "entity": e, "entity_key": k, "change": c} for g, e, k, c in rows],
    }


def _read_positions(p: Any) -> dict[str, Any]:
    conn = p.connect_state()
    try:
        conn.execute(POSITIONS_SQL)
        rows = conn.execute(
            "SELECT node_id, x, y, updated_ns FROM ui_positions ORDER BY node_id LIMIT 5000"
        ).fetchall()
        conn.commit()
    finally:
        conn.close()
    updated = max((int(r[3]) for r in rows), default=None)
    return {
        "positions": {str(r[0]): {"x": float(r[1]), "y": float(r[2])} for r in rows},
        "updated_at": iso(updated),
    }


def _write_positions(p: Any, positions: dict[str, tuple[float, float]]) -> None:
    now = time.time_ns()
    conn = p.connect_state()
    try:
        conn.execute(POSITIONS_SQL)
        with conn:
            conn.execute("DELETE FROM ui_positions")
            conn.executemany(
                "INSERT INTO ui_positions (node_id, x, y, updated_ns) VALUES (?, ?, ?, ?)",
                [(k, x, y, now) for k, (x, y) in sorted(positions.items())],
            )
    finally:
        conn.close()


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/project", name="project")
    async def get_project(pid: str) -> Response:
        p = api.project(pid)
        data = await api.query_journal(p, _project_derived)
        bag = api.bag()
        include, exclude = _scope_lists(p.settings)
        brief = project_brief(p, bag)
        lab = p.info.profile == "lab"
        body = {
            **brief,
            "created_at": iso(data["created"]),
            "scope": {"include": bag.many(include), "exclude": bag.many(exclude), "version": data["version"]},
            "lab_guard": (
                {"public_targets": _public(include), "confirmed_not_customer": data["not_customer"]}
                if lab
                else None
            ),
            "started_at": iso(data["started"]),
            "chain": {
                "head_seq": data["head_seq"],
                "head_hash": data["head_hash"],
                "head_ok": bool(p.head_ok),
            },
            "ctrl": bag.ctrl,
        }
        return await api.respond(body)

    @router.get("/p/{pid}/changes", name="changes")
    async def get_changes(pid: str, since: int = Query(..., ge=0, le=2**62)) -> Response:  # noqa: B008
        p = api.project(pid)
        res = await api.query(p, lambda c: _changes(c, since))
        bag = api.bag()
        for ch in res["changes"]:
            ch["entity_key"] = bag(ch["entity_key"])
        return await api.respond({"project_id": p.info.id, "from": since, **res})

    @router.get("/p/{pid}/ui/positions", name="positions_get")
    async def get_positions(pid: str) -> Response:
        p = api.project(pid)
        try:
            res = await asyncio.to_thread(_read_positions, p)
        except Exception as exc:
            api.same(p)
            raise ApiError("internal") from exc
        api.same(p)
        return await api.respond(res)

    @router.put("/p/{pid}/ui/positions", name="positions_put", status_code=202)
    async def put_positions(pid: str, body: PositionsRequest) -> Response:
        p = api.project(pid)
        data = {k: (v.x, v.y) for k, v in body.positions.items()}
        try:
            await asyncio.to_thread(_write_positions, p, data)
        except Exception as exc:
            api.same(p)
            raise ApiError("internal") from exc
        api.same(p)
        return await api.respond({"accepted": True}, 202)
