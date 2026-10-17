"""``GET /p/{pid}/search`` (Volltext über die Ausgabe, ``queries.search``) und
``GET /p/{pid}/files/pending`` (Warteliste, ctl ``show`` mit ``what = pending``),
``docs/web-api.md`` 13.

Treffer zeigen die Zeile so, wie ``/units/{unit_id}/lines`` sie zeigt: bekannte und eigene Secrets
verdeckt, SGR-verdeckter Text verdeckt, im Präsentationsmodus jeder Secret-Bereich.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from starlette.responses import Response

from ariadne.ingest import queries
from ariadne.web.api.common import Api
from ariadne.web.api.evidence import render_rows, secret_spans
from ariadne.web.api.text import Bag, iso
from ariadne.web.api.timeline import secret_values

__all__ = ["add_routes", "search_view", "PENDING_MAX"]

PENDING_MAX = 200


def search_view(
    conn: Any, q: str, limit: int, *, presentation: bool, redactor: Any, bag: Bag
) -> dict[str, Any]:
    hits = queries.search(conn, q, limit + 1)
    secrets = secret_values(conn)
    spans: dict[str, dict[int, list[tuple[int, int]]]] = {}
    items: list[dict[str, Any]] = []
    for h in hits[:limit]:
        row = conn.execute(
            "SELECT pos, idx, text, flags, sgr FROM unit_line WHERE unit_id = ? AND n = ?",
            (h["unit_id"], h["n"]),
        ).fetchone()
        if row is None:
            continue
        uid = str(h["unit_id"])
        if presentation and uid not in spans:
            spans[uid] = secret_spans(conn, uid)
        line = render_rows([row], secrets, spans.get(uid, {}), reveal=False, redactor=redactor)[0]
        b = bag.new()
        item = {
            "unit_id": uid,
            "line": line["n"],
            "text": line["text"],
            "kind": h.get("kind"),
            "context_label": b(h.get("context")) or "",
            "host_id": b(h.get("host")) if h.get("host") != "local" else None,
            "cmd": b(h.get("cmd")),
            "ts": iso(h.get("ts")),
        }
        item["ctrl"] = bool(line["ctrl"]) or b.ctrl
        items.append(item)
    return {"items": items, "truncated": len(hits) > limit}


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/search", name="search")
    async def get_search(
        pid: str,
        q: str = Query(..., min_length=1, max_length=200),  # noqa: B008
        limit: int = Query(default=50, ge=1, le=200),
    ) -> Response:  # noqa: B008
        p = api.project(pid)
        bag = api.bag()
        d = api.daemon
        presentation = bool(d.presentation)
        red = d.redactor
        if not q.strip():
            return await api.respond({"items": [], "truncated": False})
        res = await api.query(
            p, lambda c: search_view(c, q, limit, presentation=presentation, redactor=red, bag=bag)
        )
        return await api.respond(res)

    @router.get("/p/{pid}/files/pending", name="files_pending")
    async def get_pending(pid: str) -> Response:
        p = api.project(pid)
        res = await api.call("show", {"what": "pending", "limit": PENDING_MAX})
        api.same(p)
        bag = api.bag()
        files = []
        for f in (res or {}).get("items") or []:
            b = bag.new()
            item = {
                "path": b(f.get("path")) or "",
                "reason": b(f.get("reason")) or "",
                "cmd_id": f.get("cmd_id"),
                "terminal_id": f.get("terminal_id"),
                "ts": iso(f.get("ts")),
            }
            item["ctrl"] = b.ctrl
            files.append(item)
        return await api.respond({"files": files, "truncated": len(files) >= PENDING_MAX})
