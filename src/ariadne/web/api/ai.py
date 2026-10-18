"""KI-Denkanstoss auf Knopfdruck (Bau v0.1-KI; Architektur 6.3, E64 bis E66).

* ``GET /p/{pid}/ai/status``: Anbieter, Modell, Bereitschaft mit Grund, Budget, letzter Auftrag.
* ``POST /p/{pid}/ai/denkanstoss``: startet einen Auftrag (202); Fortschritt per SSE ``progress``
  (``kind: 'ai'``). Ein Auftrag zur Zeit (409), Policy (403), Monatslimit ohne Bestätigung (422
  ``budget_confirm``).
* ``GET /p/{pid}/ai/jobs/{job_id}``: Zustand eines Auftrags.
* ``GET /p/{pid}/ai/denkanstoesse?state=``: KI-Denkanstösse (``Suggestion`` mit ``origin: 'ai'``).

Jede Antwort geht durch ``Api.respond`` (Redaktor E72, zweite Schicht). Modelltext ist Text, nie HTML.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict
from starlette.responses import Response

from ariadne.ai import store
from ariadne.ai.gateway import Gateway, GatewayError
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError

__all__ = ["add_routes", "gateway_of"]

_STATES = ("open", "done", "dismissed", "all")


class DenkanstossRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm_budget: bool = False


def gateway_of(api: Api) -> Gateway:
    """Der Gateway dieses Web-Servers (einer pro App; Tests tauschen dort den Anbieter)."""
    gw = api.ctx.extra.get("ai")
    if not isinstance(gw, Gateway):
        gw = Gateway(api)
        api.ctx.extra["ai"] = gw
    return gw


def add_routes(router: APIRouter, api: Api) -> None:
    gw = gateway_of(api)

    @router.get("/p/{pid}/ai/status", name="ai_status")
    async def ai_status(pid: str) -> Response:
        p = api.project(pid)
        return await api.respond(await gw.status(p))

    @router.post("/p/{pid}/ai/denkanstoss", name="ai_denkanstoss", status_code=202)
    async def ai_denkanstoss(pid: str, body: DenkanstossRequest | None = None) -> Response:
        p = api.project(pid)
        try:
            job = await gw.start(p, confirm_budget=bool(body and body.confirm_budget))
        except GatewayError as exc:
            if exc.code == "busy":
                raise ApiError("conflict") from None
            if exc.code == "budget_confirm":
                raise ApiError(
                    "validation", [{"loc": ["body", "confirm_budget"], "type": "budget_confirm"}]
                ) from None
            raise ApiError("policy") from None
        return await api.respond({"job": job.json()}, 202)

    @router.get("/p/{pid}/ai/jobs/{job_id}", name="ai_job")
    async def ai_job(pid: str, job_id: str) -> Response:
        p = api.project(pid)
        job = gw.jobs.get(job_id)
        if job is None or job.project_id != p.info.id:
            raise ApiError("not_found")
        return await api.respond({"job": job.json()})

    @router.get("/p/{pid}/ai/denkanstoesse", name="ai_denkanstoesse")
    async def ai_denkanstoesse(pid: str, state: str = Query("open")) -> Response:
        p = api.project(pid)
        if state not in _STATES:
            raise ApiError("validation", [{"loc": ["query", "state"], "type": "enum"}])
        profile = p.info.profile

        def view(conn: Any) -> dict[str, Any]:
            items, truncated = store.suggestions(conn, profile=profile, state=state, limit=store.LIMIT)
            return {"suggestions": items, "truncated": truncated}

        return await api.respond(await api.query(p, view))
