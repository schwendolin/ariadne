"""Die ASGI-App des Web-Servers (Vertrag v0.1-Server 3.2).

Aufbau von aussen nach innen:

1. :class:`~ariadne.web.security.SecurityMiddleware`: Peer, Host, Fetch-Metadaten, OPTIONS,
   Origin, Grösse, Anmeldung, Header auf jeder Antwort.
2. Verteiler: ``/api/...`` an FastAPI, alles andere an die Statik (SPA). Unbekannte Pfade unter
   ``/api/`` ergeben so immer 404 JSON, nie die SPA-Shell.
3. FastAPI ohne Schema über HTTP (``docs_url``, ``redoc_url``, ``openapi_url`` aus) mit den
   Routen des Servers (``/api/v1/session``, ``/api/v1/events``) und der API
   (:func:`ariadne.web.api.register`, genau einmal).

Fehler haben überall das gemeinsame Format ``{"error": {"code", "message", "detail"?}}`` mit
festem Text pro Code; bei 422 nennt ``detail`` nur Ort und Art, nie den Wert.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from ariadne.web import api as api_mod
from ariadne.web.ctx import SessionInfo, WebContext, session_of
from ariadne.web.peer import PeerInfo
from ariadne.web.security import (
    PEER_KEY,
    SESSION_PATH,
    Receive,
    Scope,
    SecurityMiddleware,
    Send,
    allowed_hosts,
    code_for_status,
    error_message,
)
from ariadne.web.sessions import AuthError, SessionStore
from ariadne.web.sse import EventBus
from ariadne.web.static import STATIC_DIR, StaticApp

__all__ = ["WebApp", "build_app", "iso_utc", "session_view", "EVENTS_PATH"]

EVENTS_PATH = "/api/v1/events"
JSON_TYPE = "application/json; charset=utf-8"


def iso_utc(ns: int) -> str:
    """ISO-8601 in UTC mit Mikrosekunden: ``2026-10-08T12:02:11.123456Z``."""
    dt = datetime.fromtimestamp(ns // 1_000_000_000, UTC).replace(microsecond=(ns // 1000) % 1_000_000)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def session_view(info: SessionInfo) -> dict[str, Any]:
    """``SessionView`` (web-api.md 3): nie Token, Hash oder Prozess."""
    return {"session_id": info.session_id, "origin": info.origin, "created_at": iso_utc(info.created_ns),
            "expires_at": iso_utc(info.expires_ns)}


def _error(status: int, code: str, *, headers: dict[str, str] | None = None,
           detail: list[dict[str, Any]] | None = None) -> JSONResponse:
    err: dict[str, Any] = {"code": code, "message": error_message(code)}
    if detail is not None:
        err["detail"] = detail
    return JSONResponse({"error": err}, status_code=status, headers=headers, media_type=JSON_TYPE)


class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


@dataclass
class WebApp:
    asgi: SecurityMiddleware  # an uvicorn
    api: FastAPI  # innen (Tests, Schema-Erzeugung)


class _Dispatch:
    def __init__(self, api: FastAPI, static: StaticApp) -> None:
        self.api = api
        self.static = static

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = str(scope.get("path", ""))
        if path == "/api" or path.startswith("/api/"):
            await self.api(scope, receive, send)
        else:
            await self.static(scope, receive, send)


def _install_handlers(app: FastAPI) -> None:
    async def http_error(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, StarletteHTTPException)
        headers = {k: v for k, v in (exc.headers or {}).items() if k.lower() == "allow"}
        return _error(exc.status_code, code_for_status(exc.status_code), headers=headers or None)

    async def validation_error(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, RequestValidationError)
        detail = [{"loc": [p for p in e.get("loc", ()) if isinstance(p, str | int)][:8],
                   "type": str(e.get("type", "invalid"))[:64]} for e in list(exc.errors())[:20]]
        return _error(422, "validation", detail=detail)

    async def internal_error(request: Request, exc: Exception) -> Response:
        return _error(500, "internal")

    app.add_exception_handler(StarletteHTTPException, http_error)
    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_exception_handler(Exception, internal_error)


def _server_routes(app: FastAPI, sessions: SessionStore, bus: EventBus) -> None:
    @app.post(SESSION_PATH, include_in_schema=True)
    async def create_session(request: Request, body: SessionRequest) -> Response:
        """Tauscht einen Einmal-Code gegen ein Token, gebunden an den Peer (R2, R5)."""
        peer = request.scope.get("state", {}).get(PEER_KEY)
        if not isinstance(peer, PeerInfo):
            return _error(403, "forbidden")
        try:
            token, info = sessions.exchange(body.code, peer)
        except AuthError as exc:
            status = 429 if exc.code == "rate_limited" else 401
            return _error(status, exc.code)
        return JSONResponse({"token": token, "expires_at": iso_utc(info.expires_ns),
                             "session": session_view(info)}, media_type=JSON_TYPE)

    @app.get(SESSION_PATH)
    async def get_session(request: Request) -> Response:
        """Die eigene Sitzung (Herkunft «lokal» oder «über sshd»)."""
        return JSONResponse(session_view(session_of(request)), media_type=JSON_TYPE)

    @app.delete(SESSION_PATH)
    async def delete_session(request: Request) -> Response:
        """Abmelden: Token widerrufen, offene Ströme schliessen, Browser-Speicher leeren (R7)."""
        sessions.revoke(session_of(request).session_id)
        return Response(status_code=204, headers={"Clear-Site-Data": '"cache", "storage"'})

    @app.get(EVENTS_PATH)
    async def events(request: Request) -> Response:
        """Ereignisstrom (web-api.md 14): nur Hinweise, nie Daten."""
        info = session_of(request)
        sub = bus.subscribe(info.session_id, request.headers.get("last-event-id"))
        if not sessions.is_active(info.session_id):
            bus.close_session(info.session_id)
        return StreamingResponse(bus.iterate(sub), media_type="text/event-stream",
                                 headers={"X-Accel-Buffering": "no"})


def build_app(ctx: WebContext, sessions: SessionStore, bus: EventBus, *, uid: int,
              static_root: Path = STATIC_DIR) -> WebApp:
    """Baut die App für einen Server auf ``ctx.host:ctx.port`` (Port schon gebunden)."""
    api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False,
                  title="Ariadne", version="2")
    _install_handlers(api)
    _server_routes(api, sessions, bus)
    api_mod.register(api, ctx)  # genau einmal (Vertrag 3.2)
    inner = _Dispatch(api, StaticApp(static_root))
    outer = SecurityMiddleware(inner, hosts=allowed_hosts(ctx.port), sessions=sessions, uid=uid)
    return WebApp(asgi=outer, api=api)
