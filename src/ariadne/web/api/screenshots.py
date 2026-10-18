"""Screenshots (E32, Architektur 4.3): ``POST /p/{pid}/screenshots`` und ``GET /p/{pid}/screenshots``.

* ``POST``: Dashboard-Knopf. Der Server wartet ``delay_s`` (Countdown, Standard 3 s, damit die
  Oberfläche nicht selbst im Bild landet), nimmt im Daemon auf
  (:func:`ariadne.sources.screenshot_service.take`) und antwortet 201 mit dem Screenshot.
* ``GET``: Liste aus dem Journal (``shot.captured``), neueste zuerst. Im Präsentationsmodus ohne
  Fenstertitel, ``WM_CLASS`` und Notiz; das Bild selbst verweigert dann ``GET /blobs/{id}``.

Fehler der Aufnahme haben eigene Codes (``shot_display``, ``shot_wayland``, ``shot_window``,
``shot_region``, ``shot_failed``, alle 503) mit festen Texten im gemeinsamen Fehlerformat.
Fenstertitel sind Zieldaten: Ausgang nur über :meth:`Api.respond` (Redaktor, sichtbare Zeichen).
Fenstertitel und Notiz werden zudem mit den bekannten Secret-Werten (``secret_value``) maskiert wie in
Suche, Belegen und Denkanstössen (E99): Ein Ziel kann den Titel setzen (OSC-Titel, Browser).

Besitzer: Teil «screenshots» (Bau v0.1-Screenshots).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from fastapi import APIRouter, Body, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.responses import Response

from ariadne.daemon.ops_util import OpError
from ariadne.web.api.common import Api, valid_tid
from ariadne.web.api.errors import ApiError, JsonResponse, from_ctl
from ariadne.web.api.text import iso, mask_known
from ariadne.web.api.views import secret_values

__all__ = ["add_routes", "shot_view", "SHOT_STATUS"]

SHOT_STATUS = 503
DEFAULT_DELAY_S = 3


class Region(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    x: int = Field(ge=0, le=65535)
    y: int = Field(ge=0, le=65535)
    width: int = Field(ge=1, le=16384)
    height: int = Field(ge=1, le=16384)


class ShotRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    mode: Literal["window", "monitor", "region"] = "window"
    region: Region | None = None
    delay_s: int = Field(default=DEFAULT_DELAY_S, ge=0, le=10)
    terminal_id: str | None = Field(default=None, min_length=1, max_length=64)
    note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _region_matches_mode(self) -> ShotRequest:
        if (self.mode == "region") != (self.region is not None):
            raise ValueError("region passt nicht zum Modus")
        return self


def shot_error(code: str) -> JsonResponse:
    """Fehler einer Aufnahme im gemeinsamen Format, fester Text (nie Text einer Ausnahme)."""
    from ariadne.sources.screenshot import SHOT_ERRORS

    if code not in SHOT_ERRORS:
        code = "shot_failed"
    return JsonResponse({"error": {"code": code, "message": SHOT_ERRORS[code]}}, status_code=SHOT_STATUS)


def _str(v: Any) -> str | None:
    return v if isinstance(v, str) else None


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _masked(v: Any, known: Sequence[str]) -> str | None:
    t = _str(v)
    return mask_known(t, known) if t is not None else None


def shot_view(
    pid: str, h: dict[str, Any], *, presentation: bool, known: Sequence[str] = ()
) -> dict[str, Any]:
    """Ein Screenshot für die API (nur bekannte Felder mit Typprüfung). ``known``: bekannte Secret-Werte,
    längste zuerst; sie werden in Fenstertitel und Notiz maskiert."""
    blob_id = _str(h.get("blob_id"))
    out = {
        "id": _str(h.get("id")),
        "seq": _int(h.get("seq")),
        "ts": iso(h.get("ts_utc_ns")),
        "blob_id": blob_id,
        "url": f"/api/v1/p/{pid}/blobs/{blob_id}" if blob_id else None,
        "mime": "image/png",
        "mode": h.get("mode") if h.get("mode") in ("window", "monitor", "region") else None,
        "trigger": h.get("trigger") if h.get("trigger") in ("hotkey", "cli", "webui", "keystep") else None,
        "width": _int(h.get("width")),
        "height": _int(h.get("height")),
        "sha256": _str(h.get("sha256")),
        "dhash": _str(h.get("dhash")),
        "window_title": None if presentation else _masked(h.get("window_title"), known),
        "wm_class": None if presentation else _str(h.get("wm_class")),
        "terminal_id": _str(h.get("terminal_id")),
        "stream_off": _int(h.get("stream_off")),
        "host": _str(h.get("host")),
        "host_auto": h.get("host_auto") is True,
        "note": None if presentation else _masked(h.get("note"), known),
    }
    return out


def add_routes(router: APIRouter, api: Api) -> None:
    @router.post("/p/{pid}/screenshots", name="screenshots", status_code=201)
    async def take(pid: str, body: ShotRequest = Body(default_factory=ShotRequest)) -> Response:  # noqa: B008
        from ariadne.sources import screenshot_service
        from ariadne.sources.screenshot import ShotError

        p = api.project(pid)
        if body.terminal_id is not None and not valid_tid(body.terminal_id):
            raise ApiError("validation", [{"loc": ["body", "terminal_id"], "type": "invalid"}])
        region = body.region.model_dump() if body.region is not None else None
        try:
            res = await screenshot_service.take(
                api.daemon, mode=body.mode, trigger="webui", region=region, delay_s=body.delay_s,
                terminal_id=body.terminal_id, note=body.note,
            )
        except ShotError as exc:
            return shot_error(exc.code)
        except OpError as exc:
            raise from_ctl({"code": exc.code}) from None
        api.same(p)
        presentation = bool(api.daemon.presentation)
        known = await api.query(p, secret_values)
        view = shot_view(pid, res, presentation=presentation, known=known)
        return await api.respond({"screenshot": view}, 201)

    @router.get("/p/{pid}/screenshots", name="screenshots_list")
    async def list_(pid: str, limit: int = Query(default=200, ge=1, le=500)) -> Response:  # noqa: B008
        from ariadne.sources.screenshot_service import list_shots

        p = api.project(pid)
        presentation = bool(api.daemon.presentation)
        items = await api.query_journal(p, lambda _conn, journal: list_shots(journal, limit))
        known = await api.query(p, secret_values)
        return await api.respond({
            "items": [shot_view(pid, h, presentation=presentation, known=known) for h in items],
            "presentation": presentation,
        })
