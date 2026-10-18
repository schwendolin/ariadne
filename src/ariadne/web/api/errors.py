"""Fehlerformat der API (``docs/web-api.md`` 1.5) und Routen-Klasse, die es für die eigenen Routen
erzeugt (Vertrag v0.1-Server 3.2).

Jede Meldung ist ein fester deutscher Text pro Code. Nie Text aus einer Ausnahme, nie eine Meldung
einer ctl-Operation (sie kann Zieldaten enthalten), nie ein Wert aus der Anfrage. Bei 422 nennt
``detail`` nur Ort und Art des Fehlers, ohne Werte.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.requests import Request
from starlette.responses import Response

from ariadne.sources.screenshot import SHOT_ERRORS
from ariadne.web.api.text import visible_text

__all__ = [
    "MESSAGES",
    "STATUS",
    "ApiError",
    "ApiRoute",
    "JsonResponse",
    "error_response",
    "from_ctl",
    "validation_detail",
]

log = logging.getLogger("ariadne.web.api")

MESSAGES: dict[str, str] = {
    "unauthorized": "Nicht angemeldet oder Sitzung beendet.",
    "forbidden": "Anfrage abgelehnt.",
    "policy": "In diesem Profil oder Modus nicht erlaubt; im Terminal möglich.",
    "not_found": "Nicht gefunden.",
    "method": "Methode nicht erlaubt.",
    "no_project": "Kein Projekt offen: im Terminal ariadne start.",
    "project_mismatch": "Ein anderes Projekt ist offen.",
    "conflict": "Passt nicht mehr zum aktuellen Stand.",
    "too_large": "Anfrage zu gross.",
    "host": "Falscher Host.",
    "validation": "Eingabe ungültig.",
    "locked": "Gesperrt: im Terminal ariadne start oder ariadne unlock.",
    "rate_limited": "Zu viele Versuche: neuen Code holen.",
    "not_implemented": "Kommt in einer späteren Version.",
    "unavailable": "Auswertung nicht bereit, bitte später erneut.",
    "clipboard_tool": (
        "In der Kali fehlt ein Werkzeug für die Zwischenablage: xclip, xsel oder wl-copy installieren."
    ),
    "clipboard_session": "Keine grafische Sitzung in der Kali gefunden. Am Kali-Desktop anmelden.",
    "guardrail": (
        "Ziel ausserhalb der Lab-Allowlist: nur im Terminal mit ariadne scope add <ziel> --not-customer."
    ),
    "internal": "Interner Fehler.",
    **SHOT_ERRORS,  # shot_display, shot_wayland, shot_window, shot_region, shot_failed (alle 503)
}

STATUS: dict[str, int] = {
    "unauthorized": 401,
    "forbidden": 403,
    "policy": 403,
    "not_found": 404,
    "method": 405,
    "no_project": 409,
    "project_mismatch": 409,
    "conflict": 409,
    "too_large": 413,
    "host": 421,
    "validation": 422,
    "locked": 423,
    "rate_limited": 429,
    "not_implemented": 501,
    "unavailable": 503,
    "clipboard_tool": 503,
    "clipboard_session": 503,
    "guardrail": 403,
    "internal": 500,
    **dict.fromkeys(SHOT_ERRORS, 503),
}

# Codes der ctl-Operationen -> Code der API (web-api.md 1.5); alles andere ist «internal».
_CTL: dict[str, str] = {
    "locked": "locked",
    "no_project": "no_project",
    "not_found": "not_found",
    "unknown_terminal": "not_found",
    "invalid": "validation",
    "policy": "policy",
    "conflict": "conflict",
    "project_changed": "conflict",
    "guardrail": "guardrail",
    "no_ingest": "unavailable",
    "clipboard_tool": "clipboard_tool",
    "clipboard_session": "clipboard_session",
    **{code: code for code in SHOT_ERRORS},
}

_DETAIL_MAX = 50  # höchstens so viele Einträge in ``detail`` (422)


class JsonResponse(JSONResponse):
    """JSON in UTF-8 mit ausdrücklichem ``charset`` (web-api.md 1.2)."""

    media_type = "application/json; charset=utf-8"


class ApiError(Exception):
    """Fehler einer Route mit festem Code. ``detail`` nur bei 422 (Orte, ohne Werte)."""

    def __init__(self, code: str, detail: list[dict[str, Any]] | None = None) -> None:
        if code not in MESSAGES:
            code = "internal"
        super().__init__(code)
        self.code = code
        self.detail = detail


def from_ctl(error: Any) -> ApiError:
    """Abbildung eines ctl-Fehlers (``{"code", "message"}``) auf die API; die Meldung fällt weg."""
    code = error.get("code") if isinstance(error, dict) else None
    return ApiError(_CTL.get(str(code), "internal"))


def error_response(code: str, detail: list[dict[str, Any]] | None = None) -> JsonResponse:
    if code not in MESSAGES:
        code = "internal"
    body: dict[str, Any] = {"code": code, "message": MESSAGES[code]}
    if detail:
        body["detail"] = detail[:_DETAIL_MAX]
    return JsonResponse({"error": body}, status_code=STATUS[code])


def _loc_part(part: Any) -> str | int:
    if isinstance(part, int) and not isinstance(part, bool):
        return part
    return visible_text(str(part))[:64]


def validation_detail(errors: Any) -> list[dict[str, Any]]:
    """Orte und Arten aus Pydantic-Fehlern, nie die Eingabewerte (``input``, ``ctx``, ``msg``)."""
    out: list[dict[str, Any]] = []
    for e in list(errors or [])[:_DETAIL_MAX]:
        if not isinstance(e, dict):
            continue
        loc = [_loc_part(p) for p in (e.get("loc") or ())][:8]
        out.append({"loc": loc, "type": visible_text(str(e.get("type") or "invalid"))[:64]})
    return out


class ApiRoute(APIRoute):
    """Routen-Klasse der API: erzeugt das gemeinsame Fehlerformat für ihre eigenen Routen (auch
    ``RequestValidationError``), ohne Exception-Handler an der App (Vertrag 3.2)."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except ApiError as exc:
                return error_response(exc.code, exc.detail)
            except RequestValidationError as exc:
                return error_response("validation", validation_detail(exc.errors()))
            except Exception as exc:  # nie Text der Ausnahme an den Browser oder ins Log
                log.error("API-Route fehlgeschlagen (%s)", type(exc).__name__)
                return error_response("internal")

        return handler
