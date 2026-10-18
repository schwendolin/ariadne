"""``GET /p/{pid}/suggestions?state=`` (``docs/web-api.md`` 18.6): Denkanstösse mit Zustand.

Besitzer: Teil «regeln» des Baus v0.1-Oberfläche. Für die Palette und «Verworfene zeigen»: alle
Denkanstösse eines Zustands (``open`` Standard, ``done``, ``dismissed``, ``all``), höchstens 200,
Antwort ``{ suggestions, truncated }``. Die Denkanstösse kommen aus :mod:`ariadne.rules.api`
(im Thread der Auswertung, nur lesend); der Ausgang geht wie jede Antwort durch den Redaktor und die
zweite Schicht (``Api.respond``). Ariadne führt nie etwas davon aus (E10): Es gibt keinen
Ausführen-Weg, nur Text zum Kopieren.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from starlette.responses import Response

from ariadne.rules import api as rules_api
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError

__all__ = ["add_routes", "suggestions_view", "merged", "LIMIT", "STATES"]

LIMIT = 200
STATES = ("open", "done", "dismissed", "all")


def merged(conn: Any, profile: str, state: str, limit: int) -> tuple[list[dict[str, Any]], bool]:
    """Denkanstösse der KI (:mod:`ariadne.ai.store`, jüngste zuerst) vor denen der Regeln, zusammen
    höchstens ``limit``. Die KI-Denkanstösse stehen vorne, weil der Mensch sie eigens angefordert hat
    und es je Auftrag höchstens vier sind."""
    from ariadne.ai import store as ai_store

    ai, ai_cut = ai_store.suggestions(conn, profile=profile, state=state, limit=limit)
    rest = max(0, limit - len(ai))
    rules, rules_cut = rules_api.suggestions(conn, profile=profile, state=state, limit=rest)  # type: ignore[arg-type]
    return ai + rules, bool(ai_cut or rules_cut)


def suggestions_view(conn: Any, profile: str, state: str) -> dict[str, Any]:
    items, truncated = merged(conn, profile, state, LIMIT)
    return {"suggestions": items, "truncated": truncated}


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/suggestions", name="suggestions")
    async def get_suggestions(
        pid: str,
        state: str = Query(default="open", max_length=16),  # noqa: B008
    ) -> Response:
        p = api.project(pid)
        if state not in STATES:
            raise ApiError("validation", [{"loc": ["query", "state"], "type": "enum"}])
        profile = p.info.profile
        return await api.respond(await api.query(p, lambda c: suggestions_view(c, profile, state)))
