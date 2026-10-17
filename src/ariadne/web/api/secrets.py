"""``POST /p/{pid}/secrets/reveal``: genau einen Secret-Wert aufdecken (``docs/web-api.md`` 13.3,
E99, E104).

Nur im Profil lab und nie im Präsentationsmodus (403 ``policy``, geprüft vor jedem Zugriff).
Eingaben über die ctl-Operation ``input.reveal`` (Herkunft ``webui``), Claims über
``secret_value``. Eigene Secrets (sudo-Passwort, Passphrase) bleiben auch hier durch den Redaktor
ersetzt (E72); über HTTP gibt es sie nie im Klartext. Nichts davon geht ins Log.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body
from starlette.responses import Response

from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.models import RevealClaim, RevealInput, RevealRequest
from ariadne.web.api.views import loads

__all__ = ["add_routes", "claim_secret"]

_TAGS = ("<ESC>", "<BEL>", "<BS>", "<DEL>", "<CR>", "<LF>", "<TAB>", "<0x", "<U+")


def claim_secret(conn: Any, claim_key: str) -> str | None:
    """Klartext eines Secret-Werts (``identity.secret``) oder ``None``."""
    row = conn.execute("SELECT value_json, is_secret FROM claim WHERE claim_key = ?", (claim_key,)).fetchone()
    if row is None or not row[1]:
        return None
    value = loads(row[0], None)
    ref = value.get("ref") if isinstance(value, dict) else None
    if not isinstance(ref, str):
        return None
    hit = conn.execute("SELECT value FROM secret_value WHERE secret_ident = ?", (ref,)).fetchone()
    return str(hit[0]) if hit and isinstance(hit[0], str) else None


def add_routes(router: APIRouter, api: Api) -> None:
    @router.post("/p/{pid}/secrets/reveal", name="secret_reveal")
    async def reveal(pid: str, body: RevealRequest = Body(...)) -> Response:  # noqa: B008
        p = api.project(pid)
        if p.info.profile != "lab" or api.daemon.presentation:
            raise ApiError("policy")
        if isinstance(body, RevealInput):
            res = await api.call("input.reveal", {"seq": body.seq, "origin": "webui"})
            api.same(p)
            text = str(((res or {}).get("item") or {}).get("text") or "")
            ctrl = any(tag in text for tag in _TAGS)  # input.reveal liefert den Text schon sichtbar
            return await api.respond({"value": text, "ctrl": ctrl})
        assert isinstance(body, RevealClaim)
        value = await api.query(p, lambda c: claim_secret(c, body.claim_key))
        if value is None:
            raise ApiError("not_found")
        if api.daemon.presentation:  # während der Abfrage eingeschaltet
            raise ApiError("policy")
        bag = api.bag()
        shown = bag(value) or ""
        return await api.respond({"value": shown, "ctrl": bag.ctrl})
