"""``POST /p/{pid}/secrets/copy``: einen Secret-Wert in die Zwischenablage der Kali (E111,
``docs/web-api.md`` 18.7). Der Wert geht nie an den Browser.

Körper wie beim Aufdecken (13.3): ``{ref: 'input', seq}`` für eine Eingabe ohne Echo oder
``{ref: 'claim', claim_key}`` für den Secret-Wert eines Claims. Nur Profil lab, nie im
Präsentationsmodus (403 ``policy``, vor jedem Zugriff geprüft). Den Rest erledigt die ctl-Operation
``clip.copy`` im Daemon (:mod:`ariadne.daemon.clipboard`): Wert auflösen, eigene Secrets nie,
Werkzeug und grafische Sitzung finden, Wert nur über stdin, nach 30 s leeren. Fehler: 404, 403,
422 (Wert mit Steuerzeichen), 503 ``clipboard_tool`` und ``clipboard_session``.

Besitzer: Teil «backend-ui» des Baus v0.1-Oberfläche.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body
from starlette.responses import Response

from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.models import RevealClaim, RevealInput, RevealRequest

__all__ = ["add_routes"]

_TOOLS = ("wl-copy", "xclip", "xsel")


def add_routes(router: APIRouter, api: Api) -> None:
    @router.post("/p/{pid}/secrets/copy", name="secret_copy", status_code=202)
    async def copy(pid: str, body: RevealRequest = Body(...)) -> Response:  # noqa: B008
        p = api.project(pid)
        if p.info.profile != "lab" or api.daemon.presentation:
            raise ApiError("policy")
        args: dict[str, Any] = {"origin": "webui"}
        if isinstance(body, RevealInput):
            args.update(ref="input", seq=body.seq)
        else:
            assert isinstance(body, RevealClaim)
            args.update(ref="claim", claim_key=body.claim_key)
        res = await api.call("clip.copy", args)
        api.same(p)
        tool = res.get("tool") if isinstance(res, dict) else None
        clear = res.get("clear_after_s") if isinstance(res, dict) else None
        # Nur feste Felder; nie den Wert (die ctl-Antwort hat ihn ohnehin nicht)
        return await api.respond(
            {
                "copied": True,
                "target": "kali",
                "clear_after_s": int(clear) if isinstance(clear, int) and not isinstance(clear, bool) else 30,
                "tool": tool if tool in _TOOLS else "xclip",
            },
            202,
        )
