"""API v2 der Web-Oberfläche (``docs/web-api.md``, Vertrag v0.1-Server, Abschnitt 3.2).

Besitzer: Teil «api». Der Server-Kern ruft

* :func:`register` genau einmal beim Bau der App. Die Routen liegen unter ``/api/v1``
  (projektbezogen unter ``/api/v1/p/{pid}``). Anmeldung (``/api/v1/session``) und der
  Ereignisstrom (``/api/v1/events``) gehören dem Server-Kern, nicht hierher.
* :func:`attach_sources` beim Start des Web-Servers; die zurückgegebene Funktion beim Stopp.
  Sie übersetzt Ereignisse des Daemons (``daemon.add_listener``) und der Auswertung
  (``daemon.ingest.add_listener``) in Bus-Ereignisse (``ctx.bus.publish``).

Jede Route ist ``async def``, prüft nichts Sicherheitsrelevantes selbst neu (das tut die
Middleware), liefert Zieldaten nur als JSON-Strings mit sichtbaren Steuerzeichen und schickt jede
Antwort mit Zieldaten durch ``daemon.redactor.redact_json`` (E72). Fehler haben das gemeinsame
Format ``{"error": {"code", "message", "detail"?}}`` mit festen Texten (:mod:`.errors`).

Module: :mod:`.status` (Status, Pause, Präsentation), :mod:`.terminals` (Terminals, Kontext),
:mod:`.project` (Projekt, Änderungen, Positionen), :mod:`.graph` (Karte), :mod:`.hosts` (Hosts,
Services), :mod:`.next` (Als Nächstes), :mod:`.timeline` (Zeitachse, Eingaben), :mod:`.evidence`
(Belege, Logzeilen), :mod:`.decisions` (Entscheide), :mod:`.search` (Suche, Warteliste),
:mod:`.secrets` (Aufdecken), :mod:`.later` (501), :mod:`.events` (SSE-Quellen).

Bau v0.1-Oberfläche (web-api.md 18): :mod:`.ui_state` (Vorlieben, «Neu seit», Scope-Quittung),
:mod:`.findings` (Findings), :mod:`.suggestions` (Denkanstösse), :mod:`.clipboard` (in die Kali
kopieren).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ariadne.web.ctx import WebContext

__all__ = ["register", "attach_sources", "PREFIX"]

# Phase 1: Stub. Der Besitzer setzt STUB = False, sobald die echte Umsetzung steht; abhängige
# Tests anderer Teile überspringen sich bis dahin mit diesem Grund (Vertrag v0.1-Server 4).
STUB = False

PREFIX = "/api/v1"


def register(app: Any, ctx: WebContext) -> None:
    """Hängt alle Routen der API v2 an ``app`` (FastAPI)."""
    from fastapi import APIRouter

    from ariadne.web.api import (
        ai,
        blobs,
        clipboard,
        decisions,
        evidence,
        exports,
        findings,
        graph,
        hosts,
        later,
        project,
        scope,
        screenshots,
        search,
        secrets,
        status,
        suggestions,
        terminals,
        timeline,
        ui_state,
    )
    from ariadne.web.api import (
        next as next_,
    )
    from ariadne.web.api.common import Api
    from ariadne.web.api.errors import ApiRoute

    api = Api(ctx)
    router = APIRouter(prefix=PREFIX, route_class=ApiRoute)
    for mod in (
        status,
        terminals,
        project,
        graph,
        hosts,
        next_,
        timeline,
        evidence,
        decisions,
        search,
        secrets,
        # Bau v0.1-Oberfläche (web-api.md 18): vor ``later``, damit echte Routen die 501-Routen
        # mit gleichem Pfad verdecken, bis der Besitzer sie aus ``later`` entfernt.
        ui_state,
        findings,
        suggestions,
        clipboard,
        ai,  # Bau v0.1-KI: KI-Denkanstoss (Teil «ki»)
        exports,  # Bau v0.1-Export: Bericht-Export und Phasen (Teil «export»)
        screenshots,  # Bau v0.1-Screenshots: Screenshots (Teil «screenshots»)
        blobs,  # Bau v0.1-Screenshots: Bilder aus dem Blob-Store (Teil «screenshots»)
        scope,  # Korrektur nach dem Praxistest: Scope anzeigen und ändern (E129)
    ):
        mod.add_routes(router, api)
    later.add_routes(router)
    app.include_router(router)


def attach_sources(ctx: WebContext) -> Callable[[], None]:
    """Meldet Daemon- und Auswertungsereignisse auf ``ctx.bus``; gibt eine Abmeldefunktion zurück."""
    from ariadne.web.api.events import attach_sources as attach

    return attach(ctx)
