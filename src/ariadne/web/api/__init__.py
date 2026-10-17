"""API v2 der Web-Oberfläche (``docs/web-api.md``, Vertrag v0.1-Server, Abschnitt 3.2).

Besitzer: Teil «api». **Stub aus Phase 1**: Beide Einstiegspunkte haben ihre endgültige
Signatur; ``register`` hängt noch keine Routen an, ``attach_sources`` meldet nichts.

Der Server-Kern ruft

* :func:`register` genau einmal beim Bau der App. Die Routen liegen unter ``/api/v1``
  (projektbezogen unter ``/api/v1/p/{pid}``). Anmeldung (``/api/v1/session``) und der
  Ereignisstrom (``/api/v1/events``) gehören dem Server-Kern, nicht hierher.
* :func:`attach_sources` beim Start des Web-Servers; die zurückgegebene Funktion beim Stopp.
  Sie übersetzt Ereignisse des Daemons (``daemon.add_listener``) und der Auswertung
  (``daemon.ingest.add_listener``) in Bus-Ereignisse (``ctx.bus.publish``).

Jede Route ist ``async def``, prüft nichts Sicherheitsrelevantes selbst neu (das tut die
Middleware), liefert Zieldaten nur als JSON-Strings und schickt jede Antwort mit Zieldaten
durch ``daemon.redactor.redact_json`` (E72).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ariadne.web.ctx import WebContext

__all__ = ["register", "attach_sources"]

# Phase 1: Stub. Der Besitzer setzt STUB = False, sobald die echte Umsetzung steht; abhängige
# Tests anderer Teile überspringen sich bis dahin mit diesem Grund (Vertrag v0.1-Server 4).
STUB = True


def register(app: Any, ctx: WebContext) -> None:
    """Hängt alle Routen der API v2 an ``app`` (FastAPI). Stub: noch keine Routen."""
    return None


def attach_sources(ctx: WebContext) -> Callable[[], None]:
    """Meldet Daemon- und Auswertungsereignisse auf ``ctx.bus``; gibt eine Abmeldefunktion zurück."""

    def detach() -> None:
        return None

    return detach
