"""Einbindung des Web-Servers in den Daemon (Vertrag v0.1-Server, Abschnitt 3.3).

Besitzer: Teil «server». **Stub aus Phase 1**: Die Klasse hat schon ihre endgültige Form
(:class:`ariadne.daemon.core.DaemonExtension`), startet aber noch nichts.

Endzustand (Teil «server»):

* ``start(daemon)``: ``[ui]`` aus ``config.toml`` lesen (nur ``127.0.0.1`` oder ``::1``,
  sonst Fehler und kein Start, R1), Sitzungen und Bus anlegen, FastAPI-App bauen
  (:mod:`ariadne.web.app`, ruft :func:`ariadne.web.api.register`), uvicorn im Loop des
  Daemons starten (eigene Klasse ohne Signal-Handler, ``access_log=False``), danach
  ``getsockname`` prüfen, ctl-Operationen ``ui.code``, ``ui.sessions``, ``ui.revoke`` und
  ``ui.status`` mit ``daemon.add_ops`` anmelden, Widerruf über ``daemon.add_listener``
  (``locked``, ``project`` mit ``change = closed``, ``stopping``), Ereignisquellen der API mit
  :func:`ariadne.web.api.attach_sources` anhängen.
* ``stop()``: alle Sitzungen widerrufen, SSE-Ströme schliessen, uvicorn beenden.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ariadne.paths import Paths

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon

__all__ = ["WebExtension"]

log = logging.getLogger("ariadne.web")

# Phase 1: Stub. Der Besitzer setzt STUB = False, sobald die echte Umsetzung steht; abhängige
# Tests anderer Teile überspringen sich bis dahin mit diesem Grund (Vertrag v0.1-Server 4).
STUB = True


class WebExtension:
    name = "web"

    def __init__(self, paths: Paths) -> None:
        self.paths = paths
        self.daemon: Daemon | None = None

    async def start(self, daemon: Daemon) -> None:
        self.daemon = daemon
        log.info("Web-Server noch nicht gebaut (Stub)")

    async def stop(self) -> None:
        self.daemon = None
