"""Erweiterungen, die der Daemon im Betrieb lädt (Vertrag v0.1-Server).

Heute nur der Web-Server (:class:`ariadne.web.integration.WebExtension`). Er läuft im
Loop des Daemons, lauscht nur auf Loopback (E89, R1) und startet fail-closed: Kann er
nicht sicher starten, bleibt er aus und die Aufnahme läuft weiter.

``ARIADNE_WEB=0`` in der Umgebung schaltet ihn ab (Tests, die einen Daemon als Prozess
starten, damit kein Test den echten Port 7330 belegt). Abschalten macht Ariadne nur
enger, nie offener; einen Schalter, der die Loopback-Pflicht aufhebt, gibt es nicht.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import TYPE_CHECKING

from ariadne.paths import Paths

if TYPE_CHECKING:
    from ariadne.daemon.core import DaemonExtension

__all__ = ["default_extensions", "web_disabled"]

log = logging.getLogger("ariadne.daemon")


def web_disabled(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return env.get("ARIADNE_WEB", "").strip() == "0"


def default_extensions(paths: Paths, env: Mapping[str, str] | None = None) -> list[DaemonExtension]:
    """Erweiterungen für ``ariadne daemon run`` (systemd oder ``--detach``)."""
    exts: list[DaemonExtension] = []
    if web_disabled(env):
        log.info("Web-Server abgeschaltet (ARIADNE_WEB=0)")
        return exts
    try:
        from ariadne.web.integration import WebExtension
    except ImportError as exc:  # Paket unvollständig installiert: Aufnahme läuft trotzdem
        log.error("Web-Server nicht verfügbar (%s)", type(exc).__name__)
        return exts
    exts.append(WebExtension(paths))
    return exts
