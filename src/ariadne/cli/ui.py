"""``ariadne ui``: Dashboard öffnen, Code zeigen, Sitzungen ansehen und widerrufen.

Besitzer: Teil «server» (Vertrag v0.1-Server). **Stub aus Phase 1**: Die Argumente sind
festgelegt, die Befehle melden nur, dass der Web-Server noch fehlt.

Endzustand: ``ariadne ui`` holt über ``ctl.sock`` (Operation ``ui.code``) einen Einmal-Code,
schreibt eine Startdatei mit Rechten 0600 nach ``$XDG_RUNTIME_DIR/ariadne/`` (Weiterleitung auf
``http://127.0.0.1:7330/#c=<code>``, Code nur im Fragment), öffnet sie mit ``xdg-open`` und
löscht sie nach 10 s. ``--code`` zeigt stattdessen einen kurzen Tippcode (vorher
``pause_terminal``, damit er nicht in die Aufnahme kommt). ``--sessions`` listet Sitzungen mit
Herkunft (lokal oder über sshd), ``--revoke [ID]`` widerruft eine oder alle.
"""

from __future__ import annotations

import argparse
from typing import Any

from ariadne.cli.common import say
from ariadne.paths import Paths

__all__ = ["register", "cmd_ui"]


def cmd_ui(paths: Paths, args: argparse.Namespace) -> int:
    say("Die Web-UI ist noch nicht gebaut. Bis dahin: ariadne status, ariadne show, ariadne ctx.")
    return 0


def register(sub: Any) -> None:
    sp = sub.add_parser("ui", help="Dashboard öffnen (Einmal-Code), Sitzungen ansehen und widerrufen")
    grp = sp.add_mutually_exclusive_group()
    grp.add_argument("--code", action="store_true", help="kurzen Tippcode zeigen statt den Browser zu öffnen")
    grp.add_argument("--sessions", action="store_true", help="angemeldete Sitzungen mit Herkunft zeigen")
    grp.add_argument("--revoke", nargs="?", const="all", metavar="ID",
                     help="Sitzung ID widerrufen (ohne ID: alle)")
    sp.add_argument("--no-open", action="store_true", help="Startdatei nicht öffnen, nur den Pfad zeigen")
    sp.set_defaults(fn=cmd_ui)
