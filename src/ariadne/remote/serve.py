"""``ariadne remote serve``: Forced Command des Mac-Schlüssels (R5, R11, Konzept 4.2).

Besitzer: Teil «remote». **Stub aus Phase 1**: lehnt alles ab.

Endzustand: liest ``SSH_ORIGINAL_COMMAND`` (nie argv des Clients, nie eine Shell) und kennt
genau ``code``, ``unlock``, ``lock``, ``revoke``, ``backup``, ``restore`` und ``check``. Alles
andere, auch ``scp -t``, ``sftp`` bzw. ``internal-sftp``, Shell-Metazeichen, zusätzliche Wörter
und leere Befehle, endet mit einer klaren deutschen Meldung auf stderr und Exit 2.

* ``code``: Schnellprüfung (:func:`ariadne.remote.check.quick_ok`), dann ``ctl ui.code`` mit
  ``typed`` = stdin ist ein Terminal (``ssh -t``: kurzer Tippcode; ohne Terminal: 128 Bit
  für den Mac-Helfer). Der Code geht nur auf stdout dieses SSH-Kanals.
* ``unlock``: nur mit Terminal (``ssh -t``), sonst Ablehnung; dann wie ``ariadne unlock``
  (E101: öffnet das aktive Projekt, E102: Ausfallpuffer ohne Frage).
* ``lock``, ``revoke``: ctl ``lock`` bzw. ``ui.revoke`` (alle Sitzungen).
* ``backup``: nur wenn stdout kein Terminal ist; :func:`ariadne.backup.api.backup_to_stream`.
* ``restore``: nur ohne Operator-Tresor; :func:`ariadne.backup.api.restore_from_stream` von stdin.
* ``check``: Ausgabe wie ``ariadne remote check``.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping

from ariadne.paths import Paths

__all__ = ["main", "ALLOWED"]

ALLOWED = ("code", "unlock", "lock", "revoke", "backup", "restore", "check")

# Phase 1: Stub. Der Besitzer setzt STUB = False, sobald die echte Umsetzung steht; abhängige
# Tests anderer Teile überspringen sich bis dahin mit diesem Grund (Vertrag v0.1-Server 4).
STUB = True


def main(paths: Paths, env: Mapping[str, str]) -> int:
    """Führt den Befehl aus ``env['SSH_ORIGINAL_COMMAND']`` aus. Gibt den Exit-Code zurück."""
    print("Fehler: ariadne remote serve ist noch nicht gebaut. Nichts ausgeführt.", file=sys.stderr)
    return 2
