"""``ariadne backup`` und ``ariadne restore`` (E91, Konzept Fernzugriff 6).

Besitzer: Teil «backup» (Vertrag v0.1-Server). **Stub aus Phase 1**: Argumente festgelegt,
die Befehle melden, dass die Sicherung noch fehlt (Exit 1).

Endzustand: ``ariadne backup`` schreibt die age-verschlüsselte Sicherung auf stdout (verweigert,
wenn stdout ein Terminal ist) oder mit ``--to-file PFAD`` in eine neue Datei (0600, ``O_EXCL``).
``ariadne restore`` liest den entschlüsselten Strom von stdin oder ``--from-file PFAD``; mit
``--identity DATEI`` entschlüsselt es eine ``.age``-Datei selbst (Recovery-Schlüssel in der VM).
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from ariadne.paths import Paths

__all__ = ["register", "cmd_backup", "cmd_restore"]


def cmd_backup(paths: Paths, args: argparse.Namespace) -> int:
    print("Fehler: ariadne backup ist noch nicht gebaut.", file=sys.stderr)
    return 1


def cmd_restore(paths: Paths, args: argparse.Namespace) -> int:
    print("Fehler: ariadne restore ist noch nicht gebaut.", file=sys.stderr)
    return 1


def register(sub: Any) -> None:
    sp = sub.add_parser("backup", help="verschlüsselte Sicherung (age) auf stdout oder in eine Datei")
    sp.add_argument("--to-file", metavar="PFAD", help="in eine neue Datei schreiben (statt stdout)")
    sp.add_argument("--project", action="append", metavar="SLUG", help="nur diese Projekte (mehrfach)")
    sp.set_defaults(fn=cmd_backup)

    sp = sub.add_parser("restore", help="Sicherung zurückspielen (nur in eine Installation ohne Tresor)")
    sp.add_argument("--from-file", metavar="PFAD", help="aus Datei lesen (statt stdin)")
    sp.add_argument("--identity", metavar="DATEI",
                    help="age-Schlüssel, um eine verschlüsselte Datei in der VM zu entschlüsseln")
    sp.set_defaults(fn=cmd_restore)
