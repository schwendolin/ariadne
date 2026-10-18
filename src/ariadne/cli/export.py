"""``ariadne export`` (Bau v0.1-Export, E62, Architektur 8.7). Besitzer: Teil «export».

* ``ariadne export [--template cys|htb] [--klartext]`` schreibt den Bericht nach
  ``<projekt>/exports/<UTC>-<vorlage>/``. ``--klartext`` (Ziel-Credentials unmaskiert) geht nur im
  Profil lab und nach der Bestätigung im Terminal (``KLARTEXT`` tippen); eigene Secrets bleiben immer
  ersetzt (E72).
* ``ariadne export --liste`` zeigt die Exporte, ``--phasen`` die Phasen der Befehle,
  ``--phase BEFEHL PHASE`` korrigiert eine Phase (Entscheid ``d.unit.phase``).

Alles, was aus dem Projekt kommt, geht nur durch ``term_safe`` ins Terminal.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from ariadne.cli.common import CliError, _call, s, say
from ariadne.paths import Paths

__all__ = ["register", "cmd_export"]

_WARN = {
    "sync_folder": "Der Projektordner liegt in einem Sync-Ordner (Obsidian, Nextcloud, Dropbox, ...). "
    "Der Export wird mit synchronisiert.",
    "generic_secret": "Im Export stehen generische Secret-Muster (z. B. Private Key, API-Schlüssel). "
    "Vor dem Weitergeben prüfen.",
    "klartext": "Der Export enthält Zugangsdaten des Ziels im Klartext. Nicht weitergeben.",
}
_TIMEOUT = 600.0


def _confirm_klartext() -> str:
    if not sys.stdin.isatty():
        raise CliError("--klartext braucht eine Bestätigung im Terminal (stdin ist kein Terminal)")
    say("Achtung: Zugangsdaten des Ziels werden im Klartext in den Export geschrieben (nur Profil lab).")
    say("Eigene Secrets bleiben ersetzt. Zum Bestätigen KLARTEXT tippen, sonst Abbruch.")
    try:
        answer = input("> ").strip()
    except EOFError:
        answer = ""
    if answer != "KLARTEXT":
        raise CliError("abgebrochen, nichts exportiert")
    return answer


def cmd_export(paths: Paths, args: argparse.Namespace) -> int:
    template = args.template
    if args.liste:
        res = _call(paths, "export.list")
        items = res.get("exports") or []
        if not items:
            say("Noch keine Exporte.")
        for e in items:
            warn = ", ".join(s(w, 40) for w in e.get("warnings") or [])
            say(
                f"{s(e.get('export_id'), 60)}  {s(e.get('files'), 10)} Dateien"
                + (f"  Warnungen: {warn}" if warn else "")
            )
        return 0
    if args.phasen:
        res = _call(paths, "export.phases", template=template)
        for c in res.get("commands") or []:
            phase = c.get("phase") or "-"
            src = {"decision": "Entscheid", "rule": "Regel"}.get(c.get("source"), "keine Regel")
            say(
                f"{s(c.get('cmd_ref') or c.get('cmd_id'), 40):<22} {s(phase, 20):<14} {src:<12} "
                f"{s(c.get('command'), 80)}"
            )
        return 0
    if args.phase:
        ref, phase = args.phase
        res = _call(paths, "export.phase", template=template, cmd_id=ref, phase=phase)
        say(f"Phase gesetzt: {s(res.get('phase'), 20)} (Vorlage {s(res.get('template'), 8)})")
        return 0
    payload: dict[str, Any] = {"template": template}
    if args.klartext:
        payload.update(klartext=True, confirm=_confirm_klartext())
    say("Export läuft ...")
    res = _client_call(paths, payload)
    say(f"Export fertig: {s(res.get('path'), 120)} im Projektordner ({s(res.get('files'), 10)} Dateien)")
    for w in res.get("warnings") or []:
        say(f"Warnung: {_WARN.get(w, s(w, 40))}")
    return 0


def _client_call(paths: Paths, payload: dict[str, Any]) -> Any:
    from ariadne.cli.common import _client

    return _client(paths).call("export.run", timeout=_TIMEOUT, **payload)


def register(sub: Any) -> None:
    sp = sub.add_parser("export", help="Bericht als Markdown exportieren (Vorlage cys oder htb)")
    sp.add_argument("--template", choices=("cys", "htb"), default="cys", help="Vorlage (Standard: cys)")
    sp.add_argument(
        "--klartext",
        action="store_true",
        help="Zugangsdaten des Ziels im Klartext (nur Profil lab, Bestätigung im Terminal)",
    )
    grp = sp.add_mutually_exclusive_group()
    grp.add_argument("--liste", action="store_true", help="Exporte auflisten")
    grp.add_argument("--phasen", action="store_true", help="Phasen der Befehle zeigen")
    grp.add_argument(
        "--phase",
        nargs=2,
        metavar=("BEFEHL", "PHASE"),
        help="Phase eines Befehls setzen (z. B. 9f3c1a7e@1234 exploitation, omit)",
    )
    sp.set_defaults(fn=cmd_export)
