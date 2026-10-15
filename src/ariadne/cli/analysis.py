"""CLI-Befehle der Auswertung: Ansichten, Suche, Bestätigen, Verwerfen, Rückgängig, Reparse.

Gehört dem Teil «auswertung» (Vertrag v0.1-Bedienung). ``cli/main.py`` ruft nur
:func:`register` auf; neue Befehle der Auswertung kommen hierher.
Jeder Wert vom Daemon geht durch ``term_safe`` (:func:`ariadne.cli.common.s`).
"""

from __future__ import annotations

import argparse
from typing import Any

from ariadne.cli.common import _call, s, say
from ariadne.paths import Paths

__all__ = ["register"]


def cmd_show(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.cli.views import render_view

    res = _call(paths, "show", what=args.what, limit=args.limit)
    for line in render_view(args.what, res.get("items") or [], full=args.all, quiet=res.get("quiet")):
        say(line)
    ing = res.get("ingest") or {}
    if ing.get("last_error"):
        say(f"Hinweis: letzte Auswertung fehlgeschlagen ({s(ing['last_error'], 60)}), siehe Daemon-Log")
    return 0


def cmd_search(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.cli.views import render_search

    res = _call(paths, "search", text=args.text, limit=args.limit)
    for line in render_search(res.get("items") or []):
        say(line)
    return 0


def cmd_confirm(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.cli.views import render_confirm

    for line in render_confirm(_call(paths, "claim.confirm", ref=args.ref)):
        say(line)
    return 0


def cmd_undo(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.cli.views import render_undo

    for line in render_undo(_call(paths, "unit.distrust", ref=args.ref, reason=args.reason)):
        say(line)
    return 0


def cmd_reject(paths: Paths, args: argparse.Namespace) -> int:
    res = _call(paths, "claim.reject", ref=args.ref, reason=args.reason)
    for c in res.get("claims") or []:
        say(f"Verworfen: {s(c.get('subject'), 40)} {s(c.get('predicate'), 24)} = {s(c.get('value'), 60)}")
    return 0


def cmd_reparse(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.cli.views import render_reparse

    for line in render_reparse(_call(paths, "reparse")):
        say(line)
    return 0


def register(sub: Any) -> None:
    """Hängt die Befehle der Auswertung an den Subparser von ``ariadne``."""
    sp = sub.add_parser("show", help="Textansicht: hosts, services, inbox, timeline, keysteps, pending")
    sp.add_argument("what", choices=["hosts", "services", "inbox", "timeline", "keysteps", "pending"])
    sp.add_argument("--all", action="store_true", help="alle Einträge statt der ersten 25 pro Gruppe")
    sp.add_argument("--limit", type=int, default=200, help="höchstens so viele Einträge (Zeitachse)")
    sp.set_defaults(fn=cmd_show)

    sp = sub.add_parser("search", help="Volltextsuche in der aufgenommenen Ausgabe")
    sp.add_argument("text")
    sp.add_argument("--limit", type=int, default=50)
    sp.set_defaults(fn=cmd_search)

    sp = sub.add_parser("confirm", help="Werte bestätigen (Claim-Schlüssel oder Gruppe aus der Inbox; "
                                        "eine Gruppe übernimmt nur sichere Werte)")
    sp.add_argument("ref", help="Claim-Schlüssel (mind. 8 Zeichen) oder Gruppe wie g1a2b3c4d")
    sp.set_defaults(fn=cmd_confirm)

    sp = sub.add_parser("undo", help="Werte eines Befehls verwerfen (Rückgängig pro Befehl)")
    sp.add_argument("ref", help="Befehl wie 9f3c1a7e@1234 (siehe ariadne show timeline) oder volle cmd_id")
    sp.add_argument("--reason", help="Grund (steht im Journal)")
    sp.set_defaults(fn=cmd_undo)

    sp = sub.add_parser("reject", help="Claim verwerfen")
    sp.add_argument("ref", help="Claim-Schlüssel (mind. 8 Zeichen)")
    sp.add_argument("--reason")
    sp.set_defaults(fn=cmd_reject)

    sp = sub.add_parser("reparse", help="Auswertung neu aufbauen, Unterschiede zeigen")
    sp.set_defaults(fn=cmd_reparse)
