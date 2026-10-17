"""``ariadne remote check`` und ``ariadne remote serve`` (R10, R11, Konzept Fernzugriff 7).

Besitzer: Teil «remote» (Vertrag v0.1-Server). **Stub aus Phase 1** mit festgelegten Argumenten.
"""

from __future__ import annotations

import argparse
import os
from typing import Any

from ariadne.cli.common import s, say
from ariadne.paths import Paths

__all__ = ["register", "cmd_remote"]


def cmd_remote(paths: Paths, args: argparse.Namespace) -> int:
    if args.rcmd == "serve":
        from ariadne.remote.serve import main

        return main(paths, os.environ)
    from ariadne.cli.doctor import FAIL, OK
    from ariadne.remote.check import run_checks

    worst = 0
    for c in run_checks(paths, full=args.full):
        tag = {OK: "[ok]", FAIL: "[!!]"}.get(c.level, "[--]")
        say(f"{tag} {s(c.title)}" + (f": {s(c.detail, 300)}" if c.detail else ""))
        if c.level == FAIL:
            worst = 1
    return worst


def register(sub: Any) -> None:
    sp = sub.add_parser("remote", help="Fernzugriff: Systemprüfung und Forced Command für den Mac-Schlüssel")
    rsub = sp.add_subparsers(dest="rcmd", required=True, metavar="AKTION")
    rc = rsub.add_parser("check", help="Fernzugriff prüfen (sshd, Port 7330, Schlüssel, Tailscale)")
    rc.add_argument("--full", action="store_true", help="mit sudo: sshd -T und nft (fragt einmal)")
    rsub.add_parser("serve", help="Forced Command für authorized_keys (liest SSH_ORIGINAL_COMMAND)")
    sp.set_defaults(fn=cmd_remote)
