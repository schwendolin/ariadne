"""``ariadne remote check`` und ``ariadne remote serve`` (R10, R11, Konzept Fernzugriff 7).

Besitzer: Teil «remote» (Vertrag v0.1-Server 3.6).

* ``remote check [--full]``: Systemprüfung wie ``ariadne doctor``; ``--full`` fragt einmal per
  ``sudo`` und prüft zusätzlich ``sshd -T`` und den Filter (``nft``). Exit 1 bei einem ``fail``.
* ``remote serve``: Forced Command für den Mac-Schlüssel in ``authorized_keys``; liest nur
  ``SSH_ORIGINAL_COMMAND`` (:mod:`ariadne.remote.serve`).

Runtime-Ordner: In einer SSH-Sitzung fehlt ``XDG_RUNTIME_DIR`` je nach PAM-Einstellung; dann
fänden ``remote serve`` und der Daemon verschiedene ``ctl.sock``. Darum setzt ``remote`` die
Variable auf ``/run/user/<uid>``, wenn sie fehlt und der Ordner existiert, dem Benutzer gehört und
0700 hat; sonst bleibt sie leer und ``serve`` meldet das klar (kein Raten).
"""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
from collections.abc import MutableMapping
from typing import Any

from ariadne.cli.common import say
from ariadne.paths import Paths, default_paths

__all__ = ["register", "cmd_remote", "ensure_runtime_dir"]


def ensure_runtime_dir(env: MutableMapping[str, str], *, uid: int | None = None,
                       run_root: str = "/run/user") -> bool:
    """Setzt ``XDG_RUNTIME_DIR``, falls es fehlt und ``/run/user/<uid>`` sicher ist.

    Gibt zurück, ob die Variable danach gesetzt ist."""
    if env.get("XDG_RUNTIME_DIR"):
        return True
    uid = os.getuid() if uid is None else uid
    d = os.path.join(run_root, str(uid))
    try:
        st = os.lstat(d)
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or st.st_mode & 0o077:
        return False
    env["XDG_RUNTIME_DIR"] = d
    return True


def _sudo_once() -> bool:
    """Fragt einmal nach dem sudo-Passwort (``sudo -v``); danach laufen die Prüfungen mit ``sudo -n``."""
    try:
        return subprocess.run(["sudo", "-v"], check=False).returncode == 0
    except OSError:
        return False


def cmd_remote(paths: Paths, args: argparse.Namespace) -> int:
    if args.rcmd == "serve":
        from ariadne.remote import serve

        ensure_runtime_dir(os.environ)
        return serve.main(default_paths(), os.environ)
    from ariadne.remote.check import render, run_checks

    if args.full and os.getuid() != 0:
        say("remote check --full: sudo fragt einmal nach deinem Passwort (für sshd -T und nft).")
        if not _sudo_once():
            say("[!!] sudo verweigert: ohne --full prüfen oder als Administrator anmelden")
            return 1
    ensure_runtime_dir(os.environ)
    lines, worst = render(run_checks(default_paths(), full=args.full))
    for line in lines:
        say(line)
    return worst


def register(sub: Any) -> None:
    sp = sub.add_parser("remote", help="Fernzugriff: Systemprüfung und Forced Command für den Mac-Schlüssel")
    rsub = sp.add_subparsers(dest="rcmd", required=True, metavar="AKTION")
    rc = rsub.add_parser("check", help="Fernzugriff prüfen (sshd, Port 7330, Schlüssel, Tailscale)")
    rc.add_argument("--full", action="store_true", help="mit sudo: sshd -T und nft (fragt einmal)")
    rsub.add_parser("serve", help="Forced Command für authorized_keys (liest SSH_ORIGINAL_COMMAND)")
    sp.set_defaults(fn=cmd_remote)
