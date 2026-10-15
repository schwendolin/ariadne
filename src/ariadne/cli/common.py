"""Gemeinsame Bausteine der CLI (``cli/main.py`` und ``cli/analysis.py``).

Stabile Schnittstelle laut Vertrag v0.1-Bedienung: Änderungen nur additiv.
Alles, was aus Zieldaten oder vom Daemon stammt, geht durch :func:`s` (``term_safe``).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Any

from ariadne.daemon.client import CtlClient
from ariadne.paths import Paths
from ariadne.termsafe import term_safe

__all__ = ["CliError", "s", "say", "read_line_fd", "read_secret", "_client", "_call", "_terminal_id"]


class CliError(Exception):
    pass


def s(value: Any, max_len: int = 200) -> str:
    return term_safe(value, max_len=max_len)


def say(text: str = "") -> None:
    print(text, flush=True)


# --------------------------------------------------------------------------- #
# Eingaben
# --------------------------------------------------------------------------- #


def read_line_fd(fd: int) -> str:
    """Liest eine Zeile von einem geerbten Dateideskriptor (für Skripte und Tests)."""
    try:
        with os.fdopen(os.dup(fd), "r", encoding="utf-8", errors="strict", closefd=True) as fh:
            line = fh.readline()
    except (OSError, UnicodeDecodeError) as exc:
        raise CliError(f"Dateideskriptor {fd} nicht lesbar") from exc
    return line.rstrip("\r\n")


def read_secret(prompt: str, fd: int | None, *, confirm: bool = False) -> str:
    if fd is not None:
        return read_line_fd(fd)
    if not sys.stdin.isatty():
        raise CliError("keine interaktive Eingabe; --passphrase-fd N verwenden")
    value = getpass.getpass(prompt)
    if confirm and getpass.getpass("Wiederholen: ") != value:
        raise CliError("Eingaben stimmen nicht überein")
    return value


# --------------------------------------------------------------------------- #
# Daemon-Zugang
# --------------------------------------------------------------------------- #


def _client(paths: Paths, *, start: bool = True) -> CtlClient:
    client = CtlClient(paths.ctl_sock)
    if client.ping():
        return client
    if not start:
        raise CliError("Daemon läuft nicht")
    from ariadne.daemon.main import spawn_detached

    if not spawn_detached(paths, timeout=3.0):
        raise CliError(f"Daemon liess sich nicht starten (siehe {paths.daemon_log})")
    return client


def _call(paths: Paths, op: str, *, start: bool = True, **args: Any) -> Any:
    return _client(paths, start=start).call(op, **args)


def _terminal_id(args: argparse.Namespace) -> str:
    tid = getattr(args, "terminal", None) or os.environ.get("ARIADNE_TERMINAL_ID")
    if not tid:
        raise CliError("kein Terminal: ARIADNE_TERMINAL_ID fehlt (läuft der Shim?) oder --terminal angeben")
    return tid
