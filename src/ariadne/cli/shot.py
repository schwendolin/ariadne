"""``ariadne shot``: Screenshot auslösen (E32, Architektur 4.3).

Die CLI nimmt nicht selbst auf, sie schickt nur die Anfrage ``shot.take`` an den Daemon, zusammen
mit ihrer Sitzungsumgebung (``DISPLAY``, ``XAUTHORITY``, ``WAYLAND_DISPLAY``, ``XDG_RUNTIME_DIR``,
``XDG_SESSION_TYPE``), denn ein systemd-User-Dienst kennt sie unter Xfce nicht zuverlässig. Gedacht
auch für Desktop-Kürzel (``ariadne shot window``).

Besitzer: Teil «screenshots» (Bau v0.1-Screenshots).
"""

from __future__ import annotations

import argparse
import os
from typing import Any

from ariadne.cli.common import CliError, _call, s, say
from ariadne.paths import Paths

__all__ = ["register", "cmd_shot"]

_MODE_TEXT = {"window": "Fenster", "monitor": "Monitor", "region": "Bereich"}
_ENV_KEYS = ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE")


def cmd_shot(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.sources.screenshot import parse_region

    mode = args.mode
    region: list[int] | None = None
    if args.region is not None:
        if mode is None:
            mode = "region"
        try:
            region = list(parse_region(args.region))
        except ValueError:
            raise CliError("Bereich ungültig: --region X,Y,BREITE,HOEHE (ganze Zahlen, Pixel)") from None
    mode = mode or "window"
    if mode == "region" and region is None:
        raise CliError("Modus region braucht --region X,Y,BREITE,HOEHE")
    if mode != "region" and region is not None:
        raise CliError("--region nur im Modus region")
    call: dict[str, Any] = {
        "mode": mode,
        "delay_s": args.delay,
        "origin": "cli",
        "display": {k: os.environ[k] for k in _ENV_KEYS if os.environ.get(k)},
    }
    if region is not None:
        call["region"] = region
    if args.note:
        call["note"] = args.note
    tid = args.terminal or os.environ.get("ARIADNE_TERMINAL_ID")
    if tid:
        call["terminal_id"] = tid
    if args.delay:
        say(f"Screenshot in {args.delay} s ...")
    res = _call(paths, "shot.take", **call)
    size = f"{res.get('width')}x{res.get('height')}"
    say(f"Screenshot gespeichert: {_MODE_TEXT.get(res.get('mode'), 'Bild')}, {s(size, 20)}")
    title = res.get("window_title")
    if isinstance(title, str) and title:
        say(f"  Fenster: {s(title, 120)}")
    host = res.get("host")
    if isinstance(host, str) and host:
        say(f"  Host: {s(host, 120)}")
    return 0


def _delay(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("ganze Zahl von 0 bis 10") from None
    if not 0 <= n <= 10:
        raise argparse.ArgumentTypeError("ganze Zahl von 0 bis 10")
    return n


def register(sub: Any) -> None:
    sp = sub.add_parser("shot", help="Screenshot aufnehmen (X11): aktives Fenster, Monitor oder Bereich")
    sp.add_argument("mode", nargs="?", choices=["window", "monitor", "region"],
                    help="window (Standard): aktives Fenster; monitor: Monitor unter dem Mauszeiger; "
                         "region: Bereich aus --region")
    sp.add_argument("--region", metavar="X,Y,BREITE,HOEHE", help="Bereich in Bildschirmpixeln")
    sp.add_argument("--delay", type=_delay, default=0, metavar="S",
                    help="Sekunden bis zur Aufnahme (0 bis 10)")
    sp.add_argument("--note", help="Notiz zum Bild (höchstens 500 Zeichen)")
    sp.add_argument("--terminal", help="terminal_id für den Kontext (Standard: ARIADNE_TERMINAL_ID)")
    sp.set_defaults(fn=cmd_shot)
