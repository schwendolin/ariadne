"""``ariadne ai``: KI-Gateway einrichten und prüfen (E64 bis E66, Architektur 6.2).

* ``ai setup``: Anbieter (off, cloud, local), Modell-ID, Monatslimit; der API-Key nur per ``getpass``
  oder ``--key-fd``, verschlüsselt im Operator-Tresor (ctl ``ai.key.set``). Nie als Argument, nie in einer
  Datei, nie in der Umgebung. Vor der Abfrage meldet die CLI ihr Terminal per ``pause_terminal`` an.
* ``ai status``: Einstellungen, Schlüssel vorhanden, Budget, Freigabe des offenen Projekts.
* ``ai check``: Prüfliste (ok, warn, fail), Exit 1 bei ``fail``.
* ``ai allow-cloud``: ausdrückliche Freigabe der Cloud-KI für das offene Projekt (Entscheid im Journal).
"""

from __future__ import annotations

import argparse
import math
import os
import sys
from typing import Any

from ariadne.ai.config import PROVIDERS, AiConfig, ConfigError, load_config, save_config, valid_model
from ariadne.cli.common import CliError, _call, _client, pause_this_terminal, read_secret, s, say
from ariadne.paths import Paths

__all__ = ["register", "cmd_ai"]

_MARK = {"ok": "[ok]", "warn": "[!]", "fail": "[!!]"}


def _ask(prompt: str, current: str) -> str:
    if not sys.stdin.isatty():
        return current
    try:
        value = input(f"{prompt} [{current or '-'}]: ").strip()
    except EOFError:
        return current
    return value or current


def _status(paths: Paths) -> dict[str, Any] | None:
    from ariadne.daemon.client import CtlError, DaemonUnavailable

    try:
        res = _call(paths, "ai.status", start=False)
    except (CtlError, DaemonUnavailable, CliError, OSError):
        return None
    return res if isinstance(res, dict) else None


def _setup(paths: Paths, args: argparse.Namespace) -> int:
    try:
        cfg = load_config(paths)
    except ConfigError:
        say("[!] ai.toml war ungültig; es wird neu geschrieben.")
        cfg = AiConfig()
    provider = args.provider or _ask("Anbieter (off, cloud, local)", cfg.provider)
    if provider not in PROVIDERS:
        raise CliError("Anbieter muss off, cloud oder local sein")
    model = (
        args.model
        if args.model is not None
        else (cfg.model if provider == "off" else _ask("Modell-ID", cfg.model))
    )
    if model and not valid_model(model):
        raise CliError("Modell-ID enthält unzulässige Zeichen")
    if provider != "off" and not model:
        raise CliError("Modell-ID fehlt: ariadne ai setup --model <ID>")
    limit = cfg.monthly_limit_usd
    if args.limit is not None:
        limit = args.limit
    elif provider == "cloud":
        raw = _ask("Monatslimit in USD", f"{cfg.monthly_limit_usd:g}")
        try:
            limit = float(raw)
        except ValueError:
            raise CliError("Monatslimit muss eine Zahl sein") from None
    if not math.isfinite(limit) or limit < 0 or limit > 100000:
        raise CliError("Monatslimit muss zwischen 0 und 100000 USD liegen")
    if provider == "cloud" and not args.keep_key:
        _client(paths)  # Daemon nötig: der Schlüssel geht in den Operator-Tresor
        pause_this_terminal(paths)  # vor getpass: die Eingabe kommt sonst in den Vorlauf (E26)
        key = read_secret("API-Key (unsichtbar; leer lässt den bisherigen): ", args.key_fd)
        if key:
            _call(paths, "ai.key.set", value=key)
            say("API-Key verschlüsselt im Operator-Tresor gespeichert.")
        else:
            st = _status(paths)
            if not (st and st.get("key_present")):
                raise CliError("kein API-Key angegeben und keiner gespeichert")
            say("API-Key unverändert.")
        key = ""
    path = save_config(paths, cfg.with_(provider=provider, model=model, monthly_limit_usd=float(limit)))
    say(f"Einstellungen gespeichert: {s(str(path))}")
    if provider == "cloud":
        say("Cloud-KI gilt erst nach ausdrücklicher Freigabe pro Projekt: ariadne ai allow-cloud")
    say("Preise (USD pro Million Tokens) stehen in ai.toml unter [prices]; bitte an die Preisliste anpassen.")
    return 0


def _print_status(paths: Paths) -> int:
    try:
        cfg: AiConfig | None = load_config(paths)
    except ConfigError:
        cfg = None
    if cfg is None:
        say("[!!] ai.toml ungültig: ariadne ai setup")
        return 1
    say(f"Anbieter: {cfg.provider}")
    say(f"Modell: {s(cfg.model) if cfg.model else '-'}")
    say(f"Monatslimit: {cfg.monthly_limit_usd:g} USD")
    st = _status(paths)
    if st is None:
        say("Daemon nicht erreichbar: Schlüssel, Verbrauch und Freigabe unbekannt.")
        return 0
    b = st.get("budget") or {}
    say(
        f"Verbrauch {s(str(b.get('month')))}: {b.get('used_usd', 0):.4f} USD "
        f"({b.get('pct', 0)} %, {s(str(b.get('level')))})"
    )
    say(
        "API-Key: "
        + (
            "im Operator-Tresor"
            if st.get("key_present")
            else "keiner"
            if st.get("operator_unlocked")
            else "unbekannt (Operator gesperrt)"
        )
    )
    proj = st.get("project")
    if proj:
        say(
            f"Projekt {s(str(proj.get('slug')))}: Cloud-KI "
            + ("freigegeben" if proj.get("cloud_allowed") else "nicht freigegeben")
        )
    else:
        say("Kein Projekt offen.")
    if st.get("reason_text"):
        say(f"[!] {s(str(st['reason_text']))}")
    return 0


def _check(paths: Paths) -> int:
    from ariadne.ai.check import run_checks, worst

    try:
        cfg: AiConfig | None = load_config(paths)
    except ConfigError:
        cfg = None
    st = _status(paths)
    key_present = None if st is None or not st.get("operator_unlocked") else bool(st.get("key_present"))
    checks = run_checks(cfg, key_present=key_present, env=os.environ)
    for c in checks:
        say(f"{_MARK[c.level]} {c.name}: {c.text}")
    return 1 if worst(checks) == "fail" else 0


def _allow_cloud(paths: Paths, args: argparse.Namespace) -> int:
    if not args.yes:
        if not sys.stdin.isatty():
            raise CliError("Bestätigung nötig: ariadne ai allow-cloud --yes")
        say(
            "Das Lagebild dieses Projekts (Hosts, Dienste, Versionen; ohne Rohausgaben, "
            "eigene Secrets ersetzt)"
        )
        say("darf auf Knopfdruck an die Cloud-KI gehen. Nur für Lab-Projekte, nie für Kundendaten.")
        if input("Freigeben? (ja/nein): ").strip().lower() not in ("ja", "j"):
            say("Nicht freigegeben.")
            return 1
    res = _call(paths, "ai.allow_cloud")
    say(
        "Cloud-KI war schon freigegeben."
        if res.get("already")
        else "Cloud-KI für dieses Projekt freigegeben."
    )
    return 0


def cmd_ai(paths: Paths, args: argparse.Namespace) -> int:
    if args.acmd == "setup":
        return _setup(paths, args)
    if args.acmd == "status":
        return _print_status(paths)
    if args.acmd == "check":
        return _check(paths)
    if args.acmd == "allow-cloud":
        return _allow_cloud(paths, args)
    if args.acmd == "remove-key":
        res = _call(paths, "ai.key.remove")
        say("API-Key gelöscht." if res.get("removed") else "Kein API-Key gespeichert.")
        return 0
    raise CliError("unbekannte Aktion")


def register(sub: Any) -> None:
    sp = sub.add_parser("ai", help="KI-Denkanstoss: einrichten, Status, Prüfung, Freigabe")
    asub = sp.add_subparsers(dest="acmd", required=True, metavar="AKTION")
    st = asub.add_parser("setup", help="Anbieter, Modell-ID, Monatslimit, API-Key (getpass)")
    st.add_argument("--provider", choices=list(PROVIDERS))
    st.add_argument("--model", help="Modell-ID des Anbieters")
    st.add_argument("--limit", type=float, help="Monatslimit in USD (Standard 20)")
    st.add_argument("--key-fd", type=int, help="API-Key aus diesem Dateideskriptor lesen")
    st.add_argument("--keep-key", action="store_true", help="API-Key nicht abfragen")
    asub.add_parser("status", help="Einstellungen, Budget, Freigabe")
    asub.add_parser("check", help="Prüfliste: Erreichbarkeit, TLS ohne Aufbruch, Schlüssel")
    ac = asub.add_parser("allow-cloud", help="Cloud-KI für das offene Projekt freigeben")
    ac.add_argument("--yes", action="store_true", help="ohne Rückfrage")
    asub.add_parser("remove-key", help="API-Key aus dem Operator-Tresor löschen")
    sp.set_defaults(fn=cmd_ai)
