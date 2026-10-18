"""``ariadne scope``: Scope anzeigen und ändern (E129).

* ``ariadne scope`` bzw. ``scope show``: Einschlüsse, Ausschlüsse, Zeitfenster, letzte Änderungen.
* ``scope add <ziel>...``, ``scope remove <ziel>...``, ``scope exclude <ziel>...``: prüft wie beim
  Anlegen (IP, CIDR, Name, ``*.domain``), zeigt den genauen Eintrag und fragt ``[j/N]``.
* ``scope undo [<decision_id>]``: macht eine Änderung rückgängig (ohne Angabe die jüngste).

Jede Änderung ist ein Entscheid ``d.scope.update`` (ctl ``scope.change``, Herkunft ``cli``) und löst
eine Neuauswertung aus. Ziele ausserhalb der Lab-Allowlist nur mit ``--not-customer`` wie beim
Anlegen. Alles vom Daemon geht durch :func:`~ariadne.cli.common.s`.
"""

from __future__ import annotations

import argparse
import shlex
import sys
from datetime import datetime
from typing import Any

from ariadne.cli.common import CliError, _call, s, say
from ariadne.paths import Paths

__all__ = ["register", "cmd_scope", "show_lines", "add_hint"]

_OP_TEXT = {"add": "hinzugefügt", "remove": "entfernt", "exclude": "ausgeschlossen", "revert": "rückgängig"}
_ORIGIN = {"cli": "Terminal", "webui": "Dashboard"}
_VERDICT = {"in": "im Scope", "out": "ausserhalb", "excluded": "ausgeschlossen",
            "outside_window": "ausserhalb des Zeitfensters", "unknown": "unklar"}


def _time(ns: Any) -> str:
    if not isinstance(ns, int):
        return "?"
    return datetime.fromtimestamp(ns / 1e9).strftime("%d.%m. %H:%M")


def _list(title: str, items: list[Any], empty: str) -> list[str]:
    out = [f"{title}:"]
    out += [f"  {s(x, 260)}" for x in items] if items else [f"  ({empty})"]
    return out


def show_lines(res: dict[str, Any]) -> list[str]:
    lines = [f"Scope von {s(res.get('slug'), 64)} (Version {s(res.get('version'))}, "
             f"Profil {s(res.get('profile'), 16)})"]
    lines += _list("Einschlüsse", list(res.get("include") or []), "keine")
    lines += _list("Ausschlüsse", list(res.get("exclude") or []), "keine")
    wins = [" ".join(f"{k}={v}" for k, v in w.items())
            for w in res.get("windows") or [] if isinstance(w, dict)]
    lines += _list("Zeitfenster", wins, "keine: gilt jederzeit")
    if res.get("not_customer"):
        lines.append("Bestätigt: kein Kundenauftrag.")
    hist = [h for h in res.get("history") or [] if isinstance(h, dict)]
    if hist:
        lines.append("Letzte Änderungen (neueste zuerst):")
        for h in hist[:10]:
            entries = ", ".join(s(x, 120) for x in h.get("entries") or []) or "-"
            state = " [rückgängig gemacht]" if h.get("reverted_by") else ""
            where = _ORIGIN.get(str(h.get("origin")), "Terminal")
            lines.append(f"  v{s(h.get('version'))} {_time(h.get('ts_utc_ns'))} "
                         f"{_OP_TEXT.get(str(h.get('op')), s(h.get('op'), 16))}: {entries} "
                         f"({where}, {s(h.get('decision_id'), 64)}){state}")
    return lines


def add_hint(targets: list[str], include: list[str]) -> list[str]:
    """Hinweis für ``ariadne start <vorhandenes Projekt> --target X``: aktueller Scope und der Befehl,
    der ihn erweitert (nur Ziele, die noch nicht drinstehen)."""
    from ariadne.project.guardrails import InvalidTarget, parse_target

    new: list[str] = []
    bad: list[str] = []
    for t in targets:
        try:
            v = parse_target(t).value
        except InvalidTarget:
            bad.append(t)
            continue
        if v not in include and v not in new:
            new.append(v)
    lines = ["Das Projekt existiert schon; --target ändert den Scope nicht.",
             "Scope jetzt: " + (", ".join(s(x, 120) for x in include) or "(leer)")]
    if new:
        lines.append("Erweitern: ariadne scope add " + " ".join(s(shlex.quote(x), 260) for x in new))
    elif not bad:
        lines.append("Alle Ziele stehen schon im Scope.")
    if bad:
        lines.append("Ungültig (nicht übernommen): " + ", ".join(s(x, 80) for x in bad))
    return lines


def _plan_lines(res: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key, text in (("include_added", "Neu im Scope"), ("include_removed", "Aus dem Scope entfernt"),
                      ("exclude_added", "Neu ausgeschlossen"),
                      ("exclude_removed", "Nicht mehr ausgeschlossen")):
        for x in res.get(key) or []:
            out.append(f"  {text}: {s(x, 260)}")
    verdicts = res.get("verdicts") if isinstance(res.get("verdicts"), dict) else {}
    for entry, v in verdicts.items():
        if res.get("op") == "add" and v != "in":
            out.append(f"  [!] {s(entry, 260)} bleibt {_VERDICT.get(str(v), 'unklar')} (Ausschluss gilt vor)")
    return out


def _confirm(prompt: str, yes: bool) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        raise CliError("Bestätigung nötig: im Terminal mit [j/N] antworten oder --yes")
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in ("j", "ja", "y", "yes")


def _change(paths: Paths, args: argparse.Namespace, op: str) -> int:
    from ariadne.daemon.client import CtlError

    base: dict[str, Any] = {"action": op, "origin": "cli"}
    if op == "revert":
        did = args.decision_id
        if not did:
            hist = [h for h in (_call(paths, "scope.show").get("history") or []) if isinstance(h, dict)]
            last = next((h for h in hist if not h.get("reverted_by") and h.get("op") != "revert"), None)
            if last is None:
                raise CliError("Keine Scope-Änderung, die sich rückgängig machen lässt.")
            did = last.get("decision_id")
        base["decision_id"] = did
    else:
        base["entries"] = list(args.targets)
    if getattr(args, "reason", None):
        base["reason"] = args.reason
    plan = _call(paths, "scope.change", **base, dry_run=True)
    say(f"Scope-Änderung ({_OP_TEXT.get(op, op)}), danach Version {s(plan.get('version'))}:")
    for line in _plan_lines(plan):
        say(line)
    outside = [s(x, 120) for x in plan.get("outside") or []]
    if plan.get("needs_not_customer") and not args.not_customer:
        say("Ziele ausserhalb der Lab-Allowlist: " + ", ".join(outside))
        say("lab-Projekte sind nicht für Kundendaten. Wenn es sicher kein Kundenauftrag ist: --not-customer")
        return 1
    if plan.get("needs_not_customer"):
        say("Mit Bestätigung: Das ist kein Kundenauftrag.")
    if not _confirm("Übernehmen? [j/N] ", args.yes):
        say("Nicht geändert.")
        return 1
    try:
        res = _call(paths, "scope.change", **base, not_customer=bool(args.not_customer))
    except CtlError as exc:
        if exc.code == "guardrail":
            outside = exc.extra.get("outside", [])
            say("Ziele ausserhalb der Lab-Allowlist: " + ", ".join(s(x, 120) for x in outside))
            return 1
        raise
    say(f"Scope geändert (Version {s(res.get('version'))}, Entscheid {s(res.get('decision_id'), 64)}). "
        "Die Auswertung rechnet neu.")
    if op != "revert":
        say(f"Rückgängig: ariadne scope undo {s(res.get('decision_id'), 64)}")
    return 0


def cmd_scope(paths: Paths, args: argparse.Namespace) -> int:
    cmd = getattr(args, "scope_cmd", None) or "show"
    if cmd == "show":
        for line in show_lines(_call(paths, "scope.show")):
            say(line)
        return 0
    if cmd in ("add", "remove", "exclude"):
        return _change(paths, args, cmd)
    if cmd == "undo":
        return _change(paths, args, "revert")
    raise CliError("unbekannte Aktion")


def register(sub: Any) -> None:
    sp = sub.add_parser("scope", help="Scope anzeigen und ändern (hinzufügen, entfernen, ausschliessen)")
    ssub = sp.add_subparsers(dest="scope_cmd", metavar="AKTION")
    ssub.add_parser("show", help="Einschlüsse, Ausschlüsse, Zeitfenster, letzte Änderungen")
    for name, hlp in (("add", "Ziele in den Scope aufnehmen (IP, CIDR, Name, *.domain)"),
                      ("remove", "Ziele aus dem Scope entfernen (Einschluss oder Ausschluss)"),
                      ("exclude", "Ziele ausschliessen (Ausschluss schlägt Einschluss)")):
        c = ssub.add_parser(name, help=hlp)
        c.add_argument("targets", nargs="+", metavar="ZIEL")
        c.add_argument("--yes", action="store_true", help="ohne Rückfrage")
        c.add_argument("--reason", help="Grund (erscheint in der Zeitachse)")
        c.add_argument("--not-customer", action="store_true",
                       help="bestätigt: kein Kundenauftrag (für Ziele ausserhalb der Lab-Allowlist)")
    u = ssub.add_parser("undo", help="Scope-Änderung rückgängig machen (ohne Angabe: die jüngste)")
    u.add_argument("decision_id", nargs="?", help="Entscheid aus ariadne scope")
    u.add_argument("--yes", action="store_true", help="ohne Rückfrage")
    u.add_argument("--not-customer", action="store_true", help="bestätigt: kein Kundenauftrag")
    sp.set_defaults(fn=cmd_scope)
