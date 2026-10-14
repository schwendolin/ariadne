"""Befehlszeile ``ariadne`` (Architektur 8.3, 8.6).

Grundsätze:

* Passphrasen und Secrets nur per ``getpass`` oder ``--passphrase-fd N`` bzw.
  ``--value-fd N``, nie als Argument oder Umgebungsvariable.
* Befehle, die den Daemon brauchen, starten ihn bei Bedarf abgekoppelt und
  warten höchstens 3 s.
* Alles, was aus Zieldaten oder vom Daemon stammt, geht durch ``term_safe``.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Callable
from typing import Any

from ariadne import __version__
from ariadne.crypto.vault import MIN_PASSPHRASE, OperatorVault
from ariadne.daemon.client import CtlClient, CtlError, DaemonUnavailable
from ariadne.paths import Paths, default_paths
from ariadne.termsafe import term_safe

__all__ = ["main", "build_parser"]


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


def _pause_this_terminal(paths: Paths) -> None:
    """Meldet einen Befehl an, der Schlüsselmaterial zeigt (``term.gap`` sensitive_output)."""
    tid = os.environ.get("ARIADNE_TERMINAL_ID")
    if tid:
        try:
            _call(paths, "pause_terminal", terminal_id=tid)
        except (CtlError, DaemonUnavailable):
            pass


# --------------------------------------------------------------------------- #
# Befehle
# --------------------------------------------------------------------------- #


def cmd_setup(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.cli import setup

    if args.remove:
        rep = setup.remove(paths, rc=not args.no_rc, systemd=not args.no_systemd)
    else:
        rep = setup.install(paths, rc=not args.no_rc, systemd=not args.no_systemd)
    for line in rep.done:
        say(f"  {s(line)}")
    for line in rep.warnings:
        say(f"  Hinweis: {s(line, 400)}")
    if rep.missing:
        say("Shell-Dateien fehlen im Paket: " + ", ".join(s(m) for m in rep.missing))
        say("Die Aufnahme startet erst, wenn sie vorhanden sind (Paket aktualisieren, dann ariadne setup).")
        return 1
    say("Ariadne entfernt." if args.remove else "Setup abgeschlossen. Neue Terminals starten mit Ariadne.")
    return 0


def cmd_init(paths: Paths, args: argparse.Namespace) -> int:
    if OperatorVault(paths.operator_dir).exists:
        raise CliError("Operator-Tresor existiert bereits")
    say("Neuer Operator-Tresor. Die Passphrase entsperrt alle lab-Projekte.")
    pw = read_secret("Passphrase: ", args.passphrase_fd, confirm=True)
    if len(pw) < MIN_PASSPHRASE:
        raise CliError(f"Passphrase zu kurz (mindestens {MIN_PASSPHRASE} Zeichen)")
    _client(paths)
    _pause_this_terminal(paths)
    res = _call(paths, "init", passphrase=pw, handle=args.handle)
    say("Tresor angelegt und entsperrt.")
    say()
    say("Recovery-Code (genau einmal angezeigt, offline aufbewahren):")
    say()
    say(f"    {s(res['recovery_code'])}")
    say()
    say("Wer Passphrase und Recovery-Code verliert, verliert alle Daten. Es gibt keine Hintertür.")
    return 0


def cmd_unlock(paths: Paths, args: argparse.Namespace) -> int:
    if not OperatorVault(paths.operator_dir).exists:
        raise CliError("kein Operator-Tresor (ariadne init)")
    if args.recovery:
        code = read_secret("Recovery-Code: ", args.passphrase_fd)
        res = _call(paths, "unlock", recovery_code=code)
    else:
        pw = read_secret("Passphrase: ", args.passphrase_fd)
        res = _call(paths, "unlock", passphrase=pw)
    if res.get("already"):
        say("Schon entsperrt.")
    else:
        say(f"Entsperrt ({s(res.get('handle'))}).")
        if res.get("reopened"):
            say(f"Projekt wieder geöffnet: {s(res['reopened'])}")
    if args.recovery:
        say("Tipp: Passphrase prüfen, der Recovery-Code ist nur für den Notfall.")
    return 0


def cmd_lock(paths: Paths, args: argparse.Namespace) -> int:
    try:
        res = _call(paths, "lock", start=False)
    except CliError:
        say("Daemon läuft nicht, nichts entsperrt.")
        return 0
    say("Gesperrt." + (" Projekt geschlossen." if res.get("closed_project") else ""))
    return 0


def cmd_status(paths: Paths, args: argparse.Namespace) -> int:
    try:
        st = _call(paths, "status", start=False)
    except CliError:
        say("Daemon:   aus")
        say(f"Tresor:   {'angelegt' if OperatorVault(paths.operator_dir).exists else 'fehlt (ariadne init)'}")
        return 0
    op = st["operator"]
    say(f"Daemon:   läuft (pid {s(st['pid'])}, {s(st['version'])})")
    if not op["exists"]:
        say("Tresor:   fehlt (ariadne init)")
    else:
        say(f"Tresor:   {'entsperrt (' + s(op['handle']) + ')' if op['unlocked'] else 'gesperrt'}")
    p = st.get("project")
    say(f"Projekt:  {s(p['slug']) + ' (' + s(p['profile']) + ')' if p else '-'}")
    if p and p.get("chain_head_ok") is False:
        say("WARNUNG:  Kettenkopf ungültig beim Öffnen, ariadne verify ausführen")
    rec = "an" if st["rec"] else "aus"
    if st["rec"] and not p:
        rec = "an, wartet (gesperrt)"
    say(f"REC:      {rec}")
    say(f"Terminals: {st['terminals']} verbunden, {st['recording']} nehmen auf")
    ing = st.get("ingest") or {}
    if ing.get("active"):
        err = f", letzter Fehler: {s(ing['last_error'], 60)}" if ing.get("last_error") else ""
        say(f"Auswertung: aktiv ({s(ing.get('runs', 0), 10)} Durchgänge{err})")
    return 0


def cmd_project(paths: Paths, args: argparse.Namespace) -> int:
    if args.pcmd == "new":
        try:
            res = _call(paths, "project.new", slug=args.slug, targets=args.target, name=args.name,
                        not_customer=args.not_customer, open=not args.no_open)
        except CtlError as exc:
            if exc.code == "guardrail":
                say("Ziele ausserhalb der Lab-Allowlist: "
                    + ", ".join(s(x, 80) for x in exc.extra.get("outside", [])))
                say("lab-Projekte sind nicht für Kundendaten. Wenn es sicher kein Kundenauftrag ist: "
                    "--not-customer")
                return 1
            raise
        say(f"Projekt {s(res['slug'])} angelegt ({s(res['profile'])}) in {s(res['workspace'], 400)}")
        if res.get("opened"):
            say("Projekt ist offen. REC einschalten: ariadne rec on")
        return 0
    if args.pcmd == "open":
        res = _call(paths, "project.open", slug=args.slug)
        say(f"Projekt {s(res['slug'])} offen.")
        return 0
    if args.pcmd == "close":
        res = _call(paths, "project.close", start=False)
        if res.get("closed"):
            say(f"Projekt geschlossen. Kettenkopf: seq {s(res['head_seq'])} {s(res['head_hash'])}")
        else:
            say("Kein Projekt offen.")
        return 0
    if args.pcmd == "list":
        try:
            projects = _call(paths, "project.list", start=False)["projects"]
        except CliError:
            from ariadne.project.service import ProjectService

            projects = [{"slug": p.slug, "profile": p.profile, "created_utc": p.created_utc, "active": False}
                        for p in ProjectService(paths).list()]
        if not projects:
            say("Keine Projekte.")
        for p in projects:
            mark = "*" if p.get("active") else " "
            say(f"{mark} {s(p['slug']):<40} {s(p['profile']):<9} {s(p['created_utc'])}")
        return 0
    raise CliError("unbekannter Projektbefehl")


def cmd_rec(paths: Paths, args: argparse.Namespace) -> int:
    op = {"on": "rec.on", "off": "rec.off", "toggle": "rec.toggle", "status": "rec.status"}[args.rcmd]
    if args.rcmd == "status":
        try:
            res = _call(paths, op, start=False)
        except CliError:
            say("REC: aus (Daemon läuft nicht)")
            return 0
    else:
        res = _call(paths, op)
    state = {"on": "an", "off": "aus",
             "waiting": "an, wartet: Projekt gesperrt (ariadne unlock)"}[res["state"]]
    proj = res.get("project")
    say(f"REC: {state}" + (f" [{s(proj['slug'])}]" if proj else ""))
    if res["state"] == "on":
        say(f"Terminals in Aufnahme: {res['recording']}")
    return 0


def cmd_ctx(paths: Paths, args: argparse.Namespace) -> int:
    tid = _terminal_id(args)
    if args.ccmd == "show":
        res = _call(paths, "ctx.show", start=False, terminal_id=tid)
    elif args.ccmd == "set":
        res = _call(paths, "ctx.set", terminal_id=tid, host=args.host, user=args.user, kind=args.kind)
    elif args.ccmd == "push":
        res = _call(paths, "ctx.push", terminal_id=tid, host=args.host, user=args.user, kind=args.kind)
    else:
        res = _call(paths, "ctx.pop", terminal_id=tid)
    stack = res.get("stack", [])
    labels = []
    for st in stack:
        host = st.get("host") or "?"
        host = "kali" if host == "local" else host
        labels.append(s(host, 80) + (f" ({s(st['user'], 40)})" if st.get("user") else "")
                      + (f" [{s(st['kind'], 20)}]" if st.get("kind") not in ("local",) else ""))
    say("Kontext: " + " › ".join(labels))
    if args.ccmd != "show" and not res.get("stored", True):
        say("Hinweis: nicht gespeichert (kein Projekt offen oder REC aus), nur im Terminal-Stapel. "
            "Beim nächsten REC an geht der Stapel als Schnappschuss ins Journal.")
    return 0


def cmd_verify(paths: Paths, args: argparse.Namespace) -> int:
    res = _call(paths, "verify")
    say(f"Events: {res['events']}, Kettenkopf: seq {res['head_seq']} {s(res['head_hash'])}")
    if res["ok"]:
        say("Kette, Commitments und Blobs: in Ordnung.")
        return 0
    say(f"PROBLEME ({res['problem_count']}):")
    for p in res["problems"]:
        say(f"  {s(p)}")
    return 1


def cmd_redact(paths: Paths, args: argparse.Namespace) -> int:
    rng = None
    if args.range:
        try:
            a, b = (int(x) for x in args.range.split(":", 1))
        except ValueError as exc:
            raise CliError("--range erwartet START:ENDE") from exc
        rng = [a, b]
    res = _call(paths, "redact", seq=args.seq, label=args.label, reason=args.reason, range=rng)
    say(f"Event {res['ref_seq']} geschwärzt, Vermerk als Event {res['redaction_seq']}.")
    return 0


def cmd_secrets(paths: Paths, args: argparse.Namespace) -> int:
    if args.scmd == "add":
        value = read_secret(f"Wert für {s(args.label, 64)}: ", args.value_fd)
        if not value:
            raise CliError("leerer Wert")
        res = _call(paths, "secrets.add", label=args.label, value=value)
    elif args.scmd == "remove":
        res = _call(paths, "secrets.remove", label=args.label)
        if not res["removed"]:
            say("Kein Secret mit diesem Label.")
    else:
        res = _call(paths, "secrets.list")
    labels = res.get("labels", [])
    say("Eigene Secrets: " + (", ".join(s(lb, 64) for lb in labels) if labels else "keine"))
    return 0


def cmd_show(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.cli.views import render_view

    res = _call(paths, "show", what=args.what, limit=args.limit)
    for line in render_view(args.what, res.get("items") or [], full=args.all):
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
    from ariadne.cli.views import STATE_TEXT

    res = _call(paths, "claim.confirm", ref=args.ref)
    say(f"{res['confirmed']} Claim(s) bestätigt.")
    for c in (res.get("claims") or [])[:10]:
        say(f"  {s(c.get('subject'), 40)} {s(c.get('predicate'), 24)} = {s(c.get('value'), 60)} "
            f"[{STATE_TEXT.get(str(c.get('state')), '-')}]")
    return 0


def cmd_reject(paths: Paths, args: argparse.Namespace) -> int:
    res = _call(paths, "claim.reject", ref=args.ref, reason=args.reason)
    for c in res.get("claims") or []:
        say(f"Verworfen: {s(c.get('subject'), 40)} {s(c.get('predicate'), 24)} = {s(c.get('value'), 60)}")
    return 0


def cmd_mark(paths: Paths, args: argparse.Namespace) -> int:
    res = _call(paths, "keystep.mark", step=args.step, host=args.host, note=args.note,
                terminal_id=getattr(args, "terminal", None) or os.environ.get("ARIADNE_TERMINAL_ID"))
    raw = str(res.get("host") or "")
    shown = raw.split("/", 1)[1] if raw.startswith("ip:") else raw.removeprefix("name:")
    host = f" für {s(shown, 80)}" if shown else " (ohne Host)"
    say(f"Schlüsselschritt {s(res['step'], 12)} gespeichert{host}.")
    return 0


def cmd_import(paths: Paths, args: argparse.Namespace) -> int:
    path = os.path.abspath(args.path)
    res = _call(paths, "import", path=path, host=args.host)
    stored = "verschlüsselt gespeichert" if res.get("stored") else "nur Metadaten (zu gross)"
    say(f"Importiert: {s(res['path'], 300)} ({s(res['size'], 16)} Bytes, {stored}, "
        f"sha256 {s(res.get('sha256'), 64)[:16]}…)")
    return 0


def cmd_reparse(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.cli.views import render_reparse

    for line in render_reparse(_call(paths, "reparse")):
        say(line)
    return 0


def cmd_daemon(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.daemon.main import run_foreground, spawn_detached

    if args.dcmd == "stop":
        try:
            _call(paths, "shutdown", start=False)
        except CliError:
            say("Daemon läuft nicht.")
            return 0
        say("Daemon wird beendet.")
        return 0
    if args.detach:
        if spawn_detached(paths, timeout=3.0):
            say("Daemon läuft.")
            return 0
        raise CliError("Daemon liess sich nicht starten")
    return run_foreground(paths)


def cmd_hotkey(paths: Paths, args: argparse.Namespace) -> int:
    try:
        from ariadne._shim.hotkeytest import run_hotkey_test
    except ImportError:
        say("Hotkey-Test ist noch nicht verfügbar (Modul ariadne._shim.hotkeytest fehlt).")
        return 1
    res = run_hotkey_test()
    return res if isinstance(res, int) else 0


def cmd_doctor(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.cli.doctor import FAIL, OK, run_checks

    worst = 0
    for c in run_checks(paths):
        tag = {OK: "[ok]", FAIL: "[!!]"}.get(c.level, "[--]")
        say(f"{tag} {s(c.title)}" + (f": {s(c.detail, 300)}" if c.detail else ""))
        if c.level == FAIL:
            worst = 1
    return worst


def cmd_ui(paths: Paths, args: argparse.Namespace) -> int:
    say("Die Web-Oberfläche kommt mit der Web-UI. Bis dahin: ariadne status, ariadne rec, ariadne ctx.")
    return 0


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ariadne", description="Flugschreiber und Kartograf für Pentests.")
    p.add_argument("--version", action="version", version=f"ariadne {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="BEFEHL")

    sp = sub.add_parser("setup", help="Shell-Integration und systemd-Unit einrichten")
    sp.add_argument("--remove", action="store_true", help="alles wieder entfernen")
    sp.add_argument("--no-rc", action="store_true", help=".zshrc/.bashrc nicht anfassen")
    sp.add_argument("--no-systemd", action="store_true", help="keine systemd-Unit")
    sp.set_defaults(fn=cmd_setup)

    sp = sub.add_parser("init", help="Operator-Tresor anlegen")
    sp.add_argument("--handle", default="operator", help="Kürzel des Operators")
    sp.add_argument("--passphrase-fd", type=int, metavar="N", help="Passphrase von Dateideskriptor N lesen")
    sp.set_defaults(fn=cmd_init)

    sp = sub.add_parser("unlock", help="Operator-Tresor entsperren")
    sp.add_argument("--recovery", action="store_true", help="mit Recovery-Code statt Passphrase")
    sp.add_argument("--passphrase-fd", type=int, metavar="N", help="Passphrase/Code von Deskriptor N lesen")
    sp.set_defaults(fn=cmd_unlock)

    sub.add_parser("lock", help="sperren, offenes Projekt schliessen").set_defaults(fn=cmd_lock)
    sub.add_parser("status", help="Zustand anzeigen").set_defaults(fn=cmd_status)

    sp = sub.add_parser("project", help="Projekte")
    psub = sp.add_subparsers(dest="pcmd", required=True, metavar="AKTION")
    pn = psub.add_parser("new", help="Projekt anlegen (Profil lab)")
    pn.add_argument("slug")
    pn.add_argument("--target", action="append", required=True, help="IP, CIDR oder Name (mehrfach)")
    pn.add_argument("--name")
    pn.add_argument("--not-customer", action="store_true", help="bestätigt: kein Kundenauftrag")
    pn.add_argument("--no-open", action="store_true", help="nur anlegen, nicht öffnen")
    po = psub.add_parser("open", help="Projekt öffnen")
    po.add_argument("slug")
    psub.add_parser("close", help="Projekt schliessen")
    psub.add_parser("list", help="Projekte auflisten")
    sp.set_defaults(fn=cmd_project)

    sp = sub.add_parser("rec", help="Aufnahme steuern")
    sp.add_argument("rcmd", choices=["on", "off", "toggle", "status"])
    sp.set_defaults(fn=cmd_rec)

    sp = sub.add_parser("ctx", help="Kontext des aktuellen Terminals")
    csub = sp.add_subparsers(dest="ccmd", required=True, metavar="AKTION")
    for name in ("show", "set", "push", "pop"):
        c = csub.add_parser(name)
        c.add_argument("--terminal", help="terminal_id (Standard: ARIADNE_TERMINAL_ID)")
        if name in ("set", "push"):
            c.add_argument("--host")
            c.add_argument("--user")
            c.add_argument("--kind", choices=["local", "su", "ssh", "winrm", "remote", "revshell", "msf",
                                              "meterpreter", "db", "unknown"])
    sp.set_defaults(fn=cmd_ctx)

    sub.add_parser("verify", help="Hash-Kette, Commitments und Blobs prüfen").set_defaults(fn=cmd_verify)

    sp = sub.add_parser("redact", help="Body eines Events schwärzen")
    sp.add_argument("seq", type=int)
    sp.add_argument("--label", required=True)
    sp.add_argument("--reason", required=True)
    sp.add_argument("--range", help="START:ENDE (Strom-Offsets bei term.out)")
    sp.set_defaults(fn=cmd_redact)

    sp = sub.add_parser("secrets", help="eigene Secrets (werden vor dem Speichern geschwärzt)")
    ssub = sp.add_subparsers(dest="scmd", required=True, metavar="AKTION")
    sa = ssub.add_parser("add")
    sa.add_argument("label")
    sa.add_argument("--value-fd", type=int, metavar="N", help="Wert von Dateideskriptor N lesen")
    ssub.add_parser("list")
    sr = ssub.add_parser("remove")
    sr.add_argument("label")
    sp.set_defaults(fn=cmd_secrets)

    sp = sub.add_parser("show", help="Textansicht: hosts, services, inbox, timeline, keysteps, pending")
    sp.add_argument("what", choices=["hosts", "services", "inbox", "timeline", "keysteps", "pending"])
    sp.add_argument("--all", action="store_true", help="alle Einträge statt der ersten 25 pro Gruppe")
    sp.add_argument("--limit", type=int, default=200, help="höchstens so viele Einträge (Zeitachse)")
    sp.set_defaults(fn=cmd_show)

    sp = sub.add_parser("search", help="Volltextsuche in der aufgenommenen Ausgabe")
    sp.add_argument("text")
    sp.add_argument("--limit", type=int, default=50)
    sp.set_defaults(fn=cmd_search)

    sp = sub.add_parser("confirm", help="Kandidaten bestätigen (Claim-Schlüssel oder Gruppe aus der Inbox)")
    sp.add_argument("ref", help="Claim-Schlüssel (mind. 8 Zeichen) oder Gruppe wie g1a2b3c4d")
    sp.set_defaults(fn=cmd_confirm)

    sp = sub.add_parser("reject", help="Claim verwerfen")
    sp.add_argument("ref", help="Claim-Schlüssel (mind. 8 Zeichen)")
    sp.add_argument("--reason")
    sp.set_defaults(fn=cmd_reject)

    sp = sub.add_parser("mark", help="Schlüsselschritt markieren")
    sp.add_argument("step", choices=["foothold", "privesc", "pivot", "loot"])
    sp.add_argument("--host", help="IP oder Name (Standard: Host der obersten Stufe dieses Terminals)")
    sp.add_argument("--note")
    sp.add_argument("--terminal", help="terminal_id (Standard: ARIADNE_TERMINAL_ID)")
    sp.set_defaults(fn=cmd_mark)

    sp = sub.add_parser("import", help="Datei ausdrücklich ins Projekt übernehmen")
    sp.add_argument("path")
    sp.add_argument("--host", help="Host, von dem die Datei stammt (IP oder Name)")
    sp.set_defaults(fn=cmd_import)

    sp = sub.add_parser("reparse", help="Auswertung neu aufbauen, Unterschiede zeigen")
    sp.set_defaults(fn=cmd_reparse)

    sp = sub.add_parser("daemon", help="Daemon")
    dsub = sp.add_subparsers(dest="dcmd", required=True, metavar="AKTION")
    dr = dsub.add_parser("run")
    dr.add_argument("--detach", action="store_true")
    dsub.add_parser("stop", help="laufenden Daemon beenden (offenes Projekt wird geschlossen)")
    sp.set_defaults(fn=cmd_daemon)

    sp = sub.add_parser("hotkey", help="Hotkey")
    hsub = sp.add_subparsers(dest="hcmd", required=True, metavar="AKTION")
    hsub.add_parser("test")
    sp.set_defaults(fn=cmd_hotkey)

    sub.add_parser("doctor", help="Umgebung prüfen").set_defaults(fn=cmd_doctor)
    sub.add_parser("ui", help="Web-Oberfläche öffnen").set_defaults(fn=cmd_ui)
    return p


_ERROR_HINTS = {
    "wrong_passphrase": "Passphrase falsch.",
    "locked": "Gesperrt: zuerst ariadne unlock.",
    "no_project": "Kein Projekt offen (ariadne project open <slug>).",
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = default_paths()
    fn: Callable[[Paths, argparse.Namespace], int] = args.fn
    try:
        return fn(paths, args)
    except CtlError as exc:
        print(f"Fehler: {_ERROR_HINTS.get(exc.code) or s(str(exc), 400)}", file=sys.stderr)
        return 1
    except (CliError, DaemonUnavailable) as exc:
        print(f"Fehler: {s(str(exc), 400)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("abgebrochen", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
