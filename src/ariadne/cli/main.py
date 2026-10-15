"""Befehlszeile ``ariadne`` (Architektur 8.3, 8.6).

Grundsätze:

* Passphrasen und Secrets nur per ``getpass`` oder ``--passphrase-fd N`` bzw.
  ``--value-fd N``, nie als Argument oder Umgebungsvariable.
* Befehle, die den Daemon brauchen, starten ihn bei Bedarf abgekoppelt und
  warten höchstens 3 s.
* Vor jeder Abfrage eines Secrets (``getpass``) und vor dem Anzeigen von
  Recovery-Codes meldet die CLI ihr Terminal per ``pause_terminal`` an: Ariadnes
  eigene Passphrase landet so weder im Journal noch im Vorlauf (Eingaben, E26).
* Alles, was aus Zieldaten oder vom Daemon stammt, geht durch ``term_safe``.

Bedienung seit E22: ``ariadne start`` (entsperren, Projekt öffnen oder anlegen,
Vorlauf übernehmen), ``ariadne pause``/``resume`` pro Terminal, ``ariadne stop``.
Einen REC-Schalter gibt es nicht mehr.
"""

from __future__ import annotations

import argparse
import math
import os
import sys
import time
from collections.abc import Callable
from typing import Any

from ariadne import __version__
from ariadne.cli import analysis
from ariadne.cli.common import SECRET_PROMPT_S, CliError, _call, _client, _terminal_id, read_secret, s, say
from ariadne.crypto.vault import MIN_PASSPHRASE, OperatorVault
from ariadne.daemon.active import read_active
from ariadne.daemon.client import CtlError, DaemonUnavailable
from ariadne.paths import Paths, default_paths

__all__ = ["main", "build_parser", "CliError"]


def _pause_this_terminal(paths: Paths) -> None:
    """Meldet einen Befehl an, der Schlüsselmaterial zeigt (``term.gap`` sensitive_output).

    Die Anmeldung gilt bis zum nächsten Prompt, höchstens etwas länger als eine Secret-Abfrage
    dauern darf (:data:`SECRET_PROMPT_S`). Muss vor jedem ``read_secret`` stehen.
    """
    tid = os.environ.get("ARIADNE_TERMINAL_ID")
    if tid:
        try:
            _call(paths, "pause_terminal", terminal_id=tid, seconds=SECRET_PROMPT_S + 60)
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
    if args.passphrase_fd is None and not sys.stdin.isatty():
        raise CliError("keine interaktive Eingabe; --passphrase-fd N verwenden")
    say("Neuer Operator-Tresor. Die Passphrase entsperrt alle lab-Projekte.")
    _client(paths)
    _pause_this_terminal(paths)  # vor getpass: die Eingabe kommt sonst in den Vorlauf (E26)
    pw = read_secret("Passphrase: ", args.passphrase_fd, confirm=True)
    if len(pw) < MIN_PASSPHRASE:
        raise CliError(f"Passphrase zu kurz (mindestens {MIN_PASSPHRASE} Zeichen)")
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
    _client(paths)
    _pause_this_terminal(paths)
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
    if args.recovery:
        say("Tipp: Passphrase prüfen, der Recovery-Code ist nur für den Notfall.")
    say("Weiter mit ariadne start")
    return 0


def cmd_lock(paths: Paths, args: argparse.Namespace) -> int:
    try:
        res = _call(paths, "lock", start=False)
    except CliError:
        say("Daemon läuft nicht, nichts entsperrt.")
        return 0
    say("Gesperrt." + (" Projekt geschlossen." if res.get("closed_project") else ""))
    say("Weiter mit ariadne start")
    return 0


def _hhmm(ns: int | None) -> str:
    return time.strftime("%H:%M", time.localtime(ns / 1e9)) if ns else "?"


def _state_text(ts: dict[str, Any]) -> str:
    state = ts.get("state")
    if ts.get("mux"):
        return "Multiplexer (Panes nehmen auf)"
    return {
        "on": "nimmt auf",
        "paused": f"Pause bis {_hhmm(ts.get('pause_until_ns'))}",
        "held": f"Remote-Sitzung bei {s(ts.get('bound_slug') or '?', 64)} (nicht gespeichert)",
        "locked": "gesperrt (Vorlauf im RAM)",
        "preroll": f"Vorlauf {math.ceil((ts.get('preroll_s') or 0) / 60)} min",
        "off": "kein Projekt",
    }.get(str(state), s(state, 20))


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
    active = st.get("active") or {}
    if p:
        say(f"Projekt:  {s(p['slug'])} ({s(p['profile'])}), Aufnahme läuft")
    elif active and not active.get("stopped"):
        how = "nicht geöffnet" if op.get("unlocked") else "gesperrt"
        say(f"Projekt:  {s(active.get('slug'))} aktiv, {how} (weiter mit ariadne start)")
    else:
        say("Projekt:  - (ariadne start <slug> --target <ziel>)")
    if p and p.get("chain_head_ok") is False:
        say("WARNUNG:  Kettenkopf ungültig beim Öffnen, ariadne verify ausführen")
    idle = st.get("idle") or {}
    if p and idle:
        secs = int(idle.get("idle_s") or 0)
        end = idle.get("end_after_s")
        end_txt = f"Ende nach {int(end) // 3600} h" if end else "kein automatisches Ende"
        say(f"Leerlauf: {secs // 3600} h {secs % 3600 // 60:02d} min, {end_txt}")
    pre = st.get("preroll") or {}
    if not p and pre.get("terminals"):
        say(f"Vorlauf:  {math.ceil(int(pre.get('seconds') or 0) / 60)} min aus {s(pre['terminals'])} "
            f"Terminals (nur im RAM, ariadne start fragt)")
    say(f"Terminals: {st['terminals']} verbunden, {st['recording']} nehmen auf")
    for ts in st.get("terminal_states") or []:
        tid = str(ts.get("terminal_id") or "")
        say(f"  {s(tid[-8:], 8):<8}  {s(ts.get('tty') or '-', 16):<12}  {_state_text(ts):<34}  "
            f"{s(ts.get('label'), 48)}")
    ing = st.get("ingest") or {}
    if ing.get("active"):
        err = f", letzter Fehler: {s(ing['last_error'], 60)}" if ing.get("last_error") else ""
        say(f"Auswertung: aktiv ({s(ing.get('runs', 0), 10)} Durchgänge{err})")
    return 0


def _ask_yes(prompt: str) -> bool:
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in ("j", "ja", "y", "yes")


_END_TEXT = {"stop": "mit ariadne stop", "idle": "nach Leerlauf"}


def _no_active(active: dict[str, Any] | None) -> CliError:
    """Meldung ohne aktives Projekt; nennt das zuletzt beendete, wenn es eines gibt."""
    slug = (active or {}).get("slug")
    if not slug:
        return CliError("Kein aktives Projekt. ariadne start <slug> --target <ziel>")
    if (active or {}).get("end_reason") == "missing":
        return CliError(f"Projekt {s(slug, 64)} gibt es nicht mehr (Ordner fehlt). "
                        "ariadne start <slug> --target <ziel>")
    how = _END_TEXT.get(str((active or {}).get("end_reason")), "")
    return CliError(f"Projekt {s(slug, 64)} ist beendet{' ' + how if how else ''}. "
                    f"Weiter: ariadne start {s(slug, 64)}")


def cmd_start(paths: Paths, args: argparse.Namespace) -> int:
    if not OperatorVault(paths.operator_dir).exists:
        raise CliError("kein Operator-Tresor (ariadne init)")
    if args.target and not args.slug:
        raise CliError("--target braucht einen Projektnamen: ariadne start <slug> --target <ziel>")
    _client(paths)
    _pause_this_terminal(paths)
    st = _call(paths, "status")
    active = st.get("active") or {}
    if not args.slug and not st.get("project") and (not active or active.get("stopped")):
        raise _no_active(active)
    pw = None
    if not st["operator"]["unlocked"]:
        pw = read_secret("Passphrase: ", args.passphrase_fd)
    adopt = asked = False
    info = _call(paths, "preroll.info")
    if info.get("terminals") and info.get("seconds"):
        n, k = math.ceil(int(info["seconds"]) / 60), int(info["terminals"])
        if args.preroll == "yes":
            adopt = True
        elif args.preroll == "ask" and sys.stdin.isatty():
            asked = True
            adopt = _ask_yes(f"Die letzten {n} Minuten aus {k} Terminals übernehmen? [j/N] ")
    try:
        res = _call(paths, "start", passphrase=pw, slug=args.slug, targets=args.target or None,
                    name=args.name, not_customer=args.not_customer, adopt_preroll=adopt)
    except CtlError as exc:
        if exc.code == "guardrail":
            say("Ziele ausserhalb der Lab-Allowlist: "
                + ", ".join(s(x, 80) for x in exc.extra.get("outside", [])))
            say("lab-Projekte sind nicht für Kundendaten. Wenn es sicher kein Kundenauftrag ist: "
                "--not-customer")
            return 1
        if exc.code == "no_active_project":
            raise CliError(s(str(exc), 300)) from None
        if exc.code == "project_not_found":
            slug = args.slug or active.get("slug")
            if not slug:
                raise CliError("Projekt existiert nicht. ariadne start <slug> --target <ziel>") from None
            raise CliError(f"Projekt {s(slug, 64)} existiert nicht. Neu anlegen: "
                           f"ariadne start {s(slug, 64)} --target <ziel>") from None
        raise
    if res.get("unlocked"):
        say("Entsperrt.")
    if res.get("switched_from"):
        say(f"Projekt {s(res['switched_from'], 64)} beendet (Wechsel). Remote-Sitzungen bleiben dort, "
            f"bis die lokale Shell zurück ist.")
    if res.get("created"):
        say(f"Projekt {s(res['slug'])} angelegt ({s(res['profile'])}) in {s(res['workspace'], 400)}")
    else:
        say(f"Projekt {s(res['slug'])} geöffnet ({s(res['profile'])}).")
    if res.get("targets_ignored"):
        say("Hinweis: Das Projekt existiert schon, --target wurde nicht übernommen.")
    pre = res.get("preroll") or {}
    if pre.get("adopted"):
        say(f"Vorlauf übernommen: {math.ceil(int(pre.get('seconds') or 0) / 60)} min aus "
            f"{s(pre.get('terminals'))} Terminals.")
    elif pre.get("discarded_terminals") and args.preroll == "ask" and not asked:
        say(f"Vorlauf verworfen: {math.ceil(int(pre.get('discarded_seconds') or 0) / 60)} min aus "
            f"{s(pre.get('discarded_terminals'))} Terminals (ohne Terminal keine Frage; übernehmen mit "
            f"--preroll yes).")
    held = int(res.get("held") or 0)
    switching = f"; {held} wechseln an der nächsten lokalen Eingabeaufforderung" if held else ""
    say(f"Aufnahme läuft ({s(res.get('recording', 0))} Terminals{switching}). Pause: F12 r oder "
        f"ariadne pause. Ende: ariadne stop.")
    return 0


def cmd_stop(paths: Paths, args: argparse.Namespace) -> int:
    active = read_active(paths.active_file)
    # Läuft der Daemon nicht, ist ein aktives Projekt trotzdem nur in active.json beendet, die
    # allein der Daemon schreibt: dann starten (er beginnt gesperrt) und beenden lassen.
    start = active is not None and not active["stopped"]
    try:
        res = _call(paths, "stop", start=start)
    except CliError:
        if start:
            raise
        say("Daemon läuft nicht, nichts aktiv.")
        return 0
    if not res.get("stopped"):
        say("Kein aktives Projekt. Gesperrt.")
        return 0
    head = (f" Kettenkopf: seq {s(res['head_seq'])} {s(res['head_hash'])}"
            if res.get("head_seq") is not None else "")
    say(f"Projekt {s(res.get('slug'))} beendet und gesperrt.{head}")
    return 0


def _resolve_terminal(paths: Paths, ref: str) -> str:
    """Volle ``terminal_id`` oder eindeutige Kurz-ID (Anfang oder Ende, mindestens 4 Zeichen)."""
    terms = [t["terminal_id"] for t in _call(paths, "terminals", start=False)["terminals"]]
    if ref in terms:
        return ref
    hits = [t for t in terms if len(ref) >= 4 and (t.startswith(ref) or t.endswith(ref))]
    if len(hits) != 1:
        raise CliError(f"Terminal {s(ref, 64)} " + ("nicht eindeutig" if hits else "unbekannt")
                       + " (ariadne status zeigt die Kurz-IDs)")
    return hits[0]


def _pause_args(paths: Paths, args: argparse.Namespace) -> dict[str, Any]:
    if args.all:
        return {"all": True}
    ref = args.terminal or os.environ.get("ARIADNE_TERMINAL_ID")
    if not ref:
        raise CliError("kein Terminal: ARIADNE_TERMINAL_ID fehlt (läuft der Shim?), --terminal oder --all")
    return {"terminal_id": _resolve_terminal(paths, ref)}


def cmd_pause(paths: Paths, args: argparse.Namespace) -> int:
    target = _pause_args(paths, args)
    res = _call(paths, "term.pause", start=False, minutes=args.minutes, **target)
    items = res.get("paused") or []
    if not items:
        say("Kein Terminal pausiert.")
        return 0
    until = max(int(x.get("until_ns") or 0) for x in items)
    say(f"Pause bis {_hhmm(until)} ({len(items)} Terminal{'s' if len(items) != 1 else ''}). "
        f"Fortsetzen: F12 r oder ariadne resume.")
    return 0


def cmd_resume(paths: Paths, args: argparse.Namespace) -> int:
    target = _pause_args(paths, args)
    res = _call(paths, "term.resume", start=False, **target)
    n = len(res.get("resumed") or [])
    say(f"Aufnahme läuft weiter ({n} Terminal{'s' if n != 1 else ''})." if n else "Keine Pause aktiv.")
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
            say("Projekt ist offen, Aufnahme läuft.")
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


REC_GONE = ("REC gibt es nicht mehr. Die Aufnahme läuft, solange ein Projekt aktiv ist (ariadne start). "
            "Pause: F12 r oder ariadne pause. Ende: ariadne stop.")


def cmd_rec(paths: Paths, args: argparse.Namespace) -> int:
    say(REC_GONE)
    return 1


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
        say("Hinweis: nicht gespeichert (kein Projekt offen oder Terminal pausiert), nur im Terminal-Stapel. "
            "Mit der nächsten Aufnahme geht der Stapel als Schnappschuss ins Journal.")
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
        _client(paths)
        _pause_this_terminal(paths)
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


def cmd_mark(paths: Paths, args: argparse.Namespace) -> int:
    res = _call(paths, "keystep.mark", step=args.step, host=args.host, note=args.note,
                terminal_id=getattr(args, "terminal", None) or os.environ.get("ARIADNE_TERMINAL_ID"))
    raw = str(res.get("host") or "")
    shown = raw.split("/", 1)[1] if raw.startswith("ip:") else raw.removeprefix("name:")
    auto = " (auto)" if res.get("host_auto") else ""
    host = f" für {s(shown, 80)}{auto}" if shown else " (ohne Host)"
    say(f"Schlüsselschritt {s(res['step'], 12)} gespeichert{host}.")
    return 0


def cmd_import(paths: Paths, args: argparse.Namespace) -> int:
    path = os.path.abspath(args.path)
    res = _call(paths, "import", path=path, host=args.host)
    stored = "verschlüsselt gespeichert" if res.get("stored") else "nur Metadaten (zu gross)"
    say(f"Importiert: {s(res['path'], 300)} ({s(res['size'], 16)} Bytes, {stored}, "
        f"sha256 {s(res.get('sha256'), 64)[:16]}…)")
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
    say("Die Web-Oberfläche kommt mit der Web-UI. Bis dahin: ariadne status, ariadne show, ariadne ctx.")
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

    sub.add_parser("lock", help="sperren, offenes Projekt schliessen (bleibt aktiv: ariadne start)"
                   ).set_defaults(fn=cmd_lock)
    sub.add_parser("status", help="Zustand anzeigen").set_defaults(fn=cmd_status)

    sp = sub.add_parser("start", help="entsperren, Projekt öffnen oder anlegen, Aufnahme läuft")
    sp.add_argument("slug", nargs="?", help="Projekt (ohne: das zuletzt aktive)")
    sp.add_argument("--target", action="append", help="IP, CIDR oder Name (mehrfach, nur beim Anlegen)")
    sp.add_argument("--name")
    sp.add_argument("--not-customer", action="store_true", help="bestätigt: kein Kundenauftrag")
    sp.add_argument("--passphrase-fd", type=int, metavar="N", help="Passphrase von Dateideskriptor N lesen")
    sp.add_argument("--preroll", choices=["ask", "yes", "no"], default="ask",
                    help="Vorlauf (letzte Minuten aus dem RAM) übernehmen: fragen, ja, nein")
    sp.set_defaults(fn=cmd_start)

    sub.add_parser("stop", help="Projekt beenden und sperren").set_defaults(fn=cmd_stop)

    for name, fn, hlp in (("pause", cmd_pause, "Aufnahme dieses Terminals pausieren"),
                          ("resume", cmd_resume, "Pause aufheben")):
        sp = sub.add_parser(name, help=hlp)
        if name == "pause":
            sp.add_argument("--minutes", type=int, metavar="N", help="Dauer in Minuten (Standard 10)")
        grp = sp.add_mutually_exclusive_group()
        grp.add_argument("--terminal", metavar="ID", help="terminal_id oder Kurz-ID (Standard: dieses)")
        grp.add_argument("--all", action="store_true", help="alle verbundenen Terminals")
        sp.set_defaults(fn=fn)

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

    sp = sub.add_parser("rec", help="entfallen (Hinweis auf start, pause, stop)")
    sp.add_argument("rcmd", nargs="*", help=argparse.SUPPRESS)
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

    sp = sub.add_parser("secrets", help="eigene Secrets (werden vor KI, Export und Bericht ersetzt)")
    ssub = sp.add_subparsers(dest="scmd", required=True, metavar="AKTION")
    sa = ssub.add_parser("add")
    sa.add_argument("label")
    sa.add_argument("--value-fd", type=int, metavar="N", help="Wert von Dateideskriptor N lesen")
    ssub.add_parser("list")
    sr = ssub.add_parser("remove")
    sr.add_argument("label")
    sp.set_defaults(fn=cmd_secrets)

    analysis.register(sub)

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
    "locked": "Gesperrt: zuerst ariadne start.",
    "no_project": "Kein Projekt offen (ariadne start <slug>).",
    "removed": REC_GONE,
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
