"""``ariadne remote serve``: Forced Command des Mac-Schlüssels (R5, R11, Konzept 4.2, E94).

Steht in ``~/.ssh/authorized_keys`` als
``restrict,pty,port-forwarding,permitopen="127.0.0.1:7330",command="…/ariadne remote serve" <key>``.
sshd startet für diesen Schlüssel immer dieses Programm; was der Client als Befehl schickt, steht
nur als Text in ``SSH_ORIGINAL_COMMAND``. Der Text muss **genau** eines der Wörter aus
:data:`ALLOWED` sein. Alles andere (``id``, ``code; id``, ``code id``, ``scp -t /``,
``internal-sftp``, ``/usr/lib/openssh/sftp-server``, eine leere Anfrage für eine Shell) endet mit
einer deutschen Meldung auf stderr und Exit 2, ohne dass etwas ausgeführt wird. Es gibt keine
Shell, kein ``exec`` eines Client-Werts, und keine Variable des Clients wird ausgewertet.

* ``code``: Schnellprüfung (:func:`ariadne.remote.check.quick_ok`, sonst Exit 3), Daemon wie die
  CLI starten, dann ``ctl ui.code`` mit ``via = "sshd"``. Der Daemon bindet den Code an den
  sshd-Prozess dieser SSH-Verbindung. Ohne Terminal (``ssh -n``, Mac-Helfer) steht auf stdout genau
  eine Zeile ``<code>``, danach nichts mehr; mit Terminal (``ssh -t``) ein Tippcode
  ``ABCDE-FGHJK``. Danach **hält** ``code`` die Verbindung, die auch den Tunnel trägt, bis die
  Eltern-sshd endet oder SIGHUP, SIGTERM, SIGINT, SIGPIPE kommt (Exit 0). stdin wird nie gelesen.
* ``unlock``: nur mit Terminal; wie ``ariadne unlock`` (E101 öffnet das aktive Projekt, E102
  übernimmt den Ausfallpuffer ohne Frage).
* ``lock``, ``revoke``: ctl ``lock`` bzw. ``ui.revoke`` (alle Sitzungen); ohne Daemon nichts zu tun.
* ``backup``: nur wenn stdout kein Terminal ist; age-verschlüsselter Strom auf stdout
  (:func:`ariadne.backup.api.backup_to_stream`), Meldungen nur auf stderr.
* ``restore``: nur ohne Operator-Tresor (geprüft vor dem Lesen) und nur aus einer Pipe;
  :func:`ariadne.backup.api.restore_from_stream` liest den entschlüsselten Strom von stdin.
* ``check``: wie ``ariadne remote check`` (ohne ``--full``).

Exit-Codes: 0 gut, 1 Fehler, 2 abgelehnt, 3 Fernzugriff nicht bereit (Prüfung, Daemon, Web aus).
"""

from __future__ import annotations

import contextlib
import os
import signal
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from ariadne.paths import Paths

__all__ = ["main", "ALLOWED", "hold", "HOLD_SIGNALS", "parse_command", "STUB", "EXIT_REFUSED", "EXIT_UNREADY"]

ALLOWED = ("code", "unlock", "lock", "revoke", "backup", "restore", "check")

STUB = False

EXIT_OK, EXIT_ERROR, EXIT_REFUSED, EXIT_UNREADY = 0, 1, 2, 3
HOLD_SIGNALS = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT, signal.SIGPIPE)
HELP = "Erlaubt sind nur: " + ", ".join(ALLOWED) + "."
NEEDS_DAEMON = frozenset({"code", "unlock", "lock", "revoke"})


def _err(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _say(text: str) -> None:
    print(text, flush=True)


def _isatty(stream: TextIO) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def _s(value: Any, n: int = 300) -> str:
    from ariadne.termsafe import term_safe

    return term_safe(value, max_len=n)


def parse_command(raw: str | None) -> str | None:
    """Das Wort aus :data:`ALLOWED` oder ``None``. Kein Trimmen, kein Zerlegen, keine Shell."""
    if raw is None:
        return None
    return raw if raw in ALLOWED else None


# --------------------------------------------------------------------------- #
# Halten der Verbindung
# --------------------------------------------------------------------------- #


def hold(ppid: int, *, interval: float = 1.0) -> int:
    """Wartet, bis der Elternprozess (sshd dieser Verbindung) weg ist oder ein Signal aus
    :data:`HOLD_SIGNALS` kommt. Die Signale müssen vorher blockiert sein (siehe ``_code``)."""
    while os.getppid() == ppid:
        if signal.sigtimedwait(HOLD_SIGNALS, interval) is not None:
            break
    return EXIT_OK


# Austauschbar für Tests (Vertrag 3.6).
HOLD: Callable[[int], int] = hold


def _silence_stdout() -> None:
    """Nach der Code-Zeile kommt nichts mehr auf stdout (der Mac-Helfer liest genau eine Zeile)."""
    with contextlib.suppress(OSError, ValueError):
        sys.stdout.flush()
        fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(fd, sys.stdout.fileno())
        finally:
            os.close(fd)


# --------------------------------------------------------------------------- #
# Befehle
# --------------------------------------------------------------------------- #


def _code(paths: Paths, env: Mapping[str, str]) -> int:
    from ariadne.cli.common import CliError, _client, pause_this_terminal
    from ariadne.daemon.client import CtlError
    from ariadne.remote import check

    ppid = os.getppid()
    if not check.quick_ok(paths):
        reasons = ""
        with contextlib.suppress(Exception):
            fails = [c.title for c in check.quick_checks(paths) if c.level == check.FAIL]
            reasons = ": " + "; ".join(_s(t, 120) for t in fails[:5]) if fails else ""
        _err("Fernzugriff nicht sicher eingerichtet (ariadne remote check)" + reasons + ". Kein Code.")
        return EXIT_UNREADY
    typed = _isatty(sys.stdin)
    # Der Daemon startet hier (falls nötig) mit der normalen Signalmaske; erst danach blockieren.
    try:
        client = _client(paths)
    except CliError as exc:
        _err(f"Daemon nicht erreichbar: {_s(exc)}. Kein Code.")
        return EXIT_UNREADY
    pause_this_terminal(paths)
    try:
        res = client.call("ui.code", typed=typed, via="sshd")
    except CtlError as exc:
        if exc.code in ("ui_off", "not_sshd"):
            _err(f"Kein Code: {_s(exc)}")
            return EXIT_UNREADY
        if exc.code == "unknown_op":
            _err("Kein Code: Web-Oberfläche im Daemon nicht geladen (ARIADNE_WEB=0?).")
            return EXIT_UNREADY
        raise
    code = res.get("code") if isinstance(res, dict) else None
    if not isinstance(code, str) or not code:
        _err("Kein Code: ungültige Antwort des Daemons.")
        return EXIT_ERROR
    # Ab hier beendet kein Signal den Prozess hart: hold() nimmt es ab und endet mit Exit 0.
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, HOLD_SIGNALS)
    try:
        if typed:
            display = res.get("display") if isinstance(res.get("display"), str) else code
            port = res.get("port") if isinstance(res.get("port"), int) else 7330
            _say(f"Code: {_s(display, 40)} (gültig {_s(res.get('expires_in'), 8)} s, nur einmal)")
            _say(f"Im Browser auf dem Mac http://127.0.0.1:{port} öffnen und den Code eingeben.")
            _say("Tunnel offen, Ctrl-C beendet den Zugang.")
        else:
            sys.stdout.write(code + "\n")
            sys.stdout.flush()
            _silence_stdout()
        return HOLD(ppid)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def _unlock(paths: Paths, env: Mapping[str, str]) -> int:
    if not _isatty(sys.stdin):
        _err("Abgelehnt: unlock braucht ein Terminal für die Passphrase: ssh -t kali-sl unlock")
        return EXIT_REFUSED
    from ariadne.cli.main import main as cli_main

    return cli_main(["unlock"])


def _lock(paths: Paths, env: Mapping[str, str]) -> int:
    from ariadne.cli.common import CliError, _call

    try:
        res = _call(paths, "lock", start=False)
    except CliError:
        _say("Daemon läuft nicht, nichts entsperrt.")
        return EXIT_OK
    closed = isinstance(res, dict) and res.get("closed_project")
    _say("Gesperrt." + (" Projekt geschlossen, es bleibt aktiv (ssh -t kali-sl unlock)." if closed else ""))
    return EXIT_OK


def _revoke(paths: Paths, env: Mapping[str, str]) -> int:
    from ariadne.cli.common import CliError, _call
    from ariadne.daemon.client import CtlError

    try:
        res = _call(paths, "ui.revoke", start=False)
    except CliError:
        _say("Daemon läuft nicht, keine Sitzungen.")
        return EXIT_OK
    except CtlError as exc:
        if exc.code == "unknown_op":
            _say("Web-Oberfläche aus, keine Sitzungen.")
            return EXIT_OK
        raise
    n = res.get("revoked", 0) if isinstance(res, dict) else 0
    _say(f"Widerrufen: {_s(n, 8)} Sitzungen.")
    return EXIT_OK


def _backup(paths: Paths, env: Mapping[str, str]) -> int:
    if _isatty(sys.stdout):
        _err("Abgelehnt: Die Sicherung ist ein verschlüsselter Datenstrom und gehört in eine Datei: "
             "ssh kali-sl backup > kali-sl.age (oder ariadne-mac backup)")
        return EXIT_REFUSED
    from ariadne.backup import api as backup_api

    try:
        res = backup_api.backup_to_stream(sys.stdout.buffer, paths)
        sys.stdout.buffer.flush()
    except backup_api.BackupError as exc:
        hint = " Zuerst ssh kali-sl lock." if exc.code == "project_open" else ""
        _err(f"Sicherung fehlgeschlagen ({_s(exc.code, 30)}): {_s(exc)}{hint}")
        return EXIT_ERROR
    except OSError as exc:
        _err(f"Sicherung abgebrochen: Ausgabe nicht schreibbar ({type(exc).__name__}).")
        return EXIT_ERROR
    summary = getattr(backup_api, "backup_summary_lines", None)
    if summary is not None:
        for line in summary(res):
            _err(_s(line, 400))
    else:
        projects = ", ".join(_s(p, 64) for p in res.projects) or "keine"
        _err(f"Sicherung geschrieben: {res.bytes_written} Bytes, Projekte: {projects}.")
    return EXIT_OK


def _restore(paths: Paths, env: Mapping[str, str]) -> int:
    from ariadne.crypto.vault import OperatorVault

    if OperatorVault(paths.operator_dir).exists:
        _err("Abgelehnt: In dieser Kali gibt es schon einen Operator-Tresor. restore geht nur in eine "
             "frische Installation (ariadne setup, aber kein ariadne init).")
        return EXIT_REFUSED
    if _isatty(sys.stdin):
        _err("Abgelehnt: restore liest die entschlüsselte Sicherung aus einer Pipe: "
             "age -d -i mac.key.age DATEI.age | ssh kali-sl restore (oder ariadne-mac restore DATEI)")
        return EXIT_REFUSED
    from ariadne.backup import api as backup_api

    try:
        res = backup_api.restore_from_stream(sys.stdin.buffer, paths)
    except backup_api.BackupError as exc:
        _err(f"Wiederherstellung abgelehnt ({_s(exc.code, 30)}): {_s(exc)}. Nichts geschrieben.")
        return EXIT_ERROR
    except OSError as exc:
        _err(f"Wiederherstellung abgebrochen: Eingabe nicht lesbar ({type(exc).__name__}).")
        return EXIT_ERROR
    summary = getattr(backup_api, "restore_summary_lines", None)
    if summary is not None:
        for line in summary(res, remote=True):
            _say(_s(line, 400))
        return EXIT_OK
    projects = ", ".join(_s(p, 64) for p in res.projects) or "keine"
    vault = "ja" if res.operator_restored else "nein"
    _say(f"Wiederhergestellt: Operator-Tresor {vault}, Projekte: {projects}.")
    _say("Weiter: ssh -t kali-sl unlock, dann in der Kali ariadne project open SLUG und ariadne verify.")
    return EXIT_OK


def _check(paths: Paths, env: Mapping[str, str]) -> int:
    from ariadne.remote.check import render, run_checks

    lines, worst = render(run_checks(paths))
    for line in lines:
        _say(line)
    return worst


HANDLERS: dict[str, Callable[[Paths, Mapping[str, str]], int]] = {
    "code": _code,
    "unlock": _unlock,
    "lock": _lock,
    "revoke": _revoke,
    "backup": _backup,
    "restore": _restore,
    "check": _check,
}


def main(paths: Paths, env: Mapping[str, str]) -> int:
    """Führt den Befehl aus ``env['SSH_ORIGINAL_COMMAND']`` aus. Gibt den Exit-Code zurück."""
    raw = env.get("SSH_ORIGINAL_COMMAND")
    cmd = parse_command(raw)
    if cmd is None:
        what = "Dieser Schlüssel öffnet keine Shell." if not raw else "Unbekannter Befehl."
        _err(f"Abgelehnt: {what} {HELP} Nichts ausgeführt.")
        return EXIT_REFUSED
    if cmd in NEEDS_DAEMON and not env.get("XDG_RUNTIME_DIR"):
        _err("Kein Runtime-Ordner (XDG_RUNTIME_DIR fehlt, /run/user/UID nicht nutzbar): In der Kali "
             "anmelden oder einmal sudo loginctl enable-linger $USER. Nichts ausgeführt.")
        return EXIT_UNREADY
    from ariadne.cli.common import CliError
    from ariadne.daemon.client import CtlError, DaemonUnavailable

    try:
        return HANDLERS[cmd](paths, env)
    except CtlError as exc:
        _err(f"Fehler: {_s(exc)}")
        return EXIT_ERROR
    except (CliError, DaemonUnavailable) as exc:
        _err(f"Fehler: {_s(exc)}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        _err("abgebrochen")
        return 130
    except Exception as exc:  # nie einen Stacktrace mit Daten an den Mac
        _err(f"Interner Fehler ({type(exc).__name__}). Nichts weiter ausgeführt.")
        return EXIT_ERROR
