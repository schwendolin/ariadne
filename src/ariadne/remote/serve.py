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
  Endet ``code`` (Ctrl-C unter ``ssh -t``, SIGTERM), widerruft es die Sitzungen und Codes dieser
  SSH-Verbindung (ctl ``ui.revoke`` mit ``bound_pid``/``bound_start``): Ein offener SSE-Strom hält
  sonst sshd und den Tunnel am Leben, und die Anmeldung gälte weiter (Befund SEC-R1/F4).
* ``unlock``: nur mit Terminal; wie ``ariadne unlock`` (E101 öffnet das aktive Projekt, E102
  übernimmt den Ausfallpuffer ohne Frage).
* ``lock``, ``revoke``: ctl ``lock`` bzw. ``ui.revoke`` (alle Sitzungen); ohne Daemon nichts zu tun.
* ``backup``: nur wenn stdout kein Terminal ist; age-verschlüsselter Strom auf stdout
  (:func:`ariadne.backup.api.backup_to_stream`), Meldungen nur auf stderr.
* ``restore``: nur ohne Operator-Tresor (geprüft vor dem Lesen) und nur aus einer Pipe;
  :func:`ariadne.backup.api.restore_from_stream` liest den entschlüsselten Strom von stdin. Danach
  beendet sich ein laufender (gesperrter) Daemon und startet mit der zurückgespielten Konfiguration
  neu (E118, :func:`restart_daemon`).
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

__all__ = ["main", "ALLOWED", "hold", "HOLD_SIGNALS", "parse_command", "STUB", "EXIT_REFUSED", "EXIT_UNREADY",
           "restart_daemon"]

ALLOWED = ("code", "unlock", "lock", "revoke", "backup", "restore", "check")

STUB = False

EXIT_OK, EXIT_ERROR, EXIT_REFUSED, EXIT_UNREADY = 0, 1, 2, 3
HOLD_SIGNALS = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT, signal.SIGPIPE)
HELP = "Erlaubt sind nur: " + ", ".join(ALLOWED) + "."
NEEDS_DAEMON = frozenset({"code", "unlock", "lock", "revoke"})
# Kaltstart des Daemons vor dem ersten Code: unter den 15 s, die ariadne-mac start wartet (RT-3)
CODE_START_TIMEOUT_S = 10.0


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
        client = _client(paths, timeout=CODE_START_TIMEOUT_S)  # langsame Schul-VM nach dem Neustart
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
            _say("Tunnel offen. Ctrl-C beendet Tunnel und Anmeldung (auch bei offenem Dashboard).")
        else:
            sys.stdout.write(code + "\n")
            sys.stdout.flush()
            _silence_stdout()
        return HOLD(ppid)
    finally:
        _revoke_binding(client, res.get("bound"))
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def _revoke_binding(client: Any, bound: Any) -> None:
    """Sitzungen und Codes dieser SSH-Verbindung beenden (nach dem Halten). Fehler bleiben still:
    Ohne Daemon gibt es nichts zu beenden, und die 2-s-Prüfung fängt das Ende des sshd ab."""
    if not isinstance(bound, dict):
        return
    pid, start = bound.get("pid"), bound.get("start")
    if type(pid) is not int or type(start) is not int:
        return
    with contextlib.suppress(Exception):
        client.call("ui.revoke", bound_pid=pid, bound_start=start)


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
            _say(_s(line, 600))
    else:
        projects = ", ".join(_s(p, 64) for p in res.projects) or "keine"
        vault = "ja" if res.operator_restored else "nein"
        _say(f"Wiederhergestellt: Operator-Tresor {vault}, Projekte: {projects}.")
        _say("Weiter: ssh -t kali-sl unlock, dann in der Kali ariadne project open SLUG und ariadne verify.")
    _say(restart_daemon(paths))
    return EXIT_OK


# E118: Wartezeit, bis der alte Daemon weg ist (Socket zu und Sperre frei)
RESTART_WAIT_S = 10.0


def _lock_free(paths: Paths) -> bool:
    """Ist die Sperre ``daemon.lock`` frei (kein Daemon mehr)? Prüft nur, legt nichts an."""
    import fcntl

    path = paths.runtime_dir / "daemon.lock"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    finally:
        os.close(fd)


def restart_daemon(paths: Paths, *, wait_s: float | None = None) -> str:
    """Nach dem Zurückspielen (E118): Ein laufender, gesperrter Daemon beendet sich (ctl
    ``shutdown``) und startet mit der zurückgespielten Konfiguration neu, wie ``cli.common._client``
    ihn startet. Ohne laufenden Daemon gibt es nichts zu tun. Gibt die Meldung für den Mac zurück."""
    import time

    from ariadne.cli.common import CliError, _client
    from ariadne.daemon.client import CtlClient, CtlError, DaemonUnavailable

    client = CtlClient(paths.ctl_sock)
    running = False
    with contextlib.suppress(Exception):
        running = client.ping()
    if not running:
        return "Neue Einstellungen gelten beim nächsten Start des Daemons. Weiter: ariadne-mac unlock"
    status: Any = None
    with contextlib.suppress(CtlError, DaemonUnavailable, OSError):
        status = client.call("status")
    if isinstance(status, dict) and status.get("locked") is False:
        # Kann nach einem Restore ohne Tresor nicht vorkommen; ein entsperrter Daemon wird nie beendet
        return ("Daemon läuft entsperrt weiter; neue Einstellungen gelten erst nach ariadne daemon stop in "
                "der Kali.")
    with contextlib.suppress(CtlError, DaemonUnavailable, OSError):
        client.call("shutdown")
    deadline = time.monotonic() + (RESTART_WAIT_S if wait_s is None else wait_s)
    while True:
        alive = False
        with contextlib.suppress(Exception):
            alive = client.ping()
        if not alive and _lock_free(paths):
            break
        if time.monotonic() > deadline:
            return ("Der Daemon hat sich nicht beendet: in der Kali ariadne daemon stop, danach "
                    "ariadne-mac unlock.")
        time.sleep(0.1)
    try:
        _client(paths, timeout=CODE_START_TIMEOUT_S)
    except CliError:
        return "Daemon beendet, aber nicht neu gestartet. Weiter: ariadne-mac unlock (startet ihn)."
    return "Daemon mit neuer Konfiguration neu gestartet. Weiter: ariadne-mac unlock"


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
