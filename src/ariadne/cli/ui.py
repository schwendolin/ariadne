"""``ariadne ui``: Dashboard öffnen, Code zeigen, Sitzungen ansehen und widerrufen.

Besitzer: Teil «server» (Vertrag v0.1-Server 3.4, web-api.md 3, Architektur 7.2).

* ``ariadne ui`` startet **keinen** Daemon (ohne Daemon: Hinweis auf ``ariadne start``, Exit 1).
  Es prüft, dass der lauschende Socket wirklich dem Daemon gehört (Inode aus ``ui.status`` gegen
  ``/proc/net/tcp``), holt über ``ctl.sock`` einen Einmal-Code (``ui.code``, ``via = local``)
  und schreibt eine Startdatei mit Rechten 0600 nach ``$XDG_RUNTIME_DIR/ariadne/``. Sie leitet
  auf ``http://127.0.0.1:PORT/#c=<code>`` weiter (Code nur im Fragment, nie in argv), wird mit
  ``xdg-open`` geöffnet und nach 10 s gelöscht.
* ``--no-open``: Startdatei nur schreiben und den Pfad zeigen (ebenfalls nach 10 s weg).
* ``--code``: kurzen Tippcode zeigen (vorher ``pause_terminal``, damit er nicht in die
  Aufnahme kommt).
* ``--sessions``: Sitzungen mit Herkunft (lokal oder über sshd), Prozess, Beginn, letzter
  Nutzung und Ablauf, nie das Token (R7). ``--revoke [ID]``: eine oder alle widerrufen.
"""

from __future__ import annotations

import argparse
import contextlib
import html
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ariadne.cli.common import CliError, pause_this_terminal, s, say
from ariadne.daemon.client import CtlClient, CtlError, DaemonUnavailable
from ariadne.paths import Paths, ensure_private_dir

__all__ = ["register", "cmd_ui", "write_start_file", "listener_matches", "START_TTL_S"]

START_TTL_S = 10
START_PREFIX = "ui-start-"
_URL = re.compile(r"\Ahttp://(127\.0\.0\.1|\[::1\]):[0-9]{1,5}/#c=[A-Za-z0-9_-]{16,64}\Z")
_LISTEN = 0x0A
_ORIGIN = {"local": "lokal", "sshd": "über sshd"}


def _client(paths: Paths) -> CtlClient:
    client = CtlClient(paths.ctl_sock, timeout=10.0)
    if not client.ping():
        raise CliError("Daemon läuft nicht. Zuerst im Terminal: ariadne start")
    return client


def listener_matches(host: str, port: int, inode: int, *, proc_root: str = "/proc") -> bool:
    """Lauscht auf ``host:port`` genau ein Socket der eigenen UID mit diesem Inode?"""
    from ariadne.web.peer import parse_proc_net

    found = []
    for name in ("tcp", "tcp6"):
        try:
            with open(f"{proc_root}/net/{name}", encoding="ascii", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for e in parse_proc_net(text):
            if e.state == _LISTEN and e.local == (host, port):
                found.append(e)
    return len(found) == 1 and found[0].inode == inode and found[0].uid == os.getuid()


def _start_html(url: str) -> str:
    u = html.escape(url, quote=True)
    return (
        "<!doctype html>\n<html lang=\"de-CH\"><head><meta charset=\"utf-8\">\n"
        "<meta name=\"referrer\" content=\"no-referrer\">\n"
        f"<meta http-equiv=\"refresh\" content=\"0;url={u}\">\n"
        "<title>Ariadne</title></head>\n"
        f"<body><p>Weiter zu <a href=\"{u}\" rel=\"noreferrer\">Ariadne</a>.</p></body></html>\n"
    )


def _cleanup_old(runtime_dir: Path, max_age_s: float = 60.0) -> None:
    """Reste früherer Startdateien entfernen (Absturz vor dem Löschen)."""
    now = time.time()
    with contextlib.suppress(OSError):
        for p in runtime_dir.glob(f"{START_PREFIX}*.html"):
            with contextlib.suppress(OSError):
                if now - p.lstat().st_mtime > max_age_s:
                    p.unlink()


def write_start_file(paths: Paths, url: str) -> Path:
    """Startdatei (0600, neu, nie überschreiben) im privaten Runtime-Ordner."""
    if not _URL.match(url):
        raise CliError("Antwort des Daemons unerwartet (Adresse)")
    ensure_private_dir(paths.runtime_dir)
    _cleanup_old(paths.runtime_dir)
    path = paths.runtime_dir / f"{START_PREFIX}{secrets.token_hex(8)}.html"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, _start_html(url).encode("utf-8"))
    finally:
        os.close(fd)
    return path


def schedule_delete(path: Path, ttl: float | None = None) -> bool:
    """Löscht ``path`` nach ``ttl`` s (Standard :data:`START_TTL_S`) in einem abgekoppelten Prozess
    (eigene Sitzung, überlebt das Schliessen des Terminals). Der Pfad steht in argv, der Code nicht."""
    ttl = START_TTL_S if ttl is None else ttl
    script = '(sleep "$2"; rm -f -- "$1") </dev/null >/dev/null 2>&1 &'
    try:
        subprocess.run(["sh", "-c", script, "sh", str(path), str(ttl)], start_new_session=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=5, check=False)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _open(path: Path) -> bool:
    exe = shutil.which("xdg-open")
    if exe is None:
        return False
    try:
        res = subprocess.run([exe, str(path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=15, check=False, start_new_session=True)
    except (OSError, subprocess.SubprocessError):
        return False
    return res.returncode == 0


def _when(ns: Any) -> str:
    if not isinstance(ns, int) or ns <= 0:
        return "-"
    t = time.localtime(ns / 1e9)
    today = time.localtime()
    if (t.tm_year, t.tm_yday) == (today.tm_year, today.tm_yday):
        return time.strftime("%H:%M", t)
    return time.strftime("%d.%m. %H:%M", t)


def _show_sessions(client: CtlClient) -> int:
    rows = client.call("ui.sessions").get("sessions") or []
    if not rows:
        say("Keine Sitzungen.")
        return 0
    say(f"Sitzungen ({len(rows)}):")
    for r in rows:
        origin = _ORIGIN.get(str(r.get("origin")), "?")
        proc = f"{s(r.get('peer_comm') or '?', 32)} (PID {s(r.get('peer_pid'), 12)})"
        say(f"  {s(r.get('session_id'), 16):<9} {origin:<10} {proc:<28} seit {_when(r.get('created_ns'))}"
            f"  zuletzt {_when(r.get('last_used_ns'))}  bis {_when(r.get('expires_ns'))}")
    say("Widerrufen: ariadne ui --revoke ID (ohne ID: alle)")
    return 0


def _revoke(client: CtlClient, target: str) -> int:
    try:
        res = client.call("ui.revoke", **({} if target == "all" else {"session_id": target}))
    except CtlError as exc:
        if exc.code == "not_found":
            raise CliError(f"Sitzung {s(target, 32)} unbekannt (ariadne ui --sessions)") from None
        raise
    n = int(res.get("revoked") or 0)
    say("Keine Sitzung offen." if n == 0 else f"{n} Sitzung{'en' if n != 1 else ''} widerrufen.")
    return 0


def cmd_ui(paths: Paths, args: argparse.Namespace) -> int:
    try:
        client = _client(paths)
        if args.sessions:
            return _show_sessions(client)
        if args.revoke:
            return _revoke(client, args.revoke)
        status = client.call("ui.status")
        if not status.get("running"):
            raise CliError(f"Web-Oberfläche aus: {s(status.get('error') or 'nicht gestartet', 200)}")
        host, port, inode = str(status.get("host")), status.get("port"), status.get("inode")
        if not isinstance(port, int) or not isinstance(inode, int) or not listener_matches(host, port, inode):
            raise CliError("Der lauschende Port gehört nicht dem Daemon. Abbruch (nichts geöffnet).")
        if args.code:
            pause_this_terminal(paths)  # Tippcode nicht in die Aufnahme
            res = client.call("ui.code", typed=True, via="local")
            web = "[::1]" if ":" in host else host
            valid = int(res.get("expires_in") or 0)
            say(f"Tippcode: {s(res.get('display'), 16)}  (gültig {valid} s, einmal)")
            say(f"Im Browser der Kali öffnen: http://{web}:{port}/ und den Code eingeben.")
            return 0
        res = client.call("ui.code", typed=False, via="local")
        path = write_start_file(paths, str(res.get("url") or ""))
        deleting = schedule_delete(path)
        if args.no_open or not _open(path):
            if not args.no_open:
                say("Browser liess sich nicht öffnen (xdg-open).")
            say(f"Startdatei: file://{path}")
            valid = int(res.get("expires_in") or 0)
            say(f"Im Browser öffnen; der Code gilt {valid} s, die Datei wird in {START_TTL_S} s gelöscht.")
        else:
            say("Dashboard im Browser geöffnet.")
        if not deleting:  # ohne sh: selbst warten, dann löschen
            time.sleep(START_TTL_S)
            with contextlib.suppress(OSError):
                path.unlink()
        return 0
    except DaemonUnavailable:
        raise CliError("Daemon läuft nicht. Zuerst im Terminal: ariadne start") from None
    except CtlError as exc:
        if exc.code == "ui_off":
            raise CliError(s(str(exc), 300)) from None
        raise


def register(sub: Any) -> None:
    sp = sub.add_parser("ui", help="Dashboard öffnen (Einmal-Code), Sitzungen ansehen und widerrufen")
    grp = sp.add_mutually_exclusive_group()
    grp.add_argument("--code", action="store_true", help="kurzen Tippcode zeigen statt den Browser zu öffnen")
    grp.add_argument("--sessions", action="store_true", help="angemeldete Sitzungen mit Herkunft zeigen")
    grp.add_argument("--revoke", nargs="?", const="all", metavar="ID",
                     help="Sitzung ID widerrufen (ohne ID: alle)")
    sp.add_argument("--no-open", action="store_true", help="Startdatei nicht öffnen, nur den Pfad zeigen")
    sp.set_defaults(fn=cmd_ui)
