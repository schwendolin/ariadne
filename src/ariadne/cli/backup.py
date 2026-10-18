"""``ariadne backup`` und ``ariadne restore`` (E91, Konzept Fernzugriff 6, Vertrag v0.1-Server 3.5).

``ariadne backup`` schreibt die age-verschlüsselte Sicherung auf stdout (verweigert, wenn stdout
ein Terminal ist, Exit 2) oder mit ``--to-file PFAD`` in eine neue Datei (0600, ``O_EXCL``, nie
überschreiben; bei einem Fehler wird die halbe Datei gelöscht). Meldungen gehen immer nach
stderr, damit stdout nur Daten trägt.

``ariadne restore`` liest den entschlüsselten Strom von stdin oder ``--from-file PFAD``; mit
``--identity DATEI`` entschlüsselt es eine ``.age``-Datei selbst (Recovery-Schlüssel in der VM,
Konzept 6.5), mit ``--identity -`` wird der Schlüssel verdeckt eingetippt und berührt nie die
Platte. Mit Terminal (oder ``--passphrase-fd N``) prüft es danach jede Kette über den Daemon:
Passphrase, ``unlock`` ohne Öffnen, je Projekt ``project.open``, ``verify``, ``project.close``,
am Ende ``lock``. ``--no-verify`` lässt das weg; dann nennt die Ausgabe den Weg von Hand.

Exit-Codes: 0 gut, 1 Fehler (auch eine Kette mit Problemen), 2 verweigert (Terminal statt Datei
bzw. Pipe, schon ein Operator-Tresor vorhanden).
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import os
import sys
from pathlib import Path
from typing import Any, BinaryIO

from ariadne.paths import Paths

__all__ = ["register", "cmd_backup", "cmd_restore"]

MAX_IDENTITY = 64 << 10


def _err(text: str) -> None:
    from ariadne.cli.common import s

    print(f"Fehler: {s(text, 600)}", file=sys.stderr, flush=True)


def _info(text: str) -> None:
    from ariadne.cli.common import s

    print(s(text, 600), file=sys.stderr, flush=True)


def _is_tty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _exit_code(code: str) -> int:
    return 2 if code in ("tty_refused", "vault_exists") else 1


# --------------------------------------------------------------------------- #
# backup
# --------------------------------------------------------------------------- #


def _backup_to_file(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.backup.api import BackupError, backup_summary_lines, backup_to_stream
    from ariadne.crypto.files import fsync_dir

    target = Path(args.to_file).expanduser()
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        _err("Die Zieldatei existiert schon; ariadne backup überschreibt nie. Neuen Namen wählen.")
        return 1
    except OSError as exc:
        _err(f"Zieldatei lässt sich nicht anlegen ({exc.strerror or type(exc).__name__}).")
        return 1
    done = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            res = backup_to_stream(fh, paths, projects=args.project, target="file",
                                   target_path=str(target.absolute()))
            fh.flush()
            os.fsync(fh.fileno())
        with contextlib.suppress(OSError):
            fsync_dir(target.absolute().parent)
        done = True
    except BackupError as exc:
        _err(str(exc))
        return _exit_code(exc.code)
    finally:
        if not done:
            with contextlib.suppress(OSError):
                os.unlink(target)
    for line in backup_summary_lines(res):
        _info(line)
    _info(f"Datei: {target} (Rechte 600). Aus der VM holen und hier löschen, sobald sie sicher liegt.")
    return 0


def cmd_backup(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.backup.api import BackupError, backup_summary_lines, backup_to_stream

    if args.to_file:
        return _backup_to_file(paths, args)
    if _is_tty(sys.stdout):
        _err("Die Sicherung ist binär und geht nie auf ein Terminal. Umleiten (ariadne backup > "
             "datei.age) oder ariadne backup --to-file PFAD.")
        return 2
    try:
        res = backup_to_stream(sys.stdout.buffer, paths, projects=args.project, target="stdout")
    except BackupError as exc:
        _err(str(exc))
        return _exit_code(exc.code)
    for line in backup_summary_lines(res):
        _info(line)
    return 0


# --------------------------------------------------------------------------- #
# restore
# --------------------------------------------------------------------------- #


def _identity_text(paths: Paths, spec: str) -> str:
    """Schlüssel aus Datei (nur lesen, nie kopieren) oder verdeckt vom Terminal (``-``)."""
    from ariadne.backup.api import BackupError
    from ariadne.backup.reader import is_age_header
    from ariadne.cli.common import pause_this_terminal, read_secret
    from ariadne.crypto.files import read_private
    from ariadne.paths import UnsafePathError

    if spec == "-":
        pause_this_terminal(paths)  # vor getpass: der Schlüssel kommt nie in den Vorlauf (E26)
        return read_secret("Recovery-Schlüssel (AGE-SECRET-KEY-1…): ", None)
    try:
        raw = read_private(Path(spec).expanduser(), max_size=MAX_IDENTITY)
    except (OSError, UnsafePathError) as exc:
        raise BackupError("decrypt", "Schlüsseldatei nicht lesbar (fehlt, Symlink, fremder Besitzer oder "
                                     "zu gross).") from exc
    if is_age_header(raw[:64]):
        raise BackupError("decrypt", "Die Schlüsseldatei ist selbst verschlüsselt. Den Recovery-Schlüssel "
                                     "verwenden (--identity - zum Eintippen).")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackupError("decrypt", "Schlüsseldatei ist kein Text.") from exc


def _verify_chains(paths: Paths, slugs: tuple[str, ...], fd: int | None) -> dict[str, bool]:
    """Kettenprüfung über ctl (Vertrag 3.5): unlock ohne Öffnen, je Projekt open, verify, close, lock."""
    from ariadne.cli.common import CliError, _call, _client, pause_this_terminal, read_secret, s
    from ariadne.daemon.client import CtlError, DaemonUnavailable

    _client(paths)
    pause_this_terminal(paths)
    pw = read_secret("Passphrase (zum Prüfen der Ketten): ", fd)
    res = _call(paths, "unlock", passphrase=pw, open_active=False)
    already = bool(res.get("already"))
    out: dict[str, bool] = {}
    try:
        for slug in slugs:
            try:
                _call(paths, "project.open", slug=slug)
                v = _call(paths, "verify")
                ok = bool(v.get("ok"))
                out[slug] = ok
                if ok:
                    print(f"Kette {slug}: in Ordnung ({s(v.get('events'))} Events).", flush=True)
                else:
                    print(f"Kette {slug}: PROBLEME ({s(v.get('problem_count'))}):", flush=True)
                    for p in list(v.get("problems") or [])[:5]:
                        print(f"  {s(p, 300)}", flush=True)
            except CtlError as exc:
                out[slug] = False
                print(f"Kette {slug}: nicht prüfbar ({s(exc.code, 40)}: {s(str(exc), 300)})", flush=True)
            finally:
                with contextlib.suppress(CtlError, DaemonUnavailable, CliError):
                    _call(paths, "project.close")
    finally:
        if not already:
            with contextlib.suppress(CtlError, DaemonUnavailable, CliError):
                _call(paths, "lock")
    return out


def _open_source(args: argparse.Namespace) -> BinaryIO:
    from ariadne.backup.api import BackupError

    if args.from_file:
        try:
            return open(Path(args.from_file).expanduser(), "rb")  # noqa: SIM115 (schliesst cmd_restore)
        except OSError as exc:
            raise BackupError("io", f"Datei nicht lesbar ({exc.strerror or type(exc).__name__}).") from exc
    if _is_tty(sys.stdin):
        raise BackupError("tty_refused", "Die Sicherung kommt über eine Pipe (age -d … | ariadne restore) "
                                         "oder mit --from-file PFAD, nicht von der Tastatur.")
    return sys.stdin.buffer


def cmd_restore(paths: Paths, args: argparse.Namespace) -> int:
    from ariadne.backup.api import BackupError, restore_from_stream, restore_summary_lines
    from ariadne.backup.reader import DecryptingReader, load_identities
    from ariadne.cli.common import CliError, s
    from ariadne.crypto.vault import OperatorVault
    from ariadne.daemon.client import CtlError, DaemonUnavailable

    if OperatorVault(paths.operator_dir).exists:  # vor dem Lesen (Vertrag 3.5)
        _err("Hier gibt es schon einen Operator-Tresor. Wiederherstellen geht nur in eine Installation "
             "ohne Tresor (frische VM: ariadne setup, aber nicht ariadne init).")
        return 2
    if args.identity == "-" and not args.from_file:
        _err("Mit --identity - kommt die Sicherung über --from-file PFAD (stdin braucht das Eintippen).")
        return 2
    src: BinaryIO | None = None
    try:
        idents = load_identities(_identity_text(paths, args.identity)) if args.identity else None
        src = _open_source(args)
        if idents is not None:
            reader = DecryptingReader(src, idents)
            try:
                res = restore_from_stream(reader, paths)  # type: ignore[arg-type]  # Leser mit read()
            finally:
                reader.close()
        else:
            res = restore_from_stream(src, paths)
    except BackupError as exc:
        _err(str(exc))
        return _exit_code(exc.code)
    finally:
        if src is not None and src is not sys.stdin.buffer:
            src.close()

    if args.identity and args.identity != "-":
        print(f"Schlüsseldatei jetzt löschen: shred -u {s(args.identity, 300)} . Den Recovery-Schlüssel als "
              f"verbraucht betrachten: auf dem Mac einen neuen erzeugen und in backup-recipients.txt "
              f"ersetzen.", flush=True)
    can_ask = args.passphrase_fd is not None or _is_tty(sys.stdin)
    rc = 0
    if not args.no_verify and can_ask and res.projects:
        try:
            verified = _verify_chains(paths, res.projects, args.passphrase_fd)
            res = dataclasses.replace(res, verified=verified)
            if not all(verified.get(slug) for slug in res.projects):
                rc = 1
        except CtlError as exc:
            hint = "Passphrase falsch." if exc.code == "wrong_passphrase" else s(str(exc), 300)
            _err(f"Ketten nicht geprüft: {hint}")
            rc = 1
        except (CliError, DaemonUnavailable) as exc:
            _err(f"Ketten nicht geprüft: {s(str(exc), 300)}")
            rc = 1
    for line in restore_summary_lines(res):
        print(s(line, 600), flush=True)
    if res.config_added:
        print("Neue Einstellungen gelten nach einem Neustart des Daemons (ariadne daemon stop).", flush=True)
    return rc


def register(sub: Any) -> None:
    sp = sub.add_parser("backup", help="verschlüsselte Sicherung (age) auf stdout oder in eine Datei")
    sp.add_argument("--to-file", metavar="PFAD", help="in eine neue Datei schreiben (statt stdout)")
    sp.add_argument("--project", action="append", metavar="SLUG", help="nur diese Projekte (mehrfach)")
    sp.set_defaults(fn=cmd_backup)

    sp = sub.add_parser("restore", help="Sicherung zurückspielen (nur in eine Installation ohne Tresor)")
    sp.add_argument("--from-file", metavar="PFAD", help="aus Datei lesen (statt stdin)")
    sp.add_argument("--identity", metavar="DATEI",
                    help="age-Schlüssel, um eine verschlüsselte Datei in der VM zu entschlüsseln "
                         "(«-»: verdeckt eintippen, nie als Datei)")
    sp.add_argument("--no-verify", action="store_true",
                    help="Ketten nicht gleich prüfen (sonst fragt restore mit Terminal nach der Passphrase)")
    sp.add_argument("--passphrase-fd", type=int, metavar="N",
                    help="Passphrase für die Kettenprüfung von Deskriptor N (Skripte, Tests)")
    sp.set_defaults(fn=cmd_restore)
