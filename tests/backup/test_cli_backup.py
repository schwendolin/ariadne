"""``ariadne backup`` und ``ariadne restore`` als Subprozess (T16 mit Kettenprüfung über den Daemon),
Verweigerung bei Terminal, ``--to-file``, Hinweis nach ``ariadne stop``.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import signal
import stat
import sys
import time
from pathlib import Path

import pexpect
import pytest

from ariadne.backup import api
from ariadne.backup.registry import read_entries
from ariadne.daemon.client import CtlClient
from ariadne.project.service import ProjectService
from tests.backup.helpers import (
    CANARY,
    cli,
    cli_env,
    decrypt,
    new_identity,
    source_install,
    target_paths,
    write_recipients,
)
from tests.core.conftest import PASSPHRASE


def _shutdown(paths) -> None:
    client = CtlClient(paths.ctl_sock, timeout=5)
    with contextlib.suppress(Exception):
        client.call("shutdown")
    lock = paths.runtime_dir / "daemon.lock"
    with contextlib.suppress(Exception):
        time.sleep(0.3)
        os.kill(int(lock.read_text().strip()), signal.SIGTERM)


def _key_file(tmp_path: Path, ident) -> Path:
    key = tmp_path / "recovery.key"
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"# created: test\n# public key: {ident.to_public()}\n{ident}\n")
    return key


def test_backup_refuses_terminal_stdout(xdg, paths, operator):
    source_install(paths, operator)
    master, slave = os.openpty()
    try:
        res = cli(xdg, "backup", stdout=slave)
        os.set_blocking(master, False)
        with contextlib.suppress(BlockingIOError, OSError):
            leaked = os.read(master, 65536)
            assert b"age-encryption" not in leaked
    finally:
        os.close(master)
        os.close(slave)
    assert res.returncode == 2
    assert "nie auf ein Terminal" in res.stderr.decode()
    assert read_entries(paths) == []


def test_restore_refuses_terminal_stdin(tmp_path):
    env, paths = target_paths(tmp_path / "ziel")
    master, slave = os.openpty()
    try:
        res = cli(env, "restore", "--no-verify", stdin=slave)
    finally:
        os.close(master)
        os.close(slave)
    assert res.returncode == 2 and "Pipe" in res.stderr.decode()
    assert not paths.operator_dir.exists()


def test_backup_to_file_then_restore_with_identity_and_verify(xdg, paths, operator, tmp_path):
    """T16: sichern, in leeres HOME zurückspielen, Kettenkopf gleich, verify über den Daemon nach unlock."""
    src = source_install(paths, operator, ("lame", "box"))
    target = tmp_path / "out" / "kali-sl.age"
    target.parent.mkdir()
    res = cli(xdg, "backup", "--to-file", str(target))
    err = res.stderr.decode()
    assert res.returncode == 0, err
    assert res.stdout == b""  # Meldungen nur auf stderr
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    for slug, (seq, head) in src["heads"].items():
        assert f"Kettenkopf {slug}: seq {seq} {head}" in err
    data = target.read_bytes()
    assert data.startswith(b"age-encryption.org/v1\n") and CANARY not in data
    entry = read_entries(paths)[-1]
    assert entry["target"] == "file" and entry["path"] == str(target)

    # nie überschreiben
    res = cli(xdg, "backup", "--to-file", str(target))
    assert res.returncode == 1 and "existiert schon" in res.stderr.decode()
    assert target.read_bytes() == data

    key = _key_file(tmp_path, src["identity"])
    env2, paths2 = target_paths(tmp_path / "neu")
    r, w = os.pipe()
    os.write(w, PASSPHRASE.encode() + b"\n")
    os.close(w)
    try:
        res = cli(env2, "restore", "--from-file", str(target), "--identity", str(key),
                  "--passphrase-fd", str(r), pass_fds=(r,), timeout=120)
    finally:
        os.close(r)
        _shutdown(paths2)
    out = res.stdout.decode()
    assert res.returncode == 0, (out, res.stderr.decode())
    assert "Kette lame: in Ordnung" in out and "Kette box: in Ordnung" in out
    for slug, (seq, head) in src["heads"].items():
        assert f"Kettenkopf {slug}: seq {seq} {head}" in out
    assert f"shred -u {key}" in out
    assert key.exists()  # die Schlüsseldatei fasst restore nie an (nur der Hinweis)
    assert PASSPHRASE not in out and PASSPHRASE not in res.stderr.decode()
    assert (paths2.projects_root / "lame" / "loot" / "flag.txt").read_bytes() == CANARY + b"\n"
    for d in (paths2.operator_dir, paths2.projects_root / "lame", paths2.projects_root / "lame" / ".vault"):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700

    # zweites Mal: Tresor existiert, Abbruch vor dem Lesen
    res = cli(env2, "restore", "--from-file", str(target), "--identity", str(key), "--no-verify")
    assert res.returncode == 2 and "schon einen Operator-Tresor" in res.stderr.decode()


def test_restore_inner_stream_from_stdin_without_verify(xdg, paths, operator, tmp_path):
    """Weg B: der Mac entschlüsselt, ``ssh kali-sl restore`` bekommt den Klartext über die Pipe."""
    src = source_install(paths, operator)
    out = io.BytesIO()
    api.backup_to_stream(out, paths)
    inner = decrypt(out.getvalue(), src["identity"])
    env2, paths2 = target_paths(tmp_path / "neu")
    res = cli(env2, "restore", input=inner)
    text = res.stdout.decode()
    assert res.returncode == 0, res.stderr.decode()
    assert "Ketten noch nicht geprüft" in text and "ariadne unlock" in text
    assert not paths2.ctl_sock.exists()  # ohne Kettenprüfung kein Daemon
    assert (paths2.operator_dir / "vault.json").is_file()

    # verschlüsselte Datei ohne --identity: klare Meldung, nichts geschrieben
    env3, paths3 = target_paths(tmp_path / "drei")
    res = cli(env3, "restore", input=out.getvalue())
    assert res.returncode == 1 and "--identity" in res.stderr.decode()
    assert not paths3.operator_dir.exists()


def test_restore_identity_typed_on_terminal(xdg, paths, operator, tmp_path):
    """``--identity -``: Schlüssel verdeckt eintippen, er berührt nie die Platte."""
    src = source_install(paths, operator)
    target = tmp_path / "s.age"
    with open(target, "wb") as fh:
        api.backup_to_stream(fh, paths, target="file", target_path=str(target))
    env2, paths2 = target_paths(tmp_path / "neu")
    child = pexpect.spawn(sys.executable, ["-m", "ariadne.cli.main", "restore", "--from-file", str(target),
                                           "--identity", "-", "--no-verify"], env=cli_env(env2), timeout=60)
    try:
        child.expect("Recovery-Schl")
        child.sendline(str(src["identity"]))
        child.expect("Zurückgespielt".encode())
        child.expect(pexpect.EOF)
    finally:
        child.close()
    assert child.exitstatus == 0
    assert str(src["identity"]).encode() not in (child.before or b"")
    assert (paths2.projects_root / "lame" / ".vault" / "journal.db").is_file()


def test_backup_stdout_pipe_and_project_selection(xdg, paths, operator):
    src = source_install(paths, operator, ("lame", "box"))
    res = cli(xdg, "backup", "--project", "box")
    assert res.returncode == 0, res.stderr.decode()
    inner = decrypt(res.stdout, src["identity"])
    assert b"projects/box/" in inner and b"projects/lame/" not in inner
    assert read_entries(paths)[-1]["target"] == "stdout"
    res = cli(xdg, "backup", "--project", "fehlt")
    assert res.returncode == 1 and res.stdout == b"" and "nicht gefunden" in res.stderr.decode()


def test_hint_after_stop(xdg, paths, operator):
    """``ariadne stop`` nennt die Sicherung: ohne Sicherung und ohne Empfänger deutlich."""
    r, w = os.pipe()
    os.write(w, PASSPHRASE.encode() + b"\n")
    os.close(w)
    try:
        res = cli(xdg, "start", "lame", "--target", "10.10.10.3", "--passphrase-fd", str(r), pass_fds=(r,))
        assert res.returncode == 0, res.stderr.decode()
        res = cli(xdg, "stop")
    finally:
        os.close(r)
        _shutdown(paths)
    out = res.stdout.decode()
    assert res.returncode == 0, res.stderr.decode()
    assert re.search(r"Projekt lame beendet und gesperrt", out)
    assert "Erinnerung: Noch keine Sicherung von lame (E91)." in out
    assert "ariadne backup --to-file" in out and "backup-recipients.txt" in out


def test_failed_backup_leaves_no_file(xdg, paths, operator, tmp_path):
    """Ohne Empfänger und bei offenem Projekt: Fehler, keine halbe Datei, kein Registry-Eintrag."""
    source_install(paths, operator)
    (paths.config_dir / "backup-recipients.txt").unlink()
    target = tmp_path / "x.age"
    res = cli(xdg, "backup", "--to-file", str(target))
    assert res.returncode == 1 and "Keine Empfänger" in res.stderr.decode()
    assert not target.exists() and read_entries(paths) == []
    write_recipients(paths, new_identity()[1])
    p = ProjectService(paths, operator).open("lame")
    try:
        res = cli(xdg, "backup", "--to-file", str(target))
    finally:
        p.close()
    assert res.returncode == 1 and "ariadne lock" in res.stderr.decode()
    assert not target.exists()


@pytest.mark.parametrize("args", [["backup", "--help"], ["restore", "--help"]])
def test_help_texts(xdg, args):
    res = cli(xdg, *args)
    assert res.returncode == 0 and "--" in res.stdout.decode()
