"""Sicherung neben laufenden Werkzeugen (Befunde F1, RT-2, RT-7 der Prüfung v0.1-Server):
Dateien von root im Arbeitsbereich (``sudo nmap -oA``), fremde und nicht lesbare Dateien und Ordner,
Dateien, die während der Sicherung wachsen, und ``unlock`` während einer laufenden Sicherung.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from ariadne.backup import api, collect
from ariadne.project.service import BACKUP_MARKER, ProjectLocked, ProjectService
from tests.backup.helpers import clone_op_for, decrypt, manifest_of, source_install, target_paths
from tests.core.conftest import PASSPHRASE
from tests.core.fakeshim import ctl_ok
from tests.core.test_daemon import run

ME = 1000  # in diesen Tests «der Benutzer»; root (0) ist der Besitzer von sudo-Dateien


def _backup(paths, **kw) -> tuple[bytes, api.BackupResult]:
    out = io.BytesIO()
    res = api.backup_to_stream(out, paths, **kw)
    return out.getvalue(), res


def _chown_tree(root: Path, uid: int) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        os.chown(dirpath, uid, uid, follow_symlinks=False)
        for n in dirnames + filenames:
            os.chown(os.path.join(dirpath, n), uid, uid, follow_symlinks=False)


@pytest.mark.skipif(os.getuid() != 0, reason="braucht root für chown (Dateien von root und Fremden)")
def test_f1_root_files_kept_foreign_and_unreadable_skipped(paths, operator, monkeypatch, tmp_path):
    """F1: Eine Datei von root (``sudo nmap -oA``, 0644) kommt mit; eine Datei eines anderen
    Benutzers, eine nicht lesbare Datei und ein nicht lesbarer Ordner von root (0700) werden
    übersprungen, gezählt und gemeldet, statt die ganze Sicherung abzubrechen."""
    src = source_install(paths, operator)
    ws = paths.projects_root / "lame"
    _chown_tree(paths.projects_root.parent, ME)  # das ganze HOME gehört «dem Benutzer»
    sudo = ws / "scans" / "syn.xml"
    sudo.write_bytes(b"<nmaprun>sudo nmap -sS -oA scans/syn</nmaprun>\n")
    os.chmod(sudo, 0o644)  # gehört root
    other = ws / "loot" / "fremd.txt"
    other.write_bytes(b"von einem anderen Benutzer\n")
    os.chown(other, ME + 1, ME + 1)
    secret_dir = ws / "scans" / "root-only"
    secret_dir.mkdir()
    os.chmod(secret_dir, 0o700)  # gehört root
    (secret_dir / "x.txt").write_bytes(b"x\n")
    noread = ws / "loot" / "noread.txt"
    noread.write_bytes(b"0000\n")
    os.chown(noread, 0, 0)
    os.chmod(noread, 0o600)
    # Ohne root wären der Ordner und die Datei von root mit 0700/0600 nicht lesbar: nachstellen
    real_scandir, real_open = os.scandir, os.open

    def scandir(path=".", *a):
        if Path(path) == secret_dir:
            raise PermissionError(13, "Permission denied")
        return real_scandir(path, *a)

    def fake_open(path, flags, *a, **kw):
        if Path(path) == noread:
            raise PermissionError(13, "Permission denied")
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "getuid", lambda: ME)
    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(os, "open", fake_open)
    data, res = _backup(paths, register=False)  # die Registry läge in einem Ordner von root
    monkeypatch.undo()
    assert res.unreadable == 3, res
    text = "\n".join(api.backup_summary_lines(res))
    assert "WARNUNG: 3 Dateien oder Ordner im Arbeitsbereich nicht gesichert" in text
    assert "fremd" not in text and "noread" not in text  # nie Namen
    inner = decrypt(data, src["identity"])
    m = manifest_of(inner)
    names = {f["path"] for f in m["files"]}
    assert "projects/lame/scans/syn.xml" in names
    assert not any(n.endswith(("fremd.txt", "noread.txt", "root-only/x.txt")) for n in names)
    assert m["unreadable"] == 3
    # Zurückspielen geht, die Datei von root ist da und gehört jetzt dem Benutzer (0600)
    env2, paths2 = target_paths(tmp_path / "neu")
    api.restore_from_stream(io.BytesIO(inner), paths2)
    got = paths2.projects_root / "lame" / "scans" / "syn.xml"
    assert got.read_bytes() == sudo.read_bytes() and (got.stat().st_mode & 0o777) == 0o600


@pytest.mark.skipif(os.getuid() != 0, reason="braucht root für chown")
def test_f1_strict_outside_the_workspace(paths, operator, monkeypatch):
    """Im Operator-Tresor, in der Konfiguration und in ``.vault/`` bleibt es streng: Abbruch."""
    source_install(paths, operator)
    _chown_tree(paths.projects_root.parent, ME)
    os.chown(paths.projects_root / "lame" / ".vault" / "manifest.json", 0, 0)
    monkeypatch.setattr(os, "getuid", lambda: ME)
    with pytest.raises(api.BackupError) as e:
        _backup(paths, register=False)
    assert e.value.code == "io"


def test_rt2_growing_workspace_file_is_backed_up_to_its_first_length(paths, operator, monkeypatch, tmp_path):
    """RT-2: Ein Werkzeug hängt während der Sicherung an eine Datei im Arbeitsbereich an
    (``tee -a loot/listener.log``). Die Sicherung gelingt, mit genau der Länge aus dem Manifest;
    das Angehängte fehlt, die Zusammenfassung meldet es."""
    src = source_install(paths, operator)
    log = paths.projects_root / "lame" / "loot" / "listener.log"
    log.write_bytes(b"connect to [10.10.14.5] from 10.10.10.3\n" * 1000)
    first = log.read_bytes()
    real = collect.iter_file

    def growing(e):
        if e.arc.endswith("loot/listener.log"):
            with open(e.src, "ab") as fh:  # ein Werkzeug schreibt weiter
                fh.write(b"neue Zeile vom Listener\n")
        yield from real(e)

    monkeypatch.setattr("ariadne.backup.writer.iter_file", growing)
    data, res = _backup(paths)
    assert res.grown == 1
    assert "1 Dateien im Arbeitsbereich wuchsen" in "\n".join(api.backup_summary_lines(res))
    inner = decrypt(data, src["identity"])
    entry = next(f for f in manifest_of(inner)["files"] if f["path"].endswith("loot/listener.log"))
    assert entry["size"] == len(first)
    _env2, paths2 = target_paths(tmp_path / "neu")
    api.restore_from_stream(io.BytesIO(inner), paths2)
    assert (paths2.projects_root / "lame" / "loot" / "listener.log").read_bytes() == first


def test_rt2_threaded_writer_does_not_break_a_slow_backup(paths, operator, tmp_path):
    """Wie im Alltag: ein Schreiber in eigenem Thread, gedrosselte Ausgabe (Netz zum Mac)."""
    import threading
    import time

    src = source_install(paths, operator)
    ws = paths.projects_root / "lame"
    (ws / "scans" / "a-capture.pcap").write_bytes(os.urandom(4 << 20))
    log = ws / "loot" / "listener.log"
    log.write_bytes(b"start\n")
    stop = threading.Event()

    def writer() -> None:
        while not stop.is_set():
            with open(log, "ab") as fh:
                fh.write(b"zeile\n")
            time.sleep(0.005)

    class Slow(io.BytesIO):
        def write(self, b):  # noqa: ANN001
            time.sleep(0.001)
            return super().write(b)

    t = threading.Thread(target=writer)
    t.start()
    try:
        out = Slow()
        res = api.backup_to_stream(out, paths)
    finally:
        stop.set()
        t.join()
    inner = decrypt(out.getvalue(), src["identity"])
    entry = next(f for f in manifest_of(inner)["files"] if f["path"].endswith("loot/listener.log"))
    _env2, paths2 = target_paths(tmp_path / "neu")
    api.restore_from_stream(io.BytesIO(inner), paths2)
    restored = (paths2.projects_root / "lame" / "loot" / "listener.log").read_bytes()
    assert len(restored) == entry["size"] and log.read_bytes().startswith(restored)
    assert res.files > 0


def test_rt2_replaced_or_shortened_workspace_file_still_aborts_and_names_the_project(paths, operator,
                                                                                      monkeypatch):
    source_install(paths, operator)
    real = collect.iter_file

    def shrinking(e):
        if e.arc.endswith("scans/nmap.xml"):
            with open(e.src, "r+b") as fh:
                fh.truncate(10)
        yield from real(e)

    monkeypatch.setattr("ariadne.backup.writer.iter_file", shrinking)
    with pytest.raises(api.BackupError) as e:
        _backup(paths)
    assert e.value.code == "io" and "Arbeitsbereich von lame" in str(e.value)
    assert "nmap" not in str(e.value)  # nie Dateinamen


def test_rt7_unlock_during_backup_names_the_backup_and_start_works_afterwards(paths, operator):
    """RT-7: Hält eine Sicherung den flock, meldet ``unlock`` (E101) «Gerade läuft eine Sicherung»
    statt «bereits geöffnet»; nach dem Ende öffnet ``start`` das Projekt."""
    source_install(paths, operator, slugs=())

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        await ctl_ok(paths.ctl_sock, "lock")
        sel = collect.select(paths)  # wie backup_to_stream: Sperre und Markierung
        try:
            marker = paths.projects_root / "lame" / ".vault" / BACKUP_MARKER
            assert marker.read_text().split()[0] == str(os.getpid())
            res = await ctl_ok(paths.ctl_sock, "unlock", passphrase=PASSPHRASE)
            err = res["reopen_error"]
            assert err["code"] == "project_locked" and "Gerade läuft eine Sicherung" in err["message"]
            assert "bereits geöffnet" not in err["message"] and d.project is None
            assert not any(e.arc.endswith(BACKUP_MARKER) for e in sel.entries)  # nie in der Sicherung
        finally:
            sel.release()
        assert not marker.exists()
        res = await ctl_ok(paths.ctl_sock, "start")
        assert res["slug"] == "lame" and d.project is not None

    run(paths, operator, scenario)


def test_rt7_lock_held_without_marker_names_another_process(paths, operator):
    import fcntl

    source_install(paths, operator)
    vault = paths.projects_root / "lame" / ".vault"
    fd = os.open(vault / ".lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (vault / BACKUP_MARKER).write_text("999999999\n")  # liegengeblieben, Prozess weg
        with pytest.raises(ProjectLocked) as e:
            ProjectService(paths, clone_op_for(operator, paths)).open("lame")
        assert "ein zweiter Daemon" in str(e.value) and "Sicherung." not in str(e.value)
    finally:
        os.close(fd)
    assert json.loads((vault / "manifest.json").read_text())["slug"] == "lame"


def test_verify_checks_the_saved_head_that_backup_and_restore_show(paths, operator):
    """Befund F3 (Anleitung): Nach ``project open`` ist der aktuelle Kettenkopf immer neuer als der
    gesicherte. ``verify`` prüft darum den Kopf aus ``head.json`` (letztes Schliessen bzw. die
    Sicherung) gegen die Kette und zeigt ihn; ein falscher Wert ergibt einen Fehler."""
    heads = source_install(paths, operator)["heads"]
    seq, h = heads["lame"]

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame")
        res = await ctl_ok(paths.ctl_sock, "verify")
        assert res["ok"] is True and res["head_seq"] > seq  # nach dem Öffnen kamen Events dazu
        assert res["saved_head"]["seq"] == seq and res["saved_head"]["hash"] == h and res["saved_head"]["ok"]
        head_file = paths.projects_root / "lame" / ".vault" / "head.json"
        data = json.loads(head_file.read_text())
        data["head_hash"] = "ab" * 32
        head_file.write_text(json.dumps(data))
        bad = await ctl_ok(paths.ctl_sock, "verify")
        assert bad["ok"] is False and bad["saved_head"]["ok"] is False
        assert any("head.json" in p for p in bad["problems"])

    run(paths, operator, scenario)
