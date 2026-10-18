"""T16 (Konzept Fernzugriff 7.1, Vertrag v0.1-Server 5) im Prozess: sichern, in ein leeres HOME
zurückspielen, Hashes und Kettenkopf gleich, Rechte 0700/0600, Canary nie im Chiffrat, und jede
Ablehnung lässt nichts liegen.

Die Kettenprüfung über den Daemon nach ``unlock`` steht in ``test_cli_backup.py``.
"""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest

from ariadne.backup import api
from ariadne.backup.manifest import encode_manifest
from ariadne.backup.reader import DecryptingReader
from ariadne.backup.registry import read_entries
from ariadne.project.service import ProjectService
from tests.backup.helpers import (
    CANARY,
    clone_op_for,
    decrypt,
    manifest_of,
    members,
    new_identity,
    source_install,
    target_paths,
    tree_hashes,
    write_recipients,
)


def _backup(paths, **kw) -> tuple[bytes, api.BackupResult]:
    out = io.BytesIO()
    res = api.backup_to_stream(out, paths, **kw)
    return out.getvalue(), res


def _all_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*")] if root.exists() else []


def _assert_nothing_written(paths2) -> None:
    for d in (paths2.operator_dir, paths2.projects_root, paths2.config_dir, paths2.data_dir):
        leftovers = [p for p in _all_files(d)]
        assert not leftovers, leftovers
    # keine temporären Ordner
    for parent in (paths2.data_dir, paths2.projects_root, paths2.config_dir):
        if parent.exists():
            assert not [p for p in parent.iterdir() if p.name.startswith(".ariadne-restore-")]


def test_roundtrip_same_hashes_heads_modes_and_canary(paths, operator, tmp_path):
    src = source_install(paths, operator, ("lame", "htb-box"))
    data, res = _backup(paths)
    assert CANARY not in data and b"pause_minutes" not in data and b"vault.json" not in data
    assert res.projects == ("htb-box", "lame")
    for slug, head in src["heads"].items():
        assert res.chain_heads[slug] == head[1] and res.head_seqs[slug] == head[0]
    assert res.recipients == 2 and res.files > 10 and res.bytes_written == len(data)

    inner = decrypt(data, src["identity"])
    names = [m.name for m in members(inner)]
    assert names[0] == "ariadne-backup.json"
    assert all(n.split("/")[0] in ("ariadne-backup.json", "operator", "config", "projects") for n in names)
    assert not any(n.endswith((".lock", "-shm")) or "/derived" in n for n in names)
    man = manifest_of(inner)
    assert man["format"] == "ariadne.backup/1" and man["operator"]["recipient"] == operator.recipient
    assert {p["slug"]: p["head"]["head_hash"] for p in man["projects"]} == {
        s: h[1] for s, h in src["heads"].items()}
    assert operator.operator_id not in json.dumps(man)  # die Operator-ID bleibt verschlüsselt

    env2, paths2 = target_paths(tmp_path / "neu")
    rr = api.restore_from_stream(io.BytesIO(inner), paths2)
    assert rr.projects == ("htb-box", "lame") and rr.operator_restored and rr.verified == {}
    assert rr.chain_heads == res.chain_heads and rr.manifest_sha256 == res.manifest_sha256
    assert set(rr.config_added) == {"backup-recipients.txt", "config.toml"} and rr.config_kept == ()

    assert tree_hashes(paths.operator_dir) == tree_hashes(paths2.operator_dir)
    assert tree_hashes(paths.config_dir) == tree_hashes(paths2.config_dir)
    for slug in src["heads"]:
        assert tree_hashes(paths.projects_root / slug) == tree_hashes(paths2.projects_root / slug)
        head = json.loads((paths2.projects_root / slug / ".vault" / "head.json").read_text())
        assert head["head_hash"] == src["heads"][slug][1]
    assert (paths2.projects_root / "lame" / "loot" / "flag.txt").read_bytes() == CANARY + b"\n"

    # Rechte: Ordner 0700, Dateien 0600 (0700 nur, was beim Sichern für den Besitzer ausführbar war)
    for root in (paths2.operator_dir, paths2.projects_root, paths2.config_dir):
        for p in [root, *root.rglob("*")]:
            mode = stat.S_IMODE(os.lstat(p).st_mode)
            if p.is_dir():
                assert mode == 0o700, p
            elif p.name == "exploit.sh":
                assert mode == 0o700, p
            else:
                assert mode == 0o600, p
    # leere Ordner des Arbeitsbereichs kommen mit
    assert (paths2.projects_root / "lame" / "imports").is_dir()

    # Der zurückgespielte Tresor schliesst die Projekte auf (gleiche Identität)
    op2 = clone_op_for(operator, paths2)
    p = ProjectService(paths2, op2).open("lame")
    try:
        assert p.head_ok and p.journal.head()[1].hex() == src["heads"]["lame"][1]
        assert p.journal.verify().ok
    finally:
        p.close()


def test_registry_entry_for_stdout_and_file_targets(paths, operator):
    source_install(paths, operator)
    _, res = _backup(paths)
    _, res2 = _backup(paths, target="file", target_path="/x/sicherung.age")
    entries = read_entries(paths)
    assert [e["id"] for e in entries] == [res.registry_id, res2.registry_id]
    assert entries[0]["target"] == "stdout" and "path" not in entries[0]
    assert entries[1] == {"id": res2.registry_id, "ts_utc": entries[1]["ts_utc"], "projects": ["lame"],
                          "manifest_sha256": res2.manifest_sha256, "target": "file",
                          "path": "/x/sicherung.age"}
    assert stat.S_IMODE(os.stat(paths.registry_file).st_mode) == 0o600


def test_project_selection_and_unknown_project(paths, operator):
    src = source_install(paths, operator, ("lame", "box"))
    data, res = _backup(paths, projects=["lame"])
    assert res.projects == ("lame",)
    names = {m.name for m in members(decrypt(data, src["identity"]))}
    assert not any(n.startswith("projects/box") for n in names)
    assert any(n.startswith("operator/") for n in names)  # Tresor immer dabei
    with pytest.raises(api.BackupError) as e:
        _backup(paths, projects=["fehlt"])
    assert e.value.code == "not_found"


def test_open_project_is_refused_and_nothing_written(paths, operator):
    source_install(paths, operator)
    p = ProjectService(paths, operator).open("lame")  # hält den flock wie der Daemon
    try:
        out = io.BytesIO()
        with pytest.raises(api.BackupError) as e:
            api.backup_to_stream(out, paths)
        assert e.value.code == "project_open" and "ariadne lock" in str(e.value)
        assert out.getvalue() == b""
        assert read_entries(paths) == []
    finally:
        p.close()
    _backup(paths)  # nach dem Schliessen geht es


def test_lock_is_held_during_backup(paths, operator, monkeypatch):
    """Während die Sicherung schreibt, lässt sich das Projekt nicht öffnen (flock gehalten)."""
    source_install(paths, operator)
    seen = []

    class Probe(io.BytesIO):
        def write(self, b):  # noqa: ANN001
            if not seen:
                fd = os.open(paths.projects_root / "lame" / ".vault" / ".lock", os.O_RDWR)
                try:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    seen.append(True)
                finally:
                    os.close(fd)
            return super().write(b)

    api.backup_to_stream(Probe(), paths)
    assert seen == [True]
    fd = os.open(paths.projects_root / "lame" / ".vault" / ".lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # danach wieder frei
    finally:
        os.close(fd)


def test_no_vault_and_no_recipients(paths, operator, tmp_path):
    env2, paths2 = target_paths(tmp_path / "leer")
    _, recip = new_identity()
    write_recipients(paths2, recip)
    with pytest.raises(api.BackupError) as e:
        _backup(paths2)
    assert e.value.code == "no_vault"
    # Tresor da, aber keine Empfänger: nie unverschlüsselt
    out = io.BytesIO()
    with pytest.raises(api.BackupError) as e:
        api.backup_to_stream(out, paths)
    assert e.value.code == "no_recipients" and out.getvalue() == b""


def test_wrong_recipient_cannot_decrypt_and_invalid_recipient_refused(paths, operator):
    src = source_install(paths, operator)
    data, _ = _backup(paths)
    other, _ = new_identity()
    with pytest.raises(Exception):  # noqa: B017 (pyrage.DecryptError)
        decrypt(data, other)
    assert decrypt(data, src["identity"])
    # ungültiger Empfänger in der Datei: Abbruch statt still nur an die übrigen
    write_recipients(paths, src["recipient"], "age1kaputt")
    out = io.BytesIO()
    with pytest.raises(api.BackupError) as e:
        api.backup_to_stream(out, paths)
    assert e.value.code == "bad_recipient" and "Zeile 3" in str(e.value) and out.getvalue() == b""


def test_tty_output_refused(paths, operator):
    source_install(paths, operator)
    master, slave = os.openpty()
    try:
        with os.fdopen(slave, "wb", closefd=False) as tty:
            with pytest.raises(api.BackupError) as e:
                api.backup_to_stream(tty, paths)
        assert e.value.code == "tty_refused"
    finally:
        os.close(master)
        os.close(slave)
    assert read_entries(paths) == []


def test_symlinks_skipped_and_odd_names_roundtrip(paths, operator, tmp_path):
    src = source_install(paths, operator)
    loot = paths.projects_root / "lame" / "loot"
    os.symlink("/etc/passwd", loot / "passwd-link")
    odd = os.fsdecode(b"\xff\xfe-latin1") + "\x1b[31m\nname"
    (loot / odd).write_bytes(b"odd")
    os.mkfifo(loot / "fifo")
    data, res = _backup(paths)
    assert res.skipped == 2
    env2, paths2 = target_paths(tmp_path / "neu")
    api.restore_from_stream(io.BytesIO(decrypt(data, src["identity"])), paths2)
    assert (paths2.projects_root / "lame" / "loot" / odd).read_bytes() == b"odd"
    assert not os.path.lexists(paths2.projects_root / "lame" / "loot" / "passwd-link")
    assert not os.path.lexists(paths2.projects_root / "lame" / "loot" / "fifo")


def test_output_file_inside_workspace_is_not_included(paths, operator):
    source_install(paths, operator)
    target = paths.projects_root / "lame" / "exports" / "sicherung.age"
    with open(target, "wb") as fh:
        res = api.backup_to_stream(fh, paths, target="file", target_path=str(target))
    assert res.bytes_written == target.stat().st_size


def test_file_changed_during_backup_aborts_without_valid_stream(paths, operator, monkeypatch):
    src = source_install(paths, operator)
    from ariadne.backup import collect

    real = collect.iter_file

    def changing(e):
        if e.arc.endswith("loot/flag.txt"):
            e.src.write_bytes(b"geaendert waehrend der Sicherung")
        yield from real(e)

    monkeypatch.setattr("ariadne.backup.writer.iter_file", changing)
    out = io.BytesIO()
    with pytest.raises(api.BackupError) as e:
        api.backup_to_stream(out, paths)
    assert e.value.code == "io"
    with pytest.raises(Exception):  # noqa: B017 (age-Strom ohne letzten Block)
        decrypt(out.getvalue(), src["identity"])
    assert read_entries(paths) == []


def test_broken_output_is_reported(paths, operator):
    source_install(paths, operator)

    class Broken:
        def __init__(self):
            self.n = 0

        def write(self, b):  # noqa: ANN001
            self.n += 1
            if self.n > 1:
                raise BrokenPipeError(32, "Broken pipe")
            return len(b)

        def flush(self):
            pass

    with pytest.raises(api.BackupError) as e:
        api.backup_to_stream(Broken(), paths)  # type: ignore[arg-type]
    assert e.value.code == "io"
    assert read_entries(paths) == []


def test_wal_after_simulated_crash_survives(paths, operator, tmp_path):
    """Projekt nach einem Absturz (SIGKILL, WAL nicht zurückgeschrieben): die WAL-Datei kommt mit,
    nach dem Zurückspielen steht der letzte bestätigte Eintrag in der Kette."""
    import signal
    import subprocess
    import sys
    import textwrap

    from tests.core.conftest import PASSPHRASE

    src = source_install(paths, operator)
    script = textwrap.dedent("""
        import os, signal, sys
        from ariadne.crypto.vault import OperatorVault
        from ariadne.paths import default_paths
        from ariadne.project.service import ProjectService
        paths = default_paths()
        op = OperatorVault(paths.operator_dir).unlock(sys.stdin.readline().rstrip("\\n"))
        p = ProjectService(paths, op).open("lame")
        for i in range(5):
            p.journal.append("system.checkpoint", {"reason": "manual", "head_seq": i, "head_hash": "11" * 32})
        seq, h = p.journal.head()
        print(seq, h.hex(), flush=True)
        os.kill(os.getpid(), signal.SIGKILL)
    """)
    proc = subprocess.run([sys.executable, "-c", script], input=PASSPHRASE + "\n", capture_output=True,
                          text=True, env=os.environ.copy(), timeout=60, check=False)
    assert proc.returncode == -signal.SIGKILL, proc.stderr
    seq, head_hex = proc.stdout.split()
    wal = paths.projects_root / "lame" / ".vault" / "journal.db-wal"
    assert wal.stat().st_size > 0

    data, res = _backup(paths)
    inner = decrypt(data, src["identity"])
    man = manifest_of(inner)
    assert "projects/lame/.vault/journal.db-wal" in {f["path"] for f in man["files"]}
    assert not any(f["path"].endswith("-shm") for f in man["files"])
    # head.json stammt vom letzten sauberen Schliessen: älter als die Kette im WAL
    assert res.head_seqs["lame"] < int(seq)

    env2, paths2 = target_paths(tmp_path / "neu")
    api.restore_from_stream(io.BytesIO(inner), paths2)
    p = ProjectService(paths2, clone_op_for(operator, paths2)).open("lame")
    try:
        got_seq, got_hash = p.journal.head()
        assert (got_seq, got_hash.hex()) == (int(seq), head_hex)
        assert p.journal.verify().ok
    finally:
        p.close()


# --------------------------------------------------------------------------- #
# Ablehnungen beim Zurückspielen: nie etwas halb geschrieben
# --------------------------------------------------------------------------- #


@pytest.fixture
def inner_stream(paths, operator) -> bytes:
    src = source_install(paths, operator)
    data, _ = _backup(paths)
    return decrypt(data, src["identity"])


def _rebuild(inner: bytes, *, manifest_edit=None, member_edit=None, extra: list[tuple[tarfile.TarInfo, bytes]]
             | None = None, drop: str | None = None) -> bytes:
    """Baut einen veränderten inneren Strom (Manifest, Mitglieder, Zusätze)."""
    src = tarfile.open(fileobj=io.BytesIO(inner), mode="r:", encoding="utf-8", errors="surrogateescape")
    out = io.BytesIO()
    dst = tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT, encoding="utf-8",
                       errors="surrogateescape")
    with src, dst:
        for m in src.getmembers():
            fh = src.extractfile(m)
            body = fh.read() if fh is not None else b""
            if m.name == "ariadne-backup.json" and manifest_edit is not None:
                doc = json.loads(body)
                manifest_edit(doc)
                body = encode_manifest(doc)
                m.size = len(body)
            elif member_edit is not None:
                m, body = member_edit(m, body)
            if drop is not None and m.name == drop:
                continue
            dst.addfile(m, io.BytesIO(body) if m.isreg() else None)
        for ti, body in extra or []:
            dst.addfile(ti, io.BytesIO(body) if ti.isreg() else None)
    return out.getvalue()


def _restore_fails(inner: bytes, tmp_path: Path, code: str) -> None:
    env2, paths2 = target_paths(tmp_path / "ziel")
    with pytest.raises(api.BackupError) as e:
        api.restore_from_stream(io.BytesIO(inner), paths2)
    assert e.value.code == code, (e.value.code, str(e.value))
    _assert_nothing_written(paths2)


def test_restore_rejects_newer_version_and_format(inner_stream, tmp_path):
    def newer(doc):
        doc["ariadne_version"] = "99.0.0"

    _restore_fails(_rebuild(inner_stream, manifest_edit=newer), tmp_path / "a", "version")

    def fmt(doc):
        doc["format"] = "ariadne.backup/2"

    _restore_fails(_rebuild(inner_stream, manifest_edit=fmt), tmp_path / "b", "version")

    def garbage(doc):
        doc["format"] = "etwas-anderes"

    _restore_fails(_rebuild(inner_stream, manifest_edit=garbage), tmp_path / "c", "bad_manifest")


def test_restore_rejects_wrong_hash_and_size(inner_stream, tmp_path):
    def flip(m, body):
        if m.name.endswith("loot/flag.txt"):
            body = body.replace(b"CANARY", b"KANARI")
        return m, body

    _restore_fails(_rebuild(inner_stream, member_edit=flip), tmp_path / "a", "hash_mismatch")

    def longer(m, body):
        if m.name.endswith("loot/flag.txt"):
            body = body + b"mehr"
            m.size = len(body)
        return m, body

    _restore_fails(_rebuild(inner_stream, member_edit=longer), tmp_path / "b", "hash_mismatch")


def test_restore_rejects_traversal_symlink_and_unlisted(inner_stream, tmp_path):
    def traversal(doc):
        doc["files"][-1]["path"] = "projects/lame/../../../etc/x"

    _restore_fails(_rebuild(inner_stream, manifest_edit=traversal), tmp_path / "a", "unsafe_path")

    def absolute(doc):
        doc["files"][-1]["path"] = "/etc/x"

    _restore_fails(_rebuild(inner_stream, manifest_edit=absolute), tmp_path / "b", "unsafe_path")

    link = tarfile.TarInfo("projects/lame/loot/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    _restore_fails(_rebuild(inner_stream, extra=[(link, b"")]), tmp_path / "c", "unsafe_path")

    extra = tarfile.TarInfo("projects/lame/loot/extra.txt")
    extra.size = 3
    _restore_fails(_rebuild(inner_stream, extra=[(extra, b"abc")]), tmp_path / "d", "bad_manifest")

    dotdot = tarfile.TarInfo("projects/lame/../../evil")
    dotdot.size = 3
    _restore_fails(_rebuild(inner_stream, extra=[(dotdot, b"abc")]), tmp_path / "e", "bad_manifest")

    def foreign_prefix(doc):
        doc["files"][-1]["path"] = "home/.ssh/authorized_keys"

    _restore_fails(_rebuild(inner_stream, manifest_edit=foreign_prefix), tmp_path / "f", "unsafe_path")


def test_restore_rejects_corrupt_truncated_and_missing(inner_stream, tmp_path):
    _restore_fails(inner_stream[: len(inner_stream) // 2], tmp_path / "a", "bad_manifest")
    _restore_fails(b"\x00" * 4096, tmp_path / "b", "bad_manifest")
    _restore_fails(os.urandom(8192), tmp_path / "c", "bad_manifest")
    _restore_fails(_rebuild(inner_stream, drop="operator/vault.json"), tmp_path / "d", "bad_manifest")
    # Daten nach dem Tar-Ende (jenseits des letzten Tar-Satzes, den tarfile puffert): abgelehnt
    _restore_fails(inner_stream + b"M" * 30000, tmp_path / "e", "bad_manifest")
    # noch verschlüsselt: klare Meldung statt Tar-Fehler
    env2, paths2 = target_paths(tmp_path / "f")
    with pytest.raises(api.BackupError) as e:
        api.restore_from_stream(io.BytesIO(b"age-encryption.org/v1\n-> X25519 abc\n"), paths2)
    assert e.value.code == "decrypt" and "--identity" in str(e.value)


def test_restore_rejects_operator_mismatch(inner_stream, tmp_path):
    def other_op(doc):
        doc["operator"]["recipient"] = new_identity()[1]

    _restore_fails(_rebuild(inner_stream, manifest_edit=other_op), tmp_path, "bad_manifest")


def test_restore_refused_into_existing_install(inner_stream, paths, tmp_path):
    # Tresor vorhanden (die Quelle selbst): Abbruch vor dem Lesen
    class NoRead(io.BytesIO):
        def read(self, *a):  # noqa: ANN002
            raise AssertionError("darf nicht gelesen werden")

    with pytest.raises(api.BackupError) as e:
        api.restore_from_stream(NoRead(inner_stream), paths)
    assert e.value.code == "vault_exists"

    # gleichnamiges Projekt vorhanden: nichts geschrieben, das Projekt bleibt unberührt
    env2, paths2 = target_paths(tmp_path / "ziel")
    (paths2.projects_root / "lame").mkdir(parents=True)
    (paths2.projects_root / "lame" / "eigene.txt").write_text("bleibt")
    with pytest.raises(api.BackupError) as e:
        api.restore_from_stream(io.BytesIO(inner_stream), paths2)
    assert e.value.code == "project_exists"
    assert not paths2.operator_dir.exists()
    assert [p.name for p in (paths2.projects_root / "lame").iterdir()] == ["eigene.txt"]

    # leerer Projektordner (z. B. von Hand angelegt) darf ersetzt werden
    (paths2.projects_root / "lame" / "eigene.txt").unlink()
    api.restore_from_stream(io.BytesIO(inner_stream), paths2)
    assert (paths2.projects_root / "lame" / ".vault" / "manifest.json").is_file()


def test_restore_keeps_existing_config(inner_stream, tmp_path):
    env2, paths2 = target_paths(tmp_path / "ziel")
    paths2.config_dir.mkdir(parents=True)
    (paths2.config_dir / "config.toml").write_text("# neu nach ariadne setup\n")
    rr = api.restore_from_stream(io.BytesIO(inner_stream), paths2)
    assert rr.config_kept == ("config.toml",) and rr.config_added == ("backup-recipients.txt",)
    assert (paths2.config_dir / "config.toml").read_text() == "# neu nach ariadne setup\n"


def test_restore_rollback_when_commit_fails(inner_stream, tmp_path, monkeypatch):
    """Scheitert das Verschieben des Tresors, verschwinden auch die schon verschobenen Projekte."""
    env2, paths2 = target_paths(tmp_path / "ziel")
    import ariadne.backup.reader as reader

    real = reader._move_dir

    def failing(tmp, target, commit, code, message):
        if target == paths2.operator_dir:
            raise api.BackupError("io", "simuliert")
        return real(tmp, target, commit, code, message)

    monkeypatch.setattr(reader, "_move_dir", failing)
    with pytest.raises(api.BackupError):
        api.restore_from_stream(io.BytesIO(inner_stream), paths2)
    _assert_nothing_written(paths2)


def test_restore_with_identity_reader_and_bad_ciphertext(paths, operator, tmp_path):
    src = source_install(paths, operator)
    data, _ = _backup(paths)
    # beschädigtes Chiffrat (ein Byte in der Mitte): nichts geschrieben
    bad = bytearray(data)
    bad[len(bad) // 2] ^= 0x01
    for i, blob in enumerate((bytes(bad), data[: len(data) - 100])):
        env2, paths2 = target_paths(tmp_path / f"b{i}")
        r = DecryptingReader(io.BytesIO(blob), [src["identity"]])
        try:
            with pytest.raises(api.BackupError) as e:
                api.restore_from_stream(r, paths2)  # type: ignore[arg-type]
        finally:
            r.close()
        assert e.value.code in ("decrypt", "bad_manifest"), e.value.code
        _assert_nothing_written(paths2)
    # falscher Schlüssel
    env3, paths3 = target_paths(tmp_path / "c")
    other, _ = new_identity()
    r = DecryptingReader(io.BytesIO(data), [other])
    try:
        with pytest.raises(api.BackupError) as e:
            api.restore_from_stream(r, paths3)  # type: ignore[arg-type]
    finally:
        r.close()
    assert e.value.code == "decrypt"
    _assert_nothing_written(paths3)
    # richtiger Schlüssel
    env4, paths4 = target_paths(tmp_path / "d")
    r = DecryptingReader(io.BytesIO(data), [src["identity"]])
    try:
        rr = api.restore_from_stream(r, paths4)  # type: ignore[arg-type]
    finally:
        r.close()
    assert rr.projects == ("lame",)
    assert hashlib.sha256((paths4.operator_dir / "vault.json").read_bytes()).hexdigest() == \
        hashlib.sha256((paths.operator_dir / "vault.json").read_bytes()).hexdigest()


def test_tty_input_refused(tmp_path):
    env2, paths2 = target_paths(tmp_path / "ziel")
    master, slave = os.openpty()
    try:
        with os.fdopen(slave, "rb", closefd=False) as tty:
            with pytest.raises(api.BackupError) as e:
                api.restore_from_stream(tty, paths2)
        assert e.value.code == "tty_refused"
    finally:
        os.close(master)
        os.close(slave)


def test_summary_lines_have_no_target_data(paths, operator, tmp_path):
    src = source_install(paths, operator)
    data, res = _backup(paths)
    text = "\n".join(api.backup_summary_lines(res))
    assert "Kettenkopf lame: seq" in text and "1 Projekt (lame)" in text
    env2, paths2 = target_paths(tmp_path / "ziel")
    rr = api.restore_from_stream(io.BytesIO(decrypt(data, src["identity"])), paths2)
    text = "\n".join(api.restore_summary_lines(rr, remote=True))
    assert "ssh -t kali-sl unlock" in text and "ariadne verify" in text
    assert "flag.txt" not in text and CANARY.decode() not in text
