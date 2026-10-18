"""Empfänger-Parser, Versionsvergleich, Pfadregeln und Manifest-Prüfung."""

from __future__ import annotations

import os

import pytest

from ariadne.backup.config import load_recipients, parse_recipient_lines, valid_recipient
from ariadne.backup.manifest import (
    FORMAT,
    check_path,
    decode_manifest,
    encode_manifest,
    parse_version,
    version_newer,
)
from ariadne.backup.model import BackupError
from tests.backup.helpers import new_identity, write_recipients

# --------------------------------------------------------------------------- #
# Empfänger
# --------------------------------------------------------------------------- #


def test_valid_recipient_only_x25519():
    _, r = new_identity()
    assert valid_recipient(r)
    assert not valid_recipient("age1kaputt")
    assert not valid_recipient(r[:-1] + ("q" if r[-1] != "q" else "p"))  # Prüfsumme falsch
    assert not valid_recipient("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0wmN/Cr3JXqmLW7u+g9pTh+wyqDHpSQEIQ")
    assert not valid_recipient("age1yubikey1qwerty")
    assert not valid_recipient("AGE-SECRET-KEY-1ABC")


def test_parse_lines_comments_and_line_numbers():
    _, a = new_identity()
    _, b = new_identity()
    assert parse_recipient_lines(f"# Mac\n\n  {a}  \n#{b}\n{b}\n") == [a, b]
    with pytest.raises(BackupError) as e:
        parse_recipient_lines(f"{a}\n\nnicht-gueltig\n")
    assert e.value.code == "bad_recipient" and "Zeile 3" in str(e.value)
    assert "nicht-gueltig" not in str(e.value)


def test_load_from_both_sources_dedupe(paths):
    _, a = new_identity()
    _, b = new_identity()
    write_recipients(paths, a, b)
    (paths.config_dir / "config.toml").write_text(f'[backup]\nrecipients = ["{b}"]\n')
    os.chmod(paths.config_dir / "config.toml", 0o600)
    rec = load_recipients(paths)
    assert rec.recipients == (b, a)
    assert rec.sources == ("config.toml", "backup-recipients.txt")


def test_load_errors(paths):
    with pytest.raises(BackupError) as e:
        load_recipients(paths)
    assert e.value.code == "no_recipients" and "backup-recipients.txt" in str(e.value)
    _, a = new_identity()
    f = write_recipients(paths, a, mode=0o622)  # für andere beschreibbar
    with pytest.raises(BackupError) as e:
        load_recipients(paths)
    assert e.value.code == "bad_recipient" and "chmod 600" in str(e.value)
    os.chmod(f, 0o600)
    assert load_recipients(paths).recipients == (a,)
    # Symlink statt Datei
    f.unlink()
    target = paths.config_dir / "echt.txt"
    target.write_text(a + "\n")
    os.symlink(target, f)
    with pytest.raises(BackupError) as e:
        load_recipients(paths)
    assert e.value.code == "bad_recipient"
    f.unlink()
    # ungültiger Eintrag in config.toml
    (paths.config_dir / "config.toml").write_text('[backup]\nrecipients = ["age1x", 3]\n')
    os.chmod(paths.config_dir / "config.toml", 0o600)
    with pytest.raises(BackupError) as e:
        load_recipients(paths)
    assert e.value.code == "bad_recipient" and "Eintrag 1" in str(e.value)
    (paths.config_dir / "config.toml").write_text('[backup]\nrecipients = "age1x"\n')
    with pytest.raises(BackupError) as e:
        load_recipients(paths)
    assert e.value.code == "bad_recipient"
    # kaputte config.toml: nur Warnung, Datei-Empfänger zählen
    (paths.config_dir / "config.toml").write_text("[backup\n")
    write_recipients(paths, a)
    rec = load_recipients(paths)
    assert rec.recipients == (a,) and rec.warnings


# --------------------------------------------------------------------------- #
# Versionen
# --------------------------------------------------------------------------- #


def test_version_order_pep440():
    order = ["0.1.0.dev0", "0.1.0.dev3", "0.1.0a1", "0.1.0b2", "0.1.0rc1", "0.1.0", "0.1.0.post1", "0.1.1",
             "0.2", "1.0.0"]
    keys = [parse_version(v) for v in order]
    assert keys == sorted(keys)
    assert parse_version("0.1") == parse_version("0.1.0")
    assert not version_newer("0.1.0.dev0", "0.1.0.dev0")
    assert version_newer("0.2.0", "0.1.0.dev0")
    assert not version_newer("0.0.9", "0.1.0.dev0")
    assert version_newer("kaputt", "0.1.0")  # unbekannt gilt als neuer (fail-closed)
    with pytest.raises(ValueError):
        parse_version("1.0; rm -rf /")


# --------------------------------------------------------------------------- #
# Pfade
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", [
    "operator/vault.json", "config/config.toml", "projects/lame/.vault/journal.db",
    "projects/lame/loot/\udcff name", "config/sub/dir/x",
])
def test_check_path_accepts(path):
    assert check_path(path, slugs={"lame"}) == path


@pytest.mark.parametrize("path", [
    "", "/etc/passwd", "../x", "operator/../../x", "operator/./x", "operator//x", "operator",
    "projects/lame", "projects/LAME/x", "projects/andere/x", "home/x", "config/x\x00y",
    "operator/" + "a" * 256, "operator/" + "/".join(["a"] * 3000), 7, None,
])
def test_check_path_rejects(path):
    with pytest.raises(BackupError) as e:
        check_path(path, slugs={"lame"})
    assert e.value.code == "unsafe_path"
    if isinstance(path, str) and path:
        assert path not in str(e.value)


def test_check_path_dirs():
    assert check_path("projects/lame", slugs={"lame"}, is_dir=True) == "projects/lame"
    assert check_path("operator", is_dir=True) == "operator"


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #


def _doc(**kw):
    doc = {
        "format": FORMAT, "backup_id": "01900000-0000-7000-8000-000000000000",
        "created_utc": "2026-10-17T10:00:00Z", "ariadne_version": "0.1.0.dev0",
        "operator": {"recipient": new_identity()[1]},
        "projects": [{"slug": "lame", "project_id": "0190aaaa-bbbb-7ccc-8ddd-eeeeffff0000", "profile": "lab",
                      "head": {"head_seq": 3, "head_hash": "ab" * 32, "closed_utc": None}}],
        "dirs": [{"path": "projects/lame", "mode": 0o700}],
        "files": [{"path": "operator/vault.json", "size": 1, "sha256": "00" * 32, "mode": 0o600, "mtime": 0},
                  {"path": "projects/lame/.vault/manifest.json", "size": 1, "sha256": "00" * 32,
                   "mode": 0o600, "mtime": 0}],
        "skipped": 0,
    }
    doc.update(kw)
    return doc


def test_decode_manifest_ok_and_errors():
    assert decode_manifest(encode_manifest(_doc()), "0.1.0.dev0")["projects"][0]["slug"] == "lame"
    cases = {
        "bad_manifest": [
            b"kein json", b"[]", encode_manifest(_doc(format="x")),
            encode_manifest(_doc(projects=[{"slug": "Lame", "project_id": "x" * 10}])),
            encode_manifest(_doc(files=[{"path": "operator/vault.json", "size": -1, "sha256": "00" * 32}])),
            encode_manifest(_doc(files=[{"path": "operator/vault.json", "size": 1, "sha256": "zz"}])),
            encode_manifest(_doc(files=[])),  # Tresor fehlt
            encode_manifest(_doc(created_utc="gestern")),
        ],
        "version": [encode_manifest(_doc(ariadne_version="9.9.9")),
                    encode_manifest(_doc(format="ariadne.backup/2"))],
        "unsafe_path": [encode_manifest(_doc(dirs=[{"path": "../x", "mode": 0o700}]))],
    }
    for code, blobs in cases.items():
        for blob in blobs:
            with pytest.raises(BackupError) as e:
                decode_manifest(blob, "0.1.0.dev0")
            assert e.value.code == code, (code, blob[:60])
    dup = _doc()
    dup["files"].append(dict(dup["files"][0]))
    with pytest.raises(BackupError):
        decode_manifest(encode_manifest(dup), "0.1.0.dev0")
