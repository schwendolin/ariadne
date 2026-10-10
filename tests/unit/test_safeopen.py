"""Sicheres Öffnen (Architektur 4.1): keine Symlinks, keine harten Links, keine Sperrliste."""

from __future__ import annotations

import hashlib
import os

import pytest

from ariadne.sources import safeopen
from ariadne.sources.safeopen import UnsafeFile


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "ws"
    (root / "scans").mkdir(parents=True)
    (root / "scans" / "a.xml").write_bytes(b"<?xml version='1.0'?><nmaprun/>")
    return root


def test_read_beneath_ok_and_sniff(ws, tmp_path):
    fd = safeopen.read_beneath(ws, "scans/a.xml", home=tmp_path / "home")
    assert fd.data == b"<?xml version='1.0'?><nmaprun/>" and fd.size == len(fd.data)
    assert fd.sha256 == hashlib.sha256(fd.data).hexdigest()
    assert safeopen.sniff(fd.data, "scans/a.xml") == ("application/xml", "nmaprun")
    assert safeopen.sniff(b"\x00\x01", "x.bin")[0] == "application/octet-stream"
    assert safeopen.sniff(b"hello", "x.txt") == ("text/plain", None)


@pytest.mark.parametrize("rel", ["", "/etc/passwd", "scans/../scans/a.xml", "scans//a.xml", "./scans/a.xml",
                                 "scans/a.xml\0"])
def test_bad_paths(ws, tmp_path, rel):
    with pytest.raises(UnsafeFile) as e:
        safeopen.read_beneath(ws, rel, home=tmp_path / "home")
    assert e.value.reason == "path"


def test_symlinks_are_never_followed(ws, tmp_path):
    target = tmp_path / "secret.txt"
    target.write_text("geheim")
    os.symlink(target, ws / "scans" / "link.xml")
    os.symlink(tmp_path, ws / "dirlink")
    with pytest.raises(UnsafeFile) as e:
        safeopen.read_beneath(ws, "scans/link.xml", home=tmp_path / "home")
    assert e.value.reason == "symlink"
    with pytest.raises(UnsafeFile) as e:
        safeopen.read_beneath(ws, "dirlink/secret.txt", home=tmp_path / "home")
    assert e.value.reason in ("symlink", "symlink_or_not_dir")
    with pytest.raises(UnsafeFile):
        safeopen.read_absolute(str(ws / "dirlink" / "secret.txt"), home=tmp_path / "home")


def test_hardlink_fifo_missing(ws, tmp_path):
    os.link(ws / "scans" / "a.xml", ws / "scans" / "b.xml")
    with pytest.raises(UnsafeFile) as e:
        safeopen.read_beneath(ws, "scans/b.xml", home=tmp_path / "home")
    assert e.value.reason == "hardlink"
    os.mkfifo(ws / "fifo")
    with pytest.raises(UnsafeFile) as e:  # O_NONBLOCK: blockiert nicht, fstat lehnt ab
        safeopen.read_beneath(ws, "fifo", home=tmp_path / "home")
    assert e.value.reason == "not_regular"
    with pytest.raises(UnsafeFile) as e:
        safeopen.read_beneath(ws, "scans/nope.xml", home=tmp_path / "home")
    assert e.value.reason == "missing"


def test_blocklist_and_vault(tmp_path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_rsa").write_text("KEY")
    (home / "ariadne" / "p" / ".vault").mkdir(parents=True)
    (home / "ariadne" / "p" / ".vault" / "x").write_text("x")
    cases = ((home / ".ssh" / "id_rsa", "blocked"), (home / "ariadne" / "p" / ".vault" / "x", "vault"))
    for path, reason in cases:
        with pytest.raises(UnsafeFile) as e:
            safeopen.read_absolute(str(path), home=home)
        assert e.value.reason == reason
    extra = tmp_path / "state"
    extra.mkdir()
    (extra / "log").write_text("x")
    with pytest.raises(UnsafeFile):
        safeopen.read_absolute(str(extra / "log"), home=home, extra_blocked=(extra,))
    assert safeopen.blocked_reason(str(home / ".sshx" / "f"), home) is None


def test_large_file_only_hash(ws, tmp_path):
    data = b"x" * 5000
    (ws / "big").write_bytes(data)
    fd = safeopen.read_beneath(ws, "big", home=tmp_path / "home", limit=4096)
    assert fd.data is None and fd.size == 5000 and fd.sha256 == hashlib.sha256(data).hexdigest()


def test_inside():
    assert safeopen.inside("/w/p/scans/a.xml", "/w/p") == "scans/a.xml"
    assert safeopen.inside("/w/p/../q/a.xml", "/w/p") is None
    assert safeopen.inside("/w/pq/a.xml", "/w/p") is None
    assert safeopen.inside("/w/p", "/w/p") is None
