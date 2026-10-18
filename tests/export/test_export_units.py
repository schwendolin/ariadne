"""Bausteine des Exports: Markdown-Encoder, Phasenregeln, sicheres Schreiben, Sync-Ordner, Klartext."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ariadne.events import validate_header
from ariadne.export import service
from ariadne.export.collect import MASK, Masker, iso_ms
from ariadne.export.mdsafe import code_block, md_lines, md_text, slug
from ariadne.export.writer import ExportError, list_exports, sync_folder, write_export
from ariadne.ingest import proj_phases
from ariadne.secrets.redactor import Redactor
from tests.export.helpers import unsafe_markdown


@pytest.mark.parametrize(
    "raw",
    [
        "![x](http://evil/t.png)",
        "<img src=x onerror=alert(1)>",
        "[[Geheim]]",
        "![[Geheim]]",
        "`$= dv.x`",
        "%%k%%",
        "==h==",
        "# Titel",
        "> zitat",
        "| a | b |",
        "www.evil.example",
        "a\x1b[31mb",
        "‮abc​",
        "x\ny",
        "[a](javascript:alert(1))",
        "<https://evil>",
        "user@evil.example",
        "Key:: Wert",
        "$$x$$",
    ],
)
def test_md_text_is_harmless(raw):
    out = md_text(raw)
    assert "\n" not in out
    assert unsafe_markdown(f"- {out}\n") == []


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=200))
def test_md_text_property(raw):
    assert unsafe_markdown(f"- {md_text(raw)}\n{md_lines(raw)}\n") == []


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=200))
def test_code_block_cannot_be_closed_from_inside(raw):
    block = code_block(raw + "\n```\n~~~~\n`````")
    first = block.split("\n", 1)[0]
    fence = first[: len(first) - len("text")]
    assert first.endswith("text") and set(fence) == {"`"}
    body = block.split("\n")[1:-1]
    assert all(ln != fence and not ln.startswith(fence) for ln in body)
    assert unsafe_markdown(block + "\n") == []


def test_slug_and_iso_ms():
    assert slug("192.168.56.101") == "192-168-56-101"
    assert slug("../../etc/passwd") == "etc-passwd"
    assert slug("‮<>") == "x" and len(slug("a" * 99)) == 40
    assert iso_ms(1_700_000_000_123_456_789) == "2023-11-14T22:13:20.123Z"


def test_masker_own_and_target_secrets():
    red = Redactor([("sudo", "Sudo-Geheim-4711")])
    m = Masker(red, ["toor-pass"], klartext=False)
    assert "Sudo-Geheim-4711" not in m.target("x Sudo-Geheim-4711 toor-pass")
    assert MASK in m.target("pw toor-pass")
    assert m.line("abc secret xyz", [(4, 10)]) == f"abc {MASK} xyz"
    k = Masker(red, ["toor-pass"], klartext=True)
    assert "toor-pass" in k.target("pw toor-pass") and "Sudo-Geheim-4711" not in k.target("Sudo-Geheim-4711")


@pytest.mark.parametrize(
    ("cmd", "cys", "htb"),
    [
        (["nmap", "-sV", "10.0.0.1"], "scanning", "enumeration"),
        (["sudo", "-u", "root", "masscan", "-p1-65535"], "scanning", "enumeration"),
        (["proxychains", "nmap", "-sT"], "scanning", "enumeration"),
        (["nc", "-lvnp", "4444"], "exploitation", "foothold"),
        (["msfconsole", "-q"], "exploitation", "foothold"),
        (["python3", "exploit.py", "10.0.0.1"], "exploitation", "foothold"),
        (["./linpeas.sh"], "post", "privesc"),
        (["chisel", "server", "-p", "8000"], "post", "pivot"),
        (["ssh", "-D", "1080", "u@h"], "post", "pivot"),
        (["john", "hashes.txt"], "post", "loot"),
        (["whois", "example.org"], "recon", "enumeration"),
        (["vim", "notes.txt"], None, None),
    ],
)
def test_phase_rules(cmd, cys, htb):
    local = {"kind": "local", "host": "local"}
    assert proj_phases.suggest("cys", cmd, " ".join(cmd), local) == cys
    assert proj_phases.suggest("htb", cmd, " ".join(cmd), local) == htb


def test_phase_rules_remote_context():
    remote = {"kind": "revshell", "host": "ip:default/10.0.0.5"}
    assert proj_phases.suggest("cys", ["id"], "id", remote) == "post"
    assert proj_phases.suggest("htb", ["cat", "/root/root.txt"], "cat /root/root.txt", remote) == "loot"


def test_phase_decision_model():
    ok = validate_header("d.unit.phase", {"cmd_id": "abc@1", "template": "cys", "phase": "post"})
    assert ok["phase"] == "post"
    with pytest.raises(ValueError):
        validate_header("d.unit.phase", {"cmd_id": "abc@1", "template": "cys", "phase": "hack"})
    with pytest.raises(ValueError):
        validate_header("d.unit.phase", {"cmd_id": "abc@1", "template": "xyz", "phase": "post"})
    assert proj_phases.valid_phase("cys", "omit") and not proj_phases.valid_phase("cys", "foothold")


def test_klartext_policy():
    service.check_policy("lab", False, None)
    service.check_policy("lab", True, "KLARTEXT")
    with pytest.raises(service.ExportPolicy):
        service.check_policy("lab", True, "ja")
    with pytest.raises(service.ExportPolicy):
        service.check_policy("customer", True, "KLARTEXT")


def _ws(tmp_path: Path) -> Path:
    ws = tmp_path / "proj"
    ws.mkdir()
    return ws


def test_writer_layout_manifest_and_redaction(tmp_path):
    ws = _ws(tmp_path)
    red = Redactor([("sudo", "Sudo-Geheim-4711")])
    files = {
        "00 Übersicht.md": "a Sudo-Geheim-4711 b\n",
        "Hosts/abc-host.md": "h\n",
        "Belege/img/x.png": b"\x89PNG",
    }
    res = write_export(
        ws,
        files,
        template="cys",
        now_ns=1_700_000_000_000_000_000,
        redactor=red,
        manifest={"template": "cys", "created_at": "t", "chain": {"seq": 1, "hash": "ab"}},
    )
    root = ws / res["path"]
    assert res["export_id"] == "20231114T221320Z-cys"
    assert b"Sudo-Geheim-4711" not in (root / "00 Übersicht.md").read_bytes()
    man = json.loads((root / "_ariadne" / "manifest.json").read_text())
    assert {f["path"] for f in man["files"]} == set(files)
    assert oct((root / "Hosts" / "abc-host.md").stat().st_mode & 0o777) == "0o600"
    again = write_export(
        ws,
        files,
        template="cys",
        now_ns=1_700_000_000_000_000_000,
        redactor=red,
        manifest={"template": "cys"},
    )
    assert again["export_id"] == "20231114T221320Z-cys-2"
    ids = [e["export_id"] for e in list_exports(ws)]
    assert ids == ["20231114T221320Z-cys-2", "20231114T221320Z-cys"]


def test_writer_refuses_symlinks_and_bad_names(tmp_path):
    ws = _ws(tmp_path)
    target = tmp_path / "anderswo"
    target.mkdir()
    os.symlink(target, ws / "exports")
    with pytest.raises(ExportError):
        write_export(ws, {"a.md": "x"}, template="cys", now_ns=1, redactor=None, manifest={})
    assert list(target.iterdir()) == []
    ws2 = tmp_path / "p2"
    ws2.mkdir()
    for bad in ("../x.md", "/etc/x.md", "a/../../x.md", "Belege/‮x.md"):
        with pytest.raises(ExportError):
            write_export(ws2, {bad: "x"}, template="cys", now_ns=1, redactor=None, manifest={})


def test_sync_folder_detection(tmp_path):
    plain = tmp_path / "a" / "proj"
    plain.mkdir(parents=True)
    assert not sync_folder(plain)
    vault = tmp_path / "vault" / "proj"
    vault.mkdir(parents=True)
    (tmp_path / "vault" / ".obsidian").mkdir()
    assert sync_folder(vault)
    dbx = tmp_path / "Dropbox" / "proj"
    dbx.mkdir(parents=True)
    assert sync_folder(dbx)


def test_render_write_with_screenshot(tmp_path):
    ws = _ws(tmp_path)
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    sha = "ab" * 32
    data = {
        "meta": {
            "project_id": "p1",
            "slug": "lab",
            "name": "lab",
            "profile": "lab",
            "template": "htb",
            "klartext": False,
            "created_at": iso_ms(1_700_000_000_000_000_000),
            "chain_seq": 3,
            "chain_hash": "cd" * 32,
            "period": [None, None],
            "scope_include": ["10.0.0.0/24"],
            "scope_exclude": [],
        },
        "commands": [],
        "findings": [],
        "keysteps": [],
        "belege": {},
        "hosts": [],
        "timeline": [],
        "credentials": [{"kind": "-----BEGIN OPENSSH PRIVATE KEY-----", "value": MASK, "ref": "s1"}],
        "images": [
            {"unit_id": "i1", "sha256": sha, "ts": None, "data": png, "title": "root@ms2: ~ *fett*",
             "note": "root-Shell", "host": "10.10.10.3", "terminal_id": "t-abc", "stream_off": 4096},
            {"unit_id": "i2", "sha256": None, "ts": None, "data": None, "title": None},
        ],
        "masked": 0,
    }
    res = service._render_write(data, ws, "htb", 1_700_000_000_000_000_000, Redactor([]))
    root = ws / res["path"]
    assert (root / "Belege" / "img" / f"{sha[:16]}.png").read_bytes() == png
    shots = (root / "Belege" / "Screenshots.md").read_text("utf-8")
    assert f"img/{sha[:16]}.png" in shots and "nicht exportiert" in shots
    # R5: Zusammenhang des Bildes (Notiz, Fenster, Host, Terminal), Markdown-sicher
    assert "Notiz: root\\-Shell" in shots and "Host: 10.10.10.3" in shots
    assert "Stream-Offset 4096" in shots and "*fett*" not in shots
    assert unsafe_markdown(shots) == []
    wu = (root / "02 Writeup.md").read_text("utf-8")
    assert "Lessons Learned" in wu and "Privilege Escalation" in wu
    assert res["warnings"] == ["generic_secret"] and res["generic_kinds"] == ["private_key"]
