"""Projekte: Slug, Lab-Leitplanke, Anlegen, Öffnen, Schliessen, Liste."""

from __future__ import annotations

import json
import os
import sqlite3
import stat

import pytest

from ariadne.crypto.db import WrongKeyError, new_key, open_db
from ariadne.project.guardrails import InvalidTarget, LabAllowlist, parse_target, split_targets
from ariadne.project.service import (
    GuardrailError,
    ProjectError,
    ProjectExists,
    ProjectLocked,
    ProjectNotFound,
    ProjectService,
    valid_slug,
)
from ariadne.project.settings import SettingsError, parse_settings


@pytest.mark.parametrize("slug,ok", [
    ("lame", True), ("htb-lame-2", True), ("a", True), ("x" * 40, True),
    ("x" * 41, False), ("Lame", False), ("-lame", False), ("la me", False), ("../x", False),
    ("", False), ("lame_1", False), ("läme", False),
])
def test_slug(slug, ok):
    assert valid_slug(slug) is ok


@pytest.mark.parametrize("raw,kind,value", [
    ("10.10.10.3", "ip", "10.10.10.3"),
    (" 10.129.4.20 ", "ip", "10.129.4.20"),
    ("10.10.10.0/24", "cidr", "10.10.10.0/24"),
    ("10.10.10.7/24", "cidr", "10.10.10.0/24"),
    ("Lame.HTB.", "name", "lame.htb"),
    ("*.lame.htb", "name", "*.lame.htb"),
    ("fe80::1", "ip", "fe80::1"),
    ("bücher.lab", "name", "xn--bcher-kva.lab"),
])
def test_parse_target(raw, kind, value):
    t = parse_target(raw)
    assert (t.kind, t.value) == (kind, value)


@pytest.mark.parametrize("raw", ["", "10.1", "167772165", "0x0a.1", "a b", "evil\x1b[31m.htb", "a..b",
                                 "10.0.0.0/33", "-x.htb", "x" * 300])
def test_parse_target_rejects(raw):
    with pytest.raises(InvalidTarget):
        parse_target(raw)


@pytest.mark.parametrize("raw,allowed", [
    ("10.10.10.3", True), ("10.129.200.1", True), ("172.20.1.1", True), ("192.168.56.101", True),
    ("100.64.0.9", True), ("10.0.0.0/8", True), ("192.168.0.0/15", False), ("8.8.8.8", False),
    ("lame.htb", True), ("*.corp.local", True), ("dc01.lab", True), ("box.thm", True), ("x.vl", True),
    ("htb", False), ("example.com", False), ("notahtb", False), ("2001:db8::1", False),
    ("127.0.0.1", False),
])
def test_lab_allowlist(raw, allowed):
    assert LabAllowlist.default().allows(parse_target(raw)) is allowed


def test_allowlist_from_config(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[lab]\nextra_networks = ["203.0.113.0/24"]\nextra_suffixes = ["corp.test"]\n')
    al = LabAllowlist.from_config(cfg)
    assert al.allows(parse_target("203.0.113.7")) and al.allows(parse_target("dc.corp.test"))
    assert not al.allows(parse_target("8.8.8.8"))
    allt, outside = split_targets(["10.0.0.1", "10.0.0.1", "8.8.8.8"], al)
    assert [t.value for t in allt] == ["10.0.0.1", "8.8.8.8"] and [t.value for t in outside] == ["8.8.8.8"]


def test_settings_parse():
    with pytest.raises(SettingsError):
        parse_settings('schema = "anders"\n')
    with pytest.raises(SettingsError):
        parse_settings("kein toml = = =")
    data = parse_settings('schema = "ariadne.project/1"\n[project]\nname = "x"\nprofile = "lab"\n')
    assert data["llm"]["model"] == "" and data["scope"]["include"] == []


# ------------------------------------------------------------------ Service


def test_create_open_close_list(paths, operator):
    svc = ProjectService(paths, operator)
    info = svc.create("lame", ["10.10.10.3", "lame.htb"], name="Geheimname Kunde X")
    ws = paths.projects_root / "lame"
    assert info.workspace == ws and info.vault == ws / ".vault" and info.profile == "lab"
    for d in ("scans", "loot", "imports", "screenshots", "exports", ".vault", ".vault/slots", ".vault/blobs"):
        assert stat.S_IMODE(os.stat(ws / d).st_mode) == 0o700, d
    manifest = json.loads((ws / ".vault" / "manifest.json").read_text())
    assert manifest["project_id"] == info.id and manifest["slug"] == "lame"
    assert manifest["slots"][0]["recipient"] == operator.recipient
    # Keine Kundendaten im Klartext: Name und Ziele stehen nirgends unverschlüsselt
    for f in (ws / ".vault").rglob("*"):
        if f.is_file():
            raw = f.read_bytes()
            assert b"Geheimname" not in raw and b"10.10.10.3" not in raw, f
            assert stat.S_IMODE(os.stat(f).st_mode) == 0o600, f
    for db in ("journal.db", "derived.db", "state.db"):
        with pytest.raises(sqlite3.DatabaseError):
            sqlite3.connect(ws / ".vault" / db).execute("SELECT * FROM sqlite_master").fetchall()

    p = svc.open("lame")
    assert p.info == info
    assert p.settings["project"] == {"name": "Geheimname Kunde X", "profile": "lab"}
    assert p.settings["scope"]["include"] == ["10.10.10.3", "lame.htb"]
    assert p.settings["llm"]["model"] == "" and p.settings_version == 1
    kinds = [r.kind for r in p.journal.iter_events()]
    assert kinds == ["system.project_created", "d.scope.update"]
    assert len(p.project_key) == 32
    d = p.connect_derived()
    d.execute("CREATE TABLE t (x)")
    d.commit()
    d.close()
    p.connect_state().close()
    with pytest.raises(WrongKeyError):
        open_db(ws / ".vault" / "derived.db", new_key())
    ref = p.blobs.put_bytes(b"loot")
    assert p.blobs.open_bytes(ref.blob_id) == b"loot"

    with pytest.raises(ProjectLocked):
        svc.open("lame")
    seq, head = p.close()
    assert seq == 3 and len(head) == 64
    assert p.closed
    with pytest.raises(ProjectError):
        p.connect_derived()

    # wieder öffnen: Checkpoint ist da, Kette ist intakt
    p2 = svc.open("lame")
    last = list(p2.journal.iter_events())[-1]
    assert last.kind == "system.checkpoint" and last.header["reason"] == "close"
    assert p2.journal.verify().ok
    p2.close()

    listing = ProjectService(paths).list()  # ohne Operator
    assert [(s.slug, s.profile, s.project_id) for s in listing] == [("lame", "lab", info.id)]


def test_create_errors_and_guardrail(paths, operator):
    svc = ProjectService(paths, operator)
    with pytest.raises(ProjectError, match="v0.3"):
        svc.create("kunde", ["10.0.0.1"], profile="customer")
    with pytest.raises(ProjectError):
        svc.create("Bad Slug", ["10.0.0.1"])
    with pytest.raises(ProjectError):
        svc.create("leer", [])
    with pytest.raises(GuardrailError) as ei:
        svc.create("public", ["10.0.0.1", "8.8.8.8", "example.com"])
    assert ei.value.outside == ["8.8.8.8", "example.com"]
    assert not (paths.projects_root / "public").exists()
    info = svc.create("public", ["8.8.8.8"], not_customer=True)
    p = svc.open("public")
    kinds = [r.kind for r in p.journal.iter_events()]
    assert kinds == ["system.project_created", "d.scope.update", "d.lab.not_customer"]
    p.close()
    with pytest.raises(ProjectExists):
        svc.create("public", ["10.0.0.1"])
    with pytest.raises(ProjectNotFound):
        svc.open("fehlt")
    with pytest.raises(ProjectError):
        ProjectService(paths).create("x", ["10.0.0.1"])  # gesperrt
    with pytest.raises(ProjectError):
        ProjectService(paths).open(info.slug)


def test_head_check_and_readonly_journal(paths, operator):
    svc = ProjectService(paths, operator)
    svc.create("kette", ["10.0.0.0/24"])
    p = svc.open("kette")
    assert p.head_ok
    ro = p.connect_journal()
    assert ro.execute("SELECT count(*) FROM event").fetchone()[0] == 2
    with pytest.raises(Exception):
        ro.execute("INSERT INTO meta(key, value) VALUES ('x', 'y')")
    ro.close()
    p.close()
    # Letztes Event mit dem Schlüssel manipulieren (Trigger vorher entfernen)
    slot = operator.unseal((paths.projects_root / "kette" / ".vault" / "slots" / "operator.age").read_bytes())
    raw = open_db(paths.projects_root / "kette" / ".vault" / "journal.db", bytes.fromhex(slot["db_key"]))
    raw.execute("DROP TRIGGER event_redact_only")
    raw.execute("UPDATE event SET origin = 'mallory' WHERE seq = (SELECT max(seq) FROM event)")
    raw.commit()
    raw.close()
    p2 = svc.open("kette")
    assert not p2.head_ok and not p2.journal.verify().ok
    p2.close()


def test_close_writes_chain_head_without_secrets(paths, operator):
    """Sicherung (E91, Vertrag v0.1-Server 3.5): Der Kettenkopf liegt nach dem Schliessen lesbar in
    ``.vault/head.json`` (0600), ohne dass jemand das Projekt entsperren muss."""
    svc = ProjectService(paths, operator)
    info = svc.create("kopf", ["10.10.10.3"])
    p = svc.open("kopf")
    seq, head = p.close()
    f = info.vault / "head.json"
    data = json.loads(f.read_text())
    assert data["head_seq"] == seq and data["head_hash"] == head and data["project_id"] == info.id
    assert data["format"] == "ariadne.chain-head/1"
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
