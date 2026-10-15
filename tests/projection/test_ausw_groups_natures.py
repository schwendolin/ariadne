"""Evidenzgruppen (A3) und Arten von Prädikaten (A4, E45 präzisiert)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ariadne.ingest.natures import refines, split_heads
from ariadne.ontology import PREDICATES
from ariadne.parsers.api import Obs, Ref, Span
from tests.parsers.helpers import make_unit
from tests.projection.helpers import apply_items, claims, feed, inbox, new_projector, rows

GOLDEN = Path(__file__).parents[1] / "golden"
SP = Span(0, 0)
H = Ref.ip("192.168.56.101")
S21 = Ref.service(H, "tcp", 21)
S445 = Ref.service(H, "tcp", 445)
HK = "ip:default/192.168.56.101"
CMD = "0199a2b3-0000-7000-8000-000000000001@120"


def _ms2(p, *, cmd_id: str | None = CMD) -> None:
    txt = (GOLDEN / "nmap.text" / "ms2_sv_sc" / "input.txt").read_text()
    xml = (GOLDEN / "nmap.xml" / "ms2_sv_sc" / "input.xml").read_bytes()
    feed(p, make_unit(txt, cmd="nmap -sV -sC -oA scans/ms2 192.168.56.101", unit_id="cmd1", ts=1_000,
                      cmd_id=cmd_id), journal_seq=10)
    feed(p, make_unit(kind="file", data=xml, path="scans/ms2.xml", sniff="xml:nmaprun", unit_id="f:ev1",
                      ts=2_000, cmd_id=cmd_id), journal_seq=20)


# --------------------------------------------------------------------- Evidenzgruppen


def test_text_and_xml_of_one_run_are_one_witness():
    """MS2: Text und XML desselben nmap-Laufs zählen einmal (0.95 statt 0.99)."""
    conn, p = new_projector()
    _ms2(p)
    p.rebuild()
    ver = claims(conn)[(f"svc:{HK}|tcp/21", "service.version", "2.3.4")]
    assert (ver["confidence"], ver["group_key"], ver["sources"]) == (0.95, CMD, 2)
    groups = rows(conn, "SELECT DISTINCT group_key FROM claim_source WHERE obs_id IS NOT NULL")
    assert groups == [(CMD,)]
    # ohne Verknüpfung (alte Daten) bleiben es zwei Zeugen
    conn, p = new_projector()
    _ms2(p, cmd_id=None)
    p.rebuild()
    ver = claims(conn)[(f"svc:{HK}|tcp/21", "service.version", "2.3.4")]
    assert ver["confidence"] == 0.99
    assert {g for (g,) in rows(conn, "SELECT DISTINCT group_key FROM claim_source")} == {
        "unit:cmd1", "file:ev1"}


def test_max_inside_group_noisy_or_between_groups():
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="a1", cmd_id="t@1"), [Obs(S21, "service.name", "ftp", SP,
                                                                    confidence=0.5)])
    apply_items(p, make_unit("x", unit_id="a2", cmd_id="t@1"), [Obs(S21, "service.name", "ftp", SP,
                                                                    confidence=0.6)])
    p.rebuild()
    assert claims(conn)[(S21.key, "service.name", "ftp")]["confidence"] == 0.6
    apply_items(p, make_unit("x", unit_id="b1", cmd_id="t@9"), [Obs(S21, "service.name", "ftp", SP,
                                                                    confidence=0.5)])
    p.rebuild()
    assert claims(conn)[(S21.key, "service.name", "ftp")]["confidence"] == pytest.approx(1 - 0.4 * 0.5)


def test_text_beside_structured_file_is_side_evidence_without_conflicts():
    """«distccd v1» (Text) neben «distccd» (XML) desselben Laufs: kein Widerspruch."""
    conn, p = new_projector()
    s3632 = Ref.service(H, "tcp", 3632)
    apply_items(p, make_unit("x", unit_id="t1", cmd_id=CMD), [
        Obs(s3632, "service.product", "distccd v1 ((GNU) 4.2.4)", SP),
        Obs(s3632, "service.name", "distccd", SP),
    ], parser_id="nmap.text", trust="tool_text")
    apply_items(p, make_unit(kind="file", data=b"<x/>", unit_id="f:x", cmd_id=CMD), [
        Obs(s3632, "service.product", "distccd", SP), Obs(s3632, "service.version", "v1", SP),
        Obs(s3632, "service.name", "distccd", SP),
    ], parser_id="nmap.xml", trust="structured")
    p.rebuild()
    c = claims(conn)
    assert not inbox(conn, "conflict") and rows(conn, "SELECT COUNT(*) FROM conflict") == [(0,)]
    side = c[(s3632.key, "service.product", "distccd v1 ((GNU) 4.2.4)")]
    assert (side["lane"], side["lane_reason"]) == ("quiet", "side")
    assert c[(s3632.key, "service.product", "distccd")]["state"] == "auto"
    same = rows(conn, "SELECT trust, side FROM claim_source WHERE claim_key = ? ORDER BY trust",
                c[(s3632.key, "service.name", "distccd")]["claim_key"])
    assert same == [("structured", 0), ("tool_text", 1)]
    # ein zweiter, unabhängiger Lauf mit anderem Wert ist ein echter Widerspruch
    apply_items(p, make_unit("x", unit_id="t2", cmd_id="other@1"),
                [Obs(s3632, "service.product", "ProFTPD", SP)], parser_id="nmap.text", trust="tool_text")
    p.rebuild()
    assert len(inbox(conn, "conflict")) == 1


# --------------------------------------------------------------------- Arten


@pytest.mark.parametrize(("general", "specific"), [
    ("3.X - 4.X", "3.0.20-Debian"),
    ("2.6.X", "2.6.24"),
    ("distccd", "distccd v1"),
    ("Apache httpd", "Apache httpd 2.2.8"),
    ("8.3.0 - 8.3.7", "8.3.5"),
    ("Linux", "Linux 2.6.24"),
    ("2.3", "2.3.4"),
])
def test_refines(general, specific):
    assert refines(general, specific)
    assert not refines(specific, general)


@pytest.mark.parametrize(("a", "b"), [
    ("vsftpd", "ProFTPD"), ("2.3.4", "2.3.5"), ("3.X - 4.X", "5.0.1"), ("2.6.X", "2.7.1"),
    ("vsftpd", "vsftpd2"), ("2.6.X", "2.6"), ("3.X - 4.X", "3.X - 5.X"), ("x", "x"), ("", "a"),
    ("Apache", "Apache\x1b[31m"),
])
def test_does_not_refine(a, b):
    assert not refines(a, b) and not refines(b, a)


def test_nature_assignment_in_ontology():
    assert PREDICATES["service.version"].nature == "version"
    assert PREDICATES["service.state"].nature == "state"
    assert PREDICATES["host.address"].nature == "set"
    assert PREDICATES["service.name"].nature == "fact"


def test_version_precision_is_history_not_conflict():
    """Lame 445: «3.X - 4.X» und später das genauere «3.0.20-Debian»."""
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="u1", ts=1_000), [Obs(S445, "service.version", "3.X - 4.X", SP),
                                                            Obs(S445, "service.product", "Samba smbd", SP)])
    apply_items(p, make_unit("x", unit_id="u2", ts=2_000), [
        Obs(S445, "service.version", "3.0.20-Debian", SP),
        Obs(S445, "service.product", "Samba smbd 3.0.20-Debian", SP)])
    p.rebuild()
    c = claims(conn)
    assert not inbox(conn, "conflict")
    general = c[(S445.key, "service.version", "3.X - 4.X")]
    assert (general["history"], general["lane_reason"], general["state"]) == (1, "history", "candidate")
    assert c[(S445.key, "service.version", "3.0.20-Debian")]["state"] == "auto"
    (svc,) = rows(conn, "SELECT version, product FROM v_service WHERE port = 445")
    assert svc == ("3.0.20-Debian", "Samba smbd 3.0.20-Debian")


def test_versions_that_disagree_stay_conflicts():
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="u1"), [Obs(S21, "service.version", "2.3.4", SP),
                                                  Obs(S21, "service.product", "vsftpd", SP)])
    apply_items(p, make_unit("x", unit_id="u2"), [Obs(S21, "service.version", "2.3.5", SP),
                                                  Obs(S21, "service.product", "ProFTPD", SP)])
    p.rebuild()
    assert sorted(i["payload"]["predicate"] for i in inbox(conn, "conflict")) == [
        "service.product", "service.version"]


def test_general_value_refined_by_two_conflicting_values():
    conn, p = new_projector()
    for uid, v in (("u1", "Apache httpd"), ("u2", "Apache httpd 2.2.8"), ("u3", "Apache httpd 2.4.1")):
        apply_items(p, make_unit("x", unit_id=uid), [Obs(S21, "service.product", v, SP)])
    p.rebuild()
    (conf,) = inbox(conn, "conflict")
    values = sorted(v["value"] for v in conf["payload"]["values"])
    assert values == ["Apache httpd 2.2.8", "Apache httpd 2.4.1"]
    assert claims(conn)[(S21.key, "service.product", "Apache httpd")]["history"] == 1


def test_state_newest_value_wins_older_is_history():
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="u1", ts=1_000), [Obs(S21, "service.state", "open", SP),
                                                            Obs(H, "host.state", "up", SP)])
    apply_items(p, make_unit("x", unit_id="u2", ts=5_000), [Obs(S21, "service.state", "filtered", SP)])
    p.rebuild()
    c = claims(conn)
    assert not inbox(conn, "conflict")
    assert c[(S21.key, "service.state", "open")]["history"] == 1
    assert c[(S21.key, "service.state", "filtered")]["state"] == "auto"
    assert rows(conn, "SELECT state FROM v_service WHERE port = 21") == [("filtered",)]
    # gleich neue, verschiedene Zustände bleiben ein Widerspruch
    apply_items(p, make_unit("x", unit_id="u3", ts=5_000), [Obs(S21, "service.state", "closed", SP)])
    p.rebuild()
    assert len(inbox(conn, "conflict")) == 1


def test_set_nature_never_conflicts():
    conn, p = new_projector()
    apply_items(p, make_unit("x"), [Obs(H, "host.name", "a.lab", SP), Obs(H, "host.name", "b.lab", SP)])
    p.rebuild()
    assert not inbox(conn, "conflict")


def test_split_heads_directly():
    items = ["3.X - 4.X", "3.0.20-Debian", "3.0.20-Debian-extra"]
    heads, hist = split_heads(items, "version", value=lambda x: x, newest=lambda x: (0,))
    assert heads == ["3.0.20-Debian-extra"] and hist == ["3.X - 4.X", "3.0.20-Debian"]
    heads, hist = split_heads(["a", "b"], "fact", value=lambda x: x, newest=lambda x: (0,))
    assert heads == ["a", "b"] and hist == []
