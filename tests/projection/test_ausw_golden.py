"""Goldene Ziele (A9) und Sammelbestätigung (A6, E88) mit den nachgestellten Lab-Ausgaben.

Zahlen vorher (Profil customer = altes Verhalten) und nachher (Profil lab, Drei-Spuren-Regel):
MS2 86 -> 0 Inbox-Einträge und kein Scheinhost Kali, Lame 23 -> 0.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from ariadne.ingest import queries
from ariadne.parsers.api import Obs, Ref, Span
from tests.parsers.helpers import make_unit
from tests.projection.helpers import FakeScope, apply_items, claims, dec, feed, inbox, new_projector, rows

TESTS = Path(__file__).parents[1]
HK = "ip:default/192.168.56.101"
KALI = "192.168.56.102"
CMD = "0199a2b3-0000-7000-8000-000000000001@120"


def _ms2(profile: str, own=()):
    conn, p = new_projector(FakeScope(nets=["192.168.56.0/24"]), profile=profile, own=own)
    txt = (TESTS / "golden" / "nmap.text" / "ms2_sv_sc" / "input.txt").read_text()
    xml = (TESTS / "golden" / "nmap.xml" / "ms2_sv_sc" / "input.xml").read_bytes()
    feed(p, make_unit(txt, cmd="nmap -sV -sC -oA scans/ms2 192.168.56.101", unit_id="cmd1", ts=1_000,
                      cmd_id=CMD), journal_seq=10)
    feed(p, make_unit(kind="file", data=xml, path="scans/ms2.xml", sniff="xml:nmaprun", unit_id="f:ev1",
                      ts=2_000, cmd_id=CMD), journal_seq=20)
    p.rebuild()
    return conn, p


def _lame(profile: str, own=()):
    conn, p = new_projector(FakeScope(nets=["10.10.10.3/32"]), profile=profile, own=own)
    txt = (TESTS / "fixtures" / "lame" / "nmap_sv_sc.txt").read_text()
    feed(p, make_unit(txt, cmd="nmap -sV -sC 10.10.10.3", unit_id="cmd1", ts=1_000, cmd_id="t@5"),
         journal_seq=10)
    p.rebuild()
    return conn, p


def test_ms2_before_and_after():
    conn, _ = _ms2("customer")
    before = inbox(conn)
    assert len(before) == 86 and {i["kind"] for i in before} == {"candidate_group"}
    assert (f"ip:default/{KALI}",) in rows(conn, "SELECT host_id FROM v_host")  # Scheinhost Kali
    conn, _ = _ms2("lab", own=[KALI])
    assert inbox(conn) == []
    assert rows(conn, "SELECT host_id, scope, claim_state FROM v_host") == [(HK, "in", "auto")]
    svcs = {r[0]: r[1:] for r in rows(conn, "SELECT port, claim_state, product, version FROM v_service")}
    assert svcs[21] == ("auto", "vsftpd", "2.3.4") and svcs[445][0] == "auto" and len(svcs) == 23
    lanes = Counter((c["lane"], c["lane_reason"]) for c in claims(conn).values())
    assert lanes[("auto", "parser")] >= 140 and not any(k[0] == "decide" for k in lanes)
    assert rows(conn, "SELECT COUNT(*) FROM conflict") == [(0,)]


def test_ms2_without_known_own_address_has_no_inbox_but_fog():
    conn, _ = _ms2("lab")
    assert inbox(conn) == []
    hosts = dict(rows(conn, "SELECT host_id, claim_state FROM v_host"))
    assert hosts[f"ip:default/{KALI}"] == "candidate"  # nur Nebel (still), keine Klärung


def test_lame_before_and_after():
    conn, _ = _lame("customer")
    assert len(inbox(conn)) == 23
    conn, _ = _lame("lab", own=["10.10.14.5"])
    assert inbox(conn) == []
    assert rows(conn, "SELECT host_id, claim_state FROM v_host") == [("ip:default/10.10.10.3", "auto")]
    assert queries.quiet_summary(conn)["out_of_scope"] >= 0


def test_confirm_group_skips_kali_ip():
    """Pflicht-Test A6: MS2 im Profil customer, Kali 192.168.56.102 aus net.route."""
    # vorher: die Gruppe enthält die IP von Kali; die alte Sammelbestätigung nahm alle Einträge
    conn, p = _ms2("customer")
    group = next(g for g in queries.inbox(conn) if g["group_key"] == "unit:cmd1")
    kali_key = claims(conn)[(f"ip:default/{KALI}", "host.address", KALI)]["claim_key"]
    assert kali_key in [i["claim_key"] for i in group["items"]]
    plan = queries.resolve_confirm(conn, group["ref"])
    assert kali_key not in plan["keys"]  # heute schon ohne bekannte Adresse: Konfidenz 0.4 (ein Zeuge)
    # nachher: eigene Adresse bekannt
    conn, p = _ms2("customer", own=[KALI])
    group = next(g for g in queries.inbox(conn) if g["group_key"] == "unit:cmd1")
    plan = queries.resolve_confirm(conn, group["ref"])
    assert plan["group"] and plan["keys"] and plan["excluded"]["own_address"] == 1
    assert {"subject": KALI, "predicate": "host.address", "value": KALI, "reason": "own_address"} in (
        plan["excluded_sample"])
    for i, k in enumerate(plan["keys"]):
        p.apply_decision(dec(100 + i, "d.claim.confirm", claim_key=k))
    p.rebuild()
    states = {k[0] for k, c in claims(conn).items() if c["state"] == "confirmed"}
    assert states and not any(KALI in s for s in states)
    assert rows(conn, "SELECT host_id FROM v_host") == [(HK,)]
    # einzeln: eine eigene Adresse wird nie bestätigt
    conn, p = new_projector(profile="customer", own=[KALI])
    apply_items(p, make_unit("x"), [Obs(Ref.ip(KALI), "host.os", "Kali", Span(0, 0))])
    p.rebuild()
    key = claims(conn)[(f"ip:default/{KALI}", "host.os", "Kali")]["claim_key"]
    plan = queries.resolve_confirm(conn, key[:12])
    assert plan["keys"] == [] and plan["excluded"]["own_address"] == 1 and not plan["group"]


def test_confirm_group_excludes_unsafe_values():
    sp = Span(0, 0)
    h = Ref.ip("192.168.56.101")
    s21 = Ref.service(h, "tcp", 21)
    conn, p = new_projector(profile="customer")
    apply_items(p, make_unit("x", unit_id="u1"), [
        Obs(h, "host.state", "up", sp),  # sicher
        Obs(Ref.ip("10.99.0.1"), "host.state", "up", sp),  # ausserhalb
        Obs(h, "host.os", "Linux", sp, confidence=0.3),  # niedrige Konfidenz
        Obs(s21, "service.product", "vsftpd", sp),  # im Widerspruch (siehe u2)
        Obs(s21, "service.name", "ftp", sp, attrs={"suspect": "concealed"}),  # verdächtig
    ])
    apply_items(p, make_unit("x", unit_id="u2"), [Obs(s21, "service.product", "ProFTPD", sp)])
    apply_items(p, make_unit("x", unit_id="u1"), [Obs(h, "host.netbios", "LAME", sp)], parser_id="ai.x",
                trust="ai", auto_eligible=False)
    p.rebuild()
    group = next(g for g in queries.inbox(conn) if g["group_key"] == "unit:u1")
    plan = queries.resolve_confirm(conn, group["ref"])
    assert len(plan["keys"]) == 1
    ex = plan["excluded"]
    assert [ex[k] for k in ("out_of_scope", "low_confidence", "conflict", "suspect", "ai")] == [1] * 5
    # Kontext-Platzhalter nur einzeln
    conn, p = new_projector(profile="customer")
    seg = make_unit("x", kind="segment", unit_id="s1", context={"kind": "revshell", "opened_at": 5})
    apply_items(p, seg, [Obs(Ref.ctx_host(), "host.os", "Linux", sp)], trust="tool_text")
    p.rebuild()
    group = next(g for g in queries.inbox(conn) if g["group_key"] == "unit:s1")
    plan = queries.resolve_confirm(conn, group["ref"])
    assert plan["keys"] == [] and plan["excluded"]["context"] == 1


def test_confirm_lab_decide_group():
    sp = Span(0, 0)
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="u1"), [
        Obs(Ref.ip("192.168.56.101"), "host.os", "Linux", sp, attrs={"suspect": "overwritten"})])
    p.rebuild()
    (group,) = queries.inbox(conn)
    assert group["kind"] == "decide_value" and group["items"][0]["reason"] == "suspect"
    plan = queries.resolve_confirm(conn, group["ref"])
    assert plan["keys"] == [] and plan["excluded"]["suspect"] == 1
    single = queries.resolve_confirm(conn, group["items"][0]["claim_key"][:10])
    assert len(single["keys"]) == 1  # einzeln geht es
