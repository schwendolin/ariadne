"""Zustände: Entscheide (confirm/reject/edit/revoke) und Automodus-Phasen."""

from __future__ import annotations

from ariadne.parsers.api import Obs, Ref, Span
from tests.parsers.helpers import make_unit
from tests.projection.helpers import apply_items, claims, dec, inbox, new_projector

H = Ref.ip("192.168.56.101")
OUT = Ref.ip("10.99.0.1")
SP = Span(0, 0)


def _setup(items, **kw):
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id=kw.pop("unit_id", "u1")), items, **kw)
    p.rebuild()
    return conn, p


def _key(conn, subject, pred, value):
    return claims(conn)[(subject, pred, value)]["claim_key"]


def test_default_state_is_candidate():
    conn, _ = _setup([Obs(H, "host.os", "Linux", SP)])
    assert claims(conn)[(H.key, "host.os", "Linux")]["state"] == "candidate"


def test_confirm_reject_and_revoke():
    conn, p = _setup([Obs(H, "host.os", "Linux", SP)])
    k = _key(conn, H.key, "host.os", "Linux")
    p.apply_decision(dec(20, "d.claim.confirm", claim_key=k))
    p.rebuild()
    c = claims(conn)[(H.key, "host.os", "Linux")]
    assert (c["state"], c["confidence"], c["decision_id"]) == ("confirmed", 1.0, "dec-20")
    p.apply_decision(dec(21, "d.claim.reject", claim_key=k))
    p.rebuild()
    assert claims(conn)[(H.key, "host.os", "Linux")]["state"] == "rejected"
    p.apply_decision(dec(22, "d.revoke", decision_id="dec-21"))
    p.rebuild()
    assert claims(conn)[(H.key, "host.os", "Linux")]["state"] == "confirmed"
    # Widerruf des Widerrufs
    p.apply_decision(dec(23, "d.revoke", decision_id="dec-22"))
    p.rebuild()
    assert claims(conn)[(H.key, "host.os", "Linux")]["state"] == "rejected"


def test_edit_rejects_old_and_confirms_user_value():
    conn, p = _setup([Obs(H, "host.os", "Linx", SP)])
    k = _key(conn, H.key, "host.os", "Linx")
    p.apply_decision(dec(20, "d.claim.edit", claim_key=k, value="Linux 2.6"))
    p.rebuild()
    c = claims(conn)
    assert c[(H.key, "host.os", "Linx")]["state"] == "rejected"
    new = c[(H.key, "host.os", "Linux 2.6")]
    assert (new["state"], new["trust"], new["confidence"], new["parser_id"]) == (
        "confirmed",
        "user",
        1.0,
        "user",
    )
    assert not inbox(conn, "conflict")  # verworfener Wert zählt nicht als Konflikt


def test_edit_with_invalid_value_is_orphan():
    conn, p = _setup([Obs(H, "host.address", "192.168.56.101", SP)])
    k = _key(conn, H.key, "host.address", "192.168.56.101")
    p.apply_decision(dec(20, "d.claim.edit", claim_key=k, value="not an ip"))
    p.rebuild()
    assert [i["payload"]["reason"] for i in inbox(conn, "orphan_decision")] == ["ungültiger Wert"]


def _auto_case(
    *decisions, journal_seq=10, parser_id="nmap.xml", trust="structured", auto_eligible=True, items=None
):
    conn, p = new_projector()
    for d in decisions:
        p.apply_decision(d)
    apply_items(
        p,
        make_unit("x"),
        items or [Obs(H, "host.os", "Linux", SP)],
        journal_seq=journal_seq,
        parser_id=parser_id,
        trust=trust,
        auto_eligible=auto_eligible,
    )
    p.rebuild()
    return conn, p


def test_automode_phase_after_decision():
    on = dec(5, "d.automode.set", enabled=True, parsers=["nmap.xml"])
    conn, _ = _auto_case(on, journal_seq=10)
    assert claims(conn)[(H.key, "host.os", "Linux")]["state"] == "auto"
    assert not inbox(conn, "candidate_group")
    conn, _ = _auto_case(on, journal_seq=3)  # Beobachtung vor dem Einschalten
    assert claims(conn)[(H.key, "host.os", "Linux")]["state"] == "candidate"


def test_automode_off_again_and_first_observation_counts():
    conn, p = new_projector()
    p.apply_decision(dec(5, "d.automode.set", enabled=True, parsers=[]))
    p.apply_decision(dec(20, "d.automode.set", enabled=False))
    apply_items(p, make_unit("x", unit_id="u1"), [Obs(H, "host.os", "Linux", SP)], journal_seq=10)
    apply_items(
        p,
        make_unit("x", unit_id="u2"),
        [Obs(H, "host.os", "Linux", SP), Obs(H, "host.name", "a.lab", SP)],
        journal_seq=25,
    )
    p.rebuild()
    c = claims(conn)
    assert c[(H.key, "host.os", "Linux")]["state"] == "auto"  # erste Beobachtung in der Phase
    assert c[(H.key, "host.name", "a.lab")]["state"] == "candidate"


def test_automode_conditions():
    on = dec(5, "d.automode.set", enabled=True, parsers=["nmap.xml"])
    for kw in (
        {"parser_id": "nmap.text"},
        {"auto_eligible": False},
        {"trust": "ai", "parser_id": "nmap.xml"},
        {"trust": "heuristic"},
        {"items": [Obs(OUT, "host.os", "Linux", SP)]},
    ):
        conn, _ = _auto_case(on, **kw)
        assert {c["state"] for c in claims(conn).values()} == {"candidate"}, kw
    all_on = dec(5, "d.automode.set", enabled=True)
    conn, _ = _auto_case(all_on, parser_id="nmap.text", trust="tool_text")
    assert {c["state"] for c in claims(conn).values()} == {"auto"}


def test_automode_never_makes_out_of_scope_value_a_target():
    on = dec(5, "d.automode.set", enabled=True)
    conn, _ = _auto_case(
        on, items=[Obs(H, "host.address", "10.99.0.1", SP), Obs(H, "host.address", "192.168.56.101", SP)]
    )
    c = claims(conn, "host.address")
    assert c[(H.key, "host.address", "10.99.0.1")]["state"] == "candidate"
    assert c[(H.key, "host.address", "192.168.56.101")]["state"] == "auto"


def test_decision_beats_automode_and_orphans_are_reported():
    on = dec(5, "d.automode.set", enabled=True)
    conn, p = _auto_case(on)
    k = _key(conn, H.key, "host.os", "Linux")
    p.apply_decision(dec(30, "d.claim.reject", claim_key=k))
    p.apply_decision(dec(31, "d.claim.confirm", claim_key="ff" * 32))
    p.rebuild()
    assert claims(conn)[(H.key, "host.os", "Linux")]["state"] == "rejected"
    orphans = inbox(conn, "orphan_decision")
    assert [o["payload"]["decision_id"] for o in orphans] == ["dec-31"]
    assert orphans[0]["payload"]["ref"] == "ff" * 32


def test_reparse_turns_decision_into_orphan():
    conn, p = _setup([Obs(H, "host.os", "Linux", SP)])
    k = _key(conn, H.key, "host.os", "Linux")
    p.apply_decision(dec(20, "d.claim.confirm", claim_key=k))
    apply_items(p, make_unit("x"), [Obs(H, "host.os", "FreeBSD", SP)])  # neue Parser-Version liefert anderes
    p.rebuild()
    assert [o["payload"]["kind"] for o in inbox(conn, "orphan_decision")] == ["d.claim.confirm"]


def test_automode_ignores_earlier_mentions():
    from ariadne.parsers.api import Mention

    conn, p = new_projector()
    p.apply_decision(dec(5, "d.automode.set", enabled=True, parsers=["nmap.xml"]))
    apply_items(
        p,
        make_unit("x", unit_id="u0"),
        [Mention("ip", "192.168.56.101", SP)],
        journal_seq=7,
        parser_id="regex.net",
        trust="heuristic",
        auto_eligible=False,
    )
    apply_items(
        p,
        make_unit("x", unit_id="u1"),
        [Obs(H, "host.address", "192.168.56.101", SP)],
        journal_seq=9,
        parser_id="nmap.xml",
    )
    p.rebuild()
    c = claims(conn)[(H.key, "host.address", "192.168.56.101")]
    assert (c["state"], c["sources"]) == ("auto", 2)
