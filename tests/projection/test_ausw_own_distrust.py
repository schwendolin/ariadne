"""Eigene Adressen von Kali (A5) und Rückgängig pro Befehl (A2, ``d.unit.distrust``)."""

from __future__ import annotations

import sqlite3

from ariadne.ingest import queries
from ariadne.ingest.projection import record_own_addrs
from ariadne.parsers.api import Mention, Obs, Ref, Span
from tests.parsers.helpers import make_unit
from tests.projection.helpers import apply_items, claims, dec, entity, inbox, new_projector, rows

SP = Span(0, 0)
H = Ref.ip("192.168.56.101")
KALI = Ref.ip("192.168.56.102")
S21 = Ref.service(H, "tcp", 21)
CMD_A = "0199a2b3-0000-7000-8000-000000000001@100"
CMD_B = "0199a2b3-0000-7000-8000-000000000001@900"


# --------------------------------------------------------------------- eigene Adressen


def test_record_own_addrs_canonical_and_never_expiring():
    conn = sqlite3.connect(":memory:")
    try:
        from ariadne.ingest.projection import ensure_schema

        ensure_schema(conn)
        assert record_own_addrs(conn, ["10.10.14.5", "fe80::0001", "nonsense", None, "10.10.14.5"], "proc", 3)
        assert not record_own_addrs(conn, ["10.10.14.5"], "route", 9)  # nichts Neues
        assert rows(conn, "SELECT addr, source, first_seq FROM own_addr ORDER BY addr") == [
            ("10.10.14.5", "proc", 3), ("fe80::1", "proc", 3)]
    finally:
        conn.close()


def test_own_address_is_never_a_host_nor_auto_nor_merged():
    conn, p = new_projector(own=["192.168.56.102"])
    apply_items(p, make_unit("x", unit_id="u1"), [
        Obs(KALI, "host.state", "up", SP),  # Scan des eigenen Netzes trifft Kali selbst
        Obs(Ref.service(KALI, "tcp", 22), "service.state", "open", SP),
        Obs(KALI, "host.mac", "08:00:27:aa:bb:cc", SP),
        Obs(H, "host.mac", "08:00:27:aa:bb:cc", SP),  # gleiche MAC: würde sonst verbinden
        Obs(H, "host.state", "up", SP),
    ], parser_id="nmap.xml")
    apply_items(p, make_unit("x", unit_id="u2"), [Mention("ip", "192.168.56.102", SP)],
                parser_id="regex.net", trust="heuristic", auto_eligible=False)
    p.rebuild()
    assert entity(conn, KALI.key) is None
    assert rows(conn, "SELECT host_id FROM v_host") == [(H.key,)]
    kali = [c for k, c in claims(conn).items() if "192.168.56.102" in k[0]]
    assert kali and all((c["state"], c["lane_reason"], c["entity_id"]) == ("candidate", "own_address", None)
                        for c in kali)
    # die Mention erzeugt keine host.address-Quelle
    assert (KALI.key, "host.address", "192.168.56.102") not in claims(conn)
    ids = dict(rows(conn, "SELECT key, entity_id FROM identifier"))
    assert ids.get("mac:08:00:27:aa:bb:cc") == H.key  # der MAC hängt am Ziel, nicht an Kali
    assert not inbox(conn)


def test_own_address_as_value_and_from_route():
    conn, p = new_projector()
    record_own_addrs(conn, ["192.168.56.102"], "route", 7)
    apply_items(p, make_unit("x"), [Obs(H, "host.address", "192.168.56.102", SP),
                                    Obs(H, "host.address", "192.168.56.101", SP)], parser_id="nmap.xml")
    p.rebuild()
    c = claims(conn, "host.address")
    assert c[(H.key, "host.address", "192.168.56.102")]["lane_reason"] == "own_address"
    assert c[(H.key, "host.address", "192.168.56.101")]["state"] == "auto"
    attrs = rows(conn, "SELECT addresses_json FROM v_host")
    assert attrs == [('["192.168.56.101"]',)]


def test_confirming_own_address_becomes_orphan():
    conn, p = new_projector(profile="customer")
    apply_items(p, make_unit("x", unit_id="u2"), [Mention("ip", "192.168.56.102", SP)],
                parser_id="regex.net", trust="heuristic", auto_eligible=False)
    p.rebuild()
    key = claims(conn)[(KALI.key, "host.address", "192.168.56.102")]["claim_key"]
    p.apply_decision(dec(20, "d.claim.confirm", claim_key=key))  # alter Entscheid (vor A5)
    p.rebuild()
    assert claims(conn)[(KALI.key, "host.address", "192.168.56.102")]["state"] == "confirmed"
    record_own_addrs(conn, ["192.168.56.102"], "proc", 30)  # später als eigene Adresse erkannt
    p.rebuild()
    assert (KALI.key, "host.address", "192.168.56.102") not in claims(conn)
    assert [o["payload"]["reason"] for o in inbox(conn, "orphan_decision")] == ["eigene Adresse"]
    assert not rows(conn, "SELECT * FROM v_host")
    # auch eine Bestätigung eines Claims aus einer Beobachtung wird verwaist
    apply_items(p, make_unit("x", unit_id="u3"), [Obs(KALI, "host.os", "Kali", SP)], parser_id="nmap.xml")
    p.rebuild()
    k2 = claims(conn)[(KALI.key, "host.os", "Kali")]["claim_key"]
    p.apply_decision(dec(40, "d.claim.confirm", claim_key=k2))
    p.rebuild()
    assert claims(conn)[(KALI.key, "host.os", "Kali")]["state"] == "candidate"
    assert len(inbox(conn, "orphan_decision")) == 2


# --------------------------------------------------------------------- Rückgängig pro Befehl


def _two_commands():
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="a", cmd_id=CMD_A), [
        Obs(S21, "service.product", "vsftpd", SP), Obs(H, "host.os", "Linux", SP)], parser_id="nmap.text",
        trust="tool_text")
    apply_items(p, make_unit(kind="file", data=b"<x/>", unit_id="f:ev1", cmd_id=CMD_A), [
        Obs(S21, "service.version", "2.3.4", SP)], parser_id="nmap.xml")
    apply_items(p, make_unit("x", unit_id="b", cmd_id=CMD_B), [Obs(H, "host.os", "Linux", SP)],
                parser_id="nmap.text", trust="tool_text")
    p.rebuild()
    return conn, p


def test_distrust_rejects_only_values_from_that_command():
    conn, p = _two_commands()
    p.apply_decision(dec(50, "d.unit.distrust", cmd_id=CMD_A, reason="falsches Ziel"))
    p.rebuild()
    c = claims(conn)
    for key in ((S21.key, "service.product", "vsftpd"), (S21.key, "service.version", "2.3.4")):
        assert (c[key]["state"], c[key]["lane"], c[key]["decision_id"]) == ("rejected", "user", "dec-50")
    os_ = c[(H.key, "host.os", "Linux")]  # auch von Befehl B: nur geschwächt
    assert (os_["state"], os_["confidence"]) == ("auto", 0.85)
    assert rows(conn, "SELECT cmd_id, rejected, weakened FROM unit_distrust") == [(CMD_A, 2, 1)]
    assert queries.distrust_result(conn, CMD_A) == {"cmd_id": CMD_A, "cmd_ref": "00000001@100",
                                                    "rejected": 2, "weakened": 1}
    dis = rows(conn, "SELECT group_key, distrusted FROM claim_source WHERE claim_key = ? ORDER BY 1",
               os_["claim_key"])
    assert dis == [(CMD_A, 1), (CMD_B, 0)]
    # auch die zweite Gruppe misstraut: jetzt ohne Quelle -> verworfen
    p.apply_decision(dec(51, "d.unit.distrust", cmd_id=CMD_B))
    p.rebuild()
    assert claims(conn)[(H.key, "host.os", "Linux")]["state"] == "rejected"


def test_distrust_survives_rebuild_and_can_be_revoked():
    conn, p = _two_commands()
    p.apply_decision(dec(50, "d.unit.distrust", cmd_id=CMD_A))
    p.rebuild()
    before = rows(conn, "SELECT claim_key, state, lane, confidence FROM claim ORDER BY 1")
    p.rebuild()
    assert rows(conn, "SELECT claim_key, state, lane, confidence FROM claim ORDER BY 1") == before
    p.apply_decision(dec(60, "d.revoke", decision_id="dec-50"))
    p.rebuild()
    assert {c["state"] for c in claims(conn).values()} == {"auto"}
    assert rows(conn, "SELECT COUNT(*) FROM unit_distrust") == [(0,)]


def test_later_decision_wins_between_confirm_and_distrust():
    conn, p = _two_commands()
    key = claims(conn)[(S21.key, "service.product", "vsftpd")]["claim_key"]
    p.apply_decision(dec(50, "d.unit.distrust", cmd_id=CMD_A))
    p.apply_decision(dec(51, "d.claim.confirm", claim_key=key))
    p.rebuild()
    assert claims(conn)[(S21.key, "service.product", "vsftpd")]["state"] == "confirmed"
    p.apply_decision(dec(52, "d.unit.distrust", cmd_id=CMD_A))
    p.rebuild()
    assert claims(conn)[(S21.key, "service.product", "vsftpd")]["state"] == "rejected"


def test_distrust_of_unknown_command_is_orphan():
    conn, p = _two_commands()
    p.apply_decision(dec(50, "d.unit.distrust", cmd_id="nope@1"))
    p.rebuild()
    assert [o["payload"]["reason"] for o in inbox(conn, "orphan_decision")] == ["Befehl unbekannt"]
    assert {c["state"] for c in claims(conn).values()} == {"auto"}


def test_edited_value_survives_distrust():
    conn, p = _two_commands()
    key = claims(conn)[(S21.key, "service.product", "vsftpd")]["claim_key"]
    p.apply_decision(dec(50, "d.claim.edit", claim_key=key, value="vsftpd (Backport)"))
    p.apply_decision(dec(51, "d.unit.distrust", cmd_id=CMD_A))
    p.rebuild()
    c = claims(conn)
    assert c[(S21.key, "service.product", "vsftpd (Backport)")]["state"] == "confirmed"


def test_resolve_cmd_short_and_full():
    conn, p = _two_commands()
    assert queries.resolve_cmd(conn, CMD_A) == CMD_A
    assert queries.resolve_cmd(conn, "0199a2b3@900") == CMD_B
    assert queries.resolve_distrust(conn, "0199a2b3@900") == CMD_B
    apply_items(p, make_unit("x", unit_id="c", cmd_id="0199a2b3-0000-7000-8000-000000000001@5000"), [])
    p.rebuild()
    assert queries.resolve_cmd(conn, "0199a2b3@5000").endswith("@5000")
    try:
        queries.resolve_distrust(conn, "0199a2b3@5000")  # Befehl ohne Werte
    except queries.RefError:
        pass
    else:
        raise AssertionError("ohne Werte darf undo nichts schreiben")
    for bad in ("0199a2b3@5", "abc@100", "0199a2b3", "0199a2b3@x"):
        try:
            queries.resolve_cmd(conn, bad)
        except queries.RefError:
            continue
        raise AssertionError(bad)


def test_cmd_ref_unique_for_terminals_started_in_the_same_minute():
    """UUIDv7: Terminals, die kurz nacheinander starten, haben denselben Anfang der terminal_id.
    Die Kurzform nimmt deshalb das zufällige Ende (wie ``ariadne status``)."""
    conn, p = _two_commands()
    other = "0199a2b3-0000-7000-8000-00000000beef@100"  # gleicher Anfang, gleicher Offset wie CMD_A
    apply_items(p, make_unit("x", unit_id="o", cmd_id=other), [])
    p.rebuild()
    assert queries.cmd_ref(CMD_A) == "00000001@100" and queries.cmd_ref(other) == "0000beef@100"
    assert queries.resolve_cmd(conn, "00000001@100") == CMD_A
    assert queries.resolve_cmd(conn, "0000beef@100") == other
    try:
        queries.resolve_cmd(conn, "0199a2b3@100")  # Anfang: nicht eindeutig
    except queries.RefError as exc:
        assert "nicht eindeutig" in str(exc)
    else:
        raise AssertionError("Anfang zweier Terminals darf nicht eindeutig sein")
