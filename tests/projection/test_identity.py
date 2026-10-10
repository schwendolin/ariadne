"""Identitäten: Union-Find nur über starke Kennungen mit gleichem Scope-Urteil, FQDN nie."""

from __future__ import annotations

from ariadne.ingest.identity import IdentityGraph, host_identifier, normalize_identifier
from ariadne.parsers.api import Obs, Ref, Span
from tests.parsers.helpers import make_unit
from tests.projection.helpers import FakeScope, apply_items, claims, dec, entity, inbox, new_projector, rows

SP = Span(0, 0)
A, B, OUT = Ref.ip("192.168.56.10"), Ref.ip("192.168.56.11"), Ref.ip("10.99.0.5")
MAC = "00:11:22:33:44:55"


def _ids(conn):
    return dict(rows(conn, "SELECT key, entity_id FROM identifier"))


def _run(items, scope=None, decisions=()):
    conn, p = new_projector(scope)
    for d in decisions:
        p.apply_decision(d)
    apply_items(p, make_unit("x"), items)
    p.rebuild()
    return conn, p


def test_same_mac_same_verdict_merges():
    conn, _ = _run([Obs(A, "host.mac", MAC, SP), Obs(B, "host.mac", MAC, SP)])
    ids = _ids(conn)
    assert ids[A.key] == ids[B.key] == ids[f"mac:{MAC}"] == A.key
    assert rows(conn, "SELECT COUNT(*) FROM entity WHERE type = 'host'") == [(1,)]
    assert not inbox(conn, "merge_suggestion")


def test_same_mac_different_verdict_only_suggests():
    conn, _ = _run([Obs(A, "host.mac", MAC, SP), Obs(OUT, "host.mac", MAC, SP)])
    ids = _ids(conn)
    assert ids[A.key] == A.key and ids[OUT.key] == OUT.key
    (s,) = inbox(conn, "merge_suggestion")
    assert set(s["payload"]["identifiers"]) == {A.key, OUT.key, f"mac:{MAC}"}
    assert "MAC-Adresse" in s["payload"]["reason"] and "(in)" in s["payload"]["reason"]
    assert "(out)" in s["payload"]["reason"]


def test_shared_ssh_hostkey_merges():
    key = Ref.sshkey("rsa", "SHA256:abc")
    conn, _ = _run([Obs(A, "host.sshkey", key, SP), Obs(B, "host.sshkey", key, SP)])
    assert _ids(conn)[B.key] == A.key


def test_same_fqdn_never_merges():
    conn, _ = _run([Obs(A, "host.name", "www.lab", SP), Obs(B, "host.name", "www.lab", SP)])
    ids = _ids(conn)
    assert ids[A.key] != ids[B.key]
    assert ids["fqdn:www.lab"] is None  # mehrdeutig: an keinem Host
    assert not inbox(conn, "merge_suggestion")


def test_unique_name_attaches_but_never_gives_scope():
    scope = FakeScope(nets=["192.168.56.0/24"], names=["dc.lab"])
    conn, _ = _run([Obs(OUT, "host.name", "dc.lab", SP), Obs(OUT, "host.os", "Windows", SP)], scope=scope)
    ids = _ids(conn)
    assert ids["fqdn:dc.lab"] == OUT.key
    assert rows(conn, "SELECT scope_verdict FROM identifier WHERE key = 'fqdn:dc.lab'") == [("in",)]
    assert entity(conn, OUT.key)["scope"] == "out"
    assert {c["scope"] for c in claims(conn).values()} == {"out"}


def test_user_merge_forces_and_split_forbids():
    d_merge = dec(1, "d.entity.merge", identifiers=[A.key, OUT.key])
    conn, _ = _run([Obs(A, "host.os", "L", SP), Obs(OUT, "host.os", "L", SP)], decisions=[d_merge])
    ids = _ids(conn)
    assert ids[A.key] == ids[OUT.key] == A.key
    d_split = dec(2, "d.entity.split", identifiers=[A.key, B.key])
    conn, _ = _run([Obs(A, "host.mac", MAC, SP), Obs(B, "host.mac", MAC, SP)], decisions=[d_split])
    ids = _ids(conn)
    assert ids[A.key] != ids[B.key]
    # späterer Merge hebt den Split auf
    conn, _ = _run(
        [Obs(A, "host.mac", MAC, SP), Obs(B, "host.mac", MAC, SP)],
        decisions=[d_split, dec(3, "d.entity.merge", identifiers=[A.key, B.key])],
    )
    assert _ids(conn)[A.key] == _ids(conn)[B.key]


def test_merge_with_unknown_identifiers_is_orphan():
    conn, _ = _run(
        [Obs(A, "host.os", "L", SP)],
        decisions=[dec(1, "d.entity.merge", identifiers=[A.key, "ip:default/192.168.56.99"])],
    )
    assert [o["payload"]["kind"] for o in inbox(conn, "orphan_decision")] == ["d.entity.merge"]


def test_excluded_identifier_marks_whole_entity():
    scope = FakeScope(nets=["192.168.56.0/24"], excluded=["192.168.56.11"])
    d = dec(1, "d.entity.merge", identifiers=[A.key, B.key])
    conn, _ = _run([Obs(A, "host.os", "L", SP), Obs(B, "host.os", "L", SP)], scope=scope, decisions=[d])
    assert entity(conn, A.key)["scope"] == "excluded"


def test_services_follow_host_merge():
    s1, s2 = Ref.service(A, "tcp", 22), Ref.service(B, "tcp", 22)
    conn, _ = _run(
        [
            Obs(A, "host.mac", MAC, SP),
            Obs(B, "host.mac", MAC, SP),
            Obs(s1, "service.state", "open", SP),
            Obs(s2, "service.state", "open", SP),
        ]
    )
    ids = _ids(conn)
    assert ids[s1.key] == ids[s2.key] == f"svc:{A.key}|tcp/22"
    assert rows(conn, "SELECT COUNT(*) FROM entity WHERE type = 'service'") == [(1,)]


def test_identity_graph_rules_directly():
    g = IdentityGraph({"ip:default/1.1.1.1": "in", "ip:default/2.2.2.2": "in", "ip:default/3.3.3.3": "out"})
    assert g.link_strong("ip:default/1.1.1.1", "mac:aa:aa:aa:aa:aa:aa", "mac:aa:aa:aa:aa:aa:aa")
    assert g.link_strong("ip:default/2.2.2.2", "mac:aa:aa:aa:aa:aa:aa", "mac:aa:aa:aa:aa:aa:aa")
    assert not g.link_strong("ip:default/3.3.3.3", "mac:aa:aa:aa:aa:aa:aa", "mac:aa:aa:aa:aa:aa:aa")
    assert len(g.suggestions) == 1
    g.forbid(["ip:default/1.1.1.1", "ip:default/9.9.9.9"])
    assert not g.must(["ip:default/9.9.9.9", "ip:default/2.2.2.2"])
    assert g.main("mac:aa:aa:aa:aa:aa:aa") == "ip:default/1.1.1.1"


def test_normalize_identifier():
    pk = b"k" * 32
    assert normalize_identifier("ip:default/010.1.1.1") is None
    assert normalize_identifier("ip:Default/::FFFF:10.0.0.1") == "ip:default/10.0.0.1"
    assert normalize_identifier("name:Web01.LAB.") == "fqdn:web01.lab"
    assert normalize_identifier("svc:ip:default/10.0.0.1|TCP/0022") == "svc:ip:default/10.0.0.1|tcp/22"
    assert normalize_identifier("svc:fqdn:a.lab|tcp/70000") is None
    assert normalize_identifier("secret:password|x") is None  # ohne Schlüssel nie Klartext
    assert normalize_identifier("secret:password|x", pk).startswith("secret:password|h:")
    assert normalize_identifier("sid:S-1-5-21-1-2-3") == "sid:S-1-5-21-1-2-3"
    assert normalize_identifier("nonsense") is None


def test_host_identifier_from_user_input():
    assert host_identifier("10.10.10.5") == "ip:default/10.10.10.5"
    assert host_identifier("fe80::1") == "ip:default/fe80::1"
    assert host_identifier("Web01.LAB") == "fqdn:web01.lab"
    assert host_identifier("name:web01") == "fqdn:web01"
    assert host_identifier("ip:default/10.0.0.1") == "ip:default/10.0.0.1"
    assert host_identifier("url:http://x") is None
    assert host_identifier("x y") is None
