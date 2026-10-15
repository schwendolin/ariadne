"""Drei-Spuren-Regel (E42, Vertrag 6.1): jede Bedingung einzeln, Gründe der Spur
«entscheiden», Nutzerentscheid geht vor, Profil customer unverändert, Stabilität."""

from __future__ import annotations

import pytest

from ariadne.ingest import queries
from ariadne.ingest.proj_build import MASS_THRESHOLD
from ariadne.parsers.api import Mention, Obs, Ref, Span
from tests.parsers.helpers import make_unit
from tests.projection.helpers import FakeScope, apply_items, claims, dec, inbox, new_projector, rows

SP = Span(0, 0)
H = Ref.ip("192.168.56.101")
OUT = Ref.ip("10.99.0.1")
S21 = Ref.service(H, "tcp", 21)


def _one(conn, subject, pred, value):
    return claims(conn)[(subject, pred, value)]


def _lane(conn, subject, pred, value):
    c = _one(conn, subject, pred, value)
    return c["state"], c["lane"], c["lane_reason"]


def _run(items, *, profile="lab", scope=None, own=(), unit=None, **kw):
    conn, p = new_projector(scope, profile=profile, own=own)
    apply_items(p, unit or make_unit("x", unit_id="u1"), items, **kw)
    p.rebuild()
    return conn, p


# --------------------------------------------------------------------- Bedingung 1: anerkannter Parser


@pytest.mark.parametrize(("trust", "eligible", "expected"), [
    ("structured", True, ("auto", "auto", "parser")),
    ("tool_text", True, ("auto", "auto", "parser")),
    ("tool_text", False, ("candidate", "quiet", "parser")),  # Parser nicht auto_eligible
    ("heuristic", False, ("candidate", "quiet", "heuristic")),
    ("ai", False, ("candidate", "decide", "ai")),
    ("ocr", False, ("candidate", "decide", "ocr")),
])
def test_condition_1_recognized_parser(trust, eligible, expected):
    conn, _ = _run([Obs(S21, "service.product", "vsftpd", SP)], trust=trust, auto_eligible=eligible)
    assert _lane(conn, S21.key, "service.product", "vsftpd") == expected


def test_condition_1_any_source_counts_not_only_the_first():
    """Früher zählte nur die erste Beobachtung; jetzt genügt eine anerkannte Quelle."""
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="u0"), [Obs(S21, "service.product", "vsftpd", SP)], journal_seq=5,
                parser_id="other.text", trust="tool_text", auto_eligible=False)
    apply_items(p, make_unit("x", unit_id="u1"), [Mention("ip", "192.168.56.101", SP)], journal_seq=6,
                parser_id="regex.net", trust="heuristic", auto_eligible=False)
    p.rebuild()
    assert _lane(conn, S21.key, "service.product", "vsftpd")[1] == "quiet"
    assert _lane(conn, H.key, "host.address", "192.168.56.101") == ("candidate", "quiet", "mention")
    apply_items(p, make_unit("x", unit_id="u2"), [Obs(S21, "service.product", "vsftpd", SP),
                                                  Obs(H, "host.address", "192.168.56.101", SP)],
                journal_seq=9, parser_id="nmap.xml")
    p.rebuild()
    assert _lane(conn, S21.key, "service.product", "vsftpd") == ("auto", "auto", "parser")
    c = _one(conn, H.key, "host.address", "192.168.56.101")
    assert (c["state"], c["sources"]) == ("auto", 2)


# --------------------------------------------------------------------- Bedingung 2: Subjekt im Scope


@pytest.mark.parametrize(("subject", "expected"), [
    (H, ("auto", "auto", "parser")),
    (OUT, ("candidate", "quiet", "out_of_scope")),
    (Ref.ip("192.168.56.66"), ("candidate", "quiet", "out_of_scope")),  # ausgeschlossen
    (Ref.mac("08:00:27:00:00:01"), ("candidate", "quiet", "out_of_scope")),  # ohne Scope-Urteil
])
def test_condition_2_subject_verdict(subject, expected):
    scope = FakeScope(excluded=["192.168.56.66"])
    conn, _ = _run([Obs(subject, "host.os", "Linux", SP)], scope=scope)
    assert _lane(conn, subject.key, "host.os", "Linux") == expected


def test_condition_2_without_scope_nothing_is_auto():
    import sqlite3

    from ariadne.ingest.projection import Projector
    from tests.projection import helpers

    conn = sqlite3.connect(":memory:")
    helpers.OPEN.append(conn)
    p = Projector(conn, project_key=helpers.PROJECT_KEY, scope=None)
    apply_items(p, make_unit("x"), [Obs(H, "host.state", "up", SP)])
    p.rebuild()
    assert _lane(conn, H.key, "host.state", "up") == ("candidate", "quiet", "out_of_scope")


def test_condition_2_accounts_use_the_host_they_were_seen_on():
    """Konto, Secret, Hinweis: es zählt die Host-Kennung der Beobachtung; nie vererbt."""
    local_in = Ref.identity("local:ip:default/192.168.56.101", "msfadmin")
    local_out = Ref.identity("local:ip:default/10.99.0.1", "msfadmin")
    ad = Ref.identity("ad:corp.lab", "alice")
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="u1"), [Obs(local_in, "identity.exists", True, SP),
                                                  Obs(local_out, "identity.exists", True, SP)])
    on_target = make_unit("x", kind="segment", unit_id="s1",
                          context={"kind": "ssh", "host": "ip:default/192.168.56.101", "opened_at": 5})
    off_target = make_unit("x", kind="segment", unit_id="s2", terminal_id="t2",
                           context={"kind": "ssh", "host": "ip:default/10.99.0.1", "opened_at": 9})
    apply_items(p, on_target, [Obs(ad, "identity.exists", True, SP)])
    apply_items(p, off_target, [Obs(Ref.identity("ad:corp.lab", "bob"), "identity.exists", True, SP)])
    p.rebuild()
    assert _lane(conn, local_in.key, "identity.exists", "true") == ("auto", "auto", "parser")
    assert _lane(conn, local_out.key, "identity.exists", "true")[2] == "out_of_scope"
    assert _lane(conn, ad.key, "identity.exists", "true")[0] == "auto"
    assert _lane(conn, "id:ad:corp.lab|bob", "identity.exists", "true")[2] == "out_of_scope"
    # die Identität verleiht dem Host nichts: der Host ausserhalb bleibt ausserhalb
    assert rows(conn, "SELECT scope FROM entity WHERE entity_id = 'ip:default/10.99.0.1'") in ([], [("out",)])


# --------------------------------------------------------------------- Bedingung 3: Wert


def test_condition_3_value_never_makes_outside_a_target():
    scope = FakeScope(names=["metasploitable.lab"])
    conn, _ = _run([
        Obs(H, "host.address", "192.168.56.101", SP),
        Obs(H, "host.address", "10.99.0.1", SP),
        Obs(H, "host.address", "192.168.56.102", SP),  # eigene Adresse von Kali
        Obs(H, "host.name", "metasploitable.lab", SP),
        Obs(H, "host.name", "evil.example", SP),
        Obs(H, "host.mac", "08:00:27:63:7e:e7", SP),  # ohne Scope: kein Ziel
    ], scope=scope, own=["192.168.56.102"])
    assert _lane(conn, H.key, "host.address", "192.168.56.101")[0] == "auto"
    assert _lane(conn, H.key, "host.address", "10.99.0.1") == ("candidate", "quiet", "out_of_scope")
    assert _lane(conn, H.key, "host.address", "192.168.56.102") == ("candidate", "quiet", "own_address")
    assert _lane(conn, H.key, "host.name", "metasploitable.lab")[0] == "auto"
    assert _lane(conn, H.key, "host.name", "evil.example")[2] == "out_of_scope"
    assert _lane(conn, H.key, "host.mac", "08:00:27:63:7e:e7")[0] == "auto"


# --------------------------------------------------------------------- Bedingung 4: Widerspruch


def test_condition_4_open_conflict_is_decided_once():
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="u1"), [Obs(S21, "service.product", "vsftpd", SP),
                                                  Obs(H, "host.domain", "corp", SP)])
    apply_items(p, make_unit("x", unit_id="u2"), [Obs(S21, "service.product", "ProFTPD", SP),
                                                  Obs(H, "host.domain", "lab", SP)])
    p.rebuild()
    for v in ("vsftpd", "ProFTPD"):
        assert _lane(conn, S21.key, "service.product", v) == ("candidate", "decide", "conflict")
    assert len(inbox(conn, "conflict")) == 2 and not inbox(conn, "decide_value")
    ck = _one(conn, S21.key, "service.product", "vsftpd")["conflict_key"]
    p.apply_decision(dec(30, "d.conflict.resolve", conflict_key=ck, keep_open=True))
    p.rebuild()
    # bewusst offen gelassen: kein Inbox-Eintrag mehr, nie automatisch aufgelöst und nie auto (R5)
    assert len(inbox(conn, "conflict")) == 1
    assert _lane(conn, S21.key, "service.product", "vsftpd") == ("candidate", "quiet", "kept_open")


# --------------------------------------------------------------------- Bedingung 5: verdächtig, Massenfund


def test_condition_5_suspect_sources():
    conn, _ = _run([Obs(S21, "service.product", "vsftpd", SP, attrs={"suspect": "concealed"})])
    assert _lane(conn, S21.key, "service.product", "vsftpd") == ("candidate", "decide", "suspect")
    (item,) = inbox(conn, "decide_value")
    assert item["payload"]["reason"] == "suspect" and item["group"] == "unit:u1"
    forged = make_unit("x", unit_id="u9", unit_flags=["marker_forged"])
    conn, _ = _run([Obs(S21, "service.product", "vsftpd", SP)], unit=forged)
    assert _lane(conn, S21.key, "service.product", "vsftpd")[2] == "suspect"


def test_condition_5_mass_find():
    conn, p = new_projector(FakeScope(nets=["10.20.0.0/16"]))
    n = MASS_THRESHOLD + 10
    items = [Obs(Ref.ip(f"10.20.{i // 250}.{i % 250 + 1}"), "host.state", "up", Span(i, i)) for i in range(n)]
    apply_items(p, make_unit("x", cmd="nmap 10.20.0.0/16", unit_id="big"), items, parser_id="nmap.xml")
    apply_items(p, make_unit("x", cmd="nmap 10.20.99.1", unit_id="small"),
                [Obs(Ref.ip("10.20.99.1"), "host.state", "up", SP)], parser_id="nmap.xml")
    p.rebuild()
    states = rows(conn, "SELECT lane, lane_reason, COUNT(*) FROM claim GROUP BY 1, 2 ORDER BY 1")
    assert states == [("auto", "parser", 1), ("decide", "mass", n)]
    (mass,) = inbox(conn, "mass_find")
    assert mass["payload"]["hosts"] == n and mass["payload"]["candidates"] == n
    assert [i["kind"] for i in inbox(conn)] == ["mass_find"]  # ein Eintrag pro Einheit


# --------------------------------------------------------------------- Gründe «entscheiden» und «still»


def test_offered_credentials_and_important_heuristics():
    acct = Ref.identity("local:ip:default/192.168.56.101", "root")
    secret = Ref.secret("crypt", "$1$abcdefgh$0123456789abcdefghijkl")
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="u1"),
                [Obs(acct, "identity.exists", True, SP, attrs={"from_target": "1"})])
    apply_items(p, make_unit("x", unit_id="u2"), [Obs(acct, "identity.secret", secret, SP)],
                parser_id="regex.net", trust="heuristic", auto_eligible=False)
    apply_items(p, make_unit("x", unit_id="u3"), [Obs(H, "hint.finding", "maybe", SP)],
                parser_id="regex.net", trust="heuristic", auto_eligible=False)
    p.rebuild()
    reasons = {(c["predicate"], c["lane"], c["lane_reason"]) for c in claims(conn).values()}
    assert ("identity.exists", "decide", "offered") in reasons
    assert ("identity.secret", "decide", "important_heuristic") in reasons
    assert ("hint.finding", "quiet", "heuristic") in reasons  # nicht wichtig: still
    items = inbox(conn, "decide_value")
    assert sorted(i["payload"]["reason"] for i in items) == ["important_heuristic", "offered"]
    assert all("••" in str(i["payload"]["value"]) or i["payload"]["predicate"] != "identity.secret"
               for i in items)


def test_system_accounts_stay_quiet_and_are_counted():
    conn, p = new_projector()
    users = (("daemon", 1), ("www-data", 33), ("msfadmin", 1000))
    accounts = [Obs(Ref.identity("local:ip:default/192.168.56.101", n), "identity.exists", True, SP,
                    attrs={"uid": str(uid)}) for n, uid in users]
    apply_items(p, make_unit("x"), accounts)
    p.rebuild()
    lanes = {k[0]: v["lane_reason"] for k, v in claims(conn, "identity.exists").items()}
    assert lanes == {"id:local:ip:default/192.168.56.101|daemon": "system_account",
                     "id:local:ip:default/192.168.56.101|www-data": "system_account",
                     "id:local:ip:default/192.168.56.101|msfadmin": "parser"}
    assert queries.quiet_summary(conn)["system_accounts"] == 2
    assert not inbox(conn)


def test_quiet_counters_per_host_and_in_summary():
    conn, p = new_projector()
    apply_items(p, make_unit("x", unit_id="u1"), [Obs(H, "host.state", "up", SP),
                                                  Obs(H, "host.name", "outside.example", SP),
                                                  Obs(H, "host.address", "10.99.0.7", SP)])
    apply_items(p, make_unit("x", unit_id="u2"), [Mention("ip", "192.168.56.50", SP),
                                                  Mention("ip", "8.8.8.8", SP)],
                parser_id="regex.net", trust="heuristic", auto_eligible=False)
    p.rebuild()
    hosts = {h["host_id"]: h for h in queries.hosts(conn)}
    assert hosts[H.key]["quiet"] == {"heuristic": 0, "out_of_scope": 2, "mentions": 0, "system_accounts": 0}
    assert hosts["ip:default/192.168.56.50"]["quiet"]["mentions"] == 1
    assert hosts["ip:default/192.168.56.50"]["claim_state"] == "candidate"  # Nebel
    summary = queries.quiet_summary(conn)
    assert (summary["out_of_scope"], summary["mentions"]) == (2, 1)
    assert inbox(conn) == []


# --------------------------------------------------------------------- Vorrang und Profile


def test_user_decision_beats_auto_and_decide():
    conn, p = _run([Obs(H, "host.os", "Linux", SP), Obs(S21, "service.product", "vsftpd", SP,
                                                        attrs={"suspect": "overwritten"})])
    k_auto = _one(conn, H.key, "host.os", "Linux")["claim_key"]
    k_dec = _one(conn, S21.key, "service.product", "vsftpd")["claim_key"]
    p.apply_decision(dec(40, "d.claim.reject", claim_key=k_auto))
    p.apply_decision(dec(41, "d.claim.confirm", claim_key=k_dec))
    p.rebuild()
    assert _lane(conn, H.key, "host.os", "Linux") == ("rejected", "user", "rejected")
    assert _lane(conn, S21.key, "service.product", "vsftpd") == ("confirmed", "user", "confirmed")
    assert not inbox(conn, "decide_value")
    p.apply_decision(dec(42, "d.revoke", decision_id="dec-40"))
    p.rebuild()
    assert _lane(conn, H.key, "host.os", "Linux") == ("auto", "auto", "parser")


def test_customer_profile_keeps_old_behaviour():
    items = [Obs(H, "host.state", "up", SP), Obs(S21, "service.state", "open", SP),
             Obs(S21, "service.script", "ftp-anon", SP)]
    conn, p = _run(items, profile="customer")
    assert {c["state"] for c in claims(conn).values()} == {"candidate"}
    assert sorted(i["payload"]["predicate"] for i in inbox(conn, "candidate_group")) == [
        "host.state", "service.state"]
    assert {c["lane"] for c in claims(conn).values()} == {"decide", "quiet"}
    # d.automode.set wirkt nur im Profil customer
    on = dec(5, "d.automode.set", enabled=True, parsers=["test.parser"])
    for profile, state in (("customer", "auto"), ("lab", "auto")):
        conn, p = new_projector(profile=profile)
        p.apply_decision(on)
        apply_items(p, make_unit("x"), [Obs(H, "host.os", "Linux", SP)], journal_seq=10)
        p.rebuild()
        assert _one(conn, H.key, "host.os", "Linux")["state"] == state
    off = dec(5, "d.automode.set", enabled=False)
    conn, p = new_projector(profile="lab")
    p.apply_decision(off)
    apply_items(p, make_unit("x"), [Obs(H, "host.os", "Linux", SP)], journal_seq=10)
    p.rebuild()
    assert _one(conn, H.key, "host.os", "Linux")["state"] == "auto"  # im Profil lab ignoriert


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        new_projector(profile="pentest")


def test_auto_is_stable_across_rebuild_and_order():
    items_a = [Obs(H, "host.state", "up", SP), Obs(S21, "service.product", "vsftpd", SP)]
    items_b = [Obs(S21, "service.version", "2.3.4", SP), Obs(H, "host.address", "10.99.0.1", SP)]

    def project(order):
        conn, p = new_projector()
        for uid, items in order:
            apply_items(p, make_unit("x", unit_id=uid), items)
        p.rebuild()
        p.rebuild()
        return rows(conn, "SELECT claim_key, state, lane, lane_reason, confidence FROM claim ORDER BY 1")

    assert project([("u1", items_a), ("u2", items_b)]) == project([("u2", items_b), ("u1", items_a)])


def test_file_without_host_asks_for_context_once():
    conn, p = new_projector()
    loot = make_unit(kind="file", data=b"root:x:0:0", path="loot/passwd", unit_id="f:e1",
                     context={"kind": "unknown"})
    apply_items(p, loot, [Obs(Ref.ctx_host(), "host.os", "Linux", SP),
                          Obs(Ref.service(Ref.ctx_host(), "tcp", 22), "service.state", "open", SP)])
    p.rebuild()
    assert {c["lane_reason"] for c in claims(conn).values()} == {"context"}
    (item,) = [i for i in inbox(conn) if i["kind"] == "ctx_unknown"]
    assert item["payload"]["path"] == "loot/passwd" and item["payload"]["values"] == 2
    from ariadne.cli.views import render_view

    text = "\n".join(render_view("inbox", queries.inbox(conn)))
    assert "Kontext klären: Datei loot/passwd (2 Werte ohne Host" in text
