"""Kontext-Platzhalter, Callback-Vorschlag, Inbox-Gruppen und Massenfund."""

from __future__ import annotations

from ariadne.ingest.proj_build import MASS_THRESHOLD
from ariadne.parsers.api import Mention, Obs, Ref, Span
from ariadne.parsers.listener_callback import ListenerCallbackParser
from tests.parsers.helpers import make_unit
from tests.projection.helpers import (
    FakeScope,
    apply_items,
    claims,
    dec,
    entity,
    feed,
    inbox,
    new_projector,
    rows,
)

SP = Span(0, 0)
H = Ref.ip("192.168.56.101")
REV = {"kind": "revshell", "opened_at": 100, "candidate": None}


def _segment(text="x", unit_id="seg1", context=None, start=150):
    return make_unit(
        text, kind="segment", unit_id=unit_id, terminal_id="t1", context=context or REV, start=start
    )


def test_ctx_host_without_host_uses_placeholder():
    conn, p = new_projector()
    apply_items(
        p,
        _segment(),
        [
            Obs(Ref.ctx_host(), "host.os", "Linux", SP),
            Obs(Ref.service(Ref.ctx_host(), "tcp", 22), "service.state", "open", SP),
        ],
        trust="tool_text",
    )
    p.rebuild()
    c = claims(conn)
    assert ("ctx:t1@100", "host.os", "Linux") in c
    assert ("svc:ctx:t1@100|tcp/22", "service.state", "open") in c
    ph = entity(conn, "ctx:t1@100")
    assert ph["type"] == "host" and ph["scope"] == "unknown" and ph["label"] == "unbekannter Kontext"
    (item,) = inbox(conn, "ctx_unknown")
    assert item["title"] == "Kontext klären"
    assert item["payload"]["placeholder_entity"] == "ctx:t1@100"
    assert (item["payload"]["terminal_id"], item["payload"]["from_off"]) == ("t1", 100)


def test_unknown_stage_without_observations_still_asks():
    conn, p = new_projector()
    apply_items(p, _segment(), [], parser_id="regex.net", trust="heuristic")
    p.rebuild()
    assert [i["kind"] for i in inbox(conn) if i["group"].startswith("ctx:")] == ["ctx_unknown"]


def test_callback_suggests_context_host():
    conn, p = new_projector()
    text = "listening on [any] 4444 ...\nconnect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 4711\n"
    feed(p, _segment(text), journal_seq=10, parsers=[ListenerCallbackParser()])
    p.rebuild()
    (item,) = inbox(conn, "ctx_suggestion")
    assert item["payload"]["suggested_host"] == H.key
    assert "nc:4444" in item["payload"]["reason"]
    assert not inbox(conn, "ctx_unknown")


def test_known_context_host_and_ctx_set_decision():
    conn, p = new_projector()
    known = dict(REV, host="ip:default/192.168.56.101")
    apply_items(p, _segment(context=known), [Obs(Ref.ctx_host(), "host.os", "Linux", SP)])
    p.rebuild()
    assert (H.key, "host.os", "Linux") in claims(conn)
    assert not [i for i in inbox(conn) if i["group"].startswith("ctx:")]
    # unbekannt, dann per Entscheid gesetzt (auch rückwirkend für die ganze Stufe)
    conn, p = new_projector()
    apply_items(p, _segment(unit_id="s1"), [Obs(Ref.ctx_host(), "host.os", "Linux", SP)])
    apply_items(p, _segment(unit_id="s2", start=900), [Obs(Ref.ctx_host(), "host.name", "web.lab", SP)])
    p.apply_decision(dec(50, "d.ctx.set", terminal_id="t1", from_off=800, host="ip:default/192.168.56.101"))
    p.rebuild()
    c = claims(conn)
    assert (H.key, "host.os", "Linux") in c and (H.key, "host.name", "web.lab") in c
    assert entity(conn, "ctx:t1@100") is None


def test_set_unit_context_and_local_context():
    conn, p = new_projector()
    apply_items(p, _segment(), [Obs(Ref.ctx_host(), "host.os", "Linux", SP)])
    assert p.set_unit_context("seg1", dict(REV, host="name:Web01.lab"))
    p.rebuild()
    assert ("fqdn:web01.lab", "host.os", "Linux") in claims(conn)
    assert not p.set_unit_context("nope", REV)
    conn, p = new_projector()
    apply_items(p, make_unit("x", cmd="uname -a"), [Obs(Ref.ctx_host(), "host.os", "Kali", SP)])
    p.rebuild()
    assert ("local:kali", "host.os", "Kali") in claims(conn)
    assert entity(conn, "local:kali")["label"] == "Kali"


def test_candidate_groups_per_unit_with_data_titles():
    conn, p = new_projector()
    evil = "nmap 192.168.56.101 # <script>alert(1)</script>"
    apply_items(
        p,
        make_unit("x", cmd=evil, unit_id="c1", ts=1000),
        [
            Obs(H, "host.state", "up", SP),
            Obs(Ref.service(H, "tcp", 22), "service.state", "open", SP),
            Obs(Ref.service(H, "tcp", 22), "service.script", "ssh-hostkey", SP),
            Obs(Ref.ip("10.99.0.1"), "host.state", "up", SP),
        ],
    )
    apply_items(
        p,
        make_unit(kind="file", data=b"<x/>", path="scans/a.xml", unit_id="f1", ts=2000),
        [Obs(H, "host.os", "Linux", SP, confidence=0.3)],
    )
    p.rebuild()
    items = inbox(conn, "candidate_group")
    groups = {i["group"]: i for i in items}
    assert set(groups) == {"unit:c1", "unit:f1"}
    assert groups["unit:c1"]["title"] == evil  # nur Daten, kein HTML, Kodierung macht die Senke
    assert groups["unit:f1"]["title"] == "scans/a.xml"
    preds = sorted(i["payload"]["predicate"] for i in items if i["group"] == "unit:c1")
    assert preds == ["host.state", "host.state", "service.state"]  # service.script nicht in der Inbox
    summary = groups["unit:c1"]["payload"]["summary"]
    assert summary == {
        "hosts": 2,
        "services": 1,
        "credentials": 0,
        "other": 0,
        "out_of_scope": 1,
        "low_confidence": 0,
    }
    assert groups["unit:f1"]["payload"]["summary"]["low_confidence"] == 1
    k = claims(conn)[(H.key, "host.state", "up")]["claim_key"]
    p.apply_decision(dec(40, "d.claim.confirm", claim_key=k))
    p.rebuild()
    assert len(inbox(conn, "candidate_group")) == len(items) - 1


def test_ip_mentions_in_scope_become_heuristic_candidates():
    conn, p = new_projector(FakeScope(nets=["192.168.56.0/24"]))
    u = make_unit("x", kind="segment", context=REV)
    apply_items(
        p,
        u,
        [
            Mention("ip", "192.168.56.50", SP),
            Mention("ip", "8.8.8.8", SP),
            Mention("ip", "192.168.56.51", SP, {"state": "down"}),
        ],
        parser_id="regex.net",
        trust="heuristic",
        auto_eligible=False,
    )
    p.rebuild()
    c = claims(conn, "host.address")
    assert list(c) == [("ip:default/192.168.56.50", "host.address", "192.168.56.50")]
    row = c[("ip:default/192.168.56.50", "host.address", "192.168.56.50")]
    assert (row["trust"], row["confidence"], row["from_target"]) == ("heuristic", 0.4, 1)
    assert entity(conn, "ip:default/192.168.56.50")["knowledge"] == "mentioned"
    verdicts = dict(rows(conn, "SELECT value, scope_verdict FROM mention"))
    assert verdicts == {"192.168.56.50": "in", "8.8.8.8": "out", "192.168.56.51": "in"}


def test_mass_find_single_group():
    conn, p = new_projector(FakeScope(nets=["10.20.0.0/16"]))
    n = MASS_THRESHOLD + 10
    ments = [Mention("ip", f"10.20.{i // 250}.{i % 250 + 1}", Span(i, i)) for i in range(n)]
    apply_items(
        p,
        make_unit("x", cmd="cat hosts.txt", unit_id="big"),
        ments,
        parser_id="regex.net",
        trust="heuristic",
        auto_eligible=False,
    )
    apply_items(
        p,
        make_unit("x", cmd="nmap 10.20.0.1", unit_id="small"),
        [Obs(Ref.ip("10.20.9.9"), "host.state", "up", SP)],
    )
    p.rebuild()
    (mass,) = inbox(conn, "mass_find")
    assert mass["payload"]["hosts"] == n and "Honeypot" in mass["payload"]["hint"]
    assert {i["group"] for i in inbox(conn, "candidate_group")} == {"unit:small"}


def test_context_host_typed_without_prefix():
    conn, p = new_projector()
    apply_items(
        p, _segment(context=dict(REV, host="192.168.56.101")), [Obs(Ref.ctx_host(), "host.os", "L", SP)]
    )
    p.apply_decision(dec(9, "d.keystep.mark", step="foothold", host="192.168.56.101"))
    p.rebuild()
    assert (H.key, "host.os", "L") in claims(conn)
    assert rows(conn, "SELECT host_ident FROM keystep") == [(H.key,)]


def test_ctx_set_targets_running_stage_not_older_parsed_one():
    """Befund: F12 h in einer neuen, noch nicht geparsten Stufe überschrieb den Host einer
    alten, beendeten ssh-Sitzung (Zuordnung nur über schon geparste Einheiten)."""
    from ariadne.ingest.proj_build import DecisionRow, ObsRow, UnitRow, build
    from tests.projection.helpers import PROJECT_KEY, FakeScope

    t = "0190aaaa-bbbb-7ccc-8ddd-eeeeffff0000"
    u1 = UnitRow(f"u:{t}@150", "segment", t, "c1", None, None, 1_000, 150, 900, "ssh",
                 "ip:default/10.10.10.5", "root", 100, None, True, 10)
    obs = [ObsRow(1, u1.unit_id, "shell.context", "1", "tool_text", False, 10, "ctx:host", "host.os",
                  "Linux", "Linux", '{"line_end":0,"line_start":0}', 0.85, {}, 1_000, True, False, False)]
    decisions = [
        DecisionRow(5, "d1", "d.ctx.set", {"terminal_id": t, "from_off": 150, "host": "ip:default/10.10.10.5"},
                    500),
        DecisionRow(20, "d2", "d.ctx.set", {"terminal_id": t, "from_off": 3000,
                                            "host": "ip:default/10.10.10.7"}, 5000),
    ]
    spans = [(t, 100, 2000, "ssh", 100), (t, 2000, 3000, "local", 0), (t, 3000, None, "unknown", 3000)]
    res = build({u1.unit_id: u1}, obs, [], decisions, FakeScope(nets=["10.10.10.0/24"]), PROJECT_KEY,
                spans=spans)
    claims = {(c[1], c[3], c[5]) for c in res.claims}  # Subjekt, Prädikat, Wert
    assert ("ip:default/10.10.10.5", "host.os", "Linux") in claims
    assert not any(c[0] == "ip:default/10.10.10.7" for c in claims)
