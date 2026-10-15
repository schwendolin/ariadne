"""Kontext aus dem ersten Callback (A7, E23): eindeutig, mehrdeutig, Loopback, ausserhalb
des Scopes, eigene Adresse, Entscheid des Nutzers geht vor."""

from __future__ import annotations

from ariadne.ingest import queries
from ariadne.parsers.api import Mention, Obs, Ref, Span
from ariadne.parsers.listener_callback import ListenerCallbackParser
from tests.parsers.helpers import make_unit
from tests.projection.helpers import FakeScope, apply_items, claims, dec, entity, feed, inbox, new_projector

SP = Span(0, 0)
H = "ip:default/192.168.56.101"
REV = {"kind": "revshell", "opened_at": 100}
LISTEN = "listening on [any] 4444 ...\n"


def _cb(ip: str) -> str:
    return f"connect to [192.168.56.102] from (UNKNOWN) [{ip}] 4711\n"


def _seg(text: str, unit_id: str = "s1", start: int = 150, context: dict | None = None, **kw):
    return make_unit(text, kind="segment", unit_id=unit_id, terminal_id="t1", context=context or REV,
                     start=start, **kw)


def _stage(text: str, *, profile: str = "lab", scope=None, own=(), decisions=(), units=()):
    conn, p = new_projector(scope, profile=profile, own=own)
    feed(p, _seg(text + "id\nuid=33(www-data) gid=33(www-data)\n"), journal_seq=10,
         parsers=[ListenerCallbackParser()])
    apply_items(p, _seg("x", unit_id="s2", start=900), [Obs(Ref.ctx_host(), "host.os", "Linux", SP)],
                journal_seq=11, parser_id="shell.context", trust="tool_text")
    for u, items in units:
        apply_items(p, u, items, journal_seq=12)
    for d in decisions:
        p.apply_decision(d)
    p.rebuild()
    return conn, p


def test_single_first_callback_in_scope_sets_host():
    conn, _ = _stage(LISTEN + _cb("192.168.56.101"))
    assert queries.auto_contexts(conn) == [("t1", 100, H)]
    assert (H, "host.os", "Linux") in claims(conn)  # Beobachtung der Stufe landet beim Host
    assert entity(conn, "ctx:t1@100") is None
    assert not [i for i in inbox(conn) if i["kind"] in ("ctx_unknown", "ctx_suggestion")]
    (row,) = conn.execute("SELECT claim_key FROM ctx_auto").fetchall()
    assert claims(conn)[(H, "access.callback", "nc:4444")]["claim_key"] == row[0]


def test_ambiguous_callbacks_stay_manual():
    other = (_seg(LISTEN + _cb("192.168.56.103"), unit_id="s3", start=1500), None)
    conn, p = new_projector()
    feed(p, _seg(LISTEN + _cb("192.168.56.101")), journal_seq=10, parsers=[ListenerCallbackParser()])
    feed(p, other[0], journal_seq=20, parsers=[ListenerCallbackParser()])
    p.rebuild()
    assert queries.auto_contexts(conn) == []
    assert [i["kind"] for i in inbox(conn) if i["group"].startswith("ctx:")] == ["ctx_suggestion"]
    # msf-Handler mit einer zweiten Sitzung von einem anderen Host: ebenfalls mehrdeutig
    conn, p = new_projector()
    msf = {"kind": "msf", "opened_at": 100}
    apply_items(p, _seg("x", context=msf), [
        Obs(Ref.ip("192.168.56.101"), "access.callback", "msf:4444", SP),
        Mention("callback", "192.168.56.103:40001", SP, {"reason": "not_first", "listener": "msf"}),
    ], parser_id="listener.callback", trust="tool_text", auto_eligible=False)
    p.rebuild()
    assert queries.auto_contexts(conn) == []
    # gleiche IP in der zweiten Sitzung bleibt eindeutig; Text des Ziels (after_output) zählt nicht
    conn, p = new_projector()
    apply_items(p, _seg("x", context=msf), [
        Obs(Ref.ip("192.168.56.101"), "access.callback", "msf:4444", SP),
        Mention("callback", "192.168.56.101:40002", SP, {"reason": "not_first"}),
        Mention("callback", "6.6.6.6:1", SP, {"reason": "after_output"}),
    ], parser_id="listener.callback", trust="tool_text", auto_eligible=False)
    p.rebuild()
    assert queries.auto_contexts(conn) == [("t1", 100, H)]


def test_loopback_outside_scope_and_own_address_stay_manual():
    for text, kw in (
        (LISTEN + _cb("127.0.0.1"), {"scope": FakeScope(nets=["192.168.56.0/24", "127.0.0.0/8"])}),
        (LISTEN + _cb("10.99.0.1"), {}),
        (LISTEN + _cb("192.168.56.102"), {"own": ["192.168.56.102"]}),
    ):
        conn, _ = _stage(text, **kw)
        assert queries.auto_contexts(conn) == [], text
        assert entity(conn, "ctx:t1@100") is not None
        kinds = [i["kind"] for i in inbox(conn) if i["group"].startswith("ctx:")]
        assert kinds == ["ctx_suggestion"], (text, kinds)


def test_user_decision_overrides_auto_host():
    d = dec(30, "d.ctx.set", terminal_id="t1", from_off=200, host="ip:default/192.168.56.120")
    conn, _ = _stage(LISTEN + _cb("192.168.56.101"), decisions=[d])
    assert queries.auto_contexts(conn) == []
    assert ("ip:default/192.168.56.120", "host.os", "Linux") in claims(conn)
    # Host schon im Stapel (Hotkey vor dem Callback): keine Automatik
    conn, p = new_projector()
    feed(p, _seg(LISTEN + _cb("192.168.56.101"), context=dict(REV, host="ip:default/192.168.56.120")),
         journal_seq=10, parsers=[ListenerCallbackParser()])
    p.rebuild()
    assert queries.auto_contexts(conn) == []


def test_revoking_the_decision_restores_auto():
    d = dec(30, "d.ctx.set", terminal_id="t1", from_off=200, host="ip:default/192.168.56.120")
    conn, p = _stage(LISTEN + _cb("192.168.56.101"), decisions=[d])
    p.apply_decision(dec(31, "d.revoke", decision_id="dec-30"))
    p.rebuild()
    assert queries.auto_contexts(conn) == [("t1", 100, H)]


def test_customer_profile_only_suggests():
    conn, _ = _stage(LISTEN + _cb("192.168.56.101"), profile="customer")
    assert queries.auto_contexts(conn) == []
    (item,) = inbox(conn, "ctx_suggestion")
    assert item["payload"]["suggested_host"] == H


def test_context_label_marks_auto():
    assert queries.context_label({"kind": "revshell", "host": H, "host_source": "auto"}) == (
        "192.168.56.101 [revshell] (auto)")
