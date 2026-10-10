"""Konflikte (Kardinalität one, nie automatisch aufgelöst) und Secrets (HMAC, nie Klartext in Sichten)."""

from __future__ import annotations

import json

from ariadne.events import canonical_json
from ariadne.ingest.schema_claims import MASK, VIEWS_SQL
from ariadne.parsers.api import Mention, Obs, Ref, Span
from ariadne.store.chain import secret_key
from tests.parsers.helpers import make_unit
from tests.projection.helpers import PROJECT_KEY, apply_items, claims, dec, inbox, new_projector, rows

H = Ref.ip("192.168.56.101")
SP = Span(0, 0)
CANARY = "Canary-Pa55word!7"


def _two_os(conn_p=None):
    conn, p = conn_p or new_projector()
    apply_items(p, make_unit("x", unit_id="u1"), [Obs(H, "host.os", "Linux 2.6", SP)])
    apply_items(p, make_unit("x", unit_id="u2"), [Obs(H, "host.os", "FreeBSD", SP)], parser_id="other")
    p.rebuild()
    return conn, p


def test_two_values_with_cardinality_one_conflict():
    conn, p = _two_os()
    (ck, state) = rows(conn, "SELECT conflict_key, state FROM conflict")[0]
    assert state == "open"
    c = claims(conn, "host.os")
    assert {v["conflict_key"] for v in c.values()} == {ck}
    assert {v["state"] for v in c.values()} == {"candidate"}  # nie automatisch aufgelöst
    item = inbox(conn, "conflict")[0]
    assert item["payload"]["conflict_key"] == ck
    assert sorted(v["value"] for v in item["payload"]["values"]) == ["FreeBSD", "Linux 2.6"]
    assert (
        json.loads(rows(conn, "SELECT attrs_json FROM entity WHERE entity_id = ?", H.key)[0][0])["conflicts"]
        == 1
    )


def test_many_cardinality_is_no_conflict():
    conn, p = new_projector()
    apply_items(p, make_unit("x"), [Obs(H, "host.name", "a.lab", SP), Obs(H, "host.name", "b.lab", SP)])
    p.rebuild()
    assert rows(conn, "SELECT COUNT(*) FROM conflict") == [(0,)]


def test_reject_resolve_and_keep_open():
    conn, p = _two_os()
    ck = rows(conn, "SELECT conflict_key FROM conflict")[0][0]
    p.apply_decision(dec(30, "d.conflict.resolve", conflict_key=ck, choice="Linux 2.6"))
    p.rebuild()
    assert rows(conn, "SELECT state, choice FROM conflict") == [("resolved", "Linux 2.6")]
    assert not inbox(conn, "conflict")
    p.apply_decision(dec(31, "d.conflict.resolve", conflict_key=ck, keep_open=True))
    p.rebuild()
    assert rows(conn, "SELECT state FROM conflict") == [("kept_open",)]
    assert not inbox(conn, "conflict")
    k = claims(conn, "host.os")[(H.key, "host.os", "FreeBSD")]["claim_key"]
    p.apply_decision(dec(32, "d.claim.reject", claim_key=k))
    p.rebuild()
    assert rows(conn, "SELECT COUNT(*) FROM conflict") == [(0,)]


def _secret_setup():
    conn, p = new_projector()
    ident = Ref.identity("local:ip:default/192.168.56.101", "msfadmin")
    sec = Ref.secret("password", CANARY)
    u = make_unit(
        f"msfadmin:{CANARY}\n" + "aad3b435b51404eeaad3b435b51404ee x\n",
        kind="segment",
        context={"kind": "revshell", "opened_at": 5},
    )
    apply_items(
        p,
        u,
        [
            Obs(ident, "identity.secret", sec, SP),
            Obs(sec, "secret.kind", "password", SP),
            Mention("hash32", "aad3b435b51404eeaad3b435b51404ee", Span(1, 1)),
            Mention("crypt", "$1$abc$" + "b" * 22, Span(1, 1)),
        ],
        trust="tool_text",
    )
    p.rebuild()
    return conn, p


def _all_strings(conn, sql):
    out = []
    for r in conn.execute(sql):
        out.extend(str(v) for v in r if v is not None)
    return out


def test_secrets_never_in_plaintext_outside_secret_value():
    conn, _ = _secret_setup()
    views = [r[0] for r in rows(conn, "SELECT name FROM sqlite_master WHERE type = 'view'")]
    assert {"v_host", "v_service", "v_claim", "v_mention", "v_inbox", "v_keystep"} <= set(views)
    for v in views:
        text = "\n".join(_all_strings(conn, f"SELECT * FROM {v}"))
        assert CANARY not in text, v
        assert "aad3b435b51404eeaad3b435b51404ee" not in text, v
    tables = [r[0] for r in rows(conn, "SELECT name FROM sqlite_master WHERE type = 'table'")]
    for t in tables:
        if t in ("secret_value",):
            continue
        assert CANARY not in "\n".join(_all_strings(conn, f"SELECT * FROM {t}")), t
    assert ("password", CANARY) in rows(conn, "SELECT kind, value FROM secret_value")


def test_secret_identifiers_and_claim_keys_use_hmac():
    conn, _ = _secret_setup()
    h = secret_key(PROJECT_KEY, "password", CANARY)
    ident = f"secret:password|h:{h}"
    c = claims(conn, "secret.kind")
    (row,) = c.values()
    assert row["subject_identifier"] == ident and row["is_secret"] == 1
    expected = secret_key(PROJECT_KEY, "claim", canonical_json([ident, "secret.kind", "password"]))
    assert row["claim_key"] == expected
    vc = rows(conn, "SELECT value_text, value_json FROM v_claim WHERE predicate = 'identity.secret'")
    assert vc == [(MASK, None)]
    masked = rows(conn, "SELECT value_type, value FROM v_mention ORDER BY value_type")
    assert masked == [("crypt", MASK), ("hash32", MASK)]
    assert rows(conn, "SELECT COUNT(*) FROM mention WHERE value IS NOT NULL") == [(0,)]


def test_views_mask_literally():
    assert VIEWS_SQL.count(MASK) >= 2
