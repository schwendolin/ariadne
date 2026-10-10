"""Status-Achsen, progress, Faden, Generation und Änderungsfeed, Transaktionen."""

from __future__ import annotations

import json
import sqlite3

import pytest

from ariadne.ingest.projection import Projector, ensure_schema
from ariadne.parsers.api import Mention, Obs, Ref, Span
from tests.parsers.helpers import make_unit
from tests.projection import helpers
from tests.projection.helpers import (
    PROJECT_KEY,
    FakeScope,
    apply_items,
    claims,
    dec,
    entity,
    inbox,
    new_projector,
)

SP = Span(0, 0)
H = Ref.ip("192.168.56.101")
S22 = Ref.service(H, "tcp", 22)


def _host(conn):
    return entity(conn, H.key)


@pytest.mark.parametrize(
    "items,trust,knowledge,progress",
    [
        ([Mention("ip", "192.168.56.101", SP)], "heuristic", "mentioned", 0),
        ([Obs(H, "host.state", "up", SP)], "structured", "discovered", 1),
        ([Obs(S22, "service.state", "open", SP)], "tool_text", "scanned", 2),
        ([Obs(S22, "service.product", "OpenSSH", SP)], "structured", "versions", 3),
    ],
)
def test_knowledge_and_progress(items, trust, knowledge, progress):
    conn, p = new_projector()
    apply_items(p, make_unit("x"), items, trust=trust)
    p.rebuild()
    h = _host(conn)
    assert (h["knowledge"], h["access"], h["work"], h["progress"]) == (knowledge, "none", "open", progress)


def test_access_from_keysteps_claims_and_override():
    conn, p = new_projector()
    apply_items(
        p,
        make_unit("x"),
        [Obs(S22, "service.product", "OpenSSH", SP), Obs(H, "access.callback", "nc:4444", SP)],
        trust="tool_text",
    )
    p.rebuild()
    assert (_host(conn)["access"], _host(conn)["progress"]) == ("none", 3)  # Kandidat zählt nicht
    k = claims(conn, "access.callback")[(H.key, "access.callback", "nc:4444")]["claim_key"]
    p.apply_decision(dec(10, "d.claim.confirm", claim_key=k))
    p.rebuild()
    assert (_host(conn)["access"], _host(conn)["progress"]) == ("user", 4)
    p.apply_decision(dec(11, "d.keystep.mark", step="privesc", host=H.key))
    p.rebuild()
    assert (_host(conn)["access"], _host(conn)["progress"]) == ("admin", 5)
    p.apply_decision(dec(12, "d.status.access", subject=H.key, value="none"))
    p.rebuild()
    assert (_host(conn)["access"], _host(conn)["progress"]) == ("none", 3)


def test_work_tags_note_and_orphans():
    conn, p = new_projector()
    apply_items(p, make_unit("x"), [Obs(H, "host.state", "up", SP)])
    for d in (
        dec(1, "d.status.work", subject=H.key, value="dead_end", reason="nichts offen"),
        dec(2, "d.tag.add", subject=H.key, tag="web"),
        dec(3, "d.tag.add", subject=H.key, tag="dmz"),
        dec(4, "d.tag.remove", subject=H.key, tag="web"),
        dec(5, "d.note.set", subject=H.key, text="# Notiz"),
        dec(6, "d.status.work", subject="ip:default/192.168.56.250", value="done"),
    ):
        p.apply_decision(d)
    p.rebuild()
    h = _host(conn)
    assert (h["work"], h["work_reason"], json.loads(h["tags_json"]), h["note"]) == (
        "dead_end",
        "nichts offen",
        ["dmz"],
        "# Notiz",
    )
    assert h["progress"] == 1  # work ändert progress nie
    assert [o["payload"]["reason"] for o in inbox(conn, "orphan_decision")] == ["Subjekt unbekannt"]


def test_thread_from_keysteps_with_terminal_context():
    conn, p = new_projector()
    seg = make_unit(
        "x",
        kind="segment",
        unit_id="s1",
        terminal_id="t1",
        start=500,
        context={"kind": "revshell", "opened_at": 400, "host": "ip:default/192.168.56.101"},
    )
    apply_items(p, seg, [], parser_id="regex.net", trust="heuristic")
    p.apply_decision(dec(20, "d.keystep.mark", step="foothold", terminal_id="t1", stream_off=500))
    p.apply_decision(dec(21, "d.keystep.mark", step="privesc", host="ip:default/192.168.56.101", note="sudo"))
    p.apply_decision(dec(22, "d.keystep.mark", step="loot", host="name:Web02.lab"))
    p.rebuild()
    ks = [tuple(r) for r in conn.execute("SELECT ordinal, step, host_ident, entity_id, note FROM v_keystep")]
    assert ks == [
        (1, "foothold", H.key, H.key, None),
        (2, "privesc", H.key, H.key, "sudo"),
        (3, "loot", "fqdn:web02.lab", "fqdn:web02.lab", None),
    ]
    assert _host(conn)["progress"] == 5


def test_generation_and_delta():
    conn, p = new_projector()
    assert p.generation == 0
    apply_items(p, make_unit("x", unit_id="u1"), [Obs(H, "host.state", "up", SP)])
    g1 = p.rebuild()
    assert g1 == 1
    first = p.changes_since(0)
    assert ("host", H.key, "added") in {(e, k, c) for _, e, k, c in first}
    assert any(e == "claim" and c == "added" for _, e, _, c in first)
    assert any(e == "inbox" for _, e, _, _ in first)
    g2 = p.rebuild()
    assert g2 == 2 and p.changes_since(g1) == []  # nichts geändert, Generation trotzdem erhöht
    apply_items(p, make_unit("x", unit_id="u2"), [Obs(S22, "service.state", "open", SP)])
    g3 = p.rebuild()
    ch = {(e, k, c) for _, e, k, c in p.changes_since(g2)}
    assert ("service", f"svc:{H.key}|tcp/22", "added") in ch
    assert ("host", H.key, "updated") in ch
    p.clear_unit("u2")
    p.rebuild()
    ch = {(e, k, c) for _, e, k, c in p.changes_since(g3)}
    assert ("service", f"svc:{H.key}|tcp/22", "removed") in ch


def test_rebuild_is_deterministic():
    def run():
        conn, p = new_projector()
        apply_items(
            p,
            make_unit("x", unit_id="u1"),
            [
                Obs(H, "host.mac", "00:11:22:33:44:55", SP),
                Obs(Ref.ip("192.168.56.7"), "host.mac", "00:11:22:33:44:55", SP),
                Obs(S22, "service.state", "open", SP),
            ],
        )
        p.rebuild()
        return [
            list(conn.execute(f"SELECT * FROM {t} ORDER BY 1"))
            for t in ("entity", "claim", "identifier", "inbox_item", "conflict")
        ]

    assert run() == run()


def test_savepoints_respect_outer_transaction():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    helpers.OPEN.append(conn)
    p = Projector(conn, project_key=PROJECT_KEY, scope=FakeScope())
    conn.execute("BEGIN")
    apply_items(p, make_unit("x"), [Obs(H, "host.state", "up", SP)])
    p.rebuild()
    assert conn.in_transaction
    conn.execute("ROLLBACK")
    assert conn.execute("SELECT COUNT(*) FROM observation").fetchone() == (0,)
    assert p.generation == 0


def test_failed_apply_rolls_back():
    conn, p = new_projector()

    def boom():
        yield Obs(H, "host.state", "up", SP)
        raise RuntimeError("Worker kaputt")

    with pytest.raises(RuntimeError):
        apply_items(p, make_unit("x"), boom())
    assert conn.execute("SELECT COUNT(*) FROM observation").fetchone() == (0,)
    assert conn.execute("SELECT COUNT(*) FROM obs_unit").fetchone() == (0,)


def test_schema_idempotent_and_key_required():
    conn = sqlite3.connect(":memory:")
    helpers.OPEN.append(conn)
    ensure_schema(conn)
    ensure_schema(conn)
    with pytest.raises(ValueError):
        Projector(conn, project_key=b"short", scope=FakeScope())
    with pytest.raises(ValueError):
        Projector(conn, project_key=PROJECT_KEY, scope=FakeScope()).apply_unit(
            make_unit("x"),
            parser_id="p",
            parser_version="1",
            trust="magic",
            auto_eligible=False,
            journal_seq=1,
            items=[],
        )


def test_works_with_sqlcipher(tmp_path):
    sqlcipher3 = pytest.importorskip("sqlcipher3")
    conn = sqlcipher3.connect(str(tmp_path / "derived.db"))
    conn.execute("PRAGMA key = \"x'" + "ab" * 32 + "'\"")
    p = Projector(conn, project_key=PROJECT_KEY, scope=FakeScope())
    apply_items(
        p, make_unit("x"), [Obs(H, "host.state", "up", SP), Obs(S22, "service.product", "OpenSSH", SP)]
    )
    p.apply_decision(dec(5, "d.keystep.mark", step="foothold", host=H.key))
    assert p.rebuild() == 1
    conn.commit()
    row = conn.execute("SELECT progress, knowledge FROM v_host").fetchone()
    assert tuple(row) == (4, "versions")
    assert conn.execute("SELECT ordinal FROM v_keystep").fetchone()[0] == 1
    conn.close()
    assert b"SQLite format 3" not in (tmp_path / "derived.db").read_bytes()[:16]


def test_without_scope_everything_is_unknown():
    conn = sqlite3.connect(":memory:")
    helpers.OPEN.append(conn)
    p = Projector(conn, project_key=PROJECT_KEY, scope=None)
    p.apply_decision(dec(1, "d.automode.set", enabled=True))
    apply_items(p, make_unit("x"), [Obs(H, "host.state", "up", SP)], journal_seq=5)
    p.rebuild()
    assert {c["state"] for c in claims(conn).values()} == {"candidate"}
    assert entity(conn, H.key)["scope"] == "unknown"
