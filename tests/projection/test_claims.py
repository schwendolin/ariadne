"""Claims: Schlüssel, Normalisierung, Konfidenz, Ersetzen pro (Einheit, Parser)."""

from __future__ import annotations

import hashlib

import pytest

from ariadne.events import canonical_json
from ariadne.ingest.claims import combine, effective_confidence
from ariadne.parsers.api import Mention, Obs, Ref, Span
from tests.parsers.helpers import make_unit
from tests.projection.helpers import apply_items, claims, new_projector, rows

H = Ref.ip("192.168.56.101")
SP = Span(0, 0)


def test_claim_key_is_sha256_over_canonical_triple():
    conn, p = new_projector()
    apply_items(p, make_unit("x"), [Obs(H, "host.os", "Linux 2.6", SP)])
    p.rebuild()
    (key,) = [r[0] for r in rows(conn, "SELECT claim_key FROM claim")]
    expected = hashlib.sha256(
        canonical_json(["ip:default/192.168.56.101", "host.os", "Linux 2.6"])
    ).hexdigest()
    assert key == expected


def test_values_are_normalized_before_keying():
    conn, p = new_projector()
    u1, u2 = make_unit("x", unit_id="u1"), make_unit("x", unit_id="u2")
    apply_items(
        p,
        u1,
        [
            Obs(H, "host.mac", "08-00-27-63-7E-E7", SP),
            Obs(Ref("ip:default/::ffff:192.168.56.101"), "host.address", "192.168.56.101", SP),
        ],
    )
    apply_items(p, u2, [Obs(H, "host.mac", "08:00:27:63:7e:e7", SP)])
    p.rebuild()
    c = claims(conn)
    assert ("ip:default/192.168.56.101", "host.mac", "08:00:27:63:7e:e7") in c
    assert c[("ip:default/192.168.56.101", "host.mac", "08:00:27:63:7e:e7")]["sources"] == 2
    assert ("ip:default/192.168.56.101", "host.address", "192.168.56.101") in c


@pytest.mark.parametrize(
    "trust,base",
    [("structured", 0.95), ("tool_text", 0.85), ("heuristic", 0.4), ("ai", 0.5), ("ocr", 0.5), ("user", 1.0)],
)
def test_base_confidence(trust, base):
    assert effective_confidence(trust, None) == base
    assert effective_confidence(trust, 1.5) == base  # Parser dürfen nur senken
    assert effective_confidence(trust, 0.3) == min(base, 0.3)


def test_noisy_or_capped():
    assert combine([0.4, 0.4]) == pytest.approx(0.64)
    assert combine([0.95, 0.85]) == 0.99
    assert combine([]) == 0.0


def test_confidence_per_unit_max_then_noisy_or():
    conn, p = new_projector()
    u1, u2 = make_unit("x", unit_id="u1"), make_unit("x", unit_id="u2")
    svc = Ref.service(H, "tcp", 21)
    apply_items(
        p,
        u1,
        [
            Obs(svc, "service.name", "ftp", SP, confidence=0.3),
            Obs(svc, "service.name", "ftp", Span(1, 1), confidence=0.5),
        ],
        trust="tool_text",
    )
    p.rebuild()
    assert claims(conn)[(svc.key, "service.name", "ftp")]["confidence"] == 0.5
    apply_items(p, u2, [Obs(svc, "service.name", "ftp", SP, confidence=0.3)], trust="structured")
    p.rebuild()
    assert claims(conn)[(svc.key, "service.name", "ftp")]["confidence"] == pytest.approx(1 - 0.5 * 0.7)


def test_apply_unit_replaces_only_same_parser():
    conn, p = new_projector()
    u = make_unit("x")
    apply_items(p, u, [Obs(H, "host.os", "A", SP)], parser_id="p1")
    apply_items(p, u, [Obs(H, "host.name", "a.lab", SP)], parser_id="p2")
    apply_items(p, u, [Obs(H, "host.os", "B", SP)], parser_id="p1")
    p.rebuild()
    c = claims(conn)
    assert (H.key, "host.os", "B") in c and (H.key, "host.os", "A") not in c
    assert (H.key, "host.name", "a.lab") in c


def test_invalid_items_are_dropped():
    conn, p = new_projector()
    u = make_unit("x")
    bad = [
        Obs(H, "no.such.predicate", "x", SP),
        Obs(H, "host.address", "999.1.1.1", SP),
        Obs(H, "host.mac", "zz:zz", SP),
        Obs(H, "host.os", True, SP),
        Obs(H, "host.os", "", SP),
        Obs(Ref("bogus"), "host.os", "x", SP),
        Obs(Ref.service(H, "icmp", 1), "service.state", "open", SP),
        Obs(H, "host.os", "x", SP, attrs={"k": 1}),  # type: ignore[dict-item]
        {"subject": H.key, "predicate": "host.os", "value": "x", "span": {"line_start": 3, "line_end": 1}},
        {"subject": H.key, "predicate": "host.os", "value": "x", "span": {"line_start": -1, "line_end": 1}},
        {
            "subject": H.key,
            "predicate": "host.os",
            "value": "x",
            "span": {"line_start": 0, "line_end": 0},
            "confidence": "high",
        },
        Mention("ip", "not-an-ip", SP),
        Mention("bad type!", "x", SP),
        "garbage",
    ]
    assert apply_items(p, u, bad) == 0
    assert rows(conn, "SELECT COUNT(*) FROM observation") == [(0,)]


def test_worker_dicts_are_accepted():
    conn, p = new_projector()
    items = [Obs(H, "host.os", "Linux", SP).to_dict(), Mention("ip", "192.168.56.7", SP).to_dict()]
    assert apply_items(p, make_unit("x"), items) == 2


def test_subject_stays_observed_identifier_after_merge():
    conn, p = new_projector()
    a, b = Ref.ip("192.168.56.10"), Ref.ip("192.168.56.11")
    apply_items(
        p,
        make_unit("x"),
        [
            Obs(a, "host.mac", "00:11:22:33:44:55", SP),
            Obs(b, "host.mac", "00:11:22:33:44:55", SP),
            Obs(b, "host.os", "L", SP),
        ],
    )
    p.rebuild()
    c = claims(conn)
    os_claim = c[(b.key, "host.os", "L")]
    assert os_claim["subject_identifier"] == b.key
    assert os_claim["entity_id"] == a.key  # stärkste Kennung der gemeinsamen Entität
