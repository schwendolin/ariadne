"""Zustand der Denkanstösse (web-api.md 18.6): verwerfen gilt für immer, erledigt nur, solange der
Anlass gleich bleibt, ``d.revoke`` öffnet wieder, alles übersteht Reparse und Merge. Dazu
:func:`ariadne.rules.api.check_decision` mit allen Codes."""

from __future__ import annotations

import pytest

from ariadne.parsers.api import Obs, Ref, Span
from ariadne.rules import api as rules_api
from ariadne.rules.engine import evaluate, suggestion_key
from tests.parsers.helpers import make_unit
from tests.projection.helpers import FakeScope, apply_items, dec, new_projector
from tests.rules import helpers as H

U = H.MS2


def _find(items: list[dict], rule_id: str, needle: str = "") -> dict:
    return next(s for s in items if s["rule_id"] == rule_id and needle in s["title"])


def _states(conn) -> dict[str, str]:
    return {s["suggestion_key"]: s["state"] for s in H.suggestions(conn, state="all")}


def test_dismiss_is_permanent_and_revoke_reopens():
    conn, p = H.ms2(scripts=False)
    sg = _find(H.suggestions(conn), "R-ANON-ZUGRIFF", ":21 ")
    H.decide(p, 100, "d.suggestion.dismiss", suggestion_key=sg["suggestion_key"], reason="kein FTP im Lab")
    assert sg["suggestion_key"] not in {s["suggestion_key"] for s in H.suggestions(conn)}
    (gone,) = [s for s in H.suggestions(conn, state="dismissed")]
    assert gone["suggestion_key"] == sg["suggestion_key"] and gone["decision_id"] == "dec-100"
    assert gone["state"] == "dismissed" and rules_api.open_count(conn, profile="lab") == 21
    # neuer Anlass (andere Version) ändert nichts am Verwerfen
    apply_items(
        p,
        make_unit("x", unit_id="u2", ts=H.T0 + 10**12),
        [Obs(Ref.service(Ref.ip(U), "tcp", 21), "service.product", "ProFTPD", Span(0, 0))],
        journal_seq=50,
    )
    p.rebuild()
    changed = _find(H.suggestions(conn, state="all"), "R-ANON-ZUGRIFF", ":21 ")
    assert changed["basis"] != sg["basis"] and changed["state"] == "dismissed"
    H.decide(p, 101, "d.revoke", decision_id="dec-100")
    assert _states(conn)[sg["suggestion_key"]] == "open"
    H.decide(p, 102, "d.revoke", decision_id="dec-101")  # Widerruf des Widerrufs
    assert _states(conn)[sg["suggestion_key"]] == "dismissed"


def test_done_holds_while_basis_is_unchanged_and_reopens_on_new_reason():
    conn, p = new_projector(FakeScope(nets=["192.168.56.0/24"]), own=[H.KALI])
    h = Ref.ip("192.168.56.110")
    sp = Span(0, 0)

    def scan(uid: str, ports: list[int], seq: int) -> None:
        items = [Obs(h, "host.state", "up", sp)]
        for port in ports:
            s = Ref.service(h, "tcp", port)
            items += [Obs(s, "service.state", "open", sp), Obs(s, "service.name", "netbios-ssn", sp)]
        apply_items(
            p,
            make_unit("x", cmd="nmap -sV 192.168.56.110", unit_id=uid, ts=H.T0 + seq),
            items,
            journal_seq=seq,
        )
        p.rebuild()

    scan("s1", [139], 10)
    sg = _find(H.suggestions(conn), "R-SMB-SHARES")
    assert sg["reason"] == "SMB auf Port 139 ohne Liste der Shares"
    H.decide(p, 100, "d.suggestion.done", suggestion_key=sg["suggestion_key"], basis=sg["basis"])
    done = _find(H.suggestions(conn, state="done"), "R-SMB-SHARES")
    assert done["state"] == "done" and done["decision_id"] == "dec-100"
    scan("s2", [139], 20)  # derselbe Anlass noch einmal gesehen: bleibt erledigt
    assert _states(conn)[sg["suggestion_key"]] == "done"
    scan("s3", [139, 445], 30)  # neuer Anlass: Port 445 dazu
    again = _find(H.suggestions(conn), "R-SMB-SHARES")
    assert again["suggestion_key"] == sg["suggestion_key"] and again["basis"] != sg["basis"]
    assert again["state"] == "open" and again["decision_id"] is None


def test_state_survives_rebuild_and_full_reparse():
    """Der Zustand steht nur in den Entscheiden: neu gebaute Projektion (Reparse) mit denselben Einheiten
    und Entscheiden ergibt denselben Zustand."""
    conn, p = H.ms2(scripts=False)
    items = H.suggestions(conn)
    anon = _find(items, "R-ANON-ZUGRIFF", ":21 ")
    ver = _find(items, "R-VERSION-RECHERCHE", "vsftpd")
    decisions = [
        dec(100, "d.suggestion.dismiss", suggestion_key=anon["suggestion_key"]),
        dec(101, "d.suggestion.done", suggestion_key=ver["suggestion_key"], basis=ver["basis"]),
    ]
    for d in decisions:
        p.apply_decision(d)
    p.rebuild()
    before = _states(conn)
    p.rebuild()
    assert _states(conn) == before
    conn2, _p2 = H.ms2(scripts=False, decisions=decisions)  # Reparse: alles neu aus Einheiten und Journal
    after = _states(conn2)
    assert after == before
    assert after[anon["suggestion_key"]] == "dismissed" and after[ver["suggestion_key"]] == "done"


def test_aliases_keep_decisions_across_identifiers():
    """Ein Entscheid auf einen Schlüssel aus einer anderen Kennung desselben Hosts gilt (Merge)."""
    conn, p = H.ms2(scripts=False)
    f, built = evaluate(conn, profile="lab")
    full = next(b for b in built if b.cand.rule.rule_id == "R-FULL-PORTSCAN")
    assert full.aliases  # MAC, Namen … des Hosts
    mac_key = suggestion_key("R-FULL-PORTSCAN", ("mac:08:00:27:63:7e:e7",))
    assert mac_key in full.aliases
    H.decide(p, 100, "d.suggestion.dismiss", suggestion_key=mac_key)
    assert _states(conn)[full.key] == "dismissed"
    svc = next(b for b in built if b.cand.rule.rule_id == "R-WEB-INHALT")
    assert svc.aliases == tuple(sorted(svc.aliases)) and all(a.startswith("sg:") for a in svc.aliases)


def test_merge_keeps_dismissed_state():
    conn, p = new_projector(FakeScope(nets=["192.168.56.0/24", "fd00:56::/64"]), own=[H.KALI])
    sp = Span(0, 0)
    v4, v6 = Ref.ip("192.168.56.110"), Ref.ip("fd00:56::110")
    items = [Obs(v4, "host.state", "up", sp)]
    s = Ref.service(v4, "tcp", 445)
    items += [Obs(s, "service.state", "open", sp), Obs(s, "service.name", "microsoft-ds", sp)]
    items += [Obs(v6, "host.state", "up", sp)]
    s6 = Ref.service(v6, "tcp", 22)
    items += [Obs(s6, "service.state", "open", sp), Obs(s6, "service.name", "ssh", sp)]
    apply_items(p, make_unit("x", cmd="nmap 192.168.56.110 fd00:56::110", unit_id="s1", ts=H.T0), items)
    p.rebuild()
    full = {x["host_id"]: x for x in H.by_rule(H.suggestions(conn), "R-FULL-PORTSCAN")}
    assert full["ip:default/fd00:56::110"]["templates"][0]["command"] == "nmap -6 -p- -T4 fd00:56::110"
    # verworfen am IPv6-Host, dann zusammengeführt: der gemeinsame Host trägt die IPv4-Kennung
    H.decide(p, 100, "d.suggestion.dismiss", suggestion_key=full["ip:default/fd00:56::110"]["suggestion_key"])
    H.decide(p, 101, "d.entity.merge", identifiers=["ip:default/192.168.56.110", "ip:default/fd00:56::110"])
    (merged,) = H.by_rule(H.suggestions(conn, state="all"), "R-FULL-PORTSCAN")
    assert merged["host_id"] == "ip:default/192.168.56.110" and merged["state"] == "dismissed"
    assert merged["suggestion_key"] == full["ip:default/192.168.56.110"]["suggestion_key"]
    assert merged["decision_id"] == "dec-100"


def test_suggestions_state_filter_limit_and_truncated():
    conn, p = H.ms2(scripts=False)
    every, tr = rules_api.suggestions(conn, profile="lab", state="all", limit=200)
    assert len(every) == 22 and tr is False
    few, tr = rules_api.suggestions(conn, profile="lab", state="open", limit=3)
    assert [s["suggestion_key"] for s in few] == [s["suggestion_key"] for s in every[:3]] and tr is True
    none, tr = rules_api.suggestions(conn, profile="lab", state="done", limit=50)
    assert none == [] and tr is False
    with pytest.raises(ValueError):
        rules_api.suggestions(conn, profile="lab", state="bogus", limit=5)  # type: ignore[arg-type]
    assert rules_api.suggestions(conn, profile="lab", limit=0) == ([], True)


# --------------------------------------------------------------------------- check_decision


def test_check_decision_codes():
    conn, p = H.ms2(scripts=False)
    items = H.suggestions(conn)
    anon = _find(items, "R-ANON-ZUGRIFF", ":21 ")
    ver = _find(items, "R-VERSION-RECHERCHE", "vsftpd")
    check = rules_api.check_decision

    def code(kind: str, **h) -> str | None:
        try:
            check(conn, kind, h, profile="lab")
        except rules_api.RuleRefError as exc:
            return exc.code
        return None

    assert code("d.suggestion.done", suggestion_key=anon["suggestion_key"]) == "basis_required"
    assert code("d.suggestion.done", suggestion_key="sg:" + "0" * 24, basis="x") == "conflict"
    assert code("d.suggestion.dismiss", suggestion_key="sg:" + "0" * 24) == "conflict"
    assert code("d.suggestion.dismiss", suggestion_key="nicht-gültig") == "conflict"
    assert code("d.suggestion.done", suggestion_key=anon["suggestion_key"], basis="0" * 16) == "conflict"
    assert code("d.suggestion.done", suggestion_key=anon["suggestion_key"], basis=anon["basis"]) is None
    assert code("d.suggestion.dismiss", suggestion_key=anon["suggestion_key"]) is None
    assert code("d.claim.confirm", claim_key="x") is None  # andere Arten prüft die Engine nicht
    H.decide(p, 100, "d.suggestion.done", suggestion_key=anon["suggestion_key"], basis=anon["basis"])
    assert code("d.suggestion.done", suggestion_key=anon["suggestion_key"], basis=anon["basis"]) == "conflict"
    assert code("d.suggestion.dismiss", suggestion_key=anon["suggestion_key"]) is None  # erledigt, verwerfen
    H.decide(p, 101, "d.suggestion.dismiss", suggestion_key=ver["suggestion_key"])
    assert code("d.suggestion.dismiss", suggestion_key=ver["suggestion_key"]) == "conflict"  # anderer Tab
    assert code("d.suggestion.done", suggestion_key=ver["suggestion_key"], basis=ver["basis"]) == "conflict"
    # Nebenschlüssel (andere Kennung des Hosts) sind bekannt
    mac_key = suggestion_key("R-FULL-PORTSCAN", ("mac:08:00:27:63:7e:e7",))
    assert code("d.suggestion.dismiss", suggestion_key=mac_key) is None


def test_decisions_validate_in_events_model():
    """``basis`` ist im Modell optional (alte Einträge), die Pflicht prüft check_decision."""
    from ariadne.events import validate_header

    assert validate_header("d.suggestion.done", {"suggestion_key": "sg:" + "a" * 24, "basis": "b" * 16})
    with pytest.raises(Exception):  # noqa: B017
        validate_header("d.suggestion.dismiss", {"suggestion_key": "sg:x", "extra": 1})
