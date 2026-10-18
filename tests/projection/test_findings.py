"""Findings in der Projektion (E113, web-api.md 18.5): aus den Entscheiden ``d.finding.*`` in
Journal-Reihenfolge, Nummern auch für gelöschte, Belegzustand ``ok``/``distrusted``/``missing`` nach
jeder Neuberechnung, Hypothese für ATT&CK und CVE, Änderungsfeed mit der Entität ``finding``."""

from __future__ import annotations

import json
from pathlib import Path

from ariadne.ingest.proj_findings import evidence_id, fold
from tests.parsers.helpers import make_unit
from tests.projection.helpers import FakeScope, dec, feed, new_projector

TESTS = Path(__file__).parents[1]
CMD = "0199a2b3-0000-7000-8000-000000000001@120"
SVC = "svc:ip:default/192.168.56.101|tcp/21"


def _ms2():
    conn, p = new_projector(FakeScope(nets=["192.168.56.0/24"]))
    txt = (TESTS / "golden" / "nmap.text" / "ms2_sv_sc" / "input.txt").read_text()
    feed(p, make_unit(txt, cmd="nmap -sV -sC -oA scans/ms2 192.168.56.101", unit_id="cmd1", ts=1_000,
                      cmd_id=CMD), journal_seq=10)
    p.rebuild()
    return conn, p


def _claim(conn, predicate: str, subject: str) -> str:
    row = conn.execute("SELECT claim_key FROM claim WHERE predicate = ? AND subject_identifier = ? LIMIT 1",
                       (predicate, subject)).fetchone()
    assert row is not None, (predicate, subject)
    return str(row[0])


def _finding(conn, fid: str) -> dict:
    cur = conn.execute("SELECT * FROM finding WHERE finding_id = ?", (fid,))
    names = [d[0] for d in cur.description]
    r = cur.fetchone()
    return dict(zip(names, r, strict=True)) if r else {}


def _evidence(conn, fid: str) -> list[tuple]:
    return [tuple(r) for r in conn.execute(
        "SELECT evidence_id, claim_key, unit_id, line_start, line_end, state FROM finding_evidence "
        "WHERE finding_id = ? ORDER BY pos", (fid,))]


def test_create_update_evidence_delete_revoke_and_numbers():
    conn, p = _ms2()
    ck = _claim(conn, "service.product", SVC)
    seq = 100
    recs = [
        dec(seq + 1, "d.finding.create", did="f-1", title="vsftpd Backdoor", severity="critical",
            affected=[SVC], evidence=[{"claim_key": ck}],
            attack=[{"id": "T1190", "supported": True}], cves=[{"id": "CVE-2011-2523"}]),
        dec(seq + 2, "d.finding.create", did="f-2", title="Zweites"),
        dec(seq + 3, "d.finding.update", finding_id="f-1", status="final", remediation="Patchen"),
        dec(seq + 4, "d.finding.evidence.add", finding_id="f-1", unit_id="cmd1", lines=[0, 2]),
        dec(seq + 5, "d.finding.evidence.add", finding_id="f-1", unit_id="cmd1", lines=[0, 2]),  # doppelt
        dec(seq + 6, "d.finding.delete", did="del-2", finding_id="f-2", reason="falsch"),
        dec(seq + 7, "d.finding.create", did="f-3", title="Drittes"),
    ]
    for r in recs:
        p.apply_decision(r)
    gen = p.rebuild()
    f1 = _finding(conn, "f-1")
    assert f1["ordinal"] == 1 and f1["status"] == "final" and f1["severity"] == "critical"
    assert f1["remediation"] == "Patchen" and f1["deleted"] == 0
    assert json.loads(f1["affected_json"]) == [SVC]
    ev = _evidence(conn, "f-1")
    assert [e[5] for e in ev] == ["ok", "ok"] and len(ev) == 2
    assert ev[0][0] == evidence_id(ck, None, None)
    assert json.loads(f1["attack_json"]) == [{"id": "T1190", "supported": True, "hypothesis": False}]
    assert json.loads(f1["cves_json"]) == [{"id": "CVE-2011-2523", "supported": False, "hypothesis": True}]
    assert [h["kind"] for h in json.loads(f1["history_json"])] == [
        "d.finding.create", "d.finding.update", "d.finding.evidence.add"]
    assert _finding(conn, "f-2")["deleted"] == 1 and _finding(conn, "f-3")["ordinal"] == 3
    keys = {(e, k) for _g, e, k, _c in p.changes_since(gen - 1)}
    assert ("finding", "f-1") in keys and ("finding", "f-3") in keys and ("finding", "f-2") not in keys
    # Rückgängig des Löschens stellt f-2 wieder her; Rückgängig der Anlage von f-3 lässt die Nummer stehen
    p.apply_decision(dec(seq + 8, "d.revoke", decision_id="del-2"))
    p.apply_decision(dec(seq + 9, "d.revoke", decision_id="f-3"))
    p.rebuild()
    assert _finding(conn, "f-2")["deleted"] == 0 and _finding(conn, "f-2")["ordinal"] == 2
    assert _finding(conn, "f-3")["deleted"] == 1
    p.apply_decision(dec(seq + 10, "d.finding.create", did="f-4", title="Viertes"))
    p.rebuild()
    assert _finding(conn, "f-4")["ordinal"] == 4


def test_evidence_states_distrusted_and_missing_and_hypothesis():
    conn, p = _ms2()
    ck = _claim(conn, "service.product", SVC)
    p.apply_decision(dec(101, "d.finding.create", did="f-1", title="T", evidence=[{"claim_key": ck}],
                         attack=[{"id": "T1190", "supported": True}]))
    p.apply_decision(dec(102, "d.finding.evidence.add", finding_id="f-1", unit_id="cmd1", lines=[1, 1]))
    p.apply_decision(dec(103, "d.finding.evidence.add", finding_id="f-1", unit_id="cmd1", lines=[0, 99999]))
    p.apply_decision(dec(104, "d.finding.evidence.add", finding_id="f-1", unit_id="weg", lines=None))
    p.rebuild()
    states = [e[5] for e in _evidence(conn, "f-1")]
    # Zeilen ausserhalb und unbekannte Einheit: missing (ohne Pipeline-Tabellen zählt obs_unit)
    assert states[0] == "ok" and states[1] == "ok" and states[3] == "missing"
    # Rückgängig pro Befehl: Claim nur noch aus misstrauter Quelle, Einheit aus misstrautem Befehl
    p.apply_decision(dec(105, "d.unit.distrust", did="dist", cmd_id=CMD))
    p.rebuild()
    states = [e[5] for e in _evidence(conn, "f-1")]
    assert states[0] == "distrusted" and states[1] == "distrusted"
    assert json.loads(_finding(conn, "f-1")["attack_json"])[0]["hypothesis"] is True
    p.apply_decision(dec(106, "d.revoke", decision_id="dist"))
    p.rebuild()
    assert _evidence(conn, "f-1")[0][5] == "ok"
    assert json.loads(_finding(conn, "f-1")["attack_json"])[0]["hypothesis"] is False


def test_evidence_remove_and_entries_for_unknown_findings_have_no_effect():
    class D:  # wie DecisionRow
        def __init__(self, seq, did, kind, payload, ts=1):
            self.seq, self.id, self.kind, self.payload, self.ts = seq, did, kind, payload, ts

    ev = evidence_id("a" * 64, None, None)
    out = fold([
        D(1, "f", "d.finding.create", {"title": "x", "evidence": [{"claim_key": "a" * 64}]}),
        D(2, "u", "d.finding.update", {"finding_id": "gibtsnicht", "title": "y"}),
        D(3, "r", "d.finding.evidence.remove", {"finding_id": "f", "evidence_id": ev}),
        D(4, "r2", "d.finding.evidence.remove", {"finding_id": "f", "evidence_id": ev}),
    ])
    f = out["f"]
    assert f.title == "x" and f.evidence == {} and [h["decision_id"] for h in f.history] == ["f", "r"]
    assert set(out) == {"f"}
