"""Findings über echte HTTP-Anfragen gegen den echten Server (E113, web-api.md 18.5): Anlegen mit
Belegen und «angelegt aus», Ändern, Belege hinzufügen und entfernen, Schwere nur vom Menschen
(``final`` braucht eine), ATT&CK und CVE als Hypothese, Löschen als Entscheid und Wiederherstellen,
Nummern, Belegzustand nach Rückgängig pro Befehl, Übersteht ``ariadne reparse``, alle oder keiner,
feindliche Titel, Änderungsfeed ``finding``."""

from __future__ import annotations

import urllib.parse

import pytest

from ariadne.daemon.ingest import IngestService
from tests.core.fakeshim import ctl_ok
from tests.web.api.helpers import HOSTILE, TARGET, build_fixture, sync
from tests.web.server.helpers import Web, run_web

pytestmark = pytest.mark.web

HOST = f"ip:default/{TARGET}"
SVC445 = f"svc:{HOST}|tcp/445"


def _web(paths, operator, scenario) -> None:
    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))


class Client:
    def __init__(self, web: Web, token: str, pid: str) -> None:
        self.web, self.token, self.pid = web, token, pid

    async def get(self, path: str):
        return await self.web.req("GET", f"/api/v1/p/{self.pid}{path}", token=self.token)

    async def decide(self, *decisions: dict):
        return await self.web.req(
            "POST", f"/api/v1/p/{self.pid}/decisions", token=self.token,
            json_body={"decisions": list(decisions)},
        )


def _d(kind: str, **payload) -> dict:
    return {"kind": kind, "payload": payload}


async def _sources(c: Client, claim_key: str) -> dict:
    r = await c.get(f"/facts/{claim_key}/sources")
    assert r.status_code == 200, r.text
    return r.json()


def test_findings_lifecycle_validation_and_reparse(paths, operator):
    async def scenario(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, inputs=False)
        token = await web.login()
        c = Client(web, token, fx.pid)
        assert (await c.get("/findings")).json() == {"findings": []}
        detail = (await c.get(f"/hosts/{urllib.parse.quote(HOST, safe='')}")).json()
        fact = next(
            f for f in detail["facts"] if f["subject"] == SVC445 and f["predicate"] == "service.product"
        )
        src = (await _sources(c, fact["claim_key"]))["sources"][0]
        unit_id, lines = src["unit_id"], src["lines"]
        assert lines is not None
        head = d.project.journal.head()[0]

        # --- Prüfung: 422 mit eigenen Typen, 409 für unbekannte Bezüge, nichts geschrieben
        cases = [
            (_d("d.finding.create", title="x", status="final"), 422, "severity_required"),
            (_d("d.finding.create", title="x", attack=[{"id": "X1190"}]), 422, "attack"),
            (_d("d.finding.create", title="x", cves=[{"id": "CVE-11-1"}]), 422, "cve"),
            (_d("d.finding.create", title="x", affected=[""]), 422, "subject"),
            (_d("d.finding.create", title="zwei\nzeilen"), 422, None),
            (_d("d.finding.create", title="x", severity="katastrophal"), 422, None),
            (_d("d.finding.create", title="x", unbekannt=1), 422, None),
            (_d("d.finding", title="alt"), 422, "kind"),
            (_d("d.finding.create", title="x", affected=["ip:default/10.9.9.9"]), 409, None),
            (_d("d.finding.create", title="x", evidence=[{"claim_key": "0" * 64}]), 409, None),
            (_d("d.finding.create", title="x", evidence=[{"unit_id": "gibts-nicht"}]), 409, None),
            (_d("d.finding.create", title="x", evidence=[{"unit_id": unit_id, "lines": [5, 2]}]), 422, None),
            (_d("d.finding.update", finding_id="0199aaaa-0000-7000-8000-000000000000", title="y"), 409, None),
        ]
        for dec, status, typ in cases:
            r = await c.decide(dec)
            assert r.status_code == status, (dec, r.text)
            if typ is not None:
                assert typ in {x["type"] for x in r.json()["error"].get("detail") or []}, r.text
            assert "katastrophal" not in r.text and "X1190" not in r.text
        other = "0199aaaa-0000-7000-8000-000000000001"
        r = await c.decide(_d("d.finding.create", title="neu"),
                           _d("d.finding.update", finding_id=other, title="y"))
        assert r.status_code == 422 and r.json()["error"]["detail"][0]["type"] == "same_request"
        assert d.project.journal.head()[0] == head

        # --- Anlegen (wie «Als Finding» aus der Belegansicht: Beleg und created_from vorbelegt)
        r = await c.decide(_d(
            "d.finding.create", title="Samba usermap_script", severity="critical", affected=[SVC445],
            description="**Remote** Codeausführung <b>x</b>", attack=[{"id": "T1190", "supported": True}],
            cves=[{"id": "CVE-2007-2447"}], evidence=[{"claim_key": fact["claim_key"]}],
            created_from={"unit_id": unit_id, "lines": lines},
        ))
        assert r.status_code == 201, r.text
        fid = r.json()["results"][0]["decision_id"]
        # Bidi und Zero-Width im Titel: 422 (Korrektur SEC-FIND-1); HTML bleibt erlaubter Text
        r2 = await c.decide(_d("d.finding.create", title=HOSTILE))
        assert r2.status_code == 422 and r2.json()["error"]["detail"][0]["type"] == "title", r2.text
        r2 = await c.decide(_d("d.finding.create", title="<script>alert(1)</script> evil"))
        fid2 = r2.json()["results"][0]["decision_id"]
        await sync(d)
        lst = (await c.get("/findings")).json()["findings"]
        assert [f["ordinal"] for f in lst] == [1, 2]
        f1 = lst[0]
        assert f1["finding_id"] == fid and f1["severity"] == "critical" and f1["status"] == "draft"
        assert f1["affected"] == [{"subject": SVC445, "label": f"{TARGET}:445 netbios-ssn", "ctrl": False}]
        assert f1["evidence_count"] == 1 and f1["warnings"] == []
        assert lst[1]["ctrl"] is False and lst[1]["title"] == "<script>alert(1)</script> evil"
        assert set(lst[1]["warnings"]) == {"no_evidence", "no_severity"}
        det = (await c.get(f"/findings/{fid}")).json()
        assert det["description"].startswith("**Remote**")
        assert det["attack"] == [{"id": "T1190", "supported": True, "hypothesis": False}]
        assert det["cves"] == [{"id": "CVE-2007-2447", "supported": False, "hypothesis": True}]
        (ev,) = det["evidence"]
        assert ev["state"] == "ok" and ev["ref"]["claim_key"] == fact["claim_key"]
        assert ev["evidence_id"].startswith("ev:")
        assert "nmap" in ev["label"] and ev["terminal"]["ordinal"] == 1 and ev["ts"].endswith("Z")
        assert det["created_from"]["unit_id"] == unit_id and det["created_from"]["lines"] == lines
        assert "Zeile" in det["created_from"]["label"]
        assert [h["kind"] for h in det["history"]] == ["d.finding.create"]

        # --- Ändern; final verlangt eine Schwere (auch beim Ändern)
        r = await c.decide(_d("d.finding.update", finding_id=fid2, status="final"))
        assert r.status_code == 422 and r.json()["error"]["detail"][0]["type"] == "severity_required"
        r = await c.decide(
            _d("d.finding.update", finding_id=fid, status="final", remediation="Samba patchen")
        )
        assert r.status_code == 201, r.text
        # Beleg hinzufügen (Einheit mit Zeilen), doppelt ergibt 409, alle oder keiner
        r = await c.decide(_d("d.finding.evidence.add", finding_id=fid, unit_id=unit_id, lines=[0, 1]))
        assert r.status_code == 201, r.text
        head = d.project.journal.head()[0]
        r = await c.decide(_d("d.finding.update", finding_id=fid, title="neu"),
                           _d("d.finding.evidence.add", finding_id=fid, unit_id=unit_id, lines=[0, 1]))
        assert r.status_code == 409 and d.project.journal.head()[0] == head
        await sync(d)
        det = (await c.get(f"/findings/{fid}")).json()
        assert det["status"] == "final" and det["remediation"] == "Samba patchen"
        assert [e["state"] for e in det["evidence"]] == ["ok", "ok"]
        claim_ev = det["evidence"][0]["evidence_id"]

        # --- Rückgängig pro Befehl: Belege aus dem nmap-Befehl werden «distrusted», Hypothese zurück
        cmd_id = next(
            i["cmd"]["cmd_id"] for i in (await c.get("/timeline")).json()["items"]
            if i["type"] == "command" and i["unit_id"] == unit_id
        )
        r = await c.decide(_d("d.unit.distrust", cmd_id=cmd_id))
        assert r.status_code == 201, r.text
        distrust_id = r.json()["results"][0]["decision_id"]
        await sync(d)
        det = (await c.get(f"/findings/{fid}")).json()
        assert {e["state"] for e in det["evidence"]} == {"distrusted"}
        assert "evidence_distrusted" in det["warnings"] and det["attack"][0]["hypothesis"] is True
        await c.decide(_d("d.revoke", decision_id=distrust_id))
        await sync(d)
        assert {e["state"] for e in (await c.get(f"/findings/{fid}")).json()["evidence"]} == {"ok"}

        # --- Beleg entfernen; unbekannter Beleg 409
        r = await c.decide(_d("d.finding.evidence.remove", finding_id=fid, evidence_id=claim_ev))
        assert r.status_code == 201, r.text
        r = await c.decide(_d("d.finding.evidence.remove", finding_id=fid, evidence_id=claim_ev))
        assert r.status_code == 409

        # --- Änderungsfeed: Entität finding
        gen = (await web.req("GET", "/api/v1/status", token=token)).json()["generation"]
        await c.decide(_d("d.finding.update", finding_id=fid2, severity="low"))
        await sync(d)
        ch = (await c.get(f"/changes?since={gen}")).json()["changes"]
        assert {"entity": "finding", "entity_key": fid2} in [
            {"entity": x["entity"], "entity_key": x["entity_key"]} for x in ch
        ]

        # --- Löschen als Entscheid, Wiederherstellen per d.revoke, Nummern bleiben
        r = await c.decide(_d("d.finding.delete", finding_id=fid, reason="Duplikat"))
        assert r.status_code == 201, r.text
        delete_id = r.json()["results"][0]["decision_id"]
        await sync(d)
        assert [f["ordinal"] for f in (await c.get("/findings")).json()["findings"]] == [2]
        assert (await c.get(f"/findings/{fid}")).status_code == 404
        assert (await c.decide(_d("d.finding.update", finding_id=fid, title="x"))).status_code == 409
        assert (await c.decide(_d("d.finding.delete", finding_id=fid))).status_code == 409
        await c.decide(_d("d.revoke", decision_id=delete_id))
        await sync(d)
        before = (await c.get(f"/findings/{fid}")).json()
        assert before["ordinal"] == 1 and before["status"] == "final"

        # --- Übersteht ariadne reparse (gleiche Kennungen, Belege, Zustände)
        await ctl_ok(paths.ctl_sock, "reparse")
        await sync(d)
        after = (await c.get(f"/findings/{fid}")).json()
        assert after == before
        assert (await c.get("/findings/nicht-hex!")).status_code == 404
        for s in fx.shims:
            await s.close()

    _web(paths, operator, scenario)
