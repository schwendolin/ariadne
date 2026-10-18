"""Korrekturen nach der Prüfung des Baus v0.1-Oberfläche (über echte HTTP-Anfragen, wo es geht):

* SEC-UI-1/K1: mehrzeiliger Markdown des Menschen (Host-Notiz, Beschreibung und Massnahme eines
  Findings) kommt mit echten Zeilenumbrüchen zurück; Hin- und Rückweg ändern den Text nicht, andere
  Steuerzeichen bleiben sichtbar (``<ESC>``, ``<CR>``).
* SEC-FIND-1: Kennungen ganz und nur mit ASCII-Ziffern, Titel ohne Zeilentrenner und Steuerzeichen,
  ``supported`` nur als echtes bool.
* SEC-RULES-1: eine Vorlage, in der der Redaktor ein eigenes Secret ersetzen würde, ist nicht
  gerendert (``blocked_reason: 'own_secret'``).
* K3: Entscheide zu Findings und Denkanstössen haben feste deutsche Texte in der Zeitachse.
* K5: Gleichzeitige Entscheide auf denselben Bezug ergeben genau einen Treffer und sonst 409;
  derselbe Bezug zweimal in einer Anfrage ist 409.
"""

from __future__ import annotations

import asyncio
import shlex
import urllib.parse

import pytest

from ariadne.daemon.ingest import IngestService
from ariadne.rules import api as rules_api
from ariadne.rules.encoders import Scope
from ariadne.rules.templates import TEMPLATES, render
from ariadne.secrets.redactor import Redactor
from ariadne.web.api import decisions as decisions_mod
from ariadne.web.api.common import guard_templates
from ariadne.web.api.text import Bag, deep_visible, visible_multiline
from ariadne.web.api.timeline import _SUMMARY, _summary
from tests.web.api.helpers import TARGET, build_fixture, sync
from tests.web.server.helpers import Web, run_web

HOST = f"ip:default/{TARGET}"
HOST_Q = urllib.parse.quote(HOST, safe="")


def _web(paths, operator, scenario) -> None:
    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))


def _d(kind: str, **payload) -> dict:
    return {"kind": kind, "payload": payload}


class Client:
    def __init__(self, web: Web, token: str, pid: str) -> None:
        self.web, self.token, self.pid = web, token, pid

    async def get(self, path: str):
        return await self.web.req("GET", f"/api/v1/p/{self.pid}{path}", token=self.token)

    async def decide(self, *decisions: dict):
        return await self.web.req(
            "POST",
            f"/api/v1/p/{self.pid}/decisions",
            token=self.token,
            json_body={"decisions": list(decisions)},
        )


# --------------------------------------------------------------------------- Einheiten


def test_visible_multiline_keeps_lf_and_tab_only():
    assert visible_multiline("a\n\n- b\tc") == "a\n\n- b\tc"
    assert visible_multiline("x\x1b[31m\r\ny‮") == "x<ESC>[31m<CR>\ny<U+202E>"
    assert visible_multiline("ohne") == "ohne"
    b = Bag()
    assert b.text("## Titel\n\n- eins\n- zwei") == "## Titel\n\n- eins\n- zwei" and b.ctrl is False
    assert b.text("a\x07\nb") == "a<BEL>\nb" and b.ctrl is True
    # zweite Schicht: nur die genannten Schlüssel der obersten Ebene bleiben mehrzeilig
    obj = {"note": "a\nb", "label": "c\nd", "inner": {"note": "e\nf"}}
    out = deep_visible(obj, ("note",))
    assert out == {"note": "a\nb", "label": "c<LF>d", "inner": {"note": "e<LF>f"}}
    assert deep_visible(obj) == {"note": "a<LF>b", "label": "c<LF>d", "inner": {"note": "e<LF>f"}}


def test_finding_validation_strict_ids_titles_and_bool():
    bad = [
        {"title": "x", "attack": [{"id": "T1190\n"}]},
        {"title": "x", "attack": [{"id": "T١١٩٠"}]},
        {"title": "x", "cves": [{"id": "CVE-٢٠١١-٢٥٢٣"}]},
        {"title": "x", "cves": [{"id": "CVE-2011-2523\n"}]},
        {"title": "a b"},
        {"title": "a b"},
        {"title": "a\x85b"},
        {"title": "a‮b"},
        {"title": "a\x1bb"},
        {"title": "x", "attack": [{"id": "T1190", "supported": "yes"}]},
        {"title": "x", "attack": [{"id": "T1190", "supported": 1}]},
    ]
    from ariadne import events

    for payload in bad:
        with pytest.raises(ValueError):
            events.validate_header("d.finding.create", payload)
    ok = events.validate_header(
        "d.finding.create",
        {
            "title": "Samba über SMB",
            "attack": [{"id": "T1190.001", "supported": True}],
            "cves": [{"id": "CVE-2011-2523"}],
        },
    )
    assert ok["attack"] == [{"id": "T1190.001", "supported": True}]


def _scope() -> Scope:
    return Scope(ip=lambda ip: "in", name=lambda n: "in")


@pytest.mark.parametrize(
    ("own", "tpl", "values"),
    [
        ("root", "mysql-root-nopass", {"host.ip": "192.168.56.110", "service.port": 3306}),
        ("Geheim4711", "searchsploit", {"service.product": "vsftpd", "service.version": "Geheim4711"}),
    ],
)
def test_template_with_own_secret_is_not_rendered(own, tpl, values):
    red = Redactor([("sudo", own)])
    t = render(TEMPLATES[tpl], values, _scope())
    assert t["rendered"] is True and own in t["command"]  # ohne Schutz käme '****' in den Befehl
    obj = {"suggestions": [{"title": "x", "templates": [t]}]}
    guarded = guard_templates(obj, red)
    sent = deep_visible(red.redact_json(guarded)[0])
    g = sent["suggestions"][0]["templates"][0]
    assert g["rendered"] is False and g["command"] is None and g["parts"] == []
    assert g["blocked_reason"] == "own_secret"
    assert own not in str(sent)
    hit = [v for v in g["values"] if "*" in v["value"]]
    assert all(v["safe"] is False for v in hit)
    # ohne eigenes Secret im Befehl bleibt die Vorlage unverändert (dasselbe Objekt)
    clean = Redactor([("sudo", "ganz-anders-123")])
    assert guard_templates(obj, clean) is obj
    other = render(TEMPLATES[tpl], values, _scope())
    assert shlex.split(other["command"])  # Gegenprobe: gerendert und zerlegbar


def test_every_writable_decision_has_a_fixed_summary():
    """K3: Kein Entscheid der Web-API erscheint mit seiner Kennung in der Zeitachse."""
    skip = {"d.keystep.mark"}  # erscheint als eigener Typ ``keystep``
    for kind in sorted(decisions_mod.WRITABLE - skip):
        text = _summary(kind, {})
        assert text != "Entscheid" and not text.startswith("d."), kind
    assert _SUMMARY["d.finding.update"] == "Finding geändert"


# --------------------------------------------------------------------------- über HTTP


def test_multiline_note_and_finding_round_trip(paths, operator):
    async def scenario(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, inputs=False)
        token = await web.login()
        c = Client(web, token, fx.pid)
        note = "## Vorgehen\n\n- vsftpd Backdoor geprüft\n- Samba als Nächstes\n\n\tCode"
        desc = "Erste Zeile\n\n- Punkt eins\n- Punkt zwei"
        rem = "A\nB"
        r = await c.decide(
            _d("d.note.set", subject=HOST, text=note),
            _d("d.finding.create", title="Mehrzeilig", description=desc, remediation=rem),
        )
        assert r.status_code == 201, r.text
        fid = r.json()["results"][1]["decision_id"]
        await sync(d)
        det = (await c.get(f"/hosts/{HOST_Q}")).json()
        assert det["note"] == note and "<LF>" not in det["note"]
        f = (await c.get(f"/findings/{fid}")).json()
        assert (f["description"], f["remediation"]) == (desc, rem) and f["ctrl"] is False
        # Rückweg wie die Oberfläche: gelesenen Text ändern und speichern, dann wieder lesen
        r = await c.decide(
            _d("d.finding.update", finding_id=fid, description=f["description"] + " ergänzt"),
            _d("d.note.set", subject=HOST, text=det["note"] + "\n- dritter Punkt"),
        )
        assert r.status_code == 201, r.text
        await sync(d)
        f2 = (await c.get(f"/findings/{fid}")).json()
        assert f2["description"] == desc + " ergänzt" and f2["remediation"] == rem
        det2 = (await c.get(f"/hosts/{HOST_Q}")).json()
        assert det2["note"] == note + "\n- dritter Punkt"
        stored = [e.header for e in d.project.journal.iter_events(kinds=["d.finding.update"])]
        assert stored[-1]["description"] == desc + " ergänzt"  # nie «<LF>» im Journal
        # andere Steuerzeichen bleiben sichtbar, auch in mehrzeiligem Text
        r = await c.decide(_d("d.note.set", subject=HOST, text="a\x1b[2J\r\nb‮"))
        assert r.status_code == 201
        await sync(d)
        det3 = (await c.get(f"/hosts/{HOST_Q}")).json()
        assert det3["note"] == "a<ESC>[2J<CR>\nb<U+202E>" and det3["ctrl"] is True
        # sonst bleibt jede Antwort einzeilig: der Titel in der Liste
        lst = (await c.get("/findings")).json()["findings"]
        assert all("\n" not in x["title"] for x in lst)

    _web(paths, operator, scenario)


def test_finding_validation_rejected_over_http(paths, operator):
    async def scenario(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, inputs=False)
        token = await web.login()
        c = Client(web, token, fx.pid)
        head = d.project.journal.head()[0]
        cases = [
            (_d("d.finding.create", title="ID-Test", attack=[{"id": "T1190\n"}]), "attack"),
            (_d("d.finding.create", title="ID-Test", cves=[{"id": "CVE-٢٠١١-٢٥٢٣"}]), "cve"),
            (_d("d.finding.create", title="a b"), "title"),
            (_d("d.finding.create", title="a\x85b"), "title"),
            (_d("d.finding.create", title="x", attack=[{"id": "T1190", "supported": "yes"}]), "attack"),
        ]
        for dec, typ in cases:
            r = await c.decide(dec)
            assert r.status_code == 422, (dec, r.text)
            assert typ in {x["type"] for x in r.json()["error"]["detail"]}, r.text
        assert d.project.journal.head()[0] == head

    _web(paths, operator, scenario)


@pytest.mark.skipif(rules_api.STUB, reason="Regel-Engine noch Stub")
def test_concurrent_dismiss_and_duplicates_and_timeline_texts(paths, operator):
    async def scenario(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, inputs=False)
        token = await web.login()
        c = Client(web, token, fx.pid)
        nx = (await c.get("/next")).json()
        assert len(nx["suggestions"]) >= 2
        first, second = nx["suggestions"][0], nx["suggestions"][1]
        dismiss = _d("d.suggestion.dismiss", suggestion_key=first["suggestion_key"])
        # K5: drei gleichzeitige Anfragen auf denselben Denkanstoss: genau einmal 201
        rs = await asyncio.gather(*(c.decide(dismiss) for _ in range(3)))
        assert sorted(r.status_code for r in rs) == [201, 409, 409], [r.text for r in rs]
        assert len(list(d.project.journal.iter_events(kinds=["d.suggestion.dismiss"]))) == 1
        # Rückgängig öffnet ihn wieder (es gibt keinen zweiten Verwerfen-Entscheid)
        await sync(d)
        got = (await c.get("/suggestions?state=dismissed")).json()["suggestions"]
        did = next(x["decision_id"] for x in got if x["suggestion_key"] == first["suggestion_key"])
        r = await c.decide(_d("d.revoke", decision_id=did))
        assert r.status_code == 201, r.text
        await sync(d)
        nx2 = (await c.get("/next")).json()
        assert first["suggestion_key"] in {x["suggestion_key"] for x in nx2["suggestions"]}
        # derselbe Bezug zweimal in einer Anfrage
        dup = _d("d.suggestion.dismiss", suggestion_key=second["suggestion_key"])
        head = d.project.journal.head()[0]
        r = await c.decide(dup, dup)
        assert r.status_code == 409 and d.project.journal.head()[0] == head
        r = await c.decide(
            _d("d.suggestion.done", suggestion_key=second["suggestion_key"], basis=second["basis"])
        )
        assert r.status_code == 201, r.text
        # K3: feste Texte in der Zeitachse, nie die Kennung des Entscheids
        r = await c.decide(_d("d.finding.create", title="vsftpd 2.3.4 Backdoor"))
        fid = r.json()["results"][0]["decision_id"]
        r = await c.decide(_d("d.finding.update", finding_id=fid, severity="high"))
        assert r.status_code == 201, r.text
        await sync(d)
        items = (await c.get("/timeline?types=decision&limit=1000")).json()["items"]
        rows = {(i["kind"], i["summary"], i["detail"]) for i in items}
        assert ("d.finding.create", "Finding angelegt", "F1 · vsftpd 2.3.4 Backdoor") in rows
        assert ("d.finding.update", "Finding geändert", "F1 · vsftpd 2.3.4 Backdoor") in rows
        assert ("d.suggestion.done", "Denkanstoss erledigt", second["title"]) in rows
        assert ("d.suggestion.dismiss", "Denkanstoss verworfen", first["title"]) in rows
        for i in items:
            assert i["summary"] != "Entscheid", i
            assert not (i["detail"] or "").startswith("d."), i

    _web(paths, operator, scenario)


NMAP_104 = (
    b"Starting Nmap 7.94 ( https://nmap.org )\r\nNmap scan report for 10.10.10.4\r\n"
    b"Host is up (0.0010s latency).\r\nPORT   STATE SERVICE VERSION\r\n"
    b"22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)\r\n\r\n"
    b"Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds\r\n"
)


def test_seen_new_hosts_and_items(paths, operator):
    """Korrektur K6: «Neu seit» mit einem neuen Host im Scope (dessen Services zählen nicht extra)
    und neuen Klärungen (Widersprüche aus einem zweiten nmap-Lauf); im Profil customer nie
    ``candidate_group``."""
    from ariadne.ingest import queries
    from tests.core.fakeshim import FakeShim, ctl_ok
    from tests.integration.helpers import Term
    from tests.web.api.helpers import NMAP2, ms2

    async def scenario(web: Web) -> None:
        d = web.d
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=[TARGET, "10.10.10.4"])
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="on")
        term = Term(shim)
        await term.command(f"nmap -sV {TARGET}", ms2("text").replace(b"\n", b"\r\n"), cwd=res["workspace"])
        await term.acked()
        await sync(d)
        token = await web.login()
        base = f"/api/v1/p/{res['id']}/ui/seen"
        assert (await web.req("PUT", base, token=token)).status_code == 202
        r = await web.req("GET", base, token=token)
        assert r.json()["new"]["count"] == 0
        await term.command("nmap -sV 10.10.10.4", NMAP_104, cwd=res["workspace"])
        await term.command("nmap -sV -p21,445 10.10.10.3", NMAP2, cwd=res["workspace"])
        await term.acked()
        await sync(d)
        new = (await web.req("GET", base, token=token)).json()["new"]
        assert new["hosts"] == ["ip:default/10.10.10.4"], new
        assert not any(s.startswith("svc:ip:default/10.10.10.4|") for s in new["services"])
        assert new["items"], new  # Widersprüche auf tcp/21 aus dem zweiten Lauf

        def kinds(conn):
            row = conn.execute("SELECT MIN(created_ts) FROM v_inbox").fetchone()
            since = int(row[0]) - 1 if row and row[0] is not None else 0
            lab = queries.new_since(conn, since, profile="lab")["items"]
            cust = queries.new_since(conn, since, profile="customer")["items"]
            kind_of = dict(conn.execute("SELECT item_key, kind FROM v_inbox").fetchall())
            return lab, cust, kind_of

        lab, cust, kind_of = await d.ingest.query(kinds)
        assert set(new["items"]) <= set(lab) and "conflict" in {kind_of.get(k) for k in new["items"]}
        assert set(cust) == {k for k in lab if kind_of.get(k) != "candidate_group"}
        await shim.close()

    _web(paths, operator, scenario)


def test_timeline_callback_rows(paths, operator):
    """Korrektur D15: Ein Callback, der den Kontext nicht automatisch setzte, steht als eigene Zeile
    «Callback von <ip:port>» in der Zeitachse (Typ ``callback``, mit Beleg); der automatische Fall
    bleibt die Zeile ``context`` «Callback, Kontext automatisch»."""

    async def scenario(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, inputs=False, extra=True)
        token = await web.login()
        c = Client(web, token, fx.pid)
        items = (await c.get("/timeline?limit=1000")).json()["items"]
        cbs = [i for i in items if i["type"] == "callback"]
        assert [i["remote"] for i in cbs] == ["10.10.10.99:40000"], cbs
        cb = cbs[0]
        assert cb["terminal_id"] == fx.extra["callback"] and cb["listener"] == "nc:4445"
        assert cb["unit_id"] and isinstance(cb["lines"], list) and cb["scope"] != "in"
        auto = [i for i in items if i["type"] == "context" and i["change"] == "auto"]
        assert auto and all(i["terminal_id"] != fx.extra["callback"] for i in auto)
        only = (await c.get("/timeline?types=callback&limit=50")).json()["items"]
        assert [i["id"] for i in only] == [cb["id"]]
        lines = (await c.get(f"/units/{cb['unit_id']}/lines?from={cb['lines'][0]}&count=1")).json()
        assert "10.10.10.99" in lines["lines"][0]["text"]

    _web(paths, operator, scenario)
