"""Schreibwege der API v2: Entscheide (alle oder keiner, Bezüge, Idempotenz, kritische und spätere
Arten, Rückgängig pro Befehl und Aufheben), Sammelbestätigung, Kontext (auch Vorschlag übernehmen),
Pause und Fortsetzen pro Terminal, Präsentationsmodus und Aufdecken einzelner Secrets."""

from __future__ import annotations

import urllib.parse

from ariadne.web.api.events import attach_sources
from ariadne.web.api.text import MASK
from tests.web.api.helpers import BASE, CRYPT, OWN_SECRET, REMOTE_PW, TARGET, run_api, sync

HOST = f"ip:default/{TARGET}"
HOST_Q = urllib.parse.quote(HOST, safe="")


def _head(d):
    return d.project.journal.head()[0]


def _dec(kind, payload, **kw):
    return {"decisions": [{"kind": kind, "payload": payload, **kw}]}


def test_decisions_all_or_none_refs_and_kinds(paths, operator):
    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        nx = (await c.get(f"{P}/next")).json()
        conf = next(
            i["conflict"]
            for i in nx["clarify"]
            if i["kind"] == "conflict" and i["conflict"]["predicate"] == "service.product"
        )
        pro = next(v["claim_key"] for v in conf["values"] if v["value"] == "ProFTPD")
        head = _head(d)
        req = _dec(
            "d.conflict.resolve", {"conflict_key": conf["conflict_key"], "choice": pro}, client_ref="r-1"
        )
        r = await c.post(f"{P}/decisions", json=req)
        assert r.status_code == 201, r.text
        (res,) = r.json()["results"]
        assert (
            res["client_ref"] == "r-1"
            and res["seq"] == head + 1
            and res["decision_id"]
            and res["effect"] is None
        )
        rec = d.project.journal.get(res["seq"])
        assert rec.kind == "d.conflict.resolve" and rec.origin == "webui" and rec.id == res["decision_id"]
        # Wiederholung mit derselben client_ref: gleiches Ergebnis, nichts Neues im Journal
        again = await c.post(f"{P}/decisions", json=req)
        assert again.status_code == 201 and again.json()["results"] == [res] and _head(d) == head + 1
        await sync(d)
        nx = (await c.get(f"{P}/next")).json()
        assert not [
            i
            for i in nx["clarify"]
            if i["kind"] == "conflict" and i["conflict"]["predicate"] == "service.product"
        ]
        svc = (await c.get(f"{P}/services", params={"host": HOST})).json()["services"]
        assert next(s for s in svc if s["port"] == 21)["product"] == "ProFTPD"

        # alle oder keiner: ein gültiger und ein unbekannter Bezug -> 409, nichts geschrieben
        head = _head(d)
        both = {
            "decisions": [
                {"kind": "d.note.set", "payload": {"subject": HOST, "text": "x"}},
                {"kind": "d.claim.confirm", "payload": {"claim_key": "0" * 64}},
            ]
        }
        r = await c.post(f"{P}/decisions", json=both)
        assert r.status_code == 409 and r.json()["error"]["code"] == "conflict" and _head(d) == head
        cases = [
            (
                _dec("d.ctx.set", {"terminal_id": fx.shim.terminal_id, "from_off": 0, "host": TARGET}),
                422,
                "validation",
            ),
            (_dec("d.scope.update", {"version": 2, "toml": "x"}), 403, "policy"),
            (_dec("d.lab.not_customer", {"scope_version": 1}), 403, "policy"),
            (_dec("d.automode.set", {"enabled": True}), 403, "policy"),
            # Bau v0.1-Oberfläche: altes d.finding ersetzt durch d.finding.* (422), done braucht basis (422)
            (_dec("d.finding", {"title": "x"}), 422, "validation"),
            (_dec("d.suggestion.done", {"suggestion_key": "x"}), 422, "validation"),
            (_dec("d.artifact", {}), 501, "not_implemented"),
            (_dec("d.bogus", {}), 422, "validation"),
            (_dec("term.out", {}), 422, "validation"),
            (_dec("d.tag.add", {"subject": HOST}), 422, "validation"),
            (_dec("d.claim.confirm", {"claim_key": "0" * 64}), 409, "conflict"),
            (_dec("d.status.work", {"subject": "10.9.9.9", "value": "done"}), 409, "conflict"),
            (
                _dec("d.entity.merge", {"identifiers": ["ip:default/10.9.9.8", "ip:default/10.9.9.9"]}),
                409,
                "conflict",
            ),
            (_dec("d.terminal.label", {"terminal_id": "0" * 36, "label": "x"}), 409, "conflict"),
            (_dec("d.revoke", {"decision_id": "0" * 36}), 409, "conflict"),
            (_dec("d.conflict.resolve", {"conflict_key": conf["conflict_key"]}), 422, "validation"),
            (
                _dec(
                    "d.keystep.mark",
                    {"step": "foothold", "terminal_id": fx.shim.terminal_id, "stream_off": 1},
                ),
                422,
                "validation",
            ),
            (_dec("d.keystep.mark", {"step": "foothold", "host": "a b"}), 422, "validation"),
            (
                {
                    "decisions": [
                        {"kind": "d.unit.distrust", "payload": {"cmd_id": "x@1"}},
                        {"kind": "d.note.set", "payload": {"subject": HOST, "text": "x"}},
                    ]
                },
                422,
                "validation",
            ),
            ({"decisions": []}, 422, "validation"),
            ({"decisions": [{"kind": "d.note.set", "payload": {}, "extra": 1}]}, 422, "validation"),
        ]
        for req, status, code in cases:
            r = await c.post(f"{P}/decisions", json=req)
            assert (r.status_code, r.json()["error"]["code"]) == (status, code), (req, r.text)
        assert _head(d) == head
        r = await c.post(f"{P}/decisions", json=_dec("d.tag.add", {"subject": HOST}))
        loc = r.json()["error"]["detail"][0]["loc"]
        assert loc[:4] == ["body", "decisions", 0, "payload"]
        scope_dec = next(r for r in d.project.journal.iter_events(kinds=["d.scope.update"]))
        r = await c.post(f"{P}/decisions", json=_dec("d.revoke", {"decision_id": scope_dec.id}))
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy"

        # Status, Notiz (Zieldaten-frei, aber als Text), Tag, Terminalname, Schlüsselschritt
        note = "Notiz \x1b[31m<b>fett</b>\u202e"
        batch = {
            "decisions": [
                {
                    "kind": "d.status.work",
                    "payload": {"subject": TARGET, "value": "dead_end", "reason": "nichts"},
                },
                {"kind": "d.note.set", "payload": {"subject": HOST, "text": note}},
                {"kind": "d.tag.add", "payload": {"subject": HOST, "tag": "dc\x07"}},
                {
                    "kind": "d.terminal.label",
                    "payload": {"terminal_id": fx.shim.terminal_id, "label": "haupt"},
                },
                {
                    "kind": "d.keystep.mark",
                    "payload": {"step": "foothold", "host": TARGET, "note": "<i>x</i>"},
                },
            ]
        }
        r = await c.post(f"{P}/decisions", json=batch)
        assert r.status_code == 201, r.text
        seqs = [x["seq"] for x in r.json()["results"]]
        assert seqs == list(range(seqs[0], seqs[0] + 5))
        kp = d.project.journal.get(seqs[4])
        assert kp.header["host"] == HOST and kp.origin == "webui"
        await sync(d)
        det = (await c.get(f"{P}/hosts/{HOST_Q}")).json()
        assert det["work"] == "dead_end" and det["work_reason"] == "nichts"
        assert det["note"] == "Notiz <ESC>[31m<b>fett</b><U+202E>" and det["ctrl"] is True
        assert det["tags"] == ["dc<BEL>"] and det["on_thread"] is True
        assert [(t["step"], t["source"], t["target"]) for t in det["thread"]] == [("foothold", "kali", HOST)]
        g = (await c.get(f"{P}/graph", params={"layers": "thread"})).json()
        assert [(e["seq"], e["source"], e["target"]) for e in g["edges"] if e["kind"] == "thread"] == [
            (1, "kali", HOST)
        ]
        tl = (await c.get(f"{P}/timeline")).json()["items"]
        ks = next(i for i in tl if i["type"] == "keystep")
        assert ks["step"] == "foothold" and ks["ordinal"] == 1 and ks["note"] == "<i>x</i>"
        summaries = {i["summary"] for i in tl if i["type"] == "decision"}
        assert {
            "Arbeitsstand: Sackgasse",
            "Notiz gesetzt",
            "Tag hinzugefügt",
            "Terminal benannt",
            "Widerspruch gelöst",
        } <= summaries

        # Sammelbestätigung: unbekannte Gruppe, ungültiger Verweis
        r = await c.post(f"{P}/decisions/confirm-group", json={"group_ref": "g00000000"})
        assert r.status_code == 404
        r = await c.post(f"{P}/decisions/confirm-group", json={"group_ref": "0123456789ab"})
        assert r.status_code == 422

    run_api(paths, operator, body, extra=True)


def test_unit_distrust_effect_revoke_and_conflicts(paths, operator):
    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        tl = (await c.get(f"{P}/timeline")).json()["items"]
        nmap = next(i for i in tl if i["type"] == "command" and i["cmd"]["text"].startswith("nmap"))
        cat = next(i for i in tl if i["type"] == "command" and i["cmd"]["text"] == "cat loot.txt")
        r = await c.post(
            f"{P}/decisions",
            json=_dec("d.unit.distrust", {"cmd_id": nmap["cmd"]["cmd_ref"], "reason": "falsches Ziel"}),
        )
        assert r.status_code == 201, r.text
        (res,) = r.json()["results"]
        assert res["effect"]["rejected"] >= 50 and res["decision_id"] and res["seq"] is None
        recs = list(d.project.journal.iter_events(kinds=["d.unit.distrust"]))
        assert recs[-1].origin == "webui" and recs[-1].header["cmd_id"] == nmap["cmd"]["cmd_id"]
        # zweimal «Rückgängig pro Befehl» (Doppelklick, F7): 409, kein zweiter Entscheid
        r = await c.post(f"{P}/decisions", json=_dec("d.unit.distrust", {"cmd_id": nmap["cmd"]["cmd_ref"]}))
        assert r.status_code == 409 and r.json()["error"]["code"] == "conflict"
        assert len(list(d.project.journal.iter_events(kinds=["d.unit.distrust"]))) == len(recs)
        await sync(d)
        tl = (await c.get(f"{P}/timeline")).json()["items"]
        nmap2 = next(i for i in tl if i["id"] == nmap["id"])
        assert nmap2["distrusted"]["decision_id"] == res["decision_id"] and nmap2["adopted"] == 0
        assert (await c.get(f"{P}/graph")).json()["summary"]["services"] == 0  # alle aus nmap
        r = await c.post(f"{P}/decisions", json=_dec("d.revoke", {"decision_id": res["decision_id"]}))
        assert r.status_code == 201
        await sync(d)
        tl = (await c.get(f"{P}/timeline")).json()["items"]
        assert next(i for i in tl if i["id"] == nmap["id"])["distrusted"] is None  # ein Klick reicht
        assert (await c.get(f"{P}/graph")).json()["summary"]["services"] == 23
        r = await c.post(f"{P}/decisions", json=_dec("d.revoke", {"decision_id": res["decision_id"]}))
        assert r.status_code == 409  # schon aufgehoben
        r = await c.post(f"{P}/decisions", json=_dec("d.unit.distrust", {"cmd_id": cat["cmd"]["cmd_ref"]}))
        assert r.status_code == 409 and r.json()["error"]["code"] == "conflict"  # keine Werte
        r = await c.post(f"{P}/decisions", json=_dec("d.unit.distrust", {"cmd_id": "deadbeef@1"}))
        assert r.status_code == 404

    run_api(paths, operator, body)


def test_context_routes_and_suggestion(paths, operator):
    async def body(d, c, fx, bus, ctx):
        detach = attach_sources(ctx)
        t2 = fx.shim2.terminal_id
        url = f"{BASE}/terminals/{t2}/context"
        r = await c.post(url, json={"op": "set", "user": "<img/src=x>\u202e"})
        assert r.status_code == 200, r.text
        res = r.json()
        assert res["stored"] is True and res["warnings"] == []
        assert res["stack"][-1]["user"] == "<img/src=x><U+202E>"
        assert ("terminal", {"terminal_id": t2, "change": "context"}) in bus.events
        r = await c.post(url, json={"op": "set", "host": "10.10.10.99"})
        warn = {w["code"] for w in r.json()["warnings"]}
        assert warn == {"scope_out"} and r.json()["warnings"][0]["host"] == "10.10.10.99"
        r = await c.post(url, json={"op": "set", "host": "10.20.30.40"})
        assert {w["code"] for w in r.json()["warnings"]} == {"scope_out", "host_unknown"}
        r = await c.post(url, json={"op": "set", "host": TARGET})
        assert r.json()["warnings"] == [] and r.json()["stack"][-1]["host_id"] == HOST
        assert (await c.post(url, json={"op": "pop"})).status_code == 200
        r = await c.post(url, json={"op": "pop"})
        assert r.status_code == 422  # Kali lässt sich nicht schliessen
        r = await c.post(url, json={"op": "push", "kind": "ssh", "host": TARGET, "user": "root"})
        assert [s["kind"] for s in r.json()["stack"]] == ["local", "ssh"]
        assert (await c.post(url, json={"op": "pop"})).json()["stack"][-1]["kind"] == "local"
        for bad in (
            {"op": "set"},
            {"op": "set", "host": "a b"},
            {"op": "set", "user": "x", "from_off": 10**12},
            {"op": "jump"},
            {"op": "set", "kind": "rdp"},
            {"op": "pop", "x": 1},
            {"op": "set", "from_off": "0", "user": "x"},
        ):
            r = await c.post(url, json=bad)
            assert r.status_code == 422, (bad, r.text)
        assert (await c.post(f"{BASE}/terminals/{'0' * 36}/context", json={"op": "pop"})).status_code == 404
        retro = {"op": "set", "host": TARGET, "from_off": 0}  # unbekanntes Terminal (F8): 404
        assert (await c.post(f"{BASE}/terminals/{'0' * 36}/context", json=retro)).status_code == 404
        assert (await c.post(f"{BASE}/terminals/zz/context", json={"op": "pop"})).status_code == 404
        # Kontextvorschlag aus «Als Nächstes» übernehmen
        nx = (await c.get(f"{BASE}/p/{fx.pid}/next")).json()
        sug = next(i for i in nx["clarify"] if i["kind"] == "ctx_suggestion")
        tid = sug["terminal_id"]
        r = await c.post(
            f"{BASE}/terminals/{tid}/context", json={"op": "accept", "item_key": sug["item_key"]}
        )
        assert r.status_code == 200, r.text
        assert r.json()["stored"] is True and {w["code"] for w in r.json()["warnings"]} == {"scope_out"}
        await sync(d)
        rec = list(d.project.journal.iter_events(kinds=["d.ctx.set"], terminal_id=tid))[-1]
        assert rec.origin == "webui" and rec.header["from_off"] == sug["from_off"]
        assert rec.header["host"] == "ip:default/10.10.10.99"
        # die Sitzung läuft noch (nc ohne Ende): der Live-Stapel zeigt den Zielhost
        live = (await c.get(f"{BASE}/terminals")).json()["terminals"]
        stack = next(t for t in live if t["terminal_id"] == tid)["stack"]
        assert stack[-1]["host_id"] == "ip:default/10.10.10.99"
        r = await c.post(
            f"{BASE}/terminals/{tid}/context", json={"op": "accept", "item_key": sug["item_key"]}
        )
        assert r.status_code == 409  # schon entschieden
        r = await c.post(f"{BASE}/terminals/{tid}/context", json={"op": "accept", "item_key": "merge:x"})
        assert r.status_code == 404
        detach()

    run_api(paths, operator, body, extra=True)


def test_accept_after_the_session_ended_leaves_the_live_stack_in_kali(paths, operator):
    """Befund F2: Ist das Terminal wieder in Kali (Prompt der Kali-Shell nach ``from_off``), gilt der
    übernommene Vorschlag nur rückwirkend; der Live-Stapel bleibt Kali, der nächste lokale Befehl
    gilt als lokal (Companion-Dateien von ``nmap -oA`` werden erfasst)."""

    async def body(d, c, fx, bus, ctx):
        from tests.core.fakeshim import FakeShim
        from tests.integration.helpers import Term

        s5 = await FakeShim(paths.term_sock).connect(proto=2)
        fx.shims.append(s5)
        await s5.wait_state(rec="on")
        t5 = Term(s5)
        await t5.command(
            "nc -lvnp 4446",
            b"listening on [any] 4446 ...\r\n"
            b"connect to [10.10.14.5] from (UNKNOWN) [10.10.10.98] 40000\r\n"
            b"whoami\r\nwww-data\r\n",
            cwd=str(fx.ws),
        )  # Sitzung beendet, zurück in Kali
        await t5.command("id", b"uid=1000(kali)\r\n", cwd=str(fx.ws))
        await t5.acked()
        await sync(d)
        tid = s5.terminal_id
        nx = (await c.get(f"{BASE}/p/{fx.pid}/next")).json()
        sug = [i for i in nx["clarify"] if i["kind"] == "ctx_suggestion" and i["terminal_id"] == tid]
        assert sug
        acc = {"op": "accept", "item_key": sug[0]["item_key"]}
        r = await c.post(f"{BASE}/terminals/{tid}/context", json=acc)
        assert r.status_code == 200 and r.json()["stored"] is True
        shown = (await c.get(f"{BASE}/terminals")).json()["terminals"]
        assert [st["kind"] for st in next(t for t in shown if t["terminal_id"] == tid)["stack"]] == ["local"]
        assert d.terminals[tid].stack.is_local()  # MarkContext.local_before des nächsten Befehls stimmt
        await sync(d)
        rec = list(d.project.journal.iter_events(kinds=["d.ctx.set"], terminal_id=tid))[-1]
        assert rec.header["from_off"] == sug[0]["from_off"]  # rückwirkend gespeichert

    run_api(paths, operator, body)


def test_pause_resume_presentation_and_reveal(paths, operator):
    async def body(d, c, fx, bus, ctx):
        detach = attach_sources(ctx)
        t1 = fx.shim.terminal_id
        P = f"{BASE}/p/{fx.pid}"
        for req, status in (
            ({"minutes": 31}, 403),
            ({"minutes": 300}, 422),
            ({"minutes": "5"}, 422),
            ({"minutes": 0}, 422),
            ({"x": 1}, 422),
        ):
            r = await c.post(f"{BASE}/terminals/{t1}/pause", json=req)
            assert r.status_code == status, (req, r.text)
        assert r.json()["error"]["code"] == "validation"
        r = await c.post(f"{BASE}/terminals/{t1}/pause", json={"minutes": 31})
        assert r.json()["error"]["code"] == "policy"
        r = await c.post(f"{BASE}/terminals/{t1}/pause")
        assert r.status_code == 202 and r.json() == {"accepted": True}
        st = (await c.get(f"{BASE}/status")).json()
        t = next(x for x in st["terminals"] if x["terminal_id"] == t1)
        assert t["state"] == "paused" and t["pause_until"].endswith("Z") and st["recording"]["paused"] == 1
        assert any(e == ("terminal", {"terminal_id": t1, "change": "state"}) for e in bus.events)
        rec = list(d.project.journal.iter_events(kinds=["term.pause"]))[-1]
        assert rec.header["source"] == "webui"
        until = int(rec.header["until_ns"])
        assert 9 * 60 * 10**9 <= until - rec.ts_utc_ns <= 11 * 60 * 10**9  # Standard 10 Minuten
        assert (await c.post(f"{BASE}/terminals/{t1}/resume")).status_code == 202
        st = (await c.get(f"{BASE}/status")).json()
        assert next(x for x in st["terminals"] if x["terminal_id"] == t1)["state"] == "on"
        assert (await c.post(f"{BASE}/terminals/all/pause", json={"minutes": 5})).status_code == 202
        assert (await c.get(f"{BASE}/status")).json()["recording"]["paused"] == 2
        assert (await c.post(f"{BASE}/terminals/all/resume")).status_code == 202
        assert (await c.post(f"{BASE}/terminals/{'0' * 36}/pause")).status_code == 404
        assert (await c.post(f"{BASE}/terminals/..%2F/resume")).status_code == 404

        # Aufdecken: einzeln, eigene Secrets bleiben ersetzt
        inputs = (await c.get(f"{P}/inputs")).json()["items"]
        own, remote = inputs[1], inputs[2]
        r = await c.post(f"{P}/secrets/reveal", json={"ref": "input", "seq": remote["seq"]})
        assert r.status_code == 200 and r.json() == {"value": REMOTE_PW, "ctrl": False}
        r = await c.post(f"{P}/secrets/reveal", json={"ref": "input", "seq": own["seq"]})
        assert r.status_code == 200 and OWN_SECRET not in r.text and r.json()["value"]
        assert (await c.post(f"{P}/secrets/reveal", json={"ref": "input", "seq": 1})).status_code == 404
        fact = (await c.get(f"{P}/hosts/{HOST_Q}")).json()["facts"][0]
        r = await c.post(f"{P}/secrets/reveal", json={"ref": "claim", "claim_key": fact["claim_key"]})
        assert r.status_code == 404  # kein Secret-Wert
        for bad in (
            {"ref": "own"},
            {"ref": "input"},
            {"ref": "input", "seq": "3"},
            {"ref": "claim", "claim_key": "x"},
        ):
            assert (await c.post(f"{P}/secrets/reveal", json=bad)).status_code == 422

        # Präsentationsmodus: Ereignis, Status, kein Aufdecken, Logzeilen maskiert
        assert (await c.put(f"{BASE}/presentation", json={"on": "yes"})).status_code == 422
        r = await c.put(f"{BASE}/presentation", json={"on": True})
        assert r.status_code == 202 and d.presentation is True
        assert ("presentation", {"on": True}) in bus.events
        assert (await c.get(f"{BASE}/status")).json()["presentation"] is True
        r = await c.post(f"{P}/secrets/reveal", json={"ref": "input", "seq": remote["seq"]})
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
        rec = list(d.project.journal.iter_events(kinds=["term.input"]))
        assert rec  # gespeichert wird trotzdem alles
        tl = (await c.get(f"{P}/timeline")).json()["items"]
        cat = next(i for i in tl if i["type"] == "command" and i["cmd"]["text"] == "cat loot.txt")
        lines = (await c.get(f"{P}/units/{cat['unit_id']}/lines", params={"reveal_hidden": "true"})).json()
        assert CRYPT not in str(lines) and lines["lines"][1]["masked"]
        assert (await c.put(f"{BASE}/presentation", json={"on": False})).status_code == 202
        assert ("presentation", {"on": False}) in bus.events
        r = await c.post(f"{P}/secrets/reveal", json={"ref": "input", "seq": remote["seq"]})
        assert r.json()["value"] == REMOTE_PW
        assert MASK in str((await c.get(f"{P}/inputs")).json())  # Aufdecken ändert die Liste nicht
        detach()

    run_api(paths, operator, body)


SUSPECT_NMAP = (
    b"Nmap scan report for 10.10.10.3\r\nHost is up.\r\nPORT     STATE SERVICE VERSION\r\n"
    b"8888/tcp open  http    Fake httpd 9.9\r8888/tcp open  http    Evil httpd 1.0\r\n"
    b"\x1b[8m9999/tcp open  ftp     Hidden ftpd 2.0\x1b[0m\r\n\r\n"
    b"Nmap done: 1 IP address (1 host up)\r\n"
)


def test_decide_values_confirm_group_and_concealed_lines(paths, operator):
    """Verdächtige Quellen (überschrieben, SGR-verdeckt) landen in «Klären»; die Sammelbestätigung
    nimmt sie nie (E88), einzeln bestätigen geht. Verdeckter Text nur mit ``reveal_hidden``."""
    from tests.core.fakeshim import FakeShim, ctl_ok
    from tests.integration.helpers import Term

    async def body(d, c, fx, bus, ctx):
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=[TARGET])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        t = Term(s)
        await t.command(f"nmap -sV -p8888,9999 {TARGET}", SUSPECT_NMAP, cwd="/tmp")
        await t.acked()
        await sync(d)
        P = f"{BASE}/p/{res['id']}"
        nx = (await c.get(f"{P}/next")).json()
        vals = [i for i in nx["clarify"] if i["kind"] == "decide_value"]
        assert vals and all(i["reason"] == "suspect" and i["fact"]["suspect"] for i in vals)
        assert {i["group_ref"] for i in vals} == {vals[0]["group_ref"]}
        assert vals[0]["unit"]["title"].startswith("nmap") and vals[0]["unit"]["kind"] == "command"
        r = await c.post(f"{P}/decisions/confirm-group", json={"group_ref": vals[0]["group_ref"]})
        assert r.status_code == 200 and r.json()["confirmed"] == 0
        assert r.json()["excluded"]["suspect"] == len(vals) and set(r.json()["excluded"]) == {
            "own_address",
            "context",
            "out_of_scope",
            "conflict",
            "merge",
            "ai",
            "suspect",
            "low_confidence",
        }
        key = vals[0]["fact"]["claim_key"]
        r = await c.post(f"{P}/decisions", json=_dec("d.claim.confirm", {"claim_key": key}))
        assert r.status_code == 201
        await sync(d)
        nx = (await c.get(f"{P}/next")).json()
        assert key not in {i.get("fact", {}).get("claim_key") for i in nx["clarify"]}
        assert nx["open"] == len(vals) - 1
        src = (await c.get(f"{P}/facts/{key}/sources")).json()
        assert src["fact"]["state"] == "confirmed" and src["fact"]["lane"] == "user"
        unit = vals[0]["unit"]["unit_id"]
        lines = (await c.get(f"{P}/units/{unit}/lines")).json()["lines"]
        over = next(ln for ln in lines if "8888/tcp" in ln["text"])
        assert over["overwritten"] is True and "Evil" in over["text"]
        hidden = next(ln for ln in lines if ln["concealed"])
        assert "Hidden" not in hidden["text"] and hidden["masked"][0]["kind"] == "concealed"
        shown = (await c.get(f"{P}/units/{unit}/lines", params={"reveal_hidden": "true"})).json()["lines"]
        assert any("Hidden ftpd" in ln["text"] for ln in shown)
        d.presentation = True  # im Präsentationsmodus bleibt verdeckter Text verdeckt
        shown = (await c.get(f"{P}/units/{unit}/lines", params={"reveal_hidden": "true"})).json()["lines"]
        assert not any("Hidden" in ln["text"] for ln in shown)
        d.presentation = False
        await s.close()

    run_api(paths, operator, body, fixture=False)
