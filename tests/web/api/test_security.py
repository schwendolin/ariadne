"""Sicherheit der API (Vertrag v0.1-Server 5: T8 Canary, T10 Zieldaten, T11 Secrets) und Grenzfälle:
kein Secret im Klartext ausser über das Aufdecken, nie ein Steuer- oder Bidi-Zeichen in einer
Antwort, nur erlaubte ctl-Operationen, Projektwechsel während einer Anfrage (409), ohne Projekt, bei
gesperrtem Projekt und ohne Auswertung, 501-Routen."""

from __future__ import annotations

import asyncio
import json
import urllib.parse
from typing import Any

from ariadne.web.api.common import ALLOWED_OPS
from ariadne.web.api.later import LATER_ROUTES
from tests.core.fakeshim import ctl_ok
from tests.web.api.helpers import (
    BASE,
    CRYPT,
    HOSTILE,
    OWN_SECRET,
    REMOTE_PW,
    TARGET,
    all_strings,
    clean,
    client,
    make_app,
    run_api,
    sync,
)

HOST_Q = urllib.parse.quote(f"ip:default/{TARGET}", safe="")


async def _all_reads(c: Any, pid: str) -> list[tuple[str, Any]]:
    """Jede lesende Route einmal (mit den Kennungen aus den Antworten)."""
    P = f"{BASE}/p/{pid}"
    out = []
    for path in ("/status", "/terminals"):
        out.append((path, await c.get(BASE + path)))
    for path in (
        "/project",
        "/changes?since=0",
        "/graph",
        "/hosts",
        f"/hosts/{HOST_Q}",
        "/services",
        "/next",
        "/timeline?types=command,segment,file,keystep,context,decision,gap,project,input&limit=1000",
        "/inputs",
        "/search?q=admin",
        "/search?q=banner",
        "/search?q=sudo",
        "/files/pending",
        "/ui/positions",
    ):
        out.append((path, await c.get(P + path)))
    tl = (await c.get(f"{P}/timeline?limit=1000")).json()["items"]
    for item in tl:
        uid = item.get("unit_id")
        if uid:
            out.append((f"/units/{uid}", await c.get(f"{P}/units/{uid}")))
            out.append((f"/units/{uid}/lines", await c.get(f"{P}/units/{uid}/lines", params={"count": 2000})))
            out.append((f"/units/{uid}/log.txt", await c.get(f"{P}/units/{uid}/log.txt")))
    det = (await c.get(f"{P}/hosts/{HOST_Q}")).json()
    for f in det["facts"][:40]:
        out.append(("/facts", await c.get(f"{P}/facts/{f['claim_key']}/sources")))
    return out


def _check_responses(responses: list[tuple[str, Any]]) -> None:
    for path, r in responses:
        assert r.status_code == 200, (path, r.status_code, r.text[:300])
        text = r.text
        for secret in (OWN_SECRET, CRYPT, REMOTE_PW):
            assert secret not in text, (path, secret)
        assert HOSTILE not in text  # nur sichtbar gemacht
        if path.endswith("log.txt"):
            assert r.headers["content-type"] == "text/plain; charset=utf-8" and clean(text.replace("\n", ""))
            continue
        assert r.headers["content-type"] == "application/json; charset=utf-8", path
        for s in all_strings(r.json()):
            assert clean(s), (path, s)


def test_t8_t10_t11_no_secret_no_control_chars_anywhere(paths, operator):
    async def body(d, c, fx, bus, ctx):
        from ariadne.web.api import attach_sources

        detach = attach_sources(ctx)
        calls: list[str] = []
        orig = d.call

        async def spy(op, args=None):
            calls.append(op)
            return await orig(op, args)

        d.call = spy
        _check_responses(await _all_reads(c, fx.pid))
        hostile_seen = [r.text for _, r in await _all_reads(c, fx.pid) if "<U+202E>" in r.text]
        assert hostile_seen  # feindliche Werte sind da, aber sichtbar gemacht
        # Präsentationsmodus: dasselbe, und der Strom meldet ihn
        assert (await c.put(f"{BASE}/presentation", json={"on": True})).status_code == 202
        _check_responses(await _all_reads(c, fx.pid))
        assert (await c.put(f"{BASE}/presentation", json={"on": False})).status_code == 202
        # Schreibwege mit feindlichen Werten
        r = await c.post(
            f"{BASE}/p/{fx.pid}/decisions",
            json={
                "decisions": [
                    {"kind": "d.note.set", "payload": {"subject": TARGET, "text": f"{OWN_SECRET} \x1b[2J ‮"}}
                ]
            },
        )
        assert r.status_code == 201
        await sync(d)
        det = (await c.get(f"{BASE}/p/{fx.pid}/hosts/{HOST_Q}")).json()
        assert OWN_SECRET not in json.dumps(det, ensure_ascii=False) and "<ESC>[2J <U+202E>" in det["note"]
        # nur Operationen aus dem Vertrag (3.2)
        assert set(calls) <= ALLOWED_OPS and {
            "status",
            "terminals",
            "ctx.show",
            "show",
            "presentation",
        } <= set(calls)
        # SSE-Daten enthalten nie Zieldaten oder Secrets
        stream = json.dumps(bus.events, ensure_ascii=False)
        for bad in (OWN_SECRET, CRYPT, REMOTE_PW, "script", TARGET, "‮"):
            assert bad not in stream
        assert {e for e, _ in bus.events} >= {"presentation", "changes"}
        detach()

    run_api(paths, operator, body, extra=True)


def test_project_switch_during_request_and_decision(paths, operator):
    async def body(d, c, fx, bus, ctx):
        ing = d.ingest
        orig_query, orig_journal = ing.query, ing.query_journal
        gate = asyncio.Event()

        async def slow_query(fn):
            await gate.wait()
            return await orig_query(fn)

        ing.query = slow_query
        task = asyncio.ensure_future(c.get(f"{BASE}/p/{fx.pid}/hosts"))
        await asyncio.sleep(0.05)
        other = await ctl_ok(paths.ctl_sock, "start", slug="other", targets=["10.10.10.4"])
        assert d.project.info.id == other["id"] != fx.pid
        gate.set()
        r = await task
        assert r.status_code == 409 and r.json()["error"]["code"] == "project_mismatch"
        ing.query = orig_query
        # neues Projekt antwortet, altes nicht
        assert (await c.get(f"{BASE}/p/{other['id']}/hosts")).json() == {"hosts": []}
        assert (await c.get(f"{BASE}/p/{fx.pid}/hosts")).status_code == 409

        # Entscheid: Wechsel zwischen Prüfung und Schreiben -> 409, in keinem Projekt geschrieben
        heads = {}

        async def switching_journal(fn):
            res = await orig_journal(fn)
            heads["before"] = d.project.journal.head()[0]
            await ctl_ok(paths.ctl_sock, "start", slug="lame")
            return res

        ing.query_journal = switching_journal
        req = {"decisions": [{"kind": "d.keystep.mark", "payload": {"step": "loot", "note": "x"}}]}
        r = await c.post(f"{BASE}/p/{other['id']}/decisions", json=req)
        ing.query_journal = orig_journal
        assert r.status_code == 409 and r.json()["error"]["code"] == "project_mismatch", r.text
        assert d.project.info.id == fx.pid and "before" in heads
        assert not list(d.project.journal.iter_events(kinds=["d.keystep.mark"]))
        await ctl_ok(paths.ctl_sock, "start", slug="other")
        assert not list(d.project.journal.iter_events(kinds=["d.keystep.mark"]))
        r = await c.post(f"{BASE}/p/{other['id']}/decisions", json=req)  # ohne Wechsel geht es
        assert (
            r.status_code == 201 and len(list(d.project.journal.iter_events(kinds=["d.keystep.mark"]))) == 1
        )

    run_api(paths, operator, body)


def test_without_project_locked_and_without_ingest(paths, operator):
    async def body(d, c, fx, bus, ctx):
        st = (await c.get(f"{BASE}/status")).json()
        assert st["project"] is None and st["generation"] is None and st["idle"] is None
        assert st["terminals"] == [] and st["llm"]["budget"] is None and st["scope_warning"] is None
        assert (await c.get(f"{BASE}/terminals")).json() == {"terminals": []}
        r = await c.get(f"{BASE}/p/0123456789abcdef/hosts")
        assert r.status_code == 409 and r.json()["error"]["code"] == "no_project"
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=[TARGET])
        pid = res["id"]
        assert (await c.get(f"{BASE}/p/{pid}/hosts")).status_code == 200
        await ctl_ok(paths.ctl_sock, "lock")  # E103: Projekt bleibt aktiv, gesperrt
        r = await c.get(f"{BASE}/p/{pid}/hosts")
        assert r.status_code == 423 and r.json()["error"]["code"] == "locked"
        st = (await c.get(f"{BASE}/status")).json()
        assert st["locked"] is True and st["project"] is None and st["active"]["stopped"] is False
        r = await c.post(
            f"{BASE}/p/{pid}/decisions",
            json={"decisions": [{"kind": "d.tag.add", "payload": {"subject": "x", "tag": "y"}}]},
        )
        assert r.status_code == 423

    run_api(paths, operator, body, fixture=False)


def test_without_ingest_service_returns_503(paths, operator):
    from tests.core.test_daemon import run

    async def scenario(d):
        app, _ctx = make_app(d)
        async with client(app) as c:
            res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=[TARGET])
            r = await c.get(f"{BASE}/p/{res['id']}/graph")
            assert r.status_code == 503 and r.json()["error"]["code"] == "unavailable"
            st = (await c.get(f"{BASE}/status")).json()
            assert st["ingest"] is None and st["generation"] is None and st["project"]["id"] == res["id"]
            await ctl_ok(paths.ctl_sock, "stop")
            r = await c.get(f"{BASE}/p/{res['id']}/graph")
            assert r.status_code == 409 and r.json()["error"]["code"] == "no_project"

    run(paths, operator, scenario, ingest=False)


def test_later_routes_answer_501(paths, operator):
    async def body(d, c, fx, bus, ctx):
        for method, path, _name, _version in LATER_ROUTES:
            url = BASE + path.replace("{pid}", "x").replace("{cred_id}", "c1").replace("{blob_id}", "b1")
            r = await c.request(method, url)
            assert r.status_code == 501, (method, path)
            assert r.json() == {
                "error": {"code": "not_implemented", "message": "Kommt in einer späteren Version."}
            }
        # Credentials, Kopieren in die Zwischenablage (T11): 501, kein Secret
        r = await c.post(f"{BASE}/p/x/credentials/abc/copy")
        assert r.status_code == 501

    run_api(paths, operator, body, fixture=False)
