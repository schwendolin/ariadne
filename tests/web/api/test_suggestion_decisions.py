"""Denkanstösse über echte HTTP-Anfragen gegen den echten Server (web-api.md 18.6, 18.9, E10):
``d.suggestion.done`` braucht ``basis`` und gilt nur für den aktuellen Anlass, ``d.suggestion.dismiss``
bleibt (auch nach Reparse), ``d.revoke`` öffnet wieder, unbekannte Denkanstösse ergeben 409, und das
SSE-Ereignis ``suggestion`` kommt, wenn sich die Zahl offener Denkanstösse ändert."""

from __future__ import annotations

import asyncio

import pytest

from ariadne.daemon.ingest import IngestService
from ariadne.rules import api as rules_api
from tests.core.fakeshim import ctl_ok
from tests.web.api.helpers import build_fixture, sync
from tests.web.server.helpers import Stream, Web, run_web

pytestmark = [pytest.mark.web, pytest.mark.skipif(rules_api.STUB, reason="Regel-Engine noch Stub")]


async def _until(pred, timeout: float = 5.0) -> bool:
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not pred():
        if loop.time() > end:
            return False
        await asyncio.sleep(0.05)
    return True


def test_suggestion_done_dismiss_revoke_and_event(paths, operator):
    async def scenario(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, inputs=False)
        token = await web.login()
        base = f"/api/v1/p/{fx.pid}"

        async def decide(*decs):
            body = {"decisions": list(decs)}
            return await web.req("POST", f"{base}/decisions", token=token, json_body=body)

        def done(k: str, basis: str) -> dict:
            return {"kind": "d.suggestion.done", "payload": {"suggestion_key": k, "basis": basis}}

        nx = (await web.req("GET", f"{base}/next", token=token)).json()
        assert nx["suggestions_available"] is True and len(nx["suggestions"]) >= 2, nx["suggestions"]
        first, second = nx["suggestions"][0], nx["suggestions"][1]
        assert all(s["state"] == "open" for s in nx["suggestions"])
        s = Stream(web, token)
        await s.wait_open()
        key = first["suggestion_key"]
        r = await decide({"kind": "d.suggestion.done", "payload": {"suggestion_key": key}})
        assert r.status_code == 422 and r.json()["error"]["detail"][0]["type"] == "basis_required"
        r = await decide(done(key, "0" * 16))
        assert r.status_code == 409  # Anlass hat sich geändert (oder anderer Tab)
        r = await decide({"kind": "d.suggestion.dismiss", "payload": {"suggestion_key": "sg:" + "0" * 24}})
        assert r.status_code == 409
        r = await decide(done(key, first["basis"]))
        assert r.status_code == 201, r.text
        done_id = r.json()["results"][0]["decision_id"]
        await sync(d)
        nx = (await web.req("GET", f"{base}/next", token=token)).json()
        assert key not in {x["suggestion_key"] for x in nx["suggestions"]}
        got = (await web.req("GET", f"{base}/suggestions?state=done", token=token)).json()["suggestions"]
        assert [x["decision_id"] for x in got if x["suggestion_key"] == key] == [done_id]
        assert await _until(lambda: "event: suggestion" in s.text), s.text
        # zweimal erledigt: 409 («In einem anderen Tab entschieden»)
        r = await decide(done(key, first["basis"]))
        assert r.status_code == 409
        # verwerfen bleibt verworfen, auch nach Reparse
        k2 = second["suggestion_key"]
        dismiss = {"kind": "d.suggestion.dismiss", "payload": {"suggestion_key": k2, "reason": "kein Thema"}}
        r = await decide(dismiss)
        assert r.status_code == 201, r.text
        r = await decide({"kind": "d.suggestion.dismiss", "payload": {"suggestion_key": k2}})
        assert r.status_code == 409
        await ctl_ok(paths.ctl_sock, "reparse")
        await sync(d)
        dismissed = (await web.req("GET", f"{base}/suggestions?state=dismissed", token=token)).json()
        assert k2 in {x["suggestion_key"] for x in dismissed["suggestions"]}
        # Rückgängig öffnet wieder
        r = await decide({"kind": "d.revoke", "payload": {"decision_id": done_id}})
        assert r.status_code == 201, r.text
        await sync(d)
        nx = (await web.req("GET", f"{base}/next", token=token)).json()
        assert key in {x["suggestion_key"] for x in nx["suggestions"]}
        assert k2 not in {x["suggestion_key"] for x in nx["suggestions"]}
        await s.close()
        for sh in fx.shims:
            await sh.close()

    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))
