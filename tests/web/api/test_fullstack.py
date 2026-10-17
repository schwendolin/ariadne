"""Die echte API hinter dem echten Server-Kern (``WebExtension`` im Daemon, freier Loopback-Port):
T5 (Header auf den eigenen Routen, auch 4xx und 501), T8 (Canary nie im SSE-Strom), T9
(Präsentationsmodus erreicht zwei Ströme, danach kein Aufdecken). Läuft erst, wenn der Teil «server»
fertig ist (``ariadne.web.integration.STUB``)."""

from __future__ import annotations

import asyncio

import pytest

from ariadne.daemon.ingest import IngestService
from ariadne.web import integration
from tests.web.api.helpers import CRYPT, OWN_SECRET, REMOTE_PW, build_fixture, sync

pytestmark = [
    pytest.mark.web,
    pytest.mark.skipif(integration.STUB, reason="Server-Kern noch Stub (Vertrag v0.1-Server 4)"),
]

HEADERS = {
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cache-control": "no-store",
}


def _assert_headers(r) -> None:
    from ariadne.web.security import OTHER_CSP

    for k, v in HEADERS.items():
        assert r.headers.get(k) == v, (k, r.status_code)
    assert r.headers.get("content-security-policy") == OTHER_CSP
    assert not any(k.lower().startswith("access-control-") for k in r.headers)


async def _until(pred, timeout: float = 5.0) -> bool:
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not pred():
        if loop.time() > end:
            return False
        await asyncio.sleep(0.05)
    return True


def test_api_behind_real_server_headers_sse_presentation(paths, operator):
    from tests.web.server.helpers import Stream, run_web

    async def scenario(web) -> None:
        d = web.d
        fx = await build_fixture(d, paths)
        token = await web.login()
        pid = fx.pid
        r = await web.req("GET", "/api/v1/status", token=token)
        assert (
            r.status_code == 200 and r.json()["api_version"] == 2 and r.json()["session"]["origin"] == "local"
        )
        _assert_headers(r)
        for method, path, status in (
            ("GET", f"/api/v1/p/{pid}/hosts", 200),
            ("GET", f"/api/v1/p/{pid}/timeline?limit=0", 422),
            ("GET", f"/api/v1/p/{pid}/hosts/ip%3Adefault%2F1.2.3.4", 404),
            ("GET", "/api/v1/p/0000000000000000/hosts", 409),
            ("POST", f"/api/v1/p/{pid}/ai/denkanstoss", 501),
            ("POST", "/api/v1/terminals/all/pause", 202),
        ):
            r = await web.req(method, path, token=token, json_body={} if method == "POST" else None)
            assert r.status_code == status, (path, r.text)
            _assert_headers(r)
        r = await web.req("GET", f"/api/v1/p/{pid}/hosts")  # ohne Token
        assert r.status_code == 401
        r = await web.req("GET", f"/api/v1/p/{pid}/hosts?token={token}")  # Token in der URL zählt nicht
        assert r.status_code == 401
        await web.req("POST", "/api/v1/terminals/all/resume", token=token)

        s1, s2 = Stream(web, token), Stream(web, token)
        await s1.wait_open()
        await s2.wait_open()
        r = await web.req("PUT", "/api/v1/presentation", token=token, json_body={"on": True})
        assert r.status_code == 202
        assert await _until(lambda: "event: presentation" in s1.text and "event: presentation" in s2.text)
        inputs = (await web.req("GET", f"/api/v1/p/{pid}/inputs", token=token)).json()["items"]
        r = await web.req(
            "POST",
            f"/api/v1/p/{pid}/secrets/reveal",
            token=token,
            json_body={"ref": "input", "seq": inputs[-1]["seq"]},
        )
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
        # Aktivität während der Strom läuft: neuer Befehl mit Canary-Secret
        await fx.term.command(
            "cat more.txt", f"{OWN_SECRET} {CRYPT} {REMOTE_PW}\r\n".encode(), cwd=str(fx.ws)
        )
        await fx.term.acked()
        await sync(d)
        assert await _until(lambda: "event: changes" in s1.text, 5)
        lines = (await web.req("GET", f"/api/v1/p/{pid}/search?q=more.txt", token=token)).text
        assert OWN_SECRET not in lines
        await asyncio.sleep(0.5)
        for s in (s1, s2):
            for secret in (OWN_SECRET, CRYPT, REMOTE_PW, "10.10.10.3", "script"):
                assert secret not in s.text
            await s.close()
        for s in fx.shims:
            await s.close()

    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))
