"""Server-Kern mit der echten API v2 (Teil «api»): Einbindung, Header auf API-Antworten (T5 für
fremde Routen), Ereignisquellen auf dem Bus des Servers. Übersprungen, solange die API ein Stub ist.
"""

from __future__ import annotations

import asyncio

import pytest

from ariadne.web import api as api_mod
from ariadne.web.security import OTHER_CSP
from tests.core.fakeshim import ctl_ok
from tests.web.server.helpers import Stream, Web, run_web

pytestmark = [pytest.mark.web,
              pytest.mark.skipif(api_mod.STUB, reason="API v2 (Teil «api») noch nicht gebaut")]


def test_real_api_status_presentation_and_events(paths, operator):
    async def scenario(web: Web) -> None:
        token = await web.login()
        r = await web.req("GET", "/api/v1/status", token=token)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["api_version"] == 2 and body["session"]["origin"] == "local"
        assert r.headers["content-security-policy"] == OTHER_CSP and r.headers["x-frame-options"] == "DENY"
        assert r.headers["cache-control"] == "no-store"
        assert (await web.req("GET", "/api/v1/status")).status_code == 401
        streams = [Stream(web, token), Stream(web, token)]
        for s in streams:
            await s.wait_open()
        r = await web.req("PUT", "/api/v1/presentation", token=token, json_body={"on": True})
        assert r.status_code == 202, r.text
        r = await web.req("PUT", "/api/v1/presentation", token=token, json_body={"on": False}, origin=None)
        assert r.status_code == 403  # ohne Origin nie schreibend
        for s in streams:
            for _ in range(60):
                if "event: presentation" in s.text:
                    break
                await asyncio.sleep(0.05)
            assert 'event: presentation\ndata: {"on":true}' in s.text
        await ctl_ok(paths.ctl_sock, "lock")
        for s in streams:
            assert await s.ends_within(1.0)
            await s.close()
        assert (await web.req("GET", "/api/v1/status", token=token)).status_code == 401

    run_web(paths, operator, scenario)


def test_real_api_errors_carry_server_headers(paths, operator):
    async def scenario(web: Web) -> None:
        token = await web.login()
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        pid = (await ctl_ok(paths.ctl_sock, "status"))["project"]["id"]
        for method, path, status in (("POST", f"/api/v1/p/{pid}/ai/denkanstoss", 501),
                                     ("GET", f"/api/v1/p/{pid}/exports", 501),
                                     ("GET", "/api/v1/p/0199aaaa-0000-7000-8000-000000000000/hosts", 409),
                                     ("POST", "/api/v1/terminals/gibtsnicht/pause", 404)):
            r = await web.req(method, path, token=token, json_body={} if method == "POST" else None)
            assert r.status_code == status, (path, r.status_code, r.text)
            assert r.headers["content-security-policy"] == OTHER_CSP
            assert r.headers["x-frame-options"] == "DENY" and set(r.json()) == {"error"}

    run_web(paths, operator, scenario, ingest=True)
