"""E120: Die Scope-Warnung steht in ``GET /p/{pid}/next`` (Feld ``scope_warning``, Form wie
``Status.scope_warning`` in web-api.md 18.4), solange sie nicht quittiert ist. Quittieren über
``PUT /ui/scope-ack`` blendet sie aus; ein neuerer Befehl mit Ziel ausserhalb bringt sie zurück.
Echter Server im Daemon, echte HTTP-Anfragen."""

from __future__ import annotations

import asyncio

import pytest

from ariadne.daemon.ingest import IngestService
from tests.integration.helpers import TARGET
from tests.web.api.helpers import build_fixture, sync
from tests.web.server.helpers import Web, run_web

pytestmark = pytest.mark.web


def test_next_carries_unacked_scope_warning_first(paths, operator):
    async def scenario(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, inputs=False)
        token = await web.login()
        nxt = f"/api/v1/p/{fx.pid}/next"
        body = (await web.req("GET", nxt, token=token)).json()
        assert body["scope_warning"] is None
        open_before = body["open"]
        await fx.term.command(
            "nmap -sn 10.10.10.99", b"Nmap done: 1 IP address (0 hosts up)\r\n", cwd=str(fx.ws)
        )
        await fx.term.acked()
        await sync(d)
        body = (await web.req("GET", nxt, token=token)).json()
        w = body["scope_warning"]
        assert w is not None, body
        status = (await web.req("GET", "/api/v1/status", token=token)).json()["scope_warning"]
        assert w == status  # dieselbe Form und derselbe Inhalt wie in /status (18.4)
        assert w["text"] == "nmap -sn 10.10.10.99" and w["acked"] is False
        assert w["targets"] == [{"value": "10.10.10.99", "verdict": "out", "ctrl": False}]
        assert w["scope"] == [TARGET]
        assert body["open"] == open_before  # zählt nicht in «open» und hat keine Ordnungsnummer
        # quittieren: aus /next verschwunden, in /status als quittiert markiert
        r = await web.req(
            "PUT", f"/api/v1/p/{fx.pid}/ui/scope-ack", token=token, json_body={"cmd_id": w["cmd_id"]}
        )
        assert r.status_code == 202, r.text
        assert (await web.req("GET", nxt, token=token)).json()["scope_warning"] is None
        assert (await web.req("GET", "/api/v1/status", token=token)).json()["scope_warning"]["acked"] is True
        # ein neuerer Befehl mit Ziel ausserhalb: wieder da
        await asyncio.sleep(0.01)
        await fx.term.command("ping -c1 10.10.10.98", b"1 packets transmitted\r\n", cwd=str(fx.ws))
        await fx.term.acked()
        await sync(d)
        w2 = (await web.req("GET", nxt, token=token)).json()["scope_warning"]
        assert w2 is not None and "10.10.10.98" in w2["text"] and w2["cmd_id"] != w["cmd_id"]
        for s in fx.shims:
            await s.close()

    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))
