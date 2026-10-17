"""T6 bis T8 (Konzept Fernzugriff 7.1, Vertrag 5): Bindung des Tokens an einen Prozess, Ende der
Sitzung mit sofortigem Schliessen der SSE-Ströme, Browser-Speicher. Echter Server, echte
Prozesse, echte Daemon-Ereignisse.
"""

from __future__ import annotations

import asyncio
import json
import os
import time

import pytest

from tests.core.fakeshim import ctl, ctl_ok
from tests.web.server.helpers import ClientProc, FakeSshd, Stream, Web, run_web, use_test_api
from tests.web.server.test_sessions import FakeClock

pytestmark = pytest.mark.web


@pytest.fixture(autouse=True)
def _api(monkeypatch):
    use_test_api(monkeypatch)


async def _sessions(web: Web) -> list[dict]:
    return (await ctl_ok(web.paths.ctl_sock, "ui.sessions"))["sessions"]


async def _until(cond, seconds: float) -> float:
    t0 = time.monotonic()
    while time.monotonic() - t0 < seconds:
        if await cond():
            return time.monotonic() - t0
        await asyncio.sleep(0.05)
    raise AssertionError("Bedingung nicht erfüllt")


# --------------------------------------------------------------------------- #
# T6 Bindung des Tokens
# --------------------------------------------------------------------------- #


def test_t6_local_token_is_bound_to_the_process_that_logged_in(paths, operator):
    async def scenario(web: Web) -> None:
        x = await ClientProc.start(web.port)
        y = await ClientProc.start(web.port)
        try:
            status, body = await x.request("POST", "/api/v1/session", port=web.port,
                                           body={"code": await web.code()})
            assert status == 200, body
            token = json.loads(body)["token"]
            status, body = await x.request("GET", "/api/v1/test/whoami", port=web.port, token=token)
            assert status == 200
            # dieselbe Anfrage aus anderen Prozessen: 401
            assert (await web.req("GET", "/api/v1/test/whoami", token=token)).status_code == 401
            assert (await y.request("GET", "/api/v1/test/whoami", port=web.port, token=token))[0] == 401
            rows = await _sessions(web)
            assert len(rows) == 1 and rows[0]["peer_pid"] == x.proc.pid and rows[0]["origin"] == "local"
            await x.stop()  # X endet: Sitzung endet innerhalb 3 s
            took = await _until(lambda: _sessions_empty(web), 3.0)
            assert took < 3.0
            assert (await y.request("GET", "/api/v1/test/whoami", port=web.port, token=token))[0] == 401
        finally:
            await x.stop()
            await y.stop()

    run_web(paths, operator, scenario)


async def _sessions_empty(web: Web) -> bool:
    return not await _sessions(web)


def test_t6_sshd_token_is_bound_to_the_sshd_process(paths, operator, tmp_path):
    async def scenario(web: Web) -> None:
        sshd = await FakeSshd.start(tmp_path, paths.ctl_sock)
        try:
            assert sshd.result["ok"], sshd.result
            res = sshd.result["result"]
            assert res["via"] == "sshd" and res["url"].endswith(res["code"])
            web.unreadable()  # Verbindung über den Tunnel: Prozess nicht lesbar
            r = await web.req("POST", "/api/v1/session", json_body={"code": res["code"]})
            assert r.status_code == 200, r.text
            token = r.json()["token"]
            assert r.json()["session"]["origin"] == "sshd"
            assert (await web.req("GET", "/api/v1/test/whoami", token=token)).json()["origin"] == "sshd"
            rows = await _sessions(web)
            assert rows[0]["peer_pid"] == sshd.proc.pid and rows[0]["peer_comm"] == "sshd"
            web.real_resolver()  # lesbarer fremder Prozess (dieser Testprozess): 401
            assert (await web.req("GET", "/api/v1/test/whoami", token=token)).status_code == 401
            web.unreadable()
            stream = Stream(web, token)
            await stream.wait_open()
            assert stream.status == 200
            await sshd.stop()  # Tunnelende
            assert await stream.ends_within(3.0)
            assert (await web.req("GET", "/api/v1/test/whoami", token=token)).status_code == 401
            assert await _sessions(web) == []
            await stream.close()
        finally:
            await sshd.stop()

    run_web(paths, operator, scenario)


def test_t6_sshd_code_from_readable_foreign_process_and_local_code_over_tunnel(paths, operator, tmp_path):
    async def scenario(web: Web) -> None:
        sshd = await FakeSshd.start(tmp_path, paths.ctl_sock)
        try:
            code = sshd.result["result"]["code"]
            r = await web.req("POST", "/api/v1/session", json_body={"code": code})  # lesbar, nicht sshd
            assert r.status_code == 401
            # lokaler Code über eine Verbindung ohne lesbaren Prozess (Tunnel): 401
            local = await web.code()
            web.unreadable()
            assert (await web.req("POST", "/api/v1/session", json_body={"code": local})).status_code == 401
        finally:
            await sshd.stop()
        # ui.code mit via=sshd aus einem Prozess ohne sshd-Vorfahren
        res = await ctl(paths.ctl_sock, "ui.code", via="sshd")
        assert res["error"]["code"] == "not_sshd"

    run_web(paths, operator, scenario)


# --------------------------------------------------------------------------- #
# T7 Sitzungsende
# --------------------------------------------------------------------------- #


async def _ends(web: Web, trigger) -> None:
    token = await web.login()
    streams = [Stream(web, token), Stream(web, token)]
    for s in streams:
        await s.wait_open()
        assert s.status == 200 and s.text.startswith(": ok")
    await trigger()
    for s in streams:
        assert await s.ends_within(1.0), "Strom endet nicht innerhalb 1 s"
        await s.close()
    assert (await web.req("GET", "/api/v1/test/whoami", token=token)).status_code == 401
    assert (await web.req("GET", "/api/v1/session", token=token)).status_code == 401


def test_t7_lock_stop_close_revoke_end_sessions_immediately(paths, operator):
    async def scenario(web: Web) -> None:
        sock = paths.ctl_sock
        await ctl_ok(sock, "start", slug="lame", targets=["10.10.10.3"])
        await _ends(web, lambda: ctl_ok(sock, "project.close"))
        await ctl_ok(sock, "start", slug="lame")
        await _ends(web, lambda: ctl_ok(sock, "lock"))  # E103: Projekt bleibt aktiv, Sitzung endet
        await ctl_ok(sock, "unlock", passphrase="Korrekt-Pferd-Batterie-9")
        await _ends(web, lambda: ctl_ok(sock, "stop"))
        await _ends(web, lambda: ctl_ok(sock, "ui.revoke"))

        async def revoke_one() -> None:
            sid = (await _sessions(web))[0]["session_id"]
            assert (await ctl_ok(sock, "ui.revoke", session_id=sid)) == {"revoked": 1}

        await _ends(web, revoke_one)

        async def logout() -> None:
            tok = await web.login()
            r = await web.req("DELETE", "/api/v1/session", token=tok)
            assert r.status_code == 204 and r.headers["clear-site-data"] == '"cache", "storage"'
            assert (await web.req("GET", "/api/v1/session", token=tok)).status_code == 401

        await logout()

    run_web(paths, operator, scenario)


def test_t7_switch_keeps_session_idle_ends_it(paths, operator):
    async def scenario(web: Web) -> None:
        sock = paths.ctl_sock
        await ctl_ok(sock, "start", slug="lame", targets=["10.10.10.3"])
        token = await web.login()
        stream = Stream(web, token)
        await stream.wait_open()
        await ctl_ok(sock, "start", slug="legacy", targets=["10.10.10.4"])  # Projektwechsel
        assert not await stream.ends_within(0.5)
        assert (await web.req("GET", "/api/v1/test/whoami", token=token)).status_code == 200
        # Leerlauf-Ende: Ereignis wie vom Daemon (project closed, reason idle)
        web.ext._on_event("project", {"project_id": "x", "slug": "legacy", "change": "closed",
                                      "reason": "idle"})
        assert await stream.ends_within(1.0)
        await stream.close()
        assert (await web.req("GET", "/api/v1/test/whoami", token=token)).status_code == 401

    run_web(paths, operator, scenario)


def test_t7_lock_without_event_is_caught_by_the_watch(paths, operator):
    """``stop`` ohne offenes Projekt sperrt den Tresor ohne Projekt-Ereignis: die Prüfung alle 2 s
    beendet die Sitzungen trotzdem."""

    async def scenario(web: Web) -> None:
        token = await web.login()
        stream = Stream(web, token)
        await stream.wait_open()
        await ctl_ok(paths.ctl_sock, "stop")  # kein Projekt offen
        assert await stream.ends_within(3.0)
        await stream.close()
        assert (await web.req("GET", "/api/v1/test/whoami", token=token)).status_code == 401

    run_web(paths, operator, scenario)


def test_t7_expiry_after_twelve_hours(paths, operator):
    clock = FakeClock()

    async def scenario(web: Web) -> None:
        token = await web.login()
        stream = Stream(web, token)
        await stream.wait_open()
        clock.advance(12 * 3600 - 10)
        assert (await web.req("GET", "/api/v1/test/whoami", token=token)).status_code == 200
        clock.advance(11)
        assert (await web.req("GET", "/api/v1/test/whoami", token=token)).status_code == 401
        web.ext.check_now()
        assert await stream.ends_within(1.0)
        await stream.close()

    run_web(paths, operator, scenario, ext_kw={"clock": clock})


def test_t7_daemon_end_closes_streams(paths, operator):
    async def scenario(web: Web) -> None:
        token = await web.login()
        stream = Stream(web, token)
        await stream.wait_open()
        t0 = time.monotonic()
        await web.d.stop()
        assert await stream.ends_within(1.0)
        assert time.monotonic() - t0 < 3.0
        await stream.close()
        assert web.ext.server is None and not web.ext.running

    run_web(paths, operator, scenario)


def test_t7_no_token_in_listing_or_memory(paths, operator):
    async def scenario(web: Web) -> None:
        tokens = [await web.login(), await web.login()]
        listing = await ctl_ok(paths.ctl_sock, "ui.sessions")
        dump = json.dumps(listing) + repr(vars(web.ext.sessions)) + repr(web.ext.sessions._sessions)
        dump += repr(web.ext.sessions._codes) + repr(vars(web.ext))
        for t in tokens:
            assert t not in dump
        rows = listing["sessions"]
        assert {r["origin"] for r in rows} == {"local"} and all(r["peer_pid"] == os.getpid() for r in rows)
        assert set(rows[0]) == {"session_id", "origin", "created_ns", "expires_ns", "last_used_ns",
                                "peer_pid", "peer_comm"}
        st = await ctl_ok(paths.ctl_sock, "ui.status")
        assert st["sessions"] == 2

    run_web(paths, operator, scenario)


# --------------------------------------------------------------------------- #
# T8 Browser-Speicher, SSE
# --------------------------------------------------------------------------- #


def test_t8_sse_format_replay_and_stream_limit(paths, operator):
    async def scenario(web: Web) -> None:
        token = await web.login()
        stream = Stream(web, token)
        await stream.wait_open()
        assert stream.headers["content-type"].startswith("text/event-stream")
        assert stream.headers["cache-control"] == "no-store" and stream.headers["x-accel-buffering"] == "no"
        assert stream.headers["x-frame-options"] == "DENY"
        web.ext.bus.publish("presentation", {"on": True})
        web.ext.bus.publish("terminal", {"terminal_id": "t1", "change": "state"})
        await _until(lambda: _has(stream, "event: terminal"), 2.0)
        lines = [ln for ln in stream.text.split("\n") if ln.startswith("id: ")]
        first_id = lines[0].removeprefix("id: ")
        # Wiederverbinden mit Last-Event-ID: nur das Spätere kommt nach
        again = Stream(web, token, last_event_id=first_id)
        await again.wait_open()
        await _until(lambda: _has(again, "event: terminal"), 2.0)
        assert "event: presentation" not in again.text
        # höchstens 8 Ströme pro Sitzung: der neunte ersetzt den ältesten
        more = [Stream(web, token) for _ in range(7)]
        for s in more:
            await s.wait_open()
        assert await stream.ends_within(1.0)
        assert not again.ended.is_set()
        for s in [stream, again, *more]:
            await s.close()

    run_web(paths, operator, scenario)


async def _has(stream: Stream, text: str) -> bool:
    return text in stream.text


def test_t8_events_need_a_token_and_never_take_it_from_the_url(paths, operator):
    async def scenario(web: Web) -> None:
        token = await web.login()
        r = await web.req("GET", f"/api/v1/events?token={token}")
        assert r.status_code == 401
        r = await web.req("GET", "/api/v1/events", headers={"Sec-Fetch-Site": "cross-site"}, token=token)
        assert r.status_code == 403

    run_web(paths, operator, scenario)
