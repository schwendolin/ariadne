"""Screenshots über alle drei Auslöser gegen einen echten Daemon und einen eigenen Xvfb:

* Web: ``POST/GET /p/{pid}/screenshots`` und ``GET /p/{pid}/blobs/{id}`` über echte HTTP-Anfragen
  (Countdown, Modi, Kontext, Prüfung des Körpers, nur Screenshot-Blobs, Präsentationsmodus,
  klare Meldung ohne X11 und bei Wayland).
* Hotkey: ``req.shot`` vom (Fake-)Shim mit der Umgebung aus dem HELLO.
* CLI: ``ariadne shot`` mit der eigenen Umgebung.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid

import pytest

from ariadne.daemon.ingest import IngestService
from ariadne.sources import screenshot as shot
from ariadne.sources import screenshot_service
from tests.core.conftest import OWN_SECRET
from tests.core.fakeshim import FakeShim, ctl_ok
from tests.core.test_daemon import run
from tests.screenshots.conftest import Window, decode_png, pixel
from tests.web.server.helpers import Web, run_web

pytestmark = pytest.mark.web


@pytest.fixture
def no_session(monkeypatch, tmp_path):
    """Keine grafische Sitzung in der eigenen Umgebung und keine fremden Prozesse (/proc leer)."""
    for k in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_SESSION_TYPE"):
        monkeypatch.delenv(k, raising=False)
    empty = tmp_path / "noproc"
    empty.mkdir()
    monkeypatch.setattr(screenshot_service, "PROC_ROOT", empty)


def shots(d):
    return list(d.project.journal.iter_events(kinds=["shot.captured"]))


def test_web_screenshots_and_blobs(paths, operator, xserver, window, no_session):
    async def scenario(web: Web) -> None:
        d = web.d
        await ctl_ok(paths.ctl_sock, "project.new", slug="shots", targets=["10.10.10.0/24"])
        sh = await FakeShim(paths.term_sock).connect(display={"DISPLAY": xserver.display})
        await sh.wait_state(rec="on")
        await sh.out(1, 0, b"$ id\r\nuid=0(root)\r\n")
        await sh.wait_ack(1)
        await ctl_ok(paths.ctl_sock, "ctx.set", terminal_id=sh.terminal_id, host="10.10.10.5", user="root")
        pid = d.project.info.id
        token = await web.login()
        url = f"/api/v1/p/{pid}/screenshots"

        # Fenster (Standard), ohne Countdown
        r = await web.req("POST", url, token=token, json_body={"delay_s": 0, "note": "Beleg Login"})
        assert r.status_code == 201, r.text
        s1 = r.json()["screenshot"]
        assert (s1["mode"], s1["trigger"], s1["width"], s1["height"]) == ("window", "webui", 200, 120)
        assert s1["terminal_id"] == sh.terminal_id and s1["host"] == "ip:default/10.10.10.5"
        assert s1["host_auto"] is False and isinstance(s1["stream_off"], int)
        assert s1["window_title"] == "root@target:  ]0;evil  /tmp" and s1["wm_class"] == "Ariadne-test"
        assert s1["url"] == f"/api/v1/p/{pid}/blobs/{s1['blob_id']}" and s1["mime"] == "image/png"
        assert s1["note"] == "Beleg Login" and s1["ts"].endswith("Z") and len(s1["dhash"]) == 16

        # Knopf ohne Körper: Fenster nach dem Countdown von 3 s
        t0 = time.monotonic()
        r = await web.req("POST", url, token=token)
        assert r.status_code == 201, r.text
        assert time.monotonic() - t0 >= 3.0
        assert r.json()["screenshot"]["mode"] == "window"
        r = await web.req("POST", url, token=token, json_body={"mode": "monitor", "delay_s": 0})
        assert r.status_code == 201, r.text
        assert (r.json()["screenshot"]["width"], r.json()["screenshot"]["window_title"]) == (800, None)

        r = await web.req("POST", url, token=token,
                          json_body={"mode": "region", "delay_s": 0,
                                     "region": {"x": 110, "y": 60, "width": 40, "height": 30}})
        assert r.status_code == 201, r.text
        s3 = r.json()["screenshot"]
        assert (s3["mode"], s3["width"], s3["height"]) == ("region", 40, 30)

        # nur eine Aufnahme zur Zeit
        a, b = await asyncio.gather(
            web.req("POST", url, token=token, json_body={"mode": "monitor", "delay_s": 1}),
            web.req("POST", url, token=token, json_body={"mode": "monitor", "delay_s": 1}),
        )
        assert sorted([a.status_code, b.status_code]) == [201, 409]

        # Körper prüfen
        for bad in ({"mode": "region"}, {"region": {"x": 0, "y": 0, "width": 5, "height": 5}},
                    {"delay_s": 11}, {"delay_s": "3"}, {"mode": "desktop"}, {"x": 1}, {"note": "x" * 501},
                    {"terminal_id": "zz"},
                    {"mode": "region", "region": {"x": 0, "y": 0, "width": 0, "height": 5}}):
            r = await web.req("POST", url, token=token, json_body=bad)
            assert r.status_code == 422, (bad, r.text)
            assert "x" * 50 not in r.text
        r = await web.req("POST", f"/api/v1/p/{uuid.uuid4()}/screenshots", token=token, json_body={})
        assert r.status_code == 409

        # Liste: neueste zuerst
        r = await web.req("GET", url, token=token)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 5 and items[-1]["id"] == s1["id"] and r.json()["presentation"] is False
        assert [i["seq"] for i in items] == sorted((i["seq"] for i in items), reverse=True)
        assert items[0]["url"].startswith(f"/api/v1/p/{pid}/blobs/")

        # Bild ausliefern: nur PNG, nosniff, keine Metadaten, Hash wie im Ereignis
        r = await web.req("GET", s1["url"], token=token)
        assert r.status_code == 200
        assert r.headers["content-type"] == "image/png"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["content-disposition"] == 'inline; filename="screenshot.png"'
        assert "sandbox" in r.headers["content-security-policy"] and r.headers["cache-control"] == "no-store"
        assert hashlib.sha256(r.content).hexdigest() == s1["sha256"]
        assert shot.check_png(r.content) == (200, 120)
        assert pixel(decode_png(r.content), 5, 5) == (200, 30, 40)
        r = await web.req("GET", s1["url"])  # ohne Anmeldung
        assert r.status_code == 401

        # andere Blobs nie: Datei aus dem Ziel (auch ein PNG oder SVG), unbekannt, ungültige ID
        file_png = d.project.blobs.put_bytes(shot.encode_png(b"\x01" * 12, 2, 2), kind="file").blob_id
        svg = d.project.blobs.put_bytes(b"<svg xmlns='http://www.w3.org/2000/svg'><script/></svg>",
                                        kind="file").blob_id
        for bid in (file_png, svg, str(uuid.uuid4()), "nicht-uuid", s1["blob_id"].upper()):
            r = await web.req("GET", f"/api/v1/p/{pid}/blobs/{bid}", token=token)
            assert r.status_code == 404, (bid, r.status_code)
            assert "svg" not in r.headers.get("content-type", "")

        # Präsentationsmodus: Bild verdeckt, Titel und Notiz weg
        await web.req("PUT", "/api/v1/presentation", token=token, json_body={"on": True})
        r = await web.req("GET", s1["url"], token=token)
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
        r = await web.req("GET", url, token=token)
        body = r.json()
        assert body["presentation"] is True
        assert all(i["window_title"] is None and i["note"] is None and i["wm_class"] is None
                   for i in body["items"])
        assert "evil" not in r.text and "Beleg Login" not in r.text
        await web.req("PUT", "/api/v1/presentation", token=token, json_body={"on": False})
        assert (await web.req("GET", s1["url"], token=token)).status_code == 200

        # ohne X11: klare Meldung (Terminal ohne Sitzung im HELLO, keine eigene, /proc leer)
        bare = await FakeShim(paths.term_sock).connect()
        way = await FakeShim(paths.term_sock).connect(
            display={"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"})
        await bare.wait_state(rec="on")
        await way.wait_state(rec="on")
        r = await web.req("POST", url, token=token, json_body={"delay_s": 0, "terminal_id": bare.terminal_id})
        assert r.status_code == 503 and r.json()["error"] == {"code": "shot_display",
                                                             "message": shot.SHOT_ERRORS["shot_display"]}
        r = await web.req("POST", url, token=token, json_body={"delay_s": 0, "terminal_id": way.terminal_id})
        assert r.status_code == 503 and r.json()["error"]["code"] == "shot_wayland"
        assert "X11" in r.json()["error"]["message"]

        # eigenes Secret im Fenstertitel: nie in einer Antwort (E72)
        leak = Window(xserver.display, x=300, y=300, w=50, h=40, rgb=(1, 2, 3), title=f"sudo -S {OWN_SECRET}")
        try:
            r = await web.req("POST", url, token=token, json_body={"delay_s": 0})
            assert r.status_code == 201 and OWN_SECRET not in r.text
            assert r.json()["screenshot"]["width"] == 50
            r = await web.req("GET", url, token=token)
            assert OWN_SECRET not in r.text and len(r.json()["items"]) == 6
        finally:
            leak.close()

        # Journal: Ereignis mit Kontext, Blob verschlüsselt (kein PNG-Klartext auf der Platte)
        recs = shots(d)
        assert len(recs) == 6 and {r.origin for r in recs} == {"webui"}
        first = next(r for r in recs if r.id == s1["id"])
        assert first.header["stack"][-1]["host"] == "ip:default/10.10.10.5"
        assert first.terminal_id == sh.terminal_id and first.header["backend"] == "mss+xlib"
        files = list(d.project.blobs.root.rglob("*.age"))
        assert len(files) >= 4
        for f in files:
            assert b"IHDR" not in f.read_bytes()
        for s_ in (sh, bare, way):
            await s_.close()

    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))


def test_hotkey_and_cli(paths, operator, xserver, window, no_session, monkeypatch, capsys):
    from ariadne.cli.main import main as cli_main

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="hot", targets=["10.10.10.0/24"])
        sh = await FakeShim(paths.term_sock).connect(display={"DISPLAY": xserver.display})
        await sh.wait_state(rec="on")
        await sh.out(1, 0, b"$ whoami\r\nroot\r\n")
        await sh.wait_ack(1)

        # F12 s: Fenster, Ergebnis im Titel
        await sh.event(2, "req.shot", mode="window")
        await sh._wait(lambda: "Screenshot gespeichert (Fenster)" == sh.state.get("title_extra"), 10)
        # Bereich gibt es am Terminal nicht: wird zum Fenster
        await sh.event(3, "req.shot", mode="region")
        await sh._wait(lambda: len(shots(d)) == 2, 10)
        recs = shots(d)
        assert {r.header["mode"] for r in recs} == {"window"}
        assert all(r.origin == "shim" and r.header["trigger"] == "hotkey" for r in recs)
        assert recs[0].terminal_id == sh.terminal_id and isinstance(recs[0].stream_off, int)

        # CLI mit eigener Umgebung (Desktop-Kürzel)
        monkeypatch.setenv("DISPLAY", xserver.display)
        rc = await asyncio.to_thread(cli_main, ["shot", "--region", "100,50,20,10"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Screenshot gespeichert: Bereich, 20x10" in out
        rec = shots(d)[-1]
        assert rec.origin == "cli" and rec.header["trigger"] == "cli" and rec.header["width"] == 20
        assert rec.terminal_id == sh.terminal_id  # zuletzt aktives Terminal als Kontext

        rc = await asyncio.to_thread(cli_main, ["shot", "monitor", "--region", "1,1,1,1"])
        assert rc == 1
        monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
        monkeypatch.setenv("XDG_SESSION_TYPE", "wayland")
        rc = await asyncio.to_thread(cli_main, ["shot"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "nur unter X11" in err
        assert len(shots(d)) == 3

        # ohne Sitzung am Terminal und im Daemon: klare Meldung im Titel
        for k in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE"):
            monkeypatch.delenv(k)
        bare = await FakeShim(paths.term_sock).connect()
        await bare.wait_state(rec="on")
        await bare.event(1, "req.shot")
        await bare._wait(lambda: "DISPLAY fehlt" in (bare.state.get("title_extra") or ""), 10)
        await sh.close()
        await bare.close()

    run(paths, operator, scenario)


def test_hotkey_without_project_and_ops_validation(paths, operator, no_session):
    async def scenario(d) -> None:
        from tests.core.fakeshim import ctl

        res = await ctl(paths.ctl_sock, "shot.take", mode="window")
        assert res["error"]["code"] == "no_project"
        await ctl_ok(paths.ctl_sock, "project.new", slug="ops", targets=["10.10.10.0/24"])
        for bad in ({"mode": "x"}, {"mode": "region"}, {"mode": "window", "region": [0, 0, 1, 1]},
                    {"delay_s": 99}, {"origin": "webui"}, {"display": "DISPLAY=:0"}, {"note": "n" * 501}):
            res = await ctl(paths.ctl_sock, "shot.take", **bad)
            assert res["error"]["code"] == "invalid", bad
        res = await ctl(paths.ctl_sock, "shot.take", mode="monitor")
        assert res["error"]["code"] == "shot_display"
        assert res["error"]["message"] == shot.SHOT_ERRORS["shot_display"]
        assert shots(d) == []

    run(paths, operator, scenario)
