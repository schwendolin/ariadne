"""Zustand der Oberfläche auf dem Server (web-api.md 18.2 bis 18.4) über echte HTTP-Anfragen gegen
den echten Server im Daemon: Vorlieben (E112) mit Prüfung, Datei 0600 und SSE ``prefs``, «Neu seit»
(E106) mit den Kennungen des Neuen und über einen Neustart des Daemons hinweg, Scope-Quittung mit
dem Inhalt der Scope-Warnung."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import stat
from pathlib import Path

import pytest

from ariadne.crypto.vault import OperatorVault
from ariadne.daemon.ingest import IngestService
from ariadne.web.api.ui_state import DEFAULT_PREFS, PREFS_NAME, read_prefs, write_prefs
from tests.core.fakeshim import FakeShim, ctl_ok
from tests.integration.helpers import TARGET, Term
from tests.web.api.helpers import build_fixture, sync
from tests.web.server.helpers import Stream, Web, run_web

pytestmark = pytest.mark.web

NMAP_NEW = (
    b"Starting Nmap 7.94 ( https://nmap.org )\r\nNmap scan report for 10.10.10.3\r\n"
    b"Host is up (0.0010s latency).\r\nPORT     STATE SERVICE VERSION\r\n"
    b"9999/tcp open  abyss   Abyss httpd 2.6\r\n\r\n"
    b"Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds\r\n"
)


def _web(paths, operator, scenario) -> None:
    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))


async def _until(pred, timeout: float = 5.0) -> bool:
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not pred():
        if loop.time() > end:
            return False
        await asyncio.sleep(0.05)
    return True


def test_prefs_defaults_validation_file_and_event(paths, operator):
    async def scenario(web: Web) -> None:
        token = await web.login()
        # ohne Projekt: Vorlieben gehen trotzdem (Anmeldung und Zustände im richtigen Theme)
        r = await web.req("GET", "/api/v1/ui/prefs", token=token)
        assert r.status_code == 200, r.text
        assert r.json() == {"prefs": DEFAULT_PREFS, "updated_at": None}
        s = Stream(web, token)
        await s.wait_open()
        r = await web.req("PUT", "/api/v1/ui/prefs", token=token, json_body={"theme": "dark"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["prefs"] == {"theme": "dark", "density": "comfortable", "learning": True}
        assert body["updated_at"].endswith("Z")
        assert await _until(lambda: "event: prefs\ndata: {}" in s.text)
        r = await web.req(
            "PUT", "/api/v1/ui/prefs", token=token, json_body={"density": "compact", "learning": False}
        )
        assert r.json()["prefs"] == {"theme": "dark", "density": "compact", "learning": False}
        f = Path(paths.state_dir) / PREFS_NAME
        st = f.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= 4096
        assert json.loads(f.read_text())["prefs"]["theme"] == "dark"
        # ungültig: leer, unbekanntes Feld, falscher Wert, falscher Typ (strict), null, kein JSON-Objekt
        for bad in ({}, {"foo": 1}, {"theme": "blue"}, {"learning": "yes"}, {"theme": None}, [], "dark"):
            r = await web.req("PUT", "/api/v1/ui/prefs", token=token, json_body=bad)
            assert r.status_code == 422, (bad, r.text)
            assert r.json()["error"]["code"] == "validation"
            assert "blue" not in r.text and "yes" not in r.text  # keine Werte in der Fehlermeldung
        r = await web.req("PUT", "/api/v1/ui/prefs", token=token, json_body={"theme": "light"}, origin=None)
        assert r.status_code == 403  # schreibend nie ohne Origin
        assert (await web.req("GET", "/api/v1/ui/prefs")).status_code == 401
        r = await web.req("GET", "/api/v1/ui/prefs", token=token)
        assert r.json()["prefs"] == {"theme": "dark", "density": "compact", "learning": False}
        # kaputte Datei: Standardwerte, kein Fehler
        f.write_text("{kaputt")
        r = await web.req("GET", "/api/v1/ui/prefs", token=token)
        assert r.status_code == 200 and r.json() == {"prefs": DEFAULT_PREFS, "updated_at": None}
        await s.close()

    _web(paths, operator, scenario)


def test_prefs_file_fieldwise_fallback_and_size(tmp_path):
    d = tmp_path / "state"
    prefs, updated = read_prefs(d)
    assert prefs == DEFAULT_PREFS and updated is None
    d.mkdir(mode=0o700)
    stored = {"prefs": {"theme": "dark", "density": "riesig"}, "updated_ns": 5}
    (d / PREFS_NAME).write_text(json.dumps(stored))
    (d / PREFS_NAME).chmod(0o600)
    prefs, updated = read_prefs(d)
    assert prefs == {**DEFAULT_PREFS, "theme": "dark"} and updated == 5
    (d / PREFS_NAME).write_bytes(b"x" * 5000)  # über 4 KiB: Standardwerte
    assert read_prefs(d) == (DEFAULT_PREFS, None)
    with pytest.raises(ValueError):
        write_prefs(d, {"theme": "<script>"})
    prefs, now = write_prefs(d, {"learning": False})
    assert prefs["learning"] is False and now > 0


def _again(tpl, paths):
    """Derselbe Operator für einen zweiten Daemon-Lauf (der erste hat ihn beim Ende gesperrt)."""
    return dataclasses.replace(
        tpl.op, vault=OperatorVault(paths.operator_dir), _secrets=list(tpl.op.own_secrets), _api_keys={}
    )


def test_seen_new_since_ids_and_restart(paths, operator, operator_template):
    state: dict[str, str] = {}

    async def first(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, inputs=False)
        token = await web.login()
        base = f"/api/v1/p/{fx.pid}/ui/seen"
        r = await web.req("GET", base, token=token)
        assert r.status_code == 200 and r.json() == {"seen_at": None, "new": None}
        for bad in ({"seen_at": "2020-01-01T00:00:00Z"}, {"x": 1}, [1]):
            r = await web.req("PUT", base, token=token, json_body=bad)
            assert r.status_code == 422, (bad, r.text)
        r = await web.req("PUT", base, token=token)  # ohne Körper (keepalive beim Verbergen des Tabs)
        assert r.status_code == 202, r.text
        seen_at = r.json()["seen_at"]
        r = await web.req("GET", base, token=token)
        body = r.json()
        assert body["seen_at"] == seen_at
        assert body["new"] == {
            "since": seen_at, "count": 0, "hosts": [], "access": [], "services": [], "items": [],
            "keysteps": [],
        }
        # Neues nach dem Verbergen: ein Service, ein Schlüsselschritt mit Zugriff
        s3 = await FakeShim(paths.term_sock).connect(proto=2)
        await s3.wait_state(rec="on")
        t3 = Term(s3)
        await t3.command("nmap -sV -p9999 10.10.10.3", NMAP_NEW, cwd=str(fx.ws))
        await t3.acked()
        host = f"ip:default/{TARGET}"
        r = await web.req(
            "POST", f"/api/v1/p/{fx.pid}/decisions", token=token,
            json_body={
                "decisions": [{"kind": "d.keystep.mark", "payload": {"step": "foothold", "host": TARGET}}]
            },
        )
        assert r.status_code == 201, r.text
        await sync(d)
        body = (await web.req("GET", base, token=token)).json()
        new = body["new"]
        assert new["hosts"] == []  # der Host war schon da
        assert new["services"] == [f"svc:{host}|tcp/9999"]
        assert new["access"] == [host]
        assert len(new["keysteps"]) == 1 and new["keysteps"][0].startswith("t")
        graph = (await web.req("GET", f"/api/v1/p/{fx.pid}/graph", token=token)).json()
        assert new["keysteps"][0] in {e["id"] for e in graph["edges"] if e["kind"] == "thread"}
        assert new["count"] == len(new["services"]) + len(new["access"]) + len(new["keysteps"]) + len(
            new["items"]
        )
        # Neuladen: dieselbe Marke (nichts im Browser)
        assert (await web.req("GET", base, token=token)).json() == body
        # nach erneutem Verbergen ist nichts mehr neu
        await web.req("PUT", base, token=token, json_body={})
        assert (await web.req("GET", base, token=token)).json()["new"]["count"] == 0
        state["seen_at"] = (await web.req("GET", base, token=token)).json()["seen_at"]
        state["pid"] = fx.pid
        r = await web.req("GET", "/api/v1/p/0199aaaa-0000-7000-8000-000000000000/ui/seen", token=token)
        assert r.status_code == 409
        for s in fx.shims + [s3]:
            await s.close()

    async def second(web: Web) -> None:
        # Neustart des Daemons (neue Sitzung): seen_at kommt aus state.db
        await ctl_ok(paths.ctl_sock, "start", slug="lame")
        token = await web.login()
        r = await web.req("GET", f"/api/v1/p/{state['pid']}/ui/seen", token=token)
        assert r.status_code == 200, r.text
        assert r.json()["seen_at"] == state["seen_at"]

    _web(paths, operator, first)
    _web(paths, _again(operator_template, paths), second)


def test_scope_warning_content_and_ack(paths, operator):
    async def scenario(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, inputs=False)
        token = await web.login()
        st = (await web.req("GET", "/api/v1/status", token=token)).json()
        assert st["scope_warning"] is None
        out = b"Nmap done: 1 IP address (0 hosts up)\r\n"
        await fx.term.command("nmap -sn 10.10.10.99", out, cwd=str(fx.ws))
        await fx.term.acked()
        await sync(d)
        st = (await web.req("GET", "/api/v1/status", token=token)).json()
        w = st["scope_warning"]
        assert w is not None, st
        assert w["text"] == "nmap -sn 10.10.10.99" and w["ctrl"] is False
        assert w["targets"] == [{"value": "10.10.10.99", "verdict": "out", "ctrl": False, "proposals": [
            {"entry": "10.10.10.99", "kind": "ip", "outside_lab": False, "public": False}]}]
        assert w["scope"] == [TARGET]
        assert w["acked"] is False
        assert w["terminal"] == {"terminal_id": fx.shim.terminal_id, "ordinal": 1, "label": None}
        assert w["cmd_ref"] and w["cmd_id"].endswith(w["cmd_ref"].split("@")[1])
        # Terminals tragen Nummer und Web-Pausenbudget (18.8)
        t = next(x for x in st["terminals"] if x["terminal_id"] == fx.shim.terminal_id)
        assert t["ordinal"] == 1 and t["web_pause_left_s"] == 1800 and t["opened_at"].endswith("Z")
        assert st["operator"]["own_secrets"] == 1
        url = f"/api/v1/p/{fx.pid}/ui/scope-ack"
        for bad, status in (({"cmd_id": "deadbeef@1"}, 404), ({"cmd_id": "x"}, 422), ({}, 422),
                            ({"cmd_id": w["cmd_id"], "extra": 1}, 422)):
            r = await web.req("PUT", url, token=token, json_body=bad)
            assert r.status_code == status, (bad, r.text)
        r = await web.req("PUT", url, token=token, json_body={"cmd_id": w["cmd_ref"]})
        assert r.status_code == 202, r.text
        st = (await web.req("GET", "/api/v1/status", token=token)).json()
        assert st["scope_warning"]["acked"] is True
        # ein neuerer Befehl mit Ziel ausserhalb: wieder nicht quittiert
        await asyncio.sleep(0.01)
        await fx.term.command("ping -c1 10.10.10.98", b"1 packets transmitted\r\n", cwd=str(fx.ws))
        await fx.term.acked()
        await sync(d)
        st = (await web.req("GET", "/api/v1/status", token=token)).json()
        assert st["scope_warning"]["acked"] is False and "10.10.10.98" in st["scope_warning"]["text"]
        for s in fx.shims:
            await s.close()

    _web(paths, operator, scenario)
