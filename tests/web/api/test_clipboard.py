"""«In die Kali kopieren» über echte HTTP-Anfragen gegen den echten Server (E111, web-api.md 18.7):
mit Attrappen für xclip und xsel (keine echte Zwischenablage, kein X). Der Wert geht nur in die
Attrappe, nie in die Antwort, nie in argv; eigene Secrets nie; sichtbare Eingaben sind kein Secret;
Präsentationsmodus sperrt; ohne Werkzeug bzw. Sitzung 503 mit festem Text; nach der Frist leer."""

from __future__ import annotations

import asyncio
import urllib.parse

import pytest

from ariadne.daemon.clipboard import Clipboard
from ariadne.daemon.ingest import IngestService
from ariadne.web.api.errors import MESSAGES
from tests.core.test_clipboard import fake_tools
from tests.web.api.helpers import CRYPT, OWN_SECRET, REMOTE_PW, TARGET, build_fixture
from tests.web.server.helpers import Web, run_web

pytestmark = pytest.mark.web


def test_copy_to_kali_clipboard(paths, operator, tmp_path):
    bindir = fake_tools(tmp_path)
    clip = tmp_path / "clip"

    async def scenario(web: Web) -> None:
        d = web.d
        d.clipboard = Clipboard(path=str(bindir), env={"DISPLAY": ":0"}, proc_root=tmp_path / "noproc",
                                clear_after_s=0.3)
        fx = await build_fixture(d, paths)
        token = await web.login()
        url = f"/api/v1/p/{fx.pid}/secrets/copy"
        items = (await web.req("GET", f"/api/v1/p/{fx.pid}/inputs", token=token)).json()["items"]
        hidden = [i for i in items if i["hidden"]]
        visible = [i for i in items if not i["hidden"]]
        assert len(hidden) == 2 and visible
        own, remote = hidden[0], hidden[1]  # sudo-Passwort (eigenes Secret), dann das Remote-Passwort

        r = await web.req("POST", url, token=token, json_body={"ref": "input", "seq": remote["seq"]})
        assert r.status_code == 202, r.text
        assert r.json() == {"copied": True, "target": "kali", "clear_after_s": 1, "tool": "xclip"}
        assert REMOTE_PW not in r.text
        assert clip.read_text() == REMOTE_PW
        assert REMOTE_PW not in (tmp_path / "argv.log").read_text()
        await asyncio.sleep(0.8)
        assert clip.read_text() == ""  # nach der Frist geleert, weil noch derselbe Inhalt drin war

        # eigenes Secret: nie, auch nicht in die Kali
        r = await web.req("POST", url, token=token, json_body={"ref": "input", "seq": own["seq"]})
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
        assert OWN_SECRET not in clip.read_text()
        # sichtbare Eingabe ist kein Secret; unbekannte Nummer
        for seq in (visible[0]["seq"], 999_999):
            r = await web.req("POST", url, token=token, json_body={"ref": "input", "seq": seq})
            assert r.status_code == 404, r.text
        # Claim ohne Secret-Wert: 404 (Kopieren eines Claim-Secrets prüft tests/core/test_clipboard.py,
        # denn die Parser von v0.1 erzeugen im Fixture keinen Secret-Claim)
        host = urllib.parse.quote(f"ip:default/{TARGET}", safe="")
        facts = (await web.req("GET", f"/api/v1/p/{fx.pid}/hosts/{host}", token=token)).json()["facts"]
        not_secret = next(f for f in facts if not f["is_secret"])
        r = await web.req("POST", url, token=token,
                          json_body={"ref": "claim", "claim_key": not_secret["claim_key"]})
        assert r.status_code == 404
        r = await web.req("POST", url, token=token, json_body={"ref": "claim", "claim_key": "0" * 64})
        assert r.status_code == 404
        assert CRYPT not in clip.read_text()

        # Prüfung des Körpers
        for bad in ({"ref": "input"}, {"ref": "claim", "claim_key": "x"}, {"ref": "file"}, {}):
            r = await web.req("POST", url, token=token, json_body=bad)
            assert r.status_code == 422, (bad, r.text)
        # Präsentationsmodus sperrt
        await web.req("PUT", "/api/v1/presentation", token=token, json_body={"on": True})
        r = await web.req("POST", url, token=token, json_body={"ref": "input", "seq": remote["seq"]})
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
        await web.req("PUT", "/api/v1/presentation", token=token, json_body={"on": False})
        # kein Werkzeug, keine Sitzung: 503 mit festem Text
        empty = tmp_path / "leer"
        empty.mkdir()
        d.clipboard = Clipboard(path=str(empty), env={"DISPLAY": ":0"}, proc_root=tmp_path / "noproc")
        r = await web.req("POST", url, token=token, json_body={"ref": "input", "seq": remote["seq"]})
        assert r.status_code == 503 and r.json()["error"] == {
            "code": "clipboard_tool", "message": MESSAGES["clipboard_tool"]}
        d.clipboard = Clipboard(path=str(bindir), env={}, proc_root=tmp_path / "noproc")
        r = await web.req("POST", url, token=token, json_body={"ref": "input", "seq": remote["seq"]})
        assert r.status_code == 503 and r.json()["error"]["code"] == "clipboard_session"
        r = await web.req("POST", url, json_body={"ref": "input", "seq": remote["seq"]})
        assert r.status_code == 401
        for s in fx.shims:
            await s.close()

    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))
