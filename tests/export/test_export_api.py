"""Web-API des Exports: Start im Hintergrund mit SSE ``progress``, Liste, Klartext nur im Terminal,
Phasen prüfen und per Entscheid ``d.unit.phase`` korrigieren (übersteht Reparse)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from tests.core.fakeshim import ctl_ok
from tests.export.helpers import OWN_SECRET, read_tree, unsafe_markdown
from tests.web.api.helpers import BASE, CRYPT, HOSTILE, REMOTE_PW, run_api


async def _wait_done(c: Any, pid: str) -> dict[str, Any]:
    for _ in range(400):
        r = await c.get(f"{BASE}/p/{pid}/exports")
        assert r.status_code == 200
        body = r.json()
        if body["running"] is None and body["exports"]:
            return body
        await asyncio.sleep(0.05)
    raise AssertionError("Export wurde nicht fertig")


def test_api_export_progress_list_and_policy(paths, operator):
    async def body(d: Any, c: Any, fx: Any, bus: Any, ctx: Any) -> None:
        pid = fx.pid
        r = await c.post(f"{BASE}/p/{pid}/exports", json={"template": "cys", "klartext": True})
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
        r = await c.post(f"{BASE}/p/{pid}/exports", json={"template": "xyz"})
        assert r.status_code == 422
        r = await c.post(f"{BASE}/p/{pid}/exports", json={"template": "cys", "extra": 1})
        assert r.status_code == 422
        r = await c.post(f"{BASE}/p/{pid}/exports", json={"template": "cys"})
        assert r.status_code == 202, r.text
        job = r.json()["job_id"]
        r2 = await c.post(f"{BASE}/p/{pid}/exports", json={})
        assert r2.status_code in (202, 409)  # der erste kann schon fertig sein
        listing = await _wait_done(c, pid)
        e = listing["exports"][0]
        assert e["template"] == "cys" and e["path"].startswith("exports/") and e["klartext"] is False
        assert len(e["chain"]["hash"]) == 64
        prog = [data for ev, data in bus.events if ev == "progress" and data["job_id"] == job]
        assert [p["status"] for p in prog][-1] == "done"
        assert all(
            p["kind"] == "export" and set(p) == {"job_id", "kind", "status", "pct", "message"} for p in prog
        )
        tree = read_tree(fx.ws / e["path"])
        for name, data in tree.items():
            assert OWN_SECRET.encode() not in data, name
            assert CRYPT.encode() not in data, name  # Ziel-Credential maskiert
            assert REMOTE_PW.encode() not in data, name
            if name.endswith(".md"):
                assert _in_code(data), name
                assert unsafe_markdown(data.decode("utf-8")) == [], (name, unsafe_markdown(data.decode())[:3])
        cred = tree["Credentials.md"].decode("utf-8")
        assert "••••••••" in cred
        assert HOSTILE not in json.dumps({k: v.decode("utf-8", "replace") for k, v in tree.items()})

    run_api(paths, operator, body)


def _in_code(data: bytes) -> bool:
    """``<script>`` darf nur in einem Codeblock stehen (dort rendert kein Viewer HTML)."""
    from tests.export.helpers import _outside_code

    return all("<script>" not in ln for ln in _outside_code(data.decode("utf-8")))


def test_api_phases_decision_survives_reparse(paths, operator):
    async def body(d: Any, c: Any, fx: Any, bus: Any, ctx: Any) -> None:
        pid = fx.pid
        r = await c.get(f"{BASE}/p/{pid}/exports/phases", params={"template": "cys"})
        assert r.status_code == 200, r.text
        data = r.json()
        assert [p["key"] for p in data["phases"]][-1] == "omit"
        nmap = next(x for x in data["commands"] if x["command"].startswith("nmap"))
        assert nmap["phase"] == "scanning" and nmap["source"] == "rule"
        loot = next(x for x in data["commands"] if x["command"].startswith("cat loot.txt"))
        r = await c.post(
            f"{BASE}/p/{pid}/exports/phases",
            json={"template": "cys", "cmd_id": loot["cmd_id"], "phase": "post"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["phase"] == "post" and r.json()["decision_id"]
        r = await c.post(
            f"{BASE}/p/{pid}/exports/phases",
            json={"template": "cys", "cmd_id": loot["cmd_id"], "phase": "foothold"},
        )
        assert r.status_code == 422
        r = await c.post(
            f"{BASE}/p/{pid}/exports/phases", json={"template": "htb", "cmd_id": "nicht@1", "phase": "loot"}
        )
        assert r.status_code in (404, 422)
        await ctl_ok(paths.ctl_sock, "reparse")
        r = await c.get(f"{BASE}/p/{pid}/exports/phases", params={"template": "cys"})
        after = next(x for x in r.json()["commands"] if x["cmd_id"] == loot["cmd_id"])
        assert after["phase"] == "post" and after["source"] == "decision"
        # htb unabhängig von cys
        r = await c.get(f"{BASE}/p/{pid}/exports/phases", params={"template": "htb"})
        h = next(x for x in r.json()["commands"] if x["cmd_id"] == loot["cmd_id"])
        assert h["source"] != "decision"
        # Export nutzt die Korrektur
        res = await ctl_ok(paths.ctl_sock, "export.run", template="cys")
        wu = (fx.ws / res["path"] / "02 Writeup.md").read_text("utf-8")
        post = wu.split("## 4 Post-Exploitation", 1)[1]
        assert "cat loot.txt" in post and "Zuordnung: Entscheid" in post

    run_api(paths, operator, body)
