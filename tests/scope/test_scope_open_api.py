"""Offener Scope (E131) mit echtem Daemon: ctl und API ``open``/``close`` mit Leitplanke, ``noop``,
``no_include``, Rückgängig und Profil customer; Neuauswertung (Warnung vorher, nach dem Öffnen weg,
Host auf der Karte, nach dem Schliessen wieder da), Antworten mit ``open``/``scope_open``, Zeitachse,
KI-Sperre und Lagebild. Daten: ``nmap -sV 8.8.8.8`` und ``curl https://github.com/``."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from tests.core.fakeshim import FakeShim, ctl, ctl_ok
from tests.integration.helpers import Term
from tests.web.api.helpers import BASE, run_api, sync

NET = "10.36.198.0/24"
DNS = "8.8.8.8"
GH = "https://github.com/"
NMAP = (
    b"Starting Nmap 7.94 ( https://nmap.org )\r\n"
    b"Nmap scan report for 8.8.8.8\r\n"
    b"Host is up (0.010s latency).\r\n"
    b"PORT   STATE SERVICE VERSION\r\n"
    b"53/tcp open  domain  Google Public DNS\r\n\r\n"
    b"Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds\r\n"
)


async def lab(d: Any, paths: Any, slug: str = "offen") -> tuple[str, list[FakeShim]]:
    res = await ctl_ok(paths.ctl_sock, "start", slug=slug, targets=[NET])
    ws = Path(res["workspace"])
    shim = await FakeShim(paths.term_sock).connect(proto=2)
    await shim.wait_state(rec="on")
    term = Term(shim)
    await term.command(f"nmap -sV {DNS}", NMAP, cwd=str(ws))
    await term.command(f"curl {GH}", b"<html><title>GitHub</title></html>\r\n", cwd=str(ws))
    await term.acked()
    await sync(d)
    return res["id"], [shim]


def _host(graph: dict[str, Any], ip: str) -> dict[str, Any] | None:
    return next((n for n in graph["nodes"] if n.get("kind") == "host" and ip in (n.get("addresses") or [])),
                None)


def test_open_close_reevaluates_with_guardrail_noop_no_include_and_revert(paths, operator):
    async def body(d, c, _fx, bus, ctx) -> None:
        from ariadne.web.api import attach_sources

        detach = attach_sources(ctx)
        pid, shims = await lab(d, paths)
        base = f"{BASE}/p/{pid}"
        url = f"{base}/scope/changes"
        try:
            # Vorher: Scope-Warnung für github.com, 8.8.8.8 nicht auf der Karte
            nx = (await c.get(f"{base}/next")).json()
            assert nx["scope_warning"] is not None
            assert [t["value"] for t in nx["scope_warning"]["targets"]] == [GH]
            g = (await c.get(f"{base}/graph")).json()
            assert _host(g, DNS) is None
            assert any(DNS in str(i.get("identifier")) for i in g["oos"]["items"])
            sc = (await c.get(f"{base}/scope")).json()
            assert sc["open"] is False
            st = (await c.get(f"{BASE}/status")).json()
            assert st["project"]["scope_open"] is False

            # Öffnen im Dashboard: dry_run nennt die Bestätigung, ohne sie 403 guardrail (Terminal)
            r = await c.post(url, json={"op": "open", "dry_run": True})
            assert r.status_code == 200, r.text
            assert r.json()["needs_not_customer"] is True and r.json()["open"] is True
            r = await c.post(url, json={"op": "open"})
            assert r.status_code == 403 and r.json()["error"]["code"] == "guardrail"
            assert "ariadne scope open" in r.json()["error"]["message"]
            res = await ctl(paths.ctl_sock, "scope.change", action="open", origin="cli")
            assert res["ok"] is False and res["error"]["code"] == "guardrail"
            assert res["error"].get("hint") == "open"
            for bad in ({"op": "open", "entries": ["x.lab"]}, {"op": "close", "decision_id": "a"}):
                assert (await c.post(url, json=bad)).status_code == 422
            r = await c.post(url, json={"op": "close"})
            assert r.status_code == 409 and r.json()["error"]["code"] == "noop"
            assert d.project.settings_version == 1

            # Terminal-Weg mit Bestätigung: d.lab.not_customer im selben Commit
            res = await ctl_ok(paths.ctl_sock, "scope.change", action="open", origin="cli",
                               not_customer=True)
            assert res["version"] == 2 and res["open"] is True and res["needs_not_customer"] is True
            did_open = res["decision_id"]
            kinds = [r.kind for r in d.project.journal.iter_events(
                kinds=["d.lab.not_customer", "d.scope.update"])]
            assert kinds == ["d.scope.update", "d.lab.not_customer", "d.scope.update"]
            assert ("scope", {"project_id": pid, "version": 2}) in bus.events
            await sync(d)

            # Nachher: Warnung weg, Host auf der Karte, Antworten mit open/scope_open
            nx = (await c.get(f"{base}/next")).json()
            assert nx["scope_warning"] is None
            g = (await c.get(f"{base}/graph")).json()
            assert _host(g, DNS) is not None
            assert not any(DNS in str(i.get("identifier")) for i in g["oos"]["items"])
            sc = (await c.get(f"{base}/scope")).json()
            assert sc["open"] is True and sc["include"] == [NET] and sc["not_customer"] is True
            assert sc["history"][0]["op"] == "open" and sc["history"][0]["decision_id"] == did_open
            st = (await c.get(f"{BASE}/status")).json()
            assert st["project"]["scope_open"] is True and st["scope_warning"] is None
            pj = (await c.get(f"{base}/project")).json()
            assert pj["scope_open"] is True and pj["scope"]["open"] is True
            assert pj["lab_guard"]["public_targets"] is True
            tl = (await c.get(f"{base}/timeline", params={"types": "decision"})).json()["items"]
            row = next(i for i in tl if i["decision_id"] == did_open)
            assert row["summary"] == "Scope geöffnet (Version 2)"
            sch = row["scope_change"]
            assert sch["op"] == "open" and sch["revertible"] is True and sch["open_after"] is True
            assert sch["include_added"] == sch["include_removed"] == sch["exclude_added"] == []
            assert sch["exclude_removed"] == []
            r = await c.post(url, json={"op": "open"})
            assert r.status_code == 409 and r.json()["error"]["code"] == "noop"

            # KI (E126): offener Scope zählt wie öffentliche Adressen; Lagebild mit dem Host
            from ariadne.ai.gateway import policy_reason, project_flags
            from ariadne.ai.situation import build_situation

            ing = await d._sync_ingest()
            flags = await ing.query(lambda conn: project_flags(conn, "lab", True))
            assert flags["public_scope"] is True and flags["not_customer"] is True
            flags_no = {**flags, "not_customer": False}
            from ariadne.ai.config import AiConfig

            cfg = AiConfig(provider="cloud", model="m")
            assert policy_reason(cfg, key_present=True, operator_unlocked=True, profile="lab",
                                 flags=flags_no) == "public_scope"
            assert policy_reason(cfg, key_present=True, operator_unlocked=True, profile="lab",
                                 flags=flags) == "cloud_not_allowed"
            gw = ctx.extra["ai"]
            assert (await gw.flags(d.project))["public_scope"] is True
            sit = await ing.query(lambda conn: build_situation(conn, profile="lab", redactor=d.redactor))
            assert any(ln.startswith("H") and DNS in ln for ln in sit.text.splitlines()), sit.text

            # offener Scope: letzter Einschluss darf weg; schliessen dann 409 no_include
            r = await c.post(url, json={"op": "remove", "entries": [NET]})
            assert r.status_code == 201, r.text
            did_rm = r.json()["decision_id"]
            assert d.project.settings["scope"]["include"] == []
            r = await c.post(url, json={"op": "close"})
            assert r.status_code == 409 and r.json()["error"]["code"] == "no_include"
            assert r.json()["error"]["message"] == "Zuerst einen Eintrag hinzufügen: ariadne scope add <ziel>"
            res = await ctl(paths.ctl_sock, "scope.change", action="close", origin="cli")
            assert res["ok"] is False and res["error"]["code"] == "no_include"
            # Öffnen rückgängig ohne Einschluss: dieselbe Prüfung
            r = await c.post(url, json={"op": "revert", "decision_id": did_open})
            assert r.status_code == 409 and r.json()["error"]["code"] == "no_include"
            r = await c.post(url, json={"op": "revert", "decision_id": did_rm})
            assert r.status_code == 201 and r.json()["include"] == [NET]

            # Schliessen im Dashboard (keine Bestätigung nötig), Warnung wieder da
            r = await c.post(url, json={"op": "close", "dry_run": True})
            assert r.status_code == 200 and r.json()["needs_not_customer"] is False
            r = await c.post(url, json={"op": "close", "client_ref": "c1"})
            assert r.status_code == 201, r.text
            closed = r.json()
            assert closed["open"] is False
            await sync(d)
            nx = (await c.get(f"{base}/next")).json()
            assert nx["scope_warning"] is not None
            g = (await c.get(f"{base}/graph")).json()
            assert _host(g, DNS) is None
            assert (await c.get(f"{base}/scope")).json()["open"] is False
            assert (await c.get(f"{BASE}/status")).json()["project"]["scope_open"] is False
            tl = (await c.get(f"{base}/timeline", params={"types": "decision"})).json()["items"]
            row = next(i for i in tl if i["decision_id"] == closed["decision_id"])
            assert row["summary"] == f"Scope geschlossen (Version {closed['version']})"
            assert row["scope_change"]["op"] == "close"

            # Schliessen rückgängig: öffnet wieder (not_customer ist bestätigt)
            r = await c.post(url, json={"op": "revert", "decision_id": closed["decision_id"]})
            assert r.status_code == 201 and r.json()["open"] is True
            await sync(d)
            assert (await c.get(f"{base}/next")).json()["scope_warning"] is None
            # das ursprüngliche Öffnen rückgängig: geschlossen
            r = await c.post(url, json={"op": "revert", "decision_id": did_open})
            assert r.status_code == 201 and r.json()["open"] is False
            r = await c.post(url, json={"op": "revert", "decision_id": did_open})
            assert r.status_code == 409

            # Profil customer: 403 policy
            p = d.project
            orig = p.info
            p.info = dataclasses.replace(orig, profile="customer")
            try:
                for op in ("open", "close"):
                    r = await c.post(url, json={"op": op})
                    assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
                # nie im Profil customer, auch nicht im Terminal
                res = await ctl(paths.ctl_sock, "scope.change", action="open", origin="cli",
                                not_customer=True)
                assert res["ok"] is False and res["error"]["code"] == "policy"
            finally:
                p.info = orig
        finally:
            detach()
            for s in shims:
                await s.close()

    run_api(paths, operator, body, fixture=False)


def test_start_without_targets_creates_open_scope(paths, operator):
    """ctl ``start`` ohne Ziele: nur mit ``open_scope`` und ``not_customer``; danach ist alles im Scope."""

    async def body(d, c, _fx, _bus, _ctx) -> None:
        res = await ctl(paths.ctl_sock, "start", slug="leer")
        assert res["ok"] is False and res["error"]["code"] == "project_not_found"
        res = await ctl(paths.ctl_sock, "start", slug="leer", open_scope=True)
        assert res["ok"] is False and res["error"]["code"] == "guardrail"
        res = await ctl_ok(paths.ctl_sock, "start", slug="leer", open_scope=True, not_customer=True)
        assert res["created"] is True
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["project"]["scope_open"] is True
        show = await ctl_ok(paths.ctl_sock, "scope.show")
        assert show["open"] is True and show["include"] == [] and show["not_customer"] is True
        r = await c.post(f"{BASE}/p/{res['id']}/scope/changes", json={"op": "close"})
        assert r.status_code == 409 and r.json()["error"]["code"] == "no_include"

    run_api(paths, operator, body, fixture=False)
