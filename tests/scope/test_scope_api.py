"""Scope erweitern nach dem Praxistest (E129, E130, E49): Entscheid ``d.scope.update`` mit Neuauswertung,
API mit Sperre im Profil customer und feindlichen Eingaben, Klärung «In den Scope aufnehmen?» und
Rückgängig. Daten wie im Praxistest: Scope 10.36.198.0/24, nmap (MS2-Ausgabe) meldet
``recovery.vantis.internal (10.36.198.11)``, danach ``curl http://recovery.vantis.internal/login``."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from ariadne.scope.suggest import candidate_key
from tests.core.fakeshim import FakeShim, ctl, ctl_ok
from tests.integration.helpers import GOLDEN, Term
from tests.web.api.helpers import BASE, all_strings, clean, run_api, sync

NET = "10.36.198.0/24"
IP = "10.36.198.11"
NAME = "recovery.vantis.internal"
URL = f"http://{NAME}/login"
PUBLIC = "www.example.com"


def ms2_named() -> bytes:
    """MS2-Ausgabe von nmap (Golden), Ziel 10.36.198.11 mit Namen im Bericht und einem PTR-Eintrag
    mit öffentlicher Domain. «Service Info: Host: metasploitable.localdomain» bleibt (Banner)."""
    data = (GOLDEN / "nmap.text" / "ms2_sv_sc" / "input.txt").read_bytes()
    data = data.replace(b"192.168.56.102", b"10.36.198.5").replace(b"192.168.56.101", IP.encode())
    data = data.replace(f"Nmap scan report for {IP}\n".encode(),
                        f"Nmap scan report for {NAME} ({IP})\nrDNS record for {IP}: {PUBLIC}\n".encode(), 1)
    assert NAME.encode() in data and PUBLIC.encode() in data
    return data.replace(b"\n", b"\r\n")


async def lab(d: Any, paths: Any) -> tuple[str, Path, list[FakeShim]]:
    res = await ctl_ok(paths.ctl_sock, "start", slug="vantis", targets=[NET])
    ws = Path(res["workspace"])
    shim = await FakeShim(paths.term_sock).connect(proto=2)
    await shim.wait_state(rec="on")
    term = Term(shim)
    await term.command(f"nmap -sV {NET}", ms2_named(), cwd=str(ws))
    await term.command(f"curl {URL}", b"<html><title>Login</title></html>\r\n", cwd=str(ws))
    await term.acked()
    await sync(d)
    return res["id"], ws, [shim]


def _claim(d: Any, subject: str, predicate: str, value: str) -> tuple[str, str, str]:
    async def q() -> Any:
        return await d.ingest.query(lambda c: c.execute(
            "SELECT lane, lane_reason, state FROM claim WHERE subject_identifier = ? AND predicate = ? "
            "AND value_text = ?", (subject, predicate, value)).fetchone())
    return q()  # type: ignore[return-value]


def _names(nx: dict[str, Any]) -> list[dict[str, Any]]:
    return [i for i in nx["clarify"] if i["kind"] == "scope_name"]


def test_add_reevaluates_and_revert_restores(paths, operator):
    async def body(d, c, _fx, bus, ctx) -> None:
        from ariadne.web.api import attach_sources

        detach = attach_sources(ctx)  # Ereignisse des Daemons auf den Bus (SSE «scope»)
        pid, _ws, shims = await lab(d, paths)
        try:
            base = f"{BASE}/p/{pid}"
            ip_id = f"ip:default/{IP}"
            # Vorher: Name nicht im Scope (E49), Scope-Warnung mit Vorschlägen, Klärung E130
            assert await _claim(d, ip_id, "host.name", NAME) == ("quiet", "out_of_scope", "candidate")
            nx = (await c.get(f"{base}/next")).json()
            w = nx["scope_warning"]
            assert w is not None and w["change_allowed"] is True
            assert [t["value"] for t in w["targets"]] == [URL]
            assert w["targets"][0]["verdict"] == "out"
            props = w["targets"][0]["proposals"]
            assert [(p["entry"], p["kind"]) for p in props] == [
                (NAME, "url_host"), ("*.vantis.internal", "wildcard")]
            # E132: .internal steht nicht mehr in der Lab-Allowlist, ist aber keine öffentliche Endung
            assert all(p["outside_lab"] is True and p["public"] is False for p in props)
            items = {i["name"]: i for i in _names(nx)}
            assert set(items) == {NAME, PUBLIC}  # nie der Banner-Name metasploitable.localdomain
            it = items[NAME]
            assert it["text"] == f"{NAME} gehört laut nmap zu {IP} (im Scope). In den Scope aufnehmen?"
            assert [ch["entry"] for ch in it["choices"]] == [NAME, "*.vantis.internal"]
            assert it["public"] is False and it["warning"] is None and it["source"] == "nmap"
            assert it["item_key"] == it["suggestion_key"] == candidate_key(NAME)
            pub = items[PUBLIC]
            assert pub["source"] == "ptr" and pub["public"] is True and pub["warning"]
            assert pub["choices"][0]["outside_lab"] is True
            assert nx["open"] == len(nx["clarify"])

            # Bestätigungsdialog: dry_run schreibt nichts
            r = await c.post(f"{base}/scope/changes", json={"op": "add", "entries": [NAME], "dry_run": True})
            assert r.status_code == 200, r.text
            assert r.json()["include_added"] == [NAME] and r.json()["decision_id"] is None
            assert r.json()["needs_not_customer"] is True and r.json()["broad"] is False
            assert d.project.settings_version == 1
            # E132: ohne bestätigtes «kein Kundenauftrag» 403 guardrail mit Hinweis aufs Terminal
            r = await c.post(f"{base}/scope/changes", json={"op": "add", "entries": [NAME]})
            assert r.status_code == 403 and r.json()["error"]["code"] == "guardrail"
            assert "ariadne scope add" in r.json()["error"]["message"] and "--not-customer" in r.text
            assert NAME not in r.text
            from ariadne.store.api import AppendItem

            d.submit(AppendItem("d.lab.not_customer", {"scope_version": 1}, origin="cli"))
            d.flush()
            r = await c.post(f"{base}/scope/changes", json={"op": "add", "entries": [NAME], "dry_run": True})
            assert r.json()["needs_not_customer"] is False

            req = {"op": "add", "entries": [NAME], "client_ref": "u1"}
            r = await c.post(f"{base}/scope/changes", json=req)
            assert r.status_code == 201, r.text
            ch = r.json()
            assert ch["version"] == 2 and ch["include"] == [NET, NAME] and ch["decision_id"]
            assert {"entry": NAME, "verdict": "in"} in ch["verdicts"]
            assert ("scope", {"project_id": pid, "version": 2}) in bus.events
            again = await c.post(f"{base}/scope/changes", json=req)
            assert again.status_code == 201 and again.json()["decision_id"] == ch["decision_id"]
            assert d.project.settings_version == 2

            await sync(d)
            # Nachher: Name im Scope, Wert automatisch übernommen, Warnung und Klärung weg
            assert await _claim(d, ip_id, "host.name", NAME) == ("auto", "parser", "auto")
            nx = (await c.get(f"{base}/next")).json()
            assert nx["scope_warning"] is None
            assert [i["name"] for i in _names(nx)] == [PUBLIC]
            st = (await c.get(f"{BASE}/status")).json()
            assert st["scope_warning"] is None
            sc = (await c.get(f"{base}/scope")).json()
            assert sc["include"] == [NET, NAME] and sc["version"] == 2 and sc["change_allowed"] is True
            h0 = sc["history"][0]
            assert h0["decision_id"] == ch["decision_id"] and h0["origin"] == "webui"
            pj = (await c.get(f"{base}/project")).json()
            assert pj["scope"]["include"] == [NET, NAME] and pj["scope"]["version"] == 2

            # Zeitachse: Entscheid mit Rückgängig
            tl = (await c.get(f"{base}/timeline", params={"types": "decision"})).json()["items"]
            row = next(i for i in tl if i["decision_id"] == ch["decision_id"])
            assert row["summary"] == "Scope erweitert (Version 2)" and row["detail"] == NAME
            assert row["scope_change"]["revertible"] is True and row["scope_change"]["entries"] == [NAME]

            # Rückgängig
            r = await c.post(f"{base}/scope/changes", json={"op": "revert", "decision_id": ch["decision_id"]})
            assert r.status_code == 201, r.text
            assert r.json()["include"] == [NET] and r.json()["revert_of"] == ch["decision_id"]
            await sync(d)
            assert await _claim(d, ip_id, "host.name", NAME) == ("quiet", "out_of_scope", "candidate")
            nx = (await c.get(f"{base}/next")).json()
            assert nx["scope_warning"] is not None and {i["name"] for i in _names(nx)} == {NAME, PUBLIC}
            tl = (await c.get(f"{base}/timeline", params={"types": "decision"})).json()["items"]
            row = next(i for i in tl if i["decision_id"] == ch["decision_id"])
            assert row["scope_change"]["revertible"] is False and row["scope_change"]["reverted_by"]
            r = await c.post(f"{base}/scope/changes", json={"op": "revert", "decision_id": ch["decision_id"]})
            assert r.status_code == 409

            # Domain mit Wildcard (Wahl aus der Klärung)
            r = await c.post(f"{base}/scope/changes", json={"op": "add", "entries": ["*.vantis.internal"]})
            assert r.status_code == 201
            await sync(d)
            nx = (await c.get(f"{base}/next")).json()
            assert nx["scope_warning"] is None and [i["name"] for i in _names(nx)] == [PUBLIC]
        finally:
            detach()
            for s in shims:
                await s.close()

    run_api(paths, operator, body, fixture=False)


def test_dismiss_e130_is_remembered_and_never_auto(paths, operator):
    async def body(d, c, _fx, _bus, _ctx) -> None:
        pid, _ws, shims = await lab(d, paths)
        try:
            base = f"{BASE}/p/{pid}"
            key = candidate_key(PUBLIC)

            async def decide(kind: str, payload: dict[str, Any]) -> Any:
                body = {"decisions": [{"kind": kind, "payload": payload}]}
                return await c.post(f"{base}/decisions", json=body)

            r = await decide("d.suggestion.done", {"suggestion_key": key, "basis": "x"})
            assert r.status_code == 409
            r = await decide("d.suggestion.dismiss", {"suggestion_key": key})
            assert r.status_code == 201, r.text
            did = r.json()["results"][0]["decision_id"]
            await sync(d)
            nx = (await c.get(f"{base}/next")).json()
            assert [i["name"] for i in _names(nx)] == [NAME]
            assert (await decide("d.suggestion.dismiss", {"suggestion_key": key})).status_code == 409
            # nie automatisch: der verworfene Name steht nicht im Scope
            assert PUBLIC not in d.project.settings["scope"]["include"]
            # Rückgängig des Verwerfens öffnet die Klärung wieder
            assert (await decide("d.revoke", {"decision_id": did})).status_code == 201
            await sync(d)
            nx = (await c.get(f"{base}/next")).json()
            assert {i["name"] for i in _names(nx)} == {NAME, PUBLIC}
            # unbekannter E130-Schlüssel
            r = await decide("d.suggestion.dismiss", {"suggestion_key": candidate_key("x.lab")})
            assert r.status_code == 409
        finally:
            for s in shims:
                await s.close()

    run_api(paths, operator, body, fixture=False)


def test_api_rejects_hostile_input_customer_and_guardrail(paths, operator):
    async def body(d, c, _fx, _bus, _ctx) -> None:
        pid, _ws, shims = await lab(d, paths)
        try:
            base = f"{BASE}/p/{pid}"
            url = f"{base}/scope/changes"
            hostile = ["<script>alert(1)</script>", "a\x1bb.lab", "evil‮.lab", "x.lab\n", "", " ",
                       "10.0.0.1 10.0.0.2", "999.1.1.1/40", "a" * 300]
            for h in hostile:
                r = await c.post(url, json={"op": "add", "entries": [h]})
                assert r.status_code == 422, (h, r.status_code)
                assert all(clean(x) for x in all_strings(r.json())) and h not in r.text or h in ("", " ")
            for bad in ({"op": "add"}, {"op": "revert"},
                        {"op": "add", "entries": ["x.lab"], "decision_id": "a"},
                        {"op": "drop", "entries": ["x.lab"]}, {"op": "add", "entries": ["x.lab"], "extra": 1},
                        {"op": "add", "entries": [f"h{i}.lab" for i in range(21)]},
                        {"op": "add", "entries": "x.lab"}, {"op": "revert", "decision_id": "nope"}):
                r = await c.post(url, json=bad)
                assert r.status_code in (404, 422), (bad, r.status_code)
            # nichts zu tun, nicht gelistet, letzter Einschluss
            assert (await c.post(url, json={"op": "add", "entries": [NET]})).status_code == 409
            assert (await c.post(url, json={"op": "remove", "entries": ["nope.lab"]})).status_code == 409
            assert (await c.post(url, json={"op": "remove", "entries": [NET]})).status_code == 409
            # öffentliche Domain: Bestätigung «kein Kundenauftrag» nur im Terminal
            r = await c.post(url, json={"op": "add", "entries": [PUBLIC], "dry_run": True})
            assert r.status_code == 200 and r.json()["needs_not_customer"] is True
            r = await c.post(url, json={"op": "add", "entries": [PUBLIC]})
            assert r.status_code == 403 and r.json()["error"]["code"] == "guardrail"
            # kritische Arten bleiben im allgemeinen Schreibweg gesperrt
            r = await c.post(f"{base}/decisions", json={"decisions": [
                {"kind": "d.scope.update", "payload": {"version": 9, "toml": "x"}}]})
            assert r.status_code == 403
            assert d.project.settings_version == 1
            # exclude im Dashboard
            r = await c.post(url, json={"op": "exclude", "entries": ["10.36.198.99"]})
            assert r.status_code == 201 and r.json()["exclude"] == ["10.36.198.99"]

            # Profil customer: nur im Terminal (E129)
            p = d.project
            orig = p.info
            p.info = dataclasses.replace(orig, profile="customer")
            try:
                r = await c.post(url, json={"op": "add", "entries": [NAME]})
                assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
                assert "Terminal" in r.json()["error"]["message"]
                sc = (await c.get(f"{base}/scope")).json()
                assert sc["change_allowed"] is False and sc["profile"] == "customer"
                res = await ctl(paths.ctl_sock, "scope.change", action="add", entries=[NAME], origin="webui")
                assert res["ok"] is False and res["error"]["code"] == "policy"
                res = await ctl_ok(paths.ctl_sock, "scope.change", action="add", entries=[NAME], origin="cli")
                assert res["include_added"] == [NAME]
            finally:
                p.info = orig
        finally:
            for s in shims:
                await s.close()

    run_api(paths, operator, body, fixture=False)


def test_ctl_cli_origin_not_customer_and_show(paths, operator):
    """Terminal-Weg (ctl ``scope.change``, Herkunft cli): öffentliche Ziele nur mit not_customer, das
    dann ``d.lab.not_customer`` schreibt; ``scope.show`` nennt Änderungen mit ``decision_id``."""

    async def body(d, c, _fx, _bus, _ctx) -> None:
        pid, _ws, shims = await lab(d, paths)
        try:
            res = await ctl(paths.ctl_sock, "scope.change", action="add", entries=[PUBLIC], origin="cli")
            assert res["ok"] is False and res["error"]["code"] == "guardrail"
            assert res["error"]["outside"] == [PUBLIC]
            res = await ctl_ok(paths.ctl_sock, "scope.change", action="add", entries=[PUBLIC], origin="cli",
                               not_customer=True, reason="Laut Auftrag dabei")
            assert res["version"] == 2 and res["needs_not_customer"] is True
            recs = d.project.journal.iter_events(kinds=["d.lab.not_customer", "d.scope.update"])
            kinds = [r.kind for r in recs]
            assert kinds == ["d.scope.update", "d.lab.not_customer", "d.scope.update"]
            show = await ctl_ok(paths.ctl_sock, "scope.show")
            assert show["include"] == [NET, PUBLIC] and show["not_customer"] is True
            assert show["history"][0]["op"] == "add" and show["history"][0]["origin"] == "cli"
            # der Snapshot behält alle anderen Einstellungen
            assert d.project.settings["project"]["profile"] == "lab"
            assert d.project.settings["automode"]["parsers"] == ["nmap.xml"]
            await sync(d)
            pj = (await c.get(f"{BASE}/p/{pid}/project")).json()
            assert pj["lab_guard"] == {"public_targets": True, "confirmed_not_customer": True}
        finally:
            for s in shims:
                await s.close()

    run_api(paths, operator, body, fixture=False)


def test_user_case_cli_options_and_broad_wildcards(paths, operator, capsys):
    """Fall aus dem Praxistest über das Terminal: ``ariadne scope add`` gegen den echten Daemon wirkt
    wie das Dashboard (Warnung weg, Wert auto), ``ariadne scope undo`` stellt den alten Scope her.
    Dazu ``GET /scope/options`` (Vorschläge zu Zielen ohne ``proposals``) und keine Wildcards auf ganze
    Endungen (``*.com``, ``*.internal``)."""
    import asyncio

    from ariadne.cli.main import main

    async def body(d, c, _fx, _bus, _ctx) -> None:
        pid, _ws, shims = await lab(d, paths)
        try:
            base = f"{BASE}/p/{pid}"
            ip_id = f"ip:default/{IP}"
            # Vorschläge zu einem Ziel ohne mitgelieferte proposals (Out-of-Scope-Rand)
            r = await c.get(f"{base}/scope/options", params={"value": URL})
            assert r.status_code == 200, r.text
            o = r.json()
            assert o["verdict"] == "out" and o["value"] == URL and o["ctrl"] is False
            assert [(x["entry"], x["kind"]) for x in o["options"]] == [
                (NAME, "url_host"), ("*.vantis.internal", "wildcard")]
            o = (await c.get(f"{base}/scope/options", params={"value": IP})).json()
            assert o["verdict"] == "in" and o["options"] == []
            o = (await c.get(f"{base}/scope/options", params={"value": "a\x1bb.lab"})).json()
            assert o["ctrl"] is True and "\x1b" not in o["value"] and o["options"] == []
            assert (await c.get(f"{base}/scope/options", params={"value": "x" * 3000})).status_code == 422
            assert (await c.get(f"{base}/scope/options")).status_code == 422

            # keine Wildcards auf ganze Endungen, auch nicht per dry_run
            for broad in ("*", "*.com", "*.internal", "*.lab", "*.*.vantis.internal"):
                req = {"op": "add", "entries": [broad], "dry_run": True}
                r = await c.post(f"{base}/scope/changes", json=req)
                assert r.status_code == 422, (broad, r.status_code)
                assert broad not in r.text or broad == "*"
            res = await ctl(paths.ctl_sock, "scope.change", action="add", entries=["*.com"], origin="cli",
                            not_customer=True)
            assert res["ok"] is False and res["error"]["code"] == "invalid"
            # ausschliessen geht (schränkt nur ein)
            res = await ctl_ok(paths.ctl_sock, "scope.change", action="exclude", entries=["*.com"],
                               origin="cli", dry_run=True)
            assert res["exclude_added"] == ["*.com"]

            # Terminal: ariadne scope add <name> --yes (ohne TTY nur mit --yes)
            assert await _claim(d, ip_id, "host.name", NAME) == ("quiet", "out_of_scope", "candidate")
            capsys.readouterr()
            rc = await asyncio.to_thread(main, ["scope", "add", NAME])
            assert rc != 0 and d.project.settings_version == 1  # ohne Bestätigung nichts
            rc = await asyncio.to_thread(main, ["scope", "add", NAME, "--yes"])
            assert rc != 0 and d.project.settings_version == 1  # E132: .internal braucht --not-customer
            rc = await asyncio.to_thread(main, ["scope", "add", NAME, "--yes", "--not-customer"])
            out = capsys.readouterr().out
            assert rc == 0, out
            assert f"Neu im Scope: {NAME}" in out and "ariadne scope undo" in out
            assert d.project.settings_version == 2
            await sync(d)
            assert await _claim(d, ip_id, "host.name", NAME) == ("auto", "parser", "auto")
            nx = (await c.get(f"{base}/next")).json()
            assert nx["scope_warning"] is None and NAME not in [i["name"] for i in _names(nx)]
            sc = (await c.get(f"{base}/scope")).json()
            assert sc["history"][0]["origin"] == "cli" and sc["include"] == [NET, NAME]

            # ariadne scope undo: alter Scope, Warnung und Klärung wieder da
            rc = await asyncio.to_thread(main, ["scope", "undo", "--yes"])
            assert rc == 0, capsys.readouterr().out
            await sync(d)
            assert d.project.settings["scope"]["include"] == [NET]
            assert await _claim(d, ip_id, "host.name", NAME) == ("quiet", "out_of_scope", "candidate")
            nx = (await c.get(f"{base}/next")).json()
            assert nx["scope_warning"] is not None and NAME in [i["name"] for i in _names(nx)]
            rc = await asyncio.to_thread(main, ["scope"])
            out = capsys.readouterr().out
            assert rc == 0 and "[rückgängig gemacht]" in out and "Terminal" in out
        finally:
            for s in shims:
                await s.close()

    run_api(paths, operator, body, fixture=False)
