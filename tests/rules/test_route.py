"""``GET /p/{pid}/suggestions`` und ``/next`` mit echtem Daemon und dem Web-Fixture (MS2 mit feindlichem
Banner, eigenes Secret, Callback): Form, Zustandsfilter, 422, Ausgang ohne Steuerzeichen, Belegzeilen
passend zur Belegansicht, Entscheide aus dem Journal überstehen ``reparse``."""

from __future__ import annotations

import shlex

import pytest

from ariadne import events
from ariadne.store.api import AppendItem
from tests.core.fakeshim import ctl_ok
from tests.rules.test_golden import SUGGESTION_KEYS, _expected_argv
from tests.web.api.helpers import BASE, HOSTILE, OWN_SECRET, TARGET, all_strings, clean, run_api, sync


def test_suggestions_route_shape_filters_and_hostile_output(paths, operator):
    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        r = await c.get(f"{P}/suggestions")
        assert r.status_code == 200, r.text
        data = r.json()
        assert set(data) == {"suggestions", "truncated"} and data["truncated"] is False
        items = data["suggestions"]
        assert items and all(set(s) == SUGGESTION_KEYS and s["state"] == "open" for s in items)
        rules = {s["rule_id"] for s in items}
        assert {"R-FULL-PORTSCAN", "R-UDP-SCAN", "R-WEB-INHALT"} <= rules
        # Ausgang: nichts Unsichtbares, kein HTML-Bruchstück aus dem Banner im Klartext-Zusammenhang,
        # kein eigenes Secret
        text = all_strings(data)
        assert all(clean(x) for x in text)
        assert not any(OWN_SECRET in x for x in text)
        assert not any(HOSTILE in x for x in text)
        for s in items:
            for t in s["templates"]:
                if t["rendered"]:
                    assert shlex.split(t["command"]) == _expected_argv(t)
                    assert TARGET in t["command"] or "{" not in t["command"]
        # Belegzeilen zeigen auf die Zeile der Belegansicht (unit_line.pos, Anzeige n + 1)
        full = next(s for s in items if s["rule_id"] == "R-FULL-PORTSCAN")
        (ev,) = full["evidence"]
        assert ev["lines"] is not None and ev["label"].endswith(f"Zeile {ev['lines'][0] + 1}")
        assert ev["label"].startswith("nmap -sV · ")
        lines = (
            await c.get(f"{P}/units/{ev['unit_id']}/lines", params={"from": ev["lines"][0], "count": 1})
        ).json()
        assert "Host is up" in lines["lines"][0]["text"]
        # /next: dieselben offenen Denkanstösse, höchstens 50, Regel-Engine aktiv
        nx = (await c.get(f"{P}/next")).json()
        assert nx["suggestions_available"] is True
        assert [s["suggestion_key"] for s in nx["suggestions"]] == [s["suggestion_key"] for s in items][:50]
        for state in ("done", "dismissed", "all"):
            r = await c.get(f"{P}/suggestions", params={"state": state})
            assert r.status_code == 200 and isinstance(r.json()["suggestions"], list)
        r = await c.get(f"{P}/suggestions", params={"state": "offen"})
        assert r.status_code == 422
        assert r.json()["error"] == {
            "code": "validation",
            "message": "Eingabe ungültig.",
            "detail": [{"loc": ["query", "state"], "type": "enum"}],
        }
        r = await c.get(f"{BASE}/p/00000000-0000-7000-8000-000000000000/suggestions")
        assert r.status_code == 409 and r.json()["error"]["code"] == "project_mismatch"

    run_api(paths, operator, body)


def test_decisions_from_journal_survive_reparse(paths, operator):
    """Verwerfen und Erledigen stehen nur im Journal; nach ``ariadne reparse`` (neue derived.db) gilt
    derselbe Zustand. Geschrieben wird hier direkt über den Daemon (wie ``POST /decisions``)."""

    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        items = (await c.get(f"{P}/suggestions")).json()["suggestions"]
        udp = next(s for s in items if s["rule_id"] == "R-UDP-SCAN")
        full = next(s for s in items if s["rule_id"] == "R-FULL-PORTSCAN")
        for kind, header in (
            ("d.suggestion.dismiss", {"suggestion_key": udp["suggestion_key"], "reason": "kein UDP im Lab"}),
            ("d.suggestion.done", {"suggestion_key": full["suggestion_key"], "basis": full["basis"]}),
        ):
            d.submit(AppendItem(kind, events.validate_header(kind, header), origin="webui"))
        d.flush()
        await sync(d)

        async def states() -> dict[str, str]:
            got = (await c.get(f"{P}/suggestions", params={"state": "all"})).json()["suggestions"]
            return {s["suggestion_key"]: s["state"] for s in got}

        before = await states()
        assert before[udp["suggestion_key"]] == "dismissed" and before[full["suggestion_key"]] == "done"
        open_keys = [s["suggestion_key"] for s in (await c.get(f"{P}/next")).json()["suggestions"]]
        assert udp["suggestion_key"] not in open_keys and full["suggestion_key"] not in open_keys
        diff = await ctl_ok(paths.ctl_sock, "reparse")
        assert diff["orphans"] == []
        assert await states() == before

    run_api(paths, operator, body)


def test_decisions_route_uses_rule_checks(paths, operator):
    """``POST /decisions`` prüft d.suggestion.* über ``rules.api.check_decision`` (Verdrahtung durch
    backend-ui). Solange die Route 501 liefert, wird der Test übersprungen."""

    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        items = (await c.get(f"{P}/suggestions")).json()["suggestions"]
        sg = items[0]

        async def post(kind: str, payload: dict) -> tuple[int, dict]:
            r = await c.post(f"{P}/decisions", json={"decisions": [{"kind": kind, "payload": payload}]})
            return r.status_code, r.json()

        code, res = await post("d.suggestion.dismiss", {"suggestion_key": "sg:" + "0" * 24})
        if code == 501:
            pytest.skip("d.suggestion.* in web/api/decisions.py noch nicht verdrahtet (backend-ui)")
        assert code == 409 and res["error"]["code"] == "conflict"
        code, res = await post("d.suggestion.done", {"suggestion_key": sg["suggestion_key"]})
        assert code == 422
        code, res = await post(
            "d.suggestion.done", {"suggestion_key": sg["suggestion_key"], "basis": sg["basis"]}
        )
        assert code == 201, res
        await sync(d)
        after = {
            s["suggestion_key"]: s
            for s in (await c.get(f"{P}/suggestions", params={"state": "done"})).json()["suggestions"]
        }
        assert after[sg["suggestion_key"]]["decision_id"] == res["results"][0]["decision_id"]
        code, res = await post(
            "d.suggestion.done", {"suggestion_key": sg["suggestion_key"], "basis": sg["basis"]}
        )
        assert code == 409  # schon erledigt (anderer Tab)

    run_api(paths, operator, body)
