"""KI-Denkanstoss über die echte API mit echtem Daemon, MS2-Fixture und gefälschtem Transport (httpx2):
Policy, Anfrage an das SDK (Form, kein Secret, kein API-Key im Inhalt), Prüfung der Antwort, Speicherung als
Entscheid, Zustand wie bei Regeln, SSE ``progress``, Ablehnung wörtlich, Budget, ein Auftrag zur Zeit."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from typing import Any

import httpx2

from ariadne.ai import store
from ariadne.ai.config import AiConfig, save_config
from ariadne.ai.providers import CloudProvider
from tests.web.api.helpers import BASE, HOSTILE, OWN_SECRET, TARGET, all_strings, clean, run_api, sync

API_KEY = "sk-test-CANARY-KEY-0123456789"
CANARY = "OpenSSH"  # Produkt aus dem MS2-Fixture, als eigenes Secret eingetragen: darf nie hinaus


def _answer(items: list[dict[str, Any]], *, suspect: bool = False) -> dict[str, Any]:
    return {"anstoesse": items, "injection_verdacht": suspect, "injection_hinweis": ""}


def _item(**kw: Any) -> dict[str, Any]:
    base = {
        "art": "hypothese",
        "titel": "Anonymer Zugang auf dem Dienst S1",
        "begruendung": "Der Dienst ist offen und noch nicht auf anonyme Anmeldung geprüft.",
        "bestaetigt_wenn": "Die Anmeldung als anonymous gelingt.",
        "widerlegt_wenn": "Der Dienst verlangt ein Passwort.",
        "belege": ["S1"],
        "pruefziel": "PZ-AUTH-ANON",
        "frage": "Welche Daten gibt der Dienst ohne Anmeldung preis?",
        "richtung": "Anonyme Anmeldung prüfen und die Antwort lesen.",
        "vorlagen": [{"vorlage": "nmap-ftp-anon", "ziel": "S1"}],
    }
    base.update(kw)
    return base


def _message(
    text: str | None, *, stop: str = "end_turn", details: dict[str, Any] | None = None
) -> dict[str, Any]:
    content = [{"type": "text", "text": text}] if text is not None else []
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "test-model",
        "content": content,
        "stop_reason": stop,
        "stop_sequence": None,
        "stop_details": details,
        "usage": {
            "input_tokens": 1500,
            "output_tokens": 400,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        },
    }


class Transport:
    """Gefälschter Transport: merkt sich Anfragen, antwortet mit einer festen Nachricht."""

    def __init__(self, reply: dict[str, Any], gate: threading.Event | None = None) -> None:
        self.reply = reply
        self.gate = gate
        self.requests: list[httpx2.Request] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        if self.gate is not None:
            self.gate.wait(20)
        self.requests.append(request)
        return httpx2.Response(200, json=self.reply)

    def factory(self, cfg: AiConfig, key: str | None) -> CloudProvider:
        assert key == API_KEY
        return CloudProvider(key, cfg.model, transport=httpx2.MockTransport(self.handler), max_retries=0)


async def _setup(d: Any, paths: Any, *, limit: float = 20.0) -> None:
    save_config(paths, AiConfig(provider="cloud", model="test-model", monthly_limit_usd=limit))
    res = await d.call("ai.key.set", {"value": API_KEY})
    assert res["ok"], res
    res = await d.call("secrets.add", {"label": "canary", "value": CANARY})
    assert res["ok"], res


async def _wait(c: Any, P: str, job_id: str) -> dict[str, Any]:
    for _ in range(400):
        r = await c.get(f"{P}/ai/jobs/{job_id}")
        assert r.status_code == 200, r.text
        job = r.json()["job"]
        if job["status"] not in ("queued", "running"):
            return job
        await asyncio.sleep(0.05)
    raise AssertionError("KI-Auftrag endet nicht")


def test_denkanstoss_end_to_end_policy_secrets_and_state(paths, operator):
    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        # Standard: aus
        st = (await c.get(f"{P}/ai/status")).json()
        assert st["provider"] == "off" and st["ready"] is False and st["reason"] == "off"
        assert (await c.post(f"{P}/ai/denkanstoss", json={})).status_code == 403
        # eingerichtet, aber Cloud nicht freigegeben
        await _setup(d, paths)
        st = (await c.get(f"{P}/ai/status")).json()
        assert st["reason"] == "cloud_not_allowed" and st["model"] == "test-model"
        r = await c.post(f"{P}/ai/denkanstoss", json={})
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
        res = await d.call("ai.allow_cloud", {})
        assert res["ok"] and res["result"]["already"] is False
        st = (await c.get(f"{P}/ai/status")).json()
        assert st["ready"] is True and st["reason"] is None and st["budget"]["level"] == "ok"

        tr = Transport(
            _message(
                json.dumps(
                    _answer(
                        [
                            _item(),
                            _item(titel="Mehr dazu", begruendung="Siehe https://evil.example/x"),  # URL
                            _item(titel="Fremder Beleg", belege=["H99"]),  # Beleg ohne Schlüssel
                            _item(
                                art="frage",
                                titel="Welche Konten nutzt H1?",
                                belege=["H1"],
                                vorlagen=[],
                                pruefziel="",
                            ),
                            _item(titel="Fremde Adresse", begruendung="Auch 8.8.8.8 prüfen."),
                        ]
                    )
                )
            )
        )
        ctx.extra["ai"].provider_factory = tr.factory
        r = await c.post(f"{P}/ai/denkanstoss", json={})
        assert r.status_code == 202, r.text
        job = await _wait(c, P, r.json()["job"]["job_id"])
        assert job["status"] == "done", job
        assert job["created"] == 2 and job["dropped"] == 3 and job["injection_suspect"] == 3
        assert job["tokens_in"] == 1500 and job["tokens_out"] == 400 and job["cost_usd"] > 0
        assert job["masked"] >= 1  # das eigene Secret (Kanarienvogel) wurde ersetzt
        assert job["refusal"] is None and job["error"] is None

        # Anfrage an das SDK: Form, nie Secret, nie API-Key im Inhalt
        (req,) = tr.requests
        assert req.url.host == "api.anthropic.com" and req.url.path == "/v1/messages"
        assert req.headers["x-api-key"] == API_KEY
        assert "server-side-fallback-2026-07-01" in req.headers.get("anthropic-beta", "")
        raw = req.content.decode("utf-8")
        assert API_KEY not in raw
        assert OWN_SECRET not in raw and CANARY not in raw
        assert HOSTILE not in raw and "<script" not in raw
        sent = json.loads(raw)
        assert sent["model"] == "test-model" and "tools" not in sent
        assert sent["thinking"] == {"type": "adaptive"}
        assert sent["output_config"]["effort"] == "high"
        assert sent["output_config"]["format"]["type"] == "json_schema"
        assert sent["fallbacks"] == "default"
        user = sent["messages"][0]["content"]
        assert '<daten id="D1" quelle="projektion" grenze="' in user and TARGET in user
        assert "H1 ip=" in user and "S1 " in user

        # SSE: Fortschritt mit Tokens, Maskierung und Kosten, danach «suggestion»
        prog = [e for k, e in bus.events if k == "progress" and e.get("kind") == "ai"]
        assert prog[0]["status"] == "queued" and prog[-1]["status"] == "done"
        assert prog[-1]["tokens_in"] == 1500 and prog[-1]["cost_usd"] > 0 and prog[-1]["masked"] >= 1
        assert all(isinstance(e["message"], str) and "evil" not in e["message"] for e in prog)
        assert "suggestion" in bus.kinds()

        # Ergebnis: KI-Denkanstösse mit Herkunft und Kennzeichen
        await sync(d)
        data = (await c.get(f"{P}/ai/denkanstoesse")).json()
        items = data["suggestions"]
        assert len(items) == 2 and data["truncated"] is False
        assert all(s["origin"] == "ai" and "ai" in s["flags"] and s["state"] == "open" for s in items)
        assert all(s["ai"]["model"] == "test-model" and s["ai"]["confirmed_if"] for s in items)
        assert all(clean(x) for x in all_strings(data))
        hyp = next(s for s in items if s["kind"] == "hypothesis")
        assert hyp["goal_id"] == "PZ-AUTH-ANON" and hyp["service_id"] is not None
        (tpl,) = hyp["templates"]
        assert tpl["template_id"] == "nmap-ftp-anon"
        if tpl["rendered"]:
            assert TARGET in tpl["command"] and not tpl["command"].endswith("\n")

        # Zustand wie bei Regeln: done mit basis, dismiss für immer, Konflikte
        def check(kind: str, header: dict[str, Any]) -> Any:
            return d.ingest.query(lambda conn: store.check_decision(conn, kind, header))

        assert await check("d.suggestion.done", {"suggestion_key": "sg:" + "0" * 24, "basis": "x"}) is False
        assert (
            await check("d.suggestion.done", {"suggestion_key": hyp["suggestion_key"], "basis": hyp["basis"]})
            is True
        )
        # Integration: KI-Denkanstösse stehen in /next und /suggestions (vorne, Form mit items)
        nxt = (await c.get(f"{P}/next")).json()["suggestions"]
        assert [s["suggestion_key"] for s in nxt[:2]] == [s["suggestion_key"] for s in items]
        assert all(s["items"] == [] for s in nxt[:2])
        listed = (await c.get(f"{P}/suggestions")).json()["suggestions"]
        assert hyp["suggestion_key"] in [s["suggestion_key"] for s in listed]
        # Erledigen über POST /decisions (geprüft mit store.check_decision)
        r = await c.post(
            f"{P}/decisions",
            json={
                "decisions": [
                    {"kind": "d.suggestion.done", "payload": {"suggestion_key": hyp["suggestion_key"]}}
                ]
            },
        )
        assert r.status_code == 422  # basis fehlt
        r = await c.post(
            f"{P}/decisions",
            json={
                "decisions": [
                    {
                        "kind": "d.suggestion.done",
                        "payload": {"suggestion_key": hyp["suggestion_key"], "basis": hyp["basis"]},
                    }
                ]
            },
        )
        assert r.status_code == 201, r.text
        await sync(d)
        done_all = (await c.get(f"{P}/suggestions", params={"state": "done"})).json()["suggestions"]
        assert hyp["suggestion_key"] in [s["suggestion_key"] for s in done_all]
        open_ = (await c.get(f"{P}/ai/denkanstoesse")).json()["suggestions"]
        done = (await c.get(f"{P}/ai/denkanstoesse", params={"state": "done"})).json()["suggestions"]
        assert [s["suggestion_key"] for s in done] == [hyp["suggestion_key"]]
        assert hyp["suggestion_key"] not in [s["suggestion_key"] for s in open_]
        try:
            await check("d.suggestion.done", {"suggestion_key": hyp["suggestion_key"], "basis": hyp["basis"]})
            raise AssertionError("Konflikt erwartet")
        except Exception as exc:
            assert getattr(exc, "code", None) == "conflict"
        assert (await c.get(f"{P}/ai/denkanstoesse", params={"state": "x"})).status_code == 422

        # Journal: ai.call mit Metadaten, ohne Inhalte
        calls = await d.ingest.query_journal(
            lambda conn, j: [r.header for r in j.iter_events(kinds=["ai.call"])]
        )
        assert len(calls) == 1 and calls[0]["status"] == "ok" and calls[0]["cost_microusd"] > 0
        assert API_KEY not in json.dumps(calls) and CANARY not in json.dumps(calls)

    run_api(paths, operator, body)


def test_refusal_verbatim_busy_and_budget(paths, operator):
    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        await _setup(d, paths)
        assert (await d.call("ai.allow_cloud", {}))["ok"]
        refusal = "Dabei kann ich nicht helfen: Anfrage abgelehnt."
        gate = threading.Event()
        tr = Transport(
            _message(
                None, stop="refusal", details={"type": "refusal", "category": "cyber", "explanation": refusal}
            ),
            gate,
        )
        ctx.extra["ai"].provider_factory = tr.factory
        r = await c.post(f"{P}/ai/denkanstoss")
        assert r.status_code == 202
        job_id = r.json()["job"]["job_id"]
        # ein Auftrag zur Zeit
        r2 = await c.post(f"{P}/ai/denkanstoss", json={})
        assert r2.status_code == 409 and r2.json()["error"]["code"] == "conflict"
        assert (await c.get(f"{P}/ai/status")).json()["reason"] == "busy"
        gate.set()
        job = await _wait(c, P, job_id)
        assert job["status"] == "refused"
        assert job["refusal"] == {"category": "cyber", "text": refusal}  # wörtlich
        assert (await c.get(f"{P}/ai/denkanstoesse")).json()["suggestions"] == []
        prog = [e for k, e in bus.events if k == "progress" and e.get("kind") == "ai"]
        assert prog[-1]["status"] == "failed" and refusal not in json.dumps(prog)

        # Budget: Limit 0 USD, ohne Bestätigung 422, mit Bestätigung 202
        save_config(paths, AiConfig(provider="cloud", model="test-model", monthly_limit_usd=0.0))
        st = (await c.get(f"{P}/ai/status")).json()
        assert st["budget"]["level"] == "over"
        r = await c.post(f"{P}/ai/denkanstoss", json={})
        assert r.status_code == 422
        assert r.json()["error"]["detail"] == [{"loc": ["body", "confirm_budget"], "type": "budget_confirm"}]
        tr.reply = _message(json.dumps(_answer([])))
        r = await c.post(f"{P}/ai/denkanstoss", json={"confirm_budget": True})
        assert r.status_code == 202
        job = await _wait(c, P, r.json()["job"]["job_id"])
        assert job["status"] == "done" and job["created"] == 0 and job["budget_level"] == "over"
        assert (await c.get(f"{P}/ai/jobs/ai-000000000000")).status_code == 404

    run_api(paths, operator, body)


def test_ctl_status_and_key_never_returned(paths, operator):
    async def body(d, c, fx, bus, ctx):
        res = await d.call("ai.status", {})
        assert res["ok"] and res["result"]["provider"] == "off" and res["result"]["key_present"] is False
        await _setup(d, paths)
        res = await d.call("ai.status", {})
        out = res["result"]
        assert out["key_present"] is True and out["provider"] == "cloud"
        assert out["project"]["cloud_allowed"] is False and out["reason"] == "cloud_not_allowed"
        assert API_KEY not in json.dumps(res)
        assert (await d.call("ai.key.set", {"value": "zu kurz\nmit Umbruch"}))["ok"] is False
        assert API_KEY not in (paths.config_dir / "ai.toml").read_text()
        res = await d.call("ai.key.remove", {})
        assert res["result"]["removed"] is True
        assert (await d.call("ai.status", {}))["result"]["key_present"] is False
        # lokal (Ollama) braucht weder Schlüssel noch Cloud-Freigabe; nicht erreichbar: klare Meldung
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        save_config(paths, AiConfig(provider="local", model="test-model", local_port=port))
        P = f"{BASE}/p/{fx.pid}"
        assert (await c.get(f"{P}/ai/status")).json()["ready"] is True
        r = await c.post(f"{P}/ai/denkanstoss", json={})
        assert r.status_code == 202, r.text
        job = await _wait(c, P, r.json()["job"]["job_id"])
        assert job["status"] == "failed" and job["error"] == "unreachable" and "Ollama" in job["message"]

    run_api(paths, operator, body)


# --------------------------------------------------------------------------- Befunde der Prüfung (Etappe 4)

KEY_CANARY = "sk-ant-api03-REVIEWCANARY0123456789abcdef"


def test_api_key_is_own_secret_at_every_exit(paths, operator):
    """SEC4-KI-2: Der API-Key aus dem Operator-Tresor ist ein eigenes Secret des Redaktors. Steht er in einer
    aufgenommenen Ausgabe, gibt ihn weder ``redact_for_exit`` noch Zeitachse noch Export wörtlich aus."""

    async def body(d, c, fx, bus, ctx):
        from ariadne.export import service

        assert (await d.call("ai.key.set", {"value": KEY_CANARY}))["ok"]
        _red, labels = d.redactor.redact_for_exit(f"x {KEY_CANARY} y")
        assert labels and KEY_CANARY not in str(_red)
        await fx.term.command(
            "python3 -c 'import os; print(os.environ)'",
            f"environ({{'ANTHROPIC_API_KEY': '{KEY_CANARY}'}})\r\n".encode(),
            cwd=str(fx.ws),
        )
        await sync(d)
        r = await c.get(f"{BASE}/p/{fx.pid}/timeline")
        assert r.status_code == 200 and "REVIEWCANARY" not in r.text
        out = await service.run_export(d, template="cys")
        exp = fx.ws / out["path"]
        hits = [p.name for p in exp.rglob("*.md") if "REVIEWCANARY" in p.read_text("utf-8")]
        assert hits == []
        # nach dem Entfernen ist der Key kein Muster mehr (der Redaktor folgt dem Tresor)
        assert (await d.call("ai.key.remove", {}))["ok"]
        assert d.redactor.redact_for_exit(f"x {KEY_CANARY} y")[1] == []

    run_api(paths, operator, body)


def test_ai_state_survives_reparse(paths, operator):
    """R7: Erledigt und verworfen bleiben bei KI-Denkanstössen über ``reparse`` erhalten."""
    from tests.core.fakeshim import ctl as ctl_call

    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        await _setup(d, paths)
        await d.call("ai.allow_cloud", {})
        second = _item(art="frage", titel="Zweite Frage", vorlagen=[], belege=["S1"])
        tr = Transport(_message(json.dumps(_answer([_item(), second]))))
        ctx.extra["ai"].provider_factory = tr.factory
        r = await c.post(f"{P}/ai/denkanstoss", json={})
        job = await _wait(c, P, r.json()["job"]["job_id"])
        assert job["status"] == "done", job
        await sync(d)
        items = (await c.get(f"{P}/ai/denkanstoesse")).json()["suggestions"]
        assert len(items) == 2, items
        a, b = items
        done = {"suggestion_key": a["suggestion_key"], "basis": a["basis"]}
        r = await c.post(f"{P}/decisions", json={"decisions": [
            {"kind": "d.suggestion.done", "payload": done},
            {"kind": "d.suggestion.dismiss", "payload": {"suggestion_key": b["suggestion_key"]}},
        ]})
        assert r.status_code == 201, r.text
        await sync(d)

        async def states() -> dict[str, str]:
            got = (await c.get(f"{P}/suggestions", params={"state": "all"})).json()["suggestions"]
            return {s["suggestion_key"]: s["state"] for s in got if s["origin"] == "ai"}

        before = await states()
        assert (await ctl_call(paths.ctl_sock, "reparse"))["ok"]
        await sync(d)
        after = await states()
        nxt = [s["suggestion_key"] for s in (await c.get(f"{P}/next")).json()["suggestions"]
               if s.get("origin") == "ai"]
        assert before == after == {a["suggestion_key"]: "done", b["suggestion_key"]: "dismissed"}
        assert nxt == []

    run_api(paths, operator, body)


def test_fallback_content_with_partial_text_ends_done(paths, operator):
    """R1: serverseitiger Fallback mit Teiltext des ablehnenden Modells vor dem ``fallback``-Block."""

    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        await _setup(d, paths)
        await d.call("ai.allow_cloud", {})
        msg = _message(json.dumps(_answer([_item()])))
        good = msg["content"][0]
        msg["content"] = [
            {"type": "text", "text": '{"anstoesse": ['},
            {"type": "fallback", "from": {"model": "test-model"}, "to": {"model": "test-model-2"},
             "trigger": {"type": "refusal", "category": "cyber"}},
            good,
        ]
        msg["model"] = "test-model-2"
        ctx.extra["ai"].provider_factory = Transport(msg).factory
        r = await c.post(f"{P}/ai/denkanstoss", json={})
        job = await _wait(c, P, r.json()["job"]["job_id"])
        assert job["status"] == "done" and job["created"] == 1, job

    run_api(paths, operator, body)


def test_ai_scope_name_only_with_verdict_in(paths, operator):
    """SEC4-KI-3: Ein Name, der keinen Scope verleiht (PTR, nmap, Urteil ``out``), geht nicht ins Lagebild,
    auch nicht als erlaubte Adresse für den Freitext."""

    async def body(d, c, fx, bus, ctx):
        from ariadne.ai.situation import build_situation
        from ariadne.rules.engine import evaluate

        nmap = (
            b"Nmap scan report for dc01.kunde-ag.ch (10.10.10.3)\r\n"
            b"Host is up (0.00030s latency).\r\n"
            b"PORT   STATE SERVICE VERSION\r\n"
            b"22/tcp open  ssh     OpenSSH 4.7p1\r\n\r\n"
            b"Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds\r\n"
        )
        await fx.term.command("nmap -sV 10.10.10.3", nmap, cwd=str(fx.ws))
        await sync(d)
        ing = await d._sync_ingest()
        verdicts = await ing.query(lambda conn: dict(evaluate(conn, profile="lab")[0].name_verdict))
        assert verdicts.get("dc01.kunde-ag.ch") == "out", verdicts
        sit = await ing.query(lambda conn: build_situation(conn, profile="lab", redactor=d.redactor))
        assert "kunde-ag" not in sit.text
        assert not any("kunde-ag" in a for a in sit.allowed_addrs)
        assert any(ln.startswith("H") and "10.10.10.3" in ln for ln in sit.text.splitlines())

    run_api(paths, operator, body)


def test_ctl_status_without_project_says_no_project(paths, operator):
    """R6: Ohne offenes Projekt nennt ``ai.status`` nicht ``allow-cloud`` (das ginge ohne Projekt nicht)."""

    async def body(d, c, fx, bus, ctx):
        await _setup(d, paths)
        assert (await d.call("project.close", {}))["ok"]
        out = (await d.call("ai.status", {}))["result"]
        assert out["project"] is None and out["reason"] == "no_project", out
        assert "ariadne start" in out["reason_text"] and "allow-cloud" in out["reason_text"]

    run_api(paths, operator, body)
