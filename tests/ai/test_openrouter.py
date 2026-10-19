"""OpenRouter als Anbieter (E134): Anfrage, Antwort, Fehlerarten, Kosten, Einstellungen und Freigabe.

Ohne Netz: Die Verbindung ist ein Fake mit derselben Schnittstelle wie ``http.client``."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ariadne.ai.budget import Usage, cost_microusd
from ariadne.ai.check import Probe, run_checks
from ariadne.ai.config import AiConfig, Prices, api_host, is_remote, key_name, load_config, save_config
from ariadne.ai.gateway import default_factory, policy_reason
from ariadne.ai.providers import OpenRouterProvider, ProviderError

SCHEMA = {"type": "object", "properties": {"items": {"type": "array"}}, "required": ["items"]}
KEY = "sk-or-v1-testkey"


class FakeResp:
    def __init__(self, status: int, body: bytes) -> None:
        self.status, self._body = status, body

    def read(self, n: int = -1) -> bytes:
        return self._body


class FakeConn:
    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.sent: dict[str, Any] = {}

    def request(self, method: str, path: str, body: bytes, headers: dict[str, str]) -> None:
        self.sent = {"method": method, "path": path, "body": json.loads(body), "headers": headers}

    def getresponse(self) -> FakeResp:
        return FakeResp(self.status, self.body)

    def close(self) -> None:
        pass


def ok_body(content: str, *, finish: str = "stop", cost: float | None = 0.0042, **msg: Any) -> dict[str, Any]:
    usage: dict[str, Any] = {"prompt_tokens": 1200, "completion_tokens": 300,
                             "prompt_tokens_details": {"cached_tokens": 200}}
    if cost is not None:
        usage["cost"] = cost
    message = {"role": "assistant", "content": content, **msg}
    return {"model": "moonshotai/kimi-k3", "usage": usage,
            "choices": [{"finish_reason": finish, "message": message}]}


def run(conn: FakeConn, effort: str = "high"):
    prov = OpenRouterProvider(KEY, "moonshotai/kimi-k3", conn_factory=lambda: conn)
    return prov.run("SYS", "USER", SCHEMA, effort=effort, max_tokens=8000)


def test_request_shape_and_ok_result():
    conn = FakeConn(200, ok_body('{"items": []}'))
    r = run(conn)
    assert r.status == "ok" and r.text == '{"items": []}' and r.model == "moonshotai/kimi-k3"
    s = conn.sent
    assert s["method"] == "POST" and s["path"] == "/api/v1/chat/completions"
    assert s["headers"]["Authorization"] == f"Bearer {KEY}"
    b = s["body"]
    assert b["model"] == "moonshotai/kimi-k3" and b["max_tokens"] == 8000
    assert b["messages"] == [{"role": "system", "content": "SYS"}, {"role": "user", "content": "USER"}]
    assert b["response_format"]["type"] == "json_schema"
    assert b["response_format"]["json_schema"]["schema"] == SCHEMA
    assert b["usage"] == {"include": True}
    assert "provider" not in b  # E134: OpenRouter wählt den Anbieter frei
    # Kosten des Anbieters zählen, gecachte Tokens getrennt
    assert r.usage.input_tokens == 1000 and r.usage.cache_read_tokens == 200 and r.usage.output_tokens == 300
    assert cost_microusd(r.usage, Prices()) == 4200


def test_effort_outside_openrouter_values_becomes_high():
    conn = FakeConn(200, ok_body('{"items": []}'))
    run(conn, effort="max")
    assert conn.sent["body"]["reasoning"]["effort"] == "high"


def test_markdown_fence_is_removed():
    r = run(FakeConn(200, ok_body('```json\n{"items": []}\n```')))
    assert r.text == '{"items": []}'


def test_without_cost_prices_apply():
    r = run(FakeConn(200, ok_body('{"items": []}', cost=None)))
    assert r.usage.billed_usd is None
    assert cost_microusd(r.usage, Prices(input=1, output=1, cache_read=1, cache_write=1)) == 1500


@pytest.mark.parametrize("finish, extra, status", [
    ("length", {}, "truncated"),
    ("content_filter", {}, "refused"),
    ("stop", {"refusal": "nein"}, "refused"),
])
def test_finish_reasons(finish, extra, status):
    r = run(FakeConn(200, ok_body("", finish=finish, **extra)))
    assert r.status == status and r.text is None


@pytest.mark.parametrize("status, body, kind", [
    (401, {"error": {"message": "No auth credentials found"}}, "auth"),
    (402, {"error": {"message": "Insufficient credits"}}, "auth"),
    (403, {"error": {"message": "Key limit exceeded"}}, "auth"),
    (404, {"error": {"message": "No endpoints found"}}, "model"),
    (400, {"error": {"message": "x is not a valid model ID"}}, "model"),
    (400, {"error": {"message": "bad request"}}, "internal"),
    (429, {"error": {"message": "rate limited"}}, "overloaded"),
    (502, b"<html>", "overloaded"),
    (500, b"", "internal"),
])
def test_http_errors_map_to_fixed_kinds(status, body, kind):
    with pytest.raises(ProviderError) as exc:
        run(FakeConn(status, body))
    assert exc.value.kind == kind
    assert "credits" not in str(exc.value) and "model ID" not in str(exc.value)  # nie der Antworttext


def test_error_inside_200_and_bad_json():
    with pytest.raises(ProviderError) as exc:
        run(FakeConn(200, {"error": {"code": 429, "message": "upstream"}}))
    assert exc.value.kind == "overloaded"
    with pytest.raises(ProviderError) as exc:
        run(FakeConn(200, b"not json"))
    assert exc.value.kind == "schema"
    with pytest.raises(ProviderError) as exc:
        run(FakeConn(200, {"choices": []}))
    assert exc.value.kind == "schema"


def test_unreachable():
    def boom():
        raise OSError("no route")

    prov = OpenRouterProvider(KEY, "m/x", conn_factory=boom)
    with pytest.raises(ProviderError) as exc:
        prov.run("s", "u", SCHEMA, effort="high", max_tokens=1000)
    assert exc.value.kind == "unreachable"


def test_config_roundtrip_and_helpers(paths):
    save_config(paths, AiConfig(provider="openrouter", model="moonshotai/kimi-k3"))
    cfg = load_config(paths)
    assert cfg.provider == "openrouter" and cfg.model == "moonshotai/kimi-k3"
    assert is_remote("openrouter") and is_remote("cloud") and not is_remote("local") and not is_remote("off")
    assert key_name("openrouter") == "openrouter" and key_name("cloud") == "anthropic"
    assert api_host("openrouter") == "openrouter.ai" and api_host("cloud") == "api.anthropic.com"


def test_factory_and_policy_treat_openrouter_like_cloud():
    cfg = AiConfig(provider="openrouter", model="moonshotai/kimi-k3")
    assert isinstance(default_factory(cfg, KEY), OpenRouterProvider)
    with pytest.raises(ProviderError):
        default_factory(cfg, None)
    base = {"key_present": True, "operator_unlocked": True, "profile": "lab"}
    assert policy_reason(cfg, **base, flags={}) == "cloud_not_allowed"
    assert policy_reason(cfg, **base, flags={"cloud_allowed": True}) is None
    assert policy_reason(cfg, **base, flags={"cloud_allowed": True, "public_scope": True}) == "public_scope"
    assert policy_reason(cfg, **{**base, "key_present": False}, flags={"cloud_allowed": True}) == "no_key"
    assert policy_reason(cfg, **{**base, "profile": "customer"}, flags={"cloud_allowed": True}) == "profile"


def test_check_probes_openrouter_host():
    seen = []

    def probe(host, port, cafile):
        seen.append(host)
        return Probe(True, True, 200)

    cfg = AiConfig(provider="openrouter", model="moonshotai/kimi-k3")
    checks = run_checks(cfg, key_present=True, env={}, probe=probe)
    assert seen and set(seen) == {"openrouter.ai"}
    assert any("openrouter.ai" in c.text for c in checks)


def test_billed_cost_is_bounded():
    assert cost_microusd(Usage(billed_usd=float("nan"), input_tokens=1), Prices(input=1)) == 1
    assert cost_microusd(Usage(billed_usd=-1.0, input_tokens=1), Prices(input=1)) == 1
    assert cost_microusd(Usage(billed_usd=0.0, input_tokens=5), Prices(input=1)) == 0
