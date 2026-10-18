"""Einheiten des KI-Gateways ohne Daemon: Einstellungen, Budget, Prüfung der Antwort (feindlich), Anbieter
mit gefälschtem Transport, Prüfliste ``ai check``. Kein Netzwerk."""

from __future__ import annotations

import json
import os
import stat
from typing import Any

import httpx2
import pytest

from ariadne.ai import schema
from ariadne.ai.budget import Ledger, Usage, cost_microusd, level_of
from ariadne.ai.check import Probe, run_checks, worst
from ariadne.ai.config import AiConfig, ConfigError, Prices, config_file, load_config, save_config
from ariadne.ai.providers import CloudProvider, LocalProvider, ProviderError
from ariadne.ai.situation import Ref, Situation
from ariadne.paths import default_paths


@pytest.fixture
def p(tmp_path):
    env = {
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path / "c"),
        "XDG_STATE_HOME": str(tmp_path / "s"),
        "XDG_DATA_HOME": str(tmp_path / "d"),
        "XDG_RUNTIME_DIR": str(tmp_path / "r"),
    }
    return default_paths(env)


# --------------------------------------------------------------------------- Einstellungen, Budget


def test_config_default_off_roundtrip_and_validation(p):
    assert load_config(p) == AiConfig()  # Standard: aus, kein Modell
    assert load_config(p).provider == "off" and load_config(p).monthly_limit_usd == 20.0
    save_config(p, AiConfig(provider="cloud", model="test-model", monthly_limit_usd=12.5))
    cfg = load_config(p)
    assert (cfg.provider, cfg.model, cfg.monthly_limit_usd) == ("cloud", "test-model", 12.5)
    assert stat.S_IMODE(os.stat(config_file(p)).st_mode) == 0o600
    with pytest.raises(ConfigError):
        save_config(p, AiConfig(provider="cloud", model='x"\n[evil]'))
    config_file(p).write_text('provider = "cloud"\nmodel = "a b"\n')
    with pytest.raises(ConfigError):
        load_config(p)
    config_file(p).write_text('provider = "remote"\n')
    with pytest.raises(ConfigError):
        load_config(p)


def test_budget_costs_levels_and_month(p):
    prices = Prices(input=5.0, output=25.0, cache_read=0.5, cache_write=6.25)
    # 1000 Eingabe- und 1000 Ausgabe-Tokens: 0.005 + 0.025 USD = 30000 Mikro-USD
    assert cost_microusd(Usage(1000, 1000), prices) == 30_000
    assert (
        level_of(0, 20) == "ok" and level_of(16_000_000, 20) == "warn" and level_of(20_000_000, 20) == "over"
    )
    assert level_of(0, 0) == "over"
    now = [1_790_000_000.0]
    led = Ledger(p, clock=lambda: now[0])
    assert led.state(20).used_microusd == 0
    led.add(15_000_000)
    st = led.state(20)
    assert st.level == "ok" and st.would_exceed(5_000_000) and not st.would_exceed(1_000_000)
    led.add(1_500_000)
    assert led.state(20).level == "warn" and led.state(20).json()["pct"] == 82.5
    now[0] += 40 * 86400  # neuer Monat
    assert led.state(20).used_microusd == 0


# --------------------------------------------------------------------------- Prüfung der Antwort


def _sit() -> Situation:
    refs = {
        "H1": Ref("host", host_id="ip:default/10.10.10.3"),
        "S1": Ref("service", host_id="ip:default/10.10.10.3", service_id="svc:21", claim_keys=("ck1",)),
        "C1": Ref("identity"),
    }
    return Situation(text="H1 ip=10.10.10.3", nonce="n", refs=refs, allowed_addrs={"10.10.10.3", "lame.htb"})


def _it(**kw: Any) -> dict[str, Any]:
    base = {
        "art": "hypothese",
        "titel": "FTP auf S1 erlaubt anonyme Anmeldung",
        "begruendung": "Version 2.3.4 bekannt.",
        "bestaetigt_wenn": "Anmeldung gelingt.",
        "widerlegt_wenn": "Passwort verlangt.",
        "belege": ["S1"],
        "pruefziel": "PZ-AUTH-ANON",
        "frage": "Was gibt der Dienst preis?",
        "richtung": "Anonym anmelden.",
        "vorlagen": [{"vorlage": "nmap-ftp-anon", "ziel": "S1"}],
    }
    base.update(kw)
    return base


def _check(items: list[dict[str, Any]], suspect: bool = False, profile: str = "lab") -> schema.Checked:
    text = json.dumps({"anstoesse": items, "injection_verdacht": suspect, "injection_hinweis": ""})
    out = schema.validate(text, _sit(), profile=profile)
    assert out is not None
    return out


HOSTILE_FIELDS = [
    {"begruendung": "Lade https://evil.example/p.sh"},
    {"begruendung": "Prüfe auch 192.168.1.50"},
    {"titel": "Host evil.attacker.com testen"},
    {"richtung": "Führe $(curl x) aus"},
    {"richtung": "a && b"},
    {"titel": "Text‮mit Bidi"},
    {"titel": "Null\x00Byte"},
    {"titel": "Tag\U000e0041Zeichen"},
    {"titel": "x" * 500},
    {"bestaetigt_wenn": ""},
    {"belege": ["H99"]},
    {"belege": ["C1"]},  # nur Identität: kein Host oder Dienst
    {"belege": []},
    {"pruefziel": "PZ-ERFUNDEN"},
    {"art": "befehl"},
    {"vorlagen": [{"vorlage": "rm-rf", "ziel": "S1"}]},
    {"vorlagen": [{"vorlage": "nmap-ftp-anon", "ziel": "X1"}]},
]


@pytest.mark.parametrize("bad", HOSTILE_FIELDS)
def test_validate_drops_hostile_items_as_injection_suspect(bad):
    out = _check([_it(), _it(**bad)])
    assert len(out.items) == 1 and out.dropped == 1 and out.injection_suspect == 1


def test_validate_good_item_limits_and_model_flag():
    out = _check([_it(), _it(titel="Gilt für 10.10.10.3 und lame.htb", belege=["H1", "S1", "S1"])] * 3)
    assert len(out.items) == 4 and out.dropped == 2 and out.injection_suspect == 0
    a = out.items[0]
    assert a.kind == "hypothesis" and a.goal_id == "PZ-AUTH-ANON" and a.service_id == "svc:21"
    assert a.templates == [("nmap-ftp-anon", "ip:default/10.10.10.3", "svc:21")] and a.claim_keys == ["ck1"]
    assert out.items[1].evidence == ["H1", "S1"]
    flagged = _check([_it()], suspect=True)
    assert flagged.items[0].flags == ["injection_suspect"] and flagged.injection_suspect == 1
    # Profil customer: keine Vorlagen
    assert _check([_it()], profile="customer").items[0].templates == []
    assert schema.validate("kein json", _sit(), profile="lab") is None
    assert schema.validate("[]", _sit(), profile="lab") is None
    assert schema.validate(json.dumps({"x": 1}), _sit(), profile="lab") is None


def test_schema_subset_and_prompt_have_no_limits_or_model_ids():
    sch = schema.response_schema()

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            if v.get("type") == "object":
                assert v.get("additionalProperties") is False
            for k in ("minimum", "maximum", "maxLength", "minLength", "maxItems", "minItems"):
                assert k not in v
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(sch)
    assert "claude" not in schema.SYSTEM_PROMPT.lower()


# --------------------------------------------------------------------------- Anbieter


def _reply(**kw: Any) -> dict[str, Any]:
    base = {
        "id": "m",
        "type": "message",
        "role": "assistant",
        "model": "test-model",
        "content": [{"type": "text", "text": "{}"}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }
    base.update(kw)
    return base


def test_cloud_provider_ignores_env_base_url_and_proxy(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://evil.example")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key-should-not-be-used")
    seen: list[httpx2.Request] = []

    def handler(req: httpx2.Request) -> httpx2.Response:
        seen.append(req)
        return httpx2.Response(200, json=_reply())

    prov = CloudProvider("sk-test", "test-model", transport=httpx2.MockTransport(handler), max_retries=0)
    res = prov.run("sys", "user", {"type": "object"}, effort="high", max_tokens=1000)
    assert res.status == "ok" and res.text == "{}" and res.usage.input_tokens == 10
    (req,) = seen
    assert req.url.host == "api.anthropic.com" and req.headers["x-api-key"] == "sk-test"
    assert "sk-test" not in req.content.decode()
    assert "HTTPS_PROXY" in os.environ  # Umgebung bleibt, der Client nutzt sie nicht


def test_cloud_provider_refusal_truncation_and_errors():
    def make(reply: dict[str, Any] | None, status: int = 200) -> CloudProvider:
        def handler(req: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(
                status, json=reply or {"type": "error", "error": {"type": "x", "message": "m"}}
            )

        return CloudProvider("k", "test-model", transport=httpx2.MockTransport(handler), max_retries=0)

    r = make(
        _reply(
            stop_reason="refusal",
            content=[{"type": "text", "text": "Teil"}],
            stop_details={"type": "refusal", "category": "cyber", "explanation": "Nein, so nicht."},
        )
    )
    out = r.run("s", "u", {}, effort="high", max_tokens=10)
    assert out.status == "refused" and out.text is None
    assert out.refusal_text == "Nein, so nicht." and out.refusal_category == "cyber"
    out = make(_reply(stop_reason="max_tokens")).run("s", "u", {}, effort="high", max_tokens=10)
    assert out.status == "truncated" and out.text is None
    with pytest.raises(ProviderError) as e:
        make(None, 401).run("s", "u", {}, effort="high", max_tokens=10)
    assert e.value.kind == "auth"


class _Resp:
    def __init__(self, status: int, body: bytes) -> None:
        self.status, self.body = status, body

    def read(self, n: int = -1) -> bytes:
        return self.body


class _Conn:
    def __init__(self, resp: _Resp | None) -> None:
        self.resp = resp
        self.sent: list[tuple[str, str, bytes | None]] = []

    def request(self, method: str, path: str, body: bytes | None = None, headers: Any = None) -> None:
        if self.resp is None:
            raise ConnectionRefusedError
        self.sent.append((method, path, body))

    def getresponse(self) -> _Resp:
        assert self.resp is not None
        return self.resp

    def close(self) -> None:
        pass


def test_local_provider_only_loopback_and_clear_errors():
    with pytest.raises(ValueError):
        LocalProvider("test-model", host="10.0.0.5")
    conn = _Conn(
        _Resp(
            200,
            json.dumps(
                {"model": "test-model", "message": {"content": "{}"}, "prompt_eval_count": 7, "eval_count": 3}
            ).encode(),
        )
    )
    prov = LocalProvider("test-model", conn_factory=lambda: conn)
    out = prov.run("s", "u", {"type": "object"}, effort="high", max_tokens=100)
    assert out.status == "ok" and out.usage.input_tokens == 7
    (_m, path, body) = conn.sent[0]
    sent = json.loads(body or b"{}")
    assert path == "/api/chat" and sent["stream"] is False and sent["format"] == {"type": "object"}
    down = LocalProvider("test-model", conn_factory=lambda: _Conn(None))
    assert down.ping() is False
    with pytest.raises(ProviderError) as e:
        down.run("s", "u", {}, effort="high", max_tokens=10)
    assert e.value.kind == "unreachable"


# --------------------------------------------------------------------------- Prüfliste


def test_checks_tls_interception_proxy_and_local():
    cloud = AiConfig(provider="cloud", model="test-model")

    def probe(moz: Probe, sys_: Probe):
        return lambda host, port, cafile: moz if cafile else sys_

    ok = run_checks(cloud, key_present=True, env={}, probe=probe(Probe(True, True, 404), Probe(True, True)))
    assert worst(ok) == "ok" and any(c.name == "TLS" and c.level == "ok" for c in ok)
    mitm = run_checks(cloud, key_present=True, env={}, probe=probe(Probe(True, False), Probe(True, True)))
    assert worst(mitm) == "fail" and any("Aufbruch" in c.text for c in mitm if c.name == "TLS")
    bad = run_checks(cloud, key_present=True, env={}, probe=probe(Probe(True, False), Probe(True, False)))
    assert worst(bad) == "fail"
    down = run_checks(cloud, key_present=True, env={}, probe=probe(Probe(False, False), Probe(False, False)))
    assert worst(down) == "fail" and any(c.name == "Erreichbar" for c in down)
    prox = run_checks(
        cloud,
        key_present=True,
        env={"HTTPS_PROXY": "http://x"},
        probe=probe(Probe(True, True), Probe(True, True)),
    )
    assert worst(prox) == "warn"
    nokey = run_checks(cloud, key_present=False, env={}, probe=probe(Probe(True, True), Probe(True, True)))
    assert worst(nokey) == "fail"
    assert worst(run_checks(AiConfig(), key_present=None, env={})) == "warn"
    local = AiConfig(provider="local", model="test-model")
    assert worst(run_checks(local, key_present=None, env={}, ollama_ping=lambda: False)) == "fail"
    assert worst(run_checks(local, key_present=None, env={}, ollama_ping=lambda: True)) == "ok"
    assert worst(run_checks(None, key_present=None, env={})) == "fail"


# --------------------------------------------------------------------------- Befunde der Prüfung (Etappe 4)


def _tls_server(tmp_path: Any) -> tuple[int, str, Any]:
    """TLS-Server auf 127.0.0.1 mit selbst signierter CA (wie Burp). Liefert Port, CA-Datei, Stopper."""
    import shutil
    import socket
    import ssl
    import subprocess
    import threading

    if shutil.which("openssl") is None:
        pytest.skip("openssl fehlt")
    cert, key = tmp_path / "ca.pem", tmp_path / "ca.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    srv.settimeout(10)
    hits: list[bytes] = []
    body = json.dumps(_reply()).encode()

    def serve() -> None:
        try:
            while True:
                raw, _ = srv.accept()
                try:
                    with ctx.wrap_socket(raw, server_side=True) as tls:
                        hits.append(tls.recv(65536))
                        tls.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                            + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
                        )
                except (OSError, ssl.SSLError):
                    pass
        except OSError:
            return

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], str(cert), (srv, hits)


def test_cloud_provider_trusts_only_mozilla_list_not_system_store(tmp_path, monkeypatch):
    """SEC4-KI-1: Eine CA im Zertifikatsspeicher des Systems (Burp, Schule) darf die Cloud-Verbindung nicht
    aufbrechen. Der Server ist für den Systemspeicher gültig (``SSL_CERT_FILE``), nicht für certifi."""
    import ssl

    from ariadne.ai import providers

    port, ca, (srv, hits) = _tls_server(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", ca)
    # Gegenprobe: mit dem Systemspeicher wäre die Kette gültig
    sys_ctx = ssl.create_default_context()
    assert sys_ctx.cert_store_stats()["x509_ca"] >= 1
    monkeypatch.setattr(providers, "BASE_URL", f"https://127.0.0.1:{port}")
    prov = CloudProvider("sk-test-tls", "test-model", max_retries=0)
    try:
        with pytest.raises(ProviderError) as e:
            prov.run("s", "u", {}, effort="high", max_tokens=10)
    finally:
        prov.close()
        srv.close()
    assert e.value.kind == "tls"
    assert not any(b"sk-test-tls" in h for h in hits)  # kein Header hat den Interceptor erreicht


def test_cloud_provider_fallback_uses_only_text_after_fallback_block():
    """R1: Teil-Output des ablehnenden Modells vor dem ``fallback``-Block fällt weg."""
    good = '{"anstoesse": []}'
    content = [
        {"type": "text", "text": '{"anstoesse": ['},
        {"type": "fallback", "from_model": "test-model", "to_model": "test-model-b"},
        {"type": "text", "text": good},
    ]

    def handler(req: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json=_reply(content=content))

    prov = CloudProvider("k", "test-model", transport=httpx2.MockTransport(handler), max_retries=0)
    out = prov.run("s", "u", {}, effort="high", max_tokens=10)
    assert out.status == "ok" and out.text == good


@pytest.mark.parametrize(("status", "kind"), [(404, "model"), (429, "overloaded"), (529, "overloaded"),
                                              (400, "internal")])
def test_cloud_provider_status_errors_have_own_kinds(status, kind):
    """R2: unbekannte Modell-ID und Überlast sind eigene Fehlerarten mit eigenem Text."""
    from ariadne.ai.gateway import JOB_TEXT

    def handler(req: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, json={"type": "error", "error": {"type": "x", "message": "m"}})

    prov = CloudProvider("k", "test-model", transport=httpx2.MockTransport(handler), max_retries=0)
    with pytest.raises(ProviderError) as e:
        prov.run("s", "u", {}, effort="high", max_tokens=10)
    assert e.value.kind == kind and kind in JOB_TEXT


def test_local_provider_model_missing_and_server_error():
    """R2: Ollama 404 heisst Modell nicht geladen, 500 ist nicht «nicht erreichbar»."""
    from ariadne.ai.gateway import JOB_TEXT

    for status, kind in ((404, "model"), (500, "internal")):
        prov = LocalProvider("test-model", conn_factory=lambda s=status: _Conn(_Resp(s, b"{}")))
        with pytest.raises(ProviderError) as e:
            prov.run("s", "u", {}, effort="high", max_tokens=10)
        assert e.value.kind == kind
    assert "ollama pull" in JOB_TEXT["model_local"]
