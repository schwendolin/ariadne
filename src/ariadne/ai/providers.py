"""Anbieter des KI-Gateways: ``cloud`` (Anthropic-API über das Python-SDK) und ``local`` (Ollama).

Kein Modellaufruf bekommt Werkzeuge (Architektur 6). Ein Anbieter liefert nur Text, Ariadne prüft ihn.

* :class:`CloudProvider`: eigener ``http_client`` ohne Umgebungs-Proxy (``trust_env=False``), feste
  ``base_url`` (``ANTHROPIC_BASE_URL`` aus der Umgebung gilt nicht), API-Key nur als Argument aus dem
  Operator-Tresor, nie in der Umgebung. Adaptive Thinking, Effort ``high``, strukturierte Ausgabe über
  ``output_config.format``, serverseitiger Fallback bei Ablehnung. ``stop_reason`` wird vor dem Inhalt
  geprüft; bei ``refusal`` wird Teil-Output verworfen und nur die Ablehnung wörtlich übernommen.
* :class:`LocalProvider`: ``POST /api/chat`` an Ollama, nur auf ``127.0.0.1`` (ohne Proxy, über
  ``http.client``). Nicht erreichbar: klare Meldung, kein stiller Rückfall auf die Cloud.

Für Tests nimmt :class:`CloudProvider` einen ``transport`` (``httpx2``-Transport) entgegen.
"""

from __future__ import annotations

import http.client
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Literal

from ariadne.ai.budget import Usage

__all__ = ["ProviderResult", "CloudProvider", "LocalProvider", "ProviderError", "API_HOST", "BASE_URL"]

log = logging.getLogger("ariadne.ai")

API_HOST = "api.anthropic.com"
BASE_URL = f"https://{API_HOST}"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
_TIMEOUT_S = 300.0
_REFUSAL_MAX = 2000

Status = Literal["ok", "refused", "truncated", "error"]
ErrorKind = Literal["unreachable", "auth", "schema", "truncated", "internal"]


class ProviderError(Exception):
    """Anbieter nicht nutzbar; ``kind`` ist fest, ``str()`` geht nie an Browser oder Log."""

    def __init__(self, kind: ErrorKind) -> None:
        super().__init__(kind)
        self.kind: ErrorKind = kind


@dataclass
class ProviderResult:
    status: Status
    text: str | None
    model: str | None
    usage: Usage = field(default_factory=Usage)
    refusal_category: str | None = None
    refusal_text: str | None = None
    error: ErrorKind | None = None


def _int(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


class CloudProvider:
    """Anthropic-API (Python-SDK ``anthropic``)."""

    name = "cloud"
    journal_name = "claude"

    def __init__(self, api_key: str, model: str, *, transport: Any = None, max_retries: int = 2) -> None:
        import anthropic

        kw: dict[str, Any] = {"trust_env": False}
        if transport is not None:
            kw["transport"] = transport
        self.model = model
        self._client = anthropic.Anthropic(
            api_key=api_key,
            base_url=BASE_URL,
            http_client=anthropic.DefaultHttpxClient(**kw),
            max_retries=max_retries,
            timeout=_TIMEOUT_S,
        )

    def close(self) -> None:
        try:
            self._client.close()
        except Exception as exc:  # nur Aufräumen
            log.debug("Client nicht sauber geschlossen (%s)", type(exc).__name__)

    def run(self, system: str, user: str, schema: dict[str, Any], *, effort: str, max_tokens: int) -> ProviderResult:
        import anthropic

        try:
            r = self._client.beta.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": user}],
                thinking={"type": "adaptive"},
                output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
                betas=[FALLBACK_BETA],
                fallbacks="default",
            )
        except anthropic.AuthenticationError:
            raise ProviderError("auth") from None
        except anthropic.PermissionDeniedError:
            raise ProviderError("auth") from None
        except (anthropic.APIConnectionError, anthropic.APITimeoutError):
            raise ProviderError("unreachable") from None
        except anthropic.APIStatusError:
            raise ProviderError("internal") from None
        u = getattr(r, "usage", None)
        usage = Usage(
            input_tokens=_int(getattr(u, "input_tokens", 0)),
            output_tokens=_int(getattr(u, "output_tokens", 0)),
            cache_read_tokens=_int(getattr(u, "cache_read_input_tokens", 0)),
            cache_write_tokens=_int(getattr(u, "cache_creation_input_tokens", 0)),
        )
        served = getattr(r, "model", None)
        served = served if isinstance(served, str) else None
        stop = getattr(r, "stop_reason", None)
        if stop == "refusal":  # immer vor dem Inhalt prüfen; Teil-Output verwerfen
            det = getattr(r, "stop_details", None)
            cat = getattr(det, "category", None) if det is not None else None
            expl = getattr(det, "explanation", None) if det is not None else None
            text = "".join(
                getattr(b, "text", "") for b in (r.content or []) if getattr(b, "type", None) == "text"
            )
            refusal = (expl if isinstance(expl, str) and expl else text) or ""
            return ProviderResult(
                "refused",
                None,
                served,
                usage,
                refusal_category=cat if isinstance(cat, str) else None,
                refusal_text=refusal[:_REFUSAL_MAX],
            )
        if stop == "max_tokens":
            return ProviderResult("truncated", None, served, usage, error="truncated")
        text = "".join(getattr(b, "text", "") for b in (r.content or []) if getattr(b, "type", None) == "text")
        return ProviderResult("ok", text, served, usage)


def is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1")


class LocalProvider:
    """Ollama auf diesem Rechner (``127.0.0.1``), ``POST /api/chat`` mit JSON-Schema in ``format``."""

    name = "local"
    journal_name = "ollama"

    def __init__(self, model: str, *, port: int = 11434, host: str = "127.0.0.1", conn_factory: Any = None) -> None:
        if not is_loopback(host):
            raise ValueError("Ollama nur auf 127.0.0.1 oder ::1")
        self.model, self.host, self.port = model, host, port
        self._conn = conn_factory or (lambda: http.client.HTTPConnection(self.host, self.port, timeout=_TIMEOUT_S))

    def close(self) -> None:
        return None

    def ping(self) -> bool:
        """Antwortet Ollama? (``GET /api/version``, ohne Inhalte)."""
        try:
            c = self._conn()
            c.request("GET", "/api/version")
            ok = c.getresponse().status == 200
            c.close()
            return ok
        except (OSError, http.client.HTTPException):
            return False

    def run(self, system: str, user: str, schema: dict[str, Any], *, effort: str, max_tokens: int) -> ProviderResult:
        body = json.dumps(
            {
                "model": self.model,
                "stream": False,
                "format": schema,
                "options": {"num_predict": max_tokens},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            }
        ).encode("utf-8")
        try:
            c = self._conn()
            c.request("POST", "/api/chat", body=body, headers={"Content-Type": "application/json"})
            resp = c.getresponse()
            raw = resp.read(4 << 20)
            status = resp.status
            c.close()
        except (OSError, http.client.HTTPException):
            raise ProviderError("unreachable") from None
        if status != 200:
            raise ProviderError("unreachable" if status >= 500 else "internal")
        try:
            data = json.loads(raw)
        except ValueError:
            raise ProviderError("schema") from None
        msg = data.get("message") if isinstance(data, dict) else None
        text = msg.get("content") if isinstance(msg, dict) else None
        usage = Usage(input_tokens=_int(data.get("prompt_eval_count")), output_tokens=_int(data.get("eval_count")))
        model = data.get("model") if isinstance(data.get("model"), str) else self.model
        if data.get("done_reason") == "length":
            return ProviderResult("truncated", None, model, usage, error="truncated")
        if not isinstance(text, str):
            raise ProviderError("schema")
        return ProviderResult("ok", text, model, usage)
