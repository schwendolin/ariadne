"""Anbieter des KI-Gateways: ``cloud`` (Anthropic-API über das Python-SDK) und ``local`` (Ollama).

Kein Modellaufruf bekommt Werkzeuge (Architektur 6). Ein Anbieter liefert nur Text, Ariadne prüft ihn.

* :class:`CloudProvider`: eigener ``http_client`` ohne Umgebungs-Proxy (``trust_env=False``), feste
  ``base_url`` (``ANTHROPIC_BASE_URL`` aus der Umgebung gilt nicht), API-Key nur als Argument aus dem
  Operator-Tresor, nie in der Umgebung. TLS nur gegen die Mozilla-Liste (``certifi``), nie gegen den
  Zertifikatsspeicher des Systems: Eine dort installierte CA (Burp, Schule, Firma) bricht die Verbindung
  ab, statt sie aufbrechen zu lassen (E98). Fehlt ``certifi``, gibt es keine Verbindung (Fehler ``tls``).
  Adaptive Thinking, Effort ``high``, strukturierte Ausgabe über ``output_config.format``, serverseitiger
  Fallback bei Ablehnung. ``stop_reason`` wird vor dem Inhalt geprüft; bei ``refusal`` wird Teil-Output
  verworfen und nur die Ablehnung wörtlich übernommen. Nach einem Fallback zählt nur der Text nach dem
  letzten ``fallback``-Block (Teil-Output des ablehnenden Modells fällt weg).
* :class:`OpenRouterProvider`: ``POST /api/v1/chat/completions`` an ``openrouter.ai`` (E134), über
  ``http.client`` ohne Proxy, TLS wie bei ``cloud`` nur gegen die Mozilla-Liste. Strukturierte Ausgabe per
  ``response_format`` (JSON-Schema), Kosten aus ``usage.cost``. OpenRouter wählt den Anbieter des Modells
  frei (Nutzerentscheid E134). Der Text der Fehlerantwort geht nie weiter, nur die feste Fehlerart.
* :class:`LocalProvider`: ``POST /api/chat`` an Ollama, nur auf ``127.0.0.1`` (ohne Proxy, über
  ``http.client``). Nicht erreichbar: klare Meldung, kein stiller Rückfall auf die Cloud. Modell nicht
  geladen (404): Fehler ``model``.

Für Tests nimmt :class:`CloudProvider` einen ``transport`` (``httpx2``-Transport) entgegen.
"""

from __future__ import annotations

import http.client
import json
import logging
import ssl
from dataclasses import dataclass, field
from typing import Any, Literal

from ariadne.ai.budget import Usage

__all__ = [
    "ProviderResult", "CloudProvider", "OpenRouterProvider", "LocalProvider", "ProviderError", "API_HOST",
    "BASE_URL", "OPENROUTER_HOST",
]

log = logging.getLogger("ariadne.ai")

API_HOST = "api.anthropic.com"
BASE_URL = f"https://{API_HOST}"
OPENROUTER_HOST = "openrouter.ai"
_OPENROUTER_PATH = "/api/v1/chat/completions"
_MAX_BODY = 8 << 20
FALLBACK_BETA = "server-side-fallback-2026-07-01"
_TIMEOUT_S = 300.0
_REFUSAL_MAX = 2000

Status = Literal["ok", "refused", "truncated", "error"]
ErrorKind = Literal["unreachable", "auth", "schema", "truncated", "internal", "model", "overloaded", "tls"]
_OVERLOADED = (429, 503, 529)


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


def mozilla_tls_context() -> ssl.SSLContext:
    """TLS-Kontext nur mit der Mozilla-Liste (``certifi``), ohne Zertifikatsspeicher des Systems.

    Fehlt ``certifi``: :class:`ProviderError` ``tls`` (lieber keine Verbindung als eine, die eine lokal
    installierte CA aufbrechen kann)."""
    try:
        import certifi
    except ImportError:
        raise ProviderError("tls") from None
    return ssl.create_default_context(cafile=certifi.where())


def _tls_failure(exc: BaseException) -> bool:
    """Steckt in der Kette der Ausnahme ein gescheiterter Zertifikatsabgleich?"""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, ssl.SSLCertVerificationError):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False


def _final_text(content: Any) -> str:
    """Text der Antwort; nach einem serverseitigen Fallback nur der Teil nach dem letzten
    ``fallback``-Block (davor steht Teil-Output des Modells, das abgelehnt hat)."""
    blocks = list(content or [])
    last = -1
    for i, b in enumerate(blocks):
        if getattr(b, "type", None) == "fallback":
            last = i
    return "".join(getattr(b, "text", "") for b in blocks[last + 1 :] if getattr(b, "type", None) == "text")


class CloudProvider:
    """Anthropic-API (Python-SDK ``anthropic``)."""

    name = "cloud"
    journal_name = "claude"

    def __init__(self, api_key: str, model: str, *, transport: Any = None, max_retries: int = 2) -> None:
        import anthropic

        kw: dict[str, Any] = {"trust_env": False}
        if transport is not None:
            kw["transport"] = transport
        else:
            kw["verify"] = mozilla_tls_context()
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

    def run(
        self, system: str, user: str, schema: dict[str, Any], *, effort: str, max_tokens: int
    ) -> ProviderResult:
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
        except anthropic.APITimeoutError:
            raise ProviderError("unreachable") from None
        except anthropic.APIConnectionError as exc:
            raise ProviderError("tls" if _tls_failure(exc) else "unreachable") from None
        except anthropic.NotFoundError:
            raise ProviderError("model") from None  # Modell-ID unbekannt
        except anthropic.APIStatusError as exc:
            raise ProviderError("overloaded" if exc.status_code in _OVERLOADED else "internal") from None
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
            text = _final_text(r.content)
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
        return ProviderResult("ok", _final_text(r.content), served, usage)


def _strip_fence(text: str) -> str:
    """Manche Modelle setzen JSON trotz ``response_format`` in einen Markdown-Block; nur diesen entfernen."""
    t = text.strip()
    if t.startswith("```") and t.endswith("```") and t.count("```") == 2:
        first = t.find("\n")
        if first != -1:
            return t[first + 1 : -3].strip()
    return text


def _openrouter_error(status: int, raw: bytes) -> ErrorKind:
    """HTTP-Status von OpenRouter auf eine feste Fehlerart (der Text der Antwort geht nie weiter)."""
    if status in (401, 402, 403):  # Key falsch, Guthaben oder Limit des Keys aufgebraucht
        return "auth"
    if status == 404:
        return "model"
    if status == 400:
        try:
            msg = json.loads(raw).get("error", {}).get("message", "")
        except (ValueError, AttributeError):
            msg = ""
        return "model" if isinstance(msg, str) and "model" in msg.lower() else "internal"
    if status in (408, 429, 502, 503, 529):
        return "overloaded"
    return "internal"


class OpenRouterProvider:
    """OpenRouter (``openrouter.ai``), OpenAI-kompatible Schnittstelle; Modell-ID wie ``anbieter/modell``."""

    name = "openrouter"
    journal_name = "openrouter"

    def __init__(self, api_key: str, model: str, *, conn_factory: Any = None) -> None:
        self.model = model
        self._key = api_key
        self._conn = conn_factory or (
            lambda: http.client.HTTPSConnection(
                OPENROUTER_HOST, 443, timeout=_TIMEOUT_S, context=mozilla_tls_context()
            )
        )

    def close(self) -> None:
        self._key = ""

    def run(
        self, system: str, user: str, schema: dict[str, Any], *, effort: str, max_tokens: int
    ) -> ProviderResult:
        body = json.dumps(
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {"name": "denkanstoss", "strict": True, "schema": schema},
                },
                "reasoning": {"effort": effort if effort in ("low", "medium", "high") else "high",
                              "exclude": True},
                "usage": {"include": True},
            }
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._key}",
            "X-Title": "Ariadne",
        }
        try:
            c = self._conn()
            c.request("POST", _OPENROUTER_PATH, body=body, headers=headers)
            resp = c.getresponse()
            raw = resp.read(_MAX_BODY)
            status = resp.status
            c.close()
        except TimeoutError:
            raise ProviderError("unreachable") from None
        except (OSError, http.client.HTTPException) as exc:
            raise ProviderError("tls" if _tls_failure(exc) else "unreachable") from None
        if status != 200:
            raise ProviderError(_openrouter_error(status, raw))
        try:
            data = json.loads(raw)
        except ValueError:
            raise ProviderError("schema") from None
        if not isinstance(data, dict):
            raise ProviderError("schema")
        if isinstance(data.get("error"), dict):  # Fehler des weitergeleiteten Anbieters mit Status 200
            code = data["error"].get("code")
            raise ProviderError(_openrouter_error(code if isinstance(code, int) else 500, b"{}"))
        u = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        details = u.get("prompt_tokens_details") if isinstance(u.get("prompt_tokens_details"), dict) else {}
        cost = u.get("cost")
        cached = _int(details.get("cached_tokens"))
        usage = Usage(
            input_tokens=max(0, _int(u.get("prompt_tokens")) - cached),
            output_tokens=_int(u.get("completion_tokens")),
            cache_read_tokens=cached,
            billed_usd=float(cost) if isinstance(cost, (int, float)) and not isinstance(cost, bool) else None,
        )
        served = data.get("model") if isinstance(data.get("model"), str) else self.model
        choices = data.get("choices")
        choice = choices[0] if isinstance(choices, list) and choices else None
        if not isinstance(choice, dict):
            raise ProviderError("schema")
        msg = choice.get("message") if isinstance(choice.get("message"), dict) else {}
        finish = choice.get("finish_reason")
        refusal = msg.get("refusal")
        if finish == "content_filter" or (isinstance(refusal, str) and refusal):
            text = refusal if isinstance(refusal, str) else ""
            return ProviderResult("refused", None, served, usage, refusal_text=text[:_REFUSAL_MAX])
        if finish == "length":
            return ProviderResult("truncated", None, served, usage, error="truncated")
        text = msg.get("content")
        if not isinstance(text, str) or not text.strip():
            raise ProviderError("schema")
        return ProviderResult("ok", _strip_fence(text), served, usage)


def is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1")


class LocalProvider:
    """Ollama auf diesem Rechner (``127.0.0.1``), ``POST /api/chat`` mit JSON-Schema in ``format``."""

    name = "local"
    journal_name = "ollama"

    def __init__(
        self, model: str, *, port: int = 11434, host: str = "127.0.0.1", conn_factory: Any = None
    ) -> None:
        if not is_loopback(host):
            raise ValueError("Ollama nur auf 127.0.0.1 oder ::1")
        self.model, self.host, self.port = model, host, port
        self._conn = conn_factory or (
            lambda: http.client.HTTPConnection(self.host, self.port, timeout=_TIMEOUT_S)
        )

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

    def run(
        self, system: str, user: str, schema: dict[str, Any], *, effort: str, max_tokens: int
    ) -> ProviderResult:
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
            # Ollama läuft (es hat geantwortet): 404 heisst Modell nicht geladen, sonst interner Fehler
            raise ProviderError("model" if status == 404 else "internal")
        try:
            data = json.loads(raw)
        except ValueError:
            raise ProviderError("schema") from None
        msg = data.get("message") if isinstance(data, dict) else None
        text = msg.get("content") if isinstance(msg, dict) else None
        usage = Usage(
            input_tokens=_int(data.get("prompt_eval_count")), output_tokens=_int(data.get("eval_count"))
        )
        model = data.get("model") if isinstance(data.get("model"), str) else self.model
        if data.get("done_reason") == "length":
            return ProviderResult("truncated", None, model, usage, error="truncated")
        if not isinstance(text, str):
            raise ProviderError("schema")
        return ProviderResult("ok", text, model, usage)
