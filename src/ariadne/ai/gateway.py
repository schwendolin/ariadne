"""KI-Gateway: Policy, Budget, Auftrag «Denkanstoss» (Architektur 6.2, 6.3; E64 bis E66, E72).

Ablauf eines Auftrags (ein Auftrag zur Zeit pro Daemon)::

    Policy ─► Lagebild (Projektion, redact_for_exit, scan_outgoing) ─► Budget ─► Anbieter
           ─► ai.call ins Journal ─► stop_reason ─► Schema und Belege prüfen ─► d.ai.denkanstoss

Der Gateway kennt den Daemon nur über seine stabile Schnittstelle (``project``, ``operator``,
``redactor``, ``paths``, ``submit``, ``flush``) und die Web-API über :class:`~ariadne.web.api.common.Api`.
Logs enthalten nie Inhalte (nur Klassen von Ausnahmen); der API-Key verlässt den Operator-Tresor nur als
Argument an das SDK, nie in Umgebung, Datei oder Log.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import secrets as _secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ariadne.ai import schema as ai_schema
from ariadne.ai.budget import Ledger, Usage, cost_microusd
from ariadne.ai.config import AiConfig, ConfigError, is_remote, key_name, load_config
from ariadne.ai.providers import (
    CloudProvider,
    LocalProvider,
    OpenRouterProvider,
    ProviderError,
    ProviderResult,
)
from ariadne.ai.situation import Situation, build_situation
from ariadne.ai.store import done_titles
from ariadne.rules.engine import evaluate
from ariadne.scope.change import scope_open
from ariadne.store.api import AppendItem

__all__ = [
    "KEY_NAME",
    "REASONS",
    "Job",
    "Gateway",
    "project_flags",
    "policy_reason",
    "estimate_microusd",
    "JOB_TEXT",
]

log = logging.getLogger("ariadne.ai")

KEY_NAME = "anthropic"  # Name des API-Keys für cloud im Operator-Tresor (openrouter: config.key_name)
EFFORT = "high"  # Denkanstösse: Effort ausdrücklich gesetzt (Architektur 6.2)
_PROMPT_OVERHEAD_TOKENS = 1500  # System-Prompt, Listen
_PUBLIC_TLD_OK = ("htb", "local", "lab", "internal", "test", "localdomain", "home", "lan")

REASONS: dict[str, str] = {
    "off": "KI ist aus: im Terminal ariadne ai setup.",
    "config": "ai.toml ist ungültig: im Terminal ariadne ai setup.",
    "no_model": "Keine Modell-ID gesetzt: im Terminal ariadne ai setup.",
    "no_key": "Kein API-Key im Operator-Tresor: im Terminal ariadne ai setup.",
    "locked": "Operator gesperrt: im Terminal ariadne start.",
    "cloud_not_allowed": "Cloud-KI für dieses Projekt nicht freigegeben: im Terminal ariadne ai allow-cloud.",
    "profile": "Im Profil customer ist die Cloud-KI aus; nur lokal (Ollama).",
    "public_scope": "Öffentliche Adressen im Scope: zuerst «kein Kundenauftrag» im Terminal bestätigen.",
    "busy": "Ein KI-Auftrag läuft schon.",
    "no_project": (
        "Für die Cloud-KI zuerst ein Projekt öffnen: ariadne start <slug>, danach ariadne ai allow-cloud."
    ),
}

JOB_TEXT: dict[str, str] = {
    "queued": "KI-Auftrag angenommen.",
    "lagebild": "Lagebild wird erstellt.",
    "anfrage": "Anfrage an das Modell läuft.",
    "pruefung": "Antwort wird geprüft.",
    "done": "Denkanstösse erstellt.",
    "empty": "Keine gültigen Denkanstösse in der Antwort.",
    "refused": "Das Modell hat die Anfrage abgelehnt.",
    "unreachable": "Anbieter nicht erreichbar.",
    "unreachable_local": "Ollama auf 127.0.0.1 nicht erreichbar: ollama serve starten oder ariadne ai check.",
    "auth": "API-Key abgelehnt: im Terminal ariadne ai setup.",
    "model": "Modell-ID beim Anbieter unbekannt: im Terminal ariadne ai setup --model <ID>.",
    "model_local": "Modell in Ollama nicht geladen: ollama pull <ID> oder ariadne ai setup --model <ID>.",
    "overloaded": "Anbieter ausgelastet oder Ratenlimit erreicht: später erneut versuchen.",
    "tls": "TLS-Verbindung abgelehnt (fremde CA oder Aufbruch): im Terminal ariadne ai check.",
    "schema": "Antwort hat nicht das verlangte Format.",
    "truncated": "Antwort abgeschnitten (zu lang).",
    "project_changed": "Projekt wurde gewechselt; nichts gespeichert.",
    "internal": "KI-Auftrag fehlgeschlagen.",
}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def project_flags(conn: Any, profile: str = "lab", scope_open: bool = False) -> dict[str, bool]:
    """Freigabe und Leitplanken aus der Projektion: ``cloud_allowed`` (aktiver ``d.ai.allow_cloud``),
    ``not_customer`` (aktiver ``d.lab.not_customer``), ``public_scope`` (öffentliche Adresse oder
    Domain mit Urteil ``in``, Architektur 8.1; ein offener Scope zählt immer so, E131)."""
    rows = conn.execute(
        "SELECT id, kind, payload_json FROM decision "
        "WHERE kind IN ('d.ai.allow_cloud', 'd.lab.not_customer', "
        "'d.revoke') ORDER BY seq LIMIT 20000"
    ).fetchall()
    revoked: set[str] = set()
    for _id, kind, payload in reversed(rows):
        if kind != "d.revoke":
            continue
        try:
            data = json.loads(payload) if isinstance(payload, str) else {}
        except ValueError:
            data = {}
        if isinstance(data, dict) and isinstance(data.get("decision_id"), str):
            revoked.add(data["decision_id"])
    active = {str(k) for i, k, _p in rows if k != "d.revoke" and str(i) not in revoked}
    f, _built = evaluate(conn, profile=profile)
    public = any(v == "in" and _is_public(a) for a, v in f.ip_verdict.items()) or any(
        v == "in" and _is_public(n) for n, v in f.name_verdict.items()
    )
    return {
        "cloud_allowed": "d.ai.allow_cloud" in active,
        "not_customer": "d.lab.not_customer" in active,
        "public_scope": public or scope_open,
    }


def _is_public(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        name = value.lower().rstrip(".").lstrip("*.")
        if "." not in name:
            return False
        return name.rsplit(".", 1)[-1] not in _PUBLIC_TLD_OK
    return bool(ip.is_global)


def policy_reason(
    cfg: AiConfig | None, *, key_present: bool, operator_unlocked: bool, profile: str, flags: dict[str, bool]
) -> str | None:
    """Erster Grund, warum kein Auftrag möglich ist, oder ``None``."""
    if cfg is None:
        return "config"
    if cfg.provider == "off":
        return "off"
    if not cfg.model:
        return "no_model"
    if is_remote(cfg.provider):  # cloud und openrouter (E134)
        if profile != "lab":
            return "profile"
        if not operator_unlocked:
            return "locked"
        if not key_present:
            return "no_key"
        if flags.get("public_scope") and not flags.get("not_customer"):
            return "public_scope"
        if not flags.get("cloud_allowed"):
            return "cloud_not_allowed"
    return None


def estimate_microusd(cfg: AiConfig, input_tokens: int) -> int:
    """Vorsichtige Schätzung eines Auftrags: Eingabe plus volle Ausgabegrenze."""
    return cost_microusd(
        Usage(input_tokens=input_tokens + _PROMPT_OVERHEAD_TOKENS, output_tokens=cfg.max_output_tokens),
        cfg.prices,
    )


@dataclass
class Job:
    job_id: str
    project_id: str
    provider: str
    model: str
    status: str = "queued"
    step: str = "lagebild"
    message: str = JOB_TEXT["queued"]
    started_at: str = field(default_factory=_now_iso)
    ended_at: str | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    tokens_estimate: int | None = None
    masked: int = 0
    cost_usd: float | None = None
    budget_level: str = "ok"
    created: int = 0
    dropped: int = 0
    injection_suspect: int = 0
    refusal: dict[str, Any] | None = None
    error: str | None = None

    def json(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "step": self.step,
            "message": self.message,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "provider": self.provider,
            "model": self.model,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "tokens_estimate": self.tokens_estimate,
            "masked": self.masked,
            "cost_usd": self.cost_usd,
            "budget_level": self.budget_level,
            "created": self.created,
            "dropped": self.dropped,
            "injection_suspect": self.injection_suspect,
            "refusal": self.refusal,
            "error": self.error,
        }

    def progress(self) -> dict[str, Any]:
        """Daten für das SSE-Ereignis ``progress`` (nur Kennungen, Zahlen, feste Texte)."""
        pct = {"lagebild": 10, "anfrage": 40, "pruefung": 90, "fertig": 100}.get(self.step)
        status = {"queued": "queued", "running": "running", "done": "done"}.get(self.status, "failed")
        return {
            "job_id": self.job_id,
            "kind": "ai",
            "status": status,
            "pct": pct,
            "message": self.message,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "tokens_estimate": self.tokens_estimate,
            "masked": self.masked,
            "cost_usd": self.cost_usd,
            "budget_level": self.budget_level,
        }


ProviderFactory = Callable[[AiConfig, "str | None"], Any]


def default_factory(cfg: AiConfig, key: str | None) -> Any:
    if is_remote(cfg.provider):
        if not key:
            raise ProviderError("auth")
        if cfg.provider == "openrouter":
            return OpenRouterProvider(key, cfg.model)
        return CloudProvider(key, cfg.model)
    return LocalProvider(cfg.model, port=cfg.local_port)


class GatewayError(Exception):
    """Auftrag nicht möglich: ``code`` ist ``policy`` (mit ``reason``), ``busy`` oder ``budget_confirm``."""

    def __init__(self, code: str, reason: str | None = None) -> None:
        super().__init__(code)
        self.code, self.reason = code, reason


class Gateway:
    """Ein Gateway pro Web-Server (also pro Daemon-Lauf): hält den laufenden und den letzten Auftrag."""

    def __init__(self, api: Any, *, provider_factory: ProviderFactory | None = None) -> None:
        self.api = api
        self.provider_factory: ProviderFactory = provider_factory or default_factory
        self.current: Job | None = None
        self.jobs: dict[str, Job] = {}
        self._task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------ Zustand
    @property
    def daemon(self) -> Any:
        return self.api.daemon

    def config(self) -> AiConfig | None:
        try:
            return load_config(self.daemon.paths)
        except ConfigError:
            return None

    def ledger(self) -> Ledger:
        return Ledger(self.daemon.paths)

    def key(self, cfg: AiConfig | None = None) -> str | None:
        """API-Key des eingestellten Anbieters (``cfg`` fehlt: aus ``ai.toml``)."""
        op = getattr(self.daemon, "operator", None)
        if op is None:
            return None
        cfg = cfg if cfg is not None else self.config()
        return op.get_api_key(key_name(cfg.provider if cfg is not None else None))

    def busy(self) -> bool:
        return self.current is not None and self.current.status in ("queued", "running")

    async def flags(self, p: Any) -> dict[str, bool]:
        profile = p.info.profile
        is_open = scope_open(p.settings)  # E131: offener Scope zählt wie öffentliche Adressen
        await self.api.sync(p)  # Freigabe und Leitplanken aus Entscheiden: alles Gespeicherte auswerten
        return await self.api.query(p, lambda c: project_flags(c, profile, is_open))

    async def status(self, p: Any) -> dict[str, Any]:
        cfg = self.config()
        flags = await self.flags(p)
        op = getattr(self.daemon, "operator", None)
        reason = policy_reason(
            cfg,
            key_present=bool(self.key(cfg)),
            operator_unlocked=op is not None,
            profile=p.info.profile,
            flags=flags,
        )
        if reason is None and self.busy():
            reason = "busy"
        limit = cfg.monthly_limit_usd if cfg is not None else 20.0
        budget = self.ledger().state(limit)
        last = self.current
        return {
            "provider": cfg.provider if cfg is not None else "off",
            "model": (cfg.model or None) if cfg is not None else None,
            "ready": reason is None,
            "reason": reason,
            "reason_text": REASONS.get(reason) if reason else None,
            "budget": budget.json(),
            "job": last.json() if last is not None and last.project_id == p.info.id else None,
        }

    # ------------------------------------------------------------------ Auftrag
    async def start(self, p: Any, *, confirm_budget: bool = False) -> Job:
        """Prüft Policy und Budget und startet den Auftrag im Hintergrund."""
        if self.busy():
            raise GatewayError("busy")
        cfg = self.config()
        flags = await self.flags(p)
        self.api.same(p)
        reason = policy_reason(
            cfg,
            key_present=bool(self.key(cfg)),
            operator_unlocked=getattr(self.daemon, "operator", None) is not None,
            profile=p.info.profile,
            flags=flags,
        )
        if reason is not None or cfg is None:
            raise GatewayError("policy", reason)
        budget = self.ledger().state(cfg.monthly_limit_usd)
        if budget.would_exceed(estimate_microusd(cfg, 2000)) and not confirm_budget:
            raise GatewayError("budget_confirm")
        if self.busy():  # zwischen den awaits gestartet
            raise GatewayError("busy")
        job = Job(
            job_id="ai-" + _secrets.token_hex(6),
            project_id=p.info.id,
            provider=cfg.provider,
            model=cfg.model,
            budget_level=budget.level,
        )
        self.current = job
        self.jobs[job.job_id] = job
        while len(self.jobs) > 20:
            self.jobs.pop(next(iter(self.jobs)))
        self._publish(job)
        self._task = asyncio.ensure_future(self._run(p, cfg, job))
        return job

    def _publish(self, job: Job) -> None:
        bus = getattr(self.api.ctx, "bus", None)
        if bus is None:
            return
        try:
            bus.publish("progress", job.progress())
        except Exception as exc:
            log.error("SSE progress nicht gesendet (%s)", type(exc).__name__)

    def _finish(self, job: Job, status: str, text_key: str, error: str | None = None) -> None:
        job.status = status
        job.step = "fertig"
        job.message = JOB_TEXT[text_key]
        job.error = error
        job.ended_at = _now_iso()
        self._publish(job)

    async def _run(self, p: Any, cfg: AiConfig, job: Job) -> None:
        try:
            await self._run_inner(p, cfg, job)
        except Exception as exc:
            from ariadne.web.api.errors import ApiError

            if isinstance(exc, ApiError) and exc.code == "project_mismatch":
                self._finish(job, "failed", "project_changed", "project_changed")
            else:
                log.error("KI-Auftrag fehlgeschlagen (%s)", type(exc).__name__)
                self._finish(job, "failed", "internal", "internal")

    async def _run_inner(self, p: Any, cfg: AiConfig, job: Job) -> None:
        d = self.daemon
        job.status, job.step, job.message = "running", "lagebild", JOB_TEXT["lagebild"]
        self._publish(job)
        profile = p.info.profile
        redactor = d.redactor

        def build(conn: Any) -> Situation:
            return build_situation(conn, profile=profile, redactor=redactor, ai_done=done_titles(conn))

        sit = await self.api.query(p, build)
        user = ai_schema.user_content(sit)
        # Zweite Sicherung: der fertige Nutzerteil geht noch einmal durch den Redaktor (E72)
        red, labels = redactor.redact_for_exit(user)
        user = str(red)
        job.masked = sit.masked + len(labels)
        job.tokens_estimate = sit.tokens_estimate + _PROMPT_OVERHEAD_TOKENS
        job.step, job.message = "anfrage", JOB_TEXT["anfrage"]
        self._publish(job)
        key = self.key(cfg) if is_remote(cfg.provider) else None
        call_id = _secrets.token_hex(8)
        try:
            result: ProviderResult = await asyncio.to_thread(self._call, cfg, key, user)
        except ProviderError as exc:
            status = "offline" if exc.kind == "unreachable" else "error"
            self._journal_call(p, cfg, job, call_id, None, status)
            text_key: str = exc.kind
            if cfg.provider == "local" and exc.kind in ("unreachable", "model"):
                text_key = f"{exc.kind}_local"
            self._finish(job, "failed", text_key, exc.kind)
            return
        finally:
            key = None
        cost = cost_microusd(result.usage, cfg.prices)
        used = self.ledger().add(cost)
        from ariadne.ai.budget import level_of

        job.tokens_in = (
            result.usage.input_tokens + result.usage.cache_read_tokens + result.usage.cache_write_tokens
        )
        job.tokens_out = result.usage.output_tokens
        job.cost_usd = round(cost / 1_000_000, 6)
        job.budget_level = level_of(used, cfg.monthly_limit_usd)
        status = {"ok": "ok", "refused": "refused", "truncated": "truncated"}.get(result.status, "error")
        self.api.same(p)
        self._journal_call(p, cfg, job, call_id, result, status, cost)
        if result.status == "refused":
            job.refusal = {"category": result.refusal_category, "text": result.refusal_text or ""}
            self._finish(job, "refused", "refused")
            return
        if result.status != "ok":
            self._finish(
                job,
                "failed",
                "truncated" if result.status == "truncated" else "internal",
                "truncated" if result.status == "truncated" else "internal",
            )
            return
        job.step, job.message = "pruefung", JOB_TEXT["pruefung"]
        self._publish(job)
        checked = ai_schema.validate(result.text, sit, profile=profile)
        if checked is None:
            self._finish(job, "failed", "schema", "schema")
            return
        job.dropped, job.injection_suspect = checked.dropped, checked.injection_suspect
        job.created = len(checked.items)
        if checked.items or checked.injection_suspect:
            header = {
                "job_id": job.job_id,
                "call_id": call_id,
                "provider": cfg.provider,
                "model": (result.model or cfg.model)[:100],
                "prompt_version": ai_schema.PROMPT_VERSION,
                "items": [i.header() for i in checked.items],
                "dropped": checked.dropped,
                "injection_suspect": checked.injection_suspect,
            }
            self.api.same(p)
            d.submit(AppendItem("d.ai.denkanstoss", header, origin="gateway"))
            d.flush()
        if checked.items:
            await self._announce(p)
        self._finish(job, "done", "done" if checked.items else "empty")

    def _call(self, cfg: AiConfig, key: str | None, user: str) -> ProviderResult:
        provider = self.provider_factory(cfg, key)
        try:
            return provider.run(
                ai_schema.SYSTEM_PROMPT,
                user,
                ai_schema.response_schema(),
                effort=EFFORT,
                max_tokens=cfg.max_output_tokens,
            )
        finally:
            close = getattr(provider, "close", None)
            if callable(close):
                close()

    def _journal_call(
        self,
        p: Any,
        cfg: AiConfig,
        job: Job,
        call_id: str,
        result: ProviderResult | None,
        status: str,
        cost: int | None = None,
    ) -> None:
        """``ai.call`` ins Journal (nur Metadaten: Anbieter, Modell, Tokens, Kosten, Status)."""
        d = self.daemon
        if d.project is not p:
            return
        u = result.usage if result is not None else None
        header: dict[str, Any] = {
            "call_id": call_id,
            "function": "denkanstoss",
            "provider": {"cloud": "claude", "openrouter": "openrouter"}.get(cfg.provider, "ollama"),
            "model_requested": cfg.model,
            "model_served": (result.model if result is not None else None),
            "prompt_version": ai_schema.PROMPT_VERSION,
            "status": status,
            "refusal_category": result.refusal_category if result is not None else None,
            "input_tokens": u.input_tokens if u is not None else None,
            "output_tokens": u.output_tokens if u is not None else None,
            "cache_read_tokens": u.cache_read_tokens if u is not None else None,
            "cost_microusd": cost,
        }
        try:
            d.submit(
                AppendItem("ai.call", {k: v for k, v in header.items() if v is not None}, origin="gateway")
            )
            d.flush()
        except Exception as exc:
            log.error("ai.call nicht gespeichert (%s)", type(exc).__name__)

    async def _announce(self, p: Any) -> None:
        """Nach neuen Denkanstössen: SSE ``suggestion`` mit der Zahl offener (Regeln und KI)."""
        bus = getattr(self.api.ctx, "bus", None)
        if bus is None:
            return
        from ariadne.ai import store
        from ariadne.rules import api as rules_api

        profile = p.info.profile

        def count(conn: Any) -> int:
            n = rules_api.open_count(conn, profile=profile)
            items, _t = store.suggestions(conn, profile=profile, state="open", limit=1000)
            return n + len(items)

        try:
            await self.api.sync(p)
            n = await self.api.query(p, count)
            bus.publish("suggestion", {"project_id": p.info.id, "open": n})
        except Exception as exc:
            log.error("SSE suggestion nicht gesendet (%s)", type(exc).__name__)
