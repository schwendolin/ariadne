"""Einstellungen des KI-Gateways (``~/.config/ariadne/ai.toml``, 0600, ohne Secrets).

Der API-Key steht nie hier, sondern verschlüsselt im Operator-Tresor (``api_keys["anthropic"]``).
Die Modell-ID setzt der Nutzer mit ``ariadne ai setup``; Ariadne kennt keinen Standard. Preise sind
Konfiguration, nicht Code (Architektur 6.2): USD pro Million Tokens.

Beispiel::

    provider = "cloud"           # off | cloud | local
    model = "<Modell-ID>"
    monthly_limit_usd = 20.0

    [prices]                     # USD pro Million Tokens
    input = 5.0
    output = 25.0
    cache_read = 0.5
    cache_write = 6.25

    [local]
    port = 11434                 # Ollama, nur 127.0.0.1
"""

from __future__ import annotations

import math
import os
import re
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal

from ariadne.paths import Paths, ensure_private_dir

__all__ = [
    "AiConfig",
    "Prices",
    "Provider",
    "PROVIDERS",
    "config_file",
    "load_config",
    "save_config",
    "valid_model",
    "ConfigError",
]

Provider = Literal["off", "cloud", "local"]
PROVIDERS: tuple[str, ...] = ("off", "cloud", "local")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}")
DEFAULT_LIMIT_USD = 20.0


class ConfigError(ValueError):
    """``ai.toml`` ist ungültig (die Meldung ist fester Text ohne Inhalte der Datei)."""


@dataclass(frozen=True)
class Prices:
    """USD pro Million Tokens. Vorsichtige Standardwerte; bitte an die Preisliste des Anbieters anpassen."""

    input: float = 5.0
    output: float = 25.0
    cache_read: float = 0.5
    cache_write: float = 6.25


@dataclass(frozen=True)
class AiConfig:
    provider: Provider = "off"
    model: str = ""
    monthly_limit_usd: float = DEFAULT_LIMIT_USD
    prices: Prices = field(default_factory=Prices)
    local_port: int = 11434
    max_output_tokens: int = 8000

    def with_(self, **kw: Any) -> AiConfig:
        return replace(self, **kw)


def config_file(paths: Paths) -> Path:
    return paths.config_dir / "ai.toml"


def valid_model(model: str) -> bool:
    """Modell-IDs nur aus harmlosen Zeichen (sie stehen in Anfragen und Anzeigen)."""
    return bool(_MODEL_RE.fullmatch(model))


def _num(v: Any, default: float, *, lo: float, hi: float) -> float:
    if isinstance(v, bool) or not isinstance(v, int | float):
        return default
    f = float(v)
    if not math.isfinite(f) or f < lo or f > hi:
        raise ConfigError("Zahl ausserhalb des erlaubten Bereichs in ai.toml")
    return f


def load_config(paths: Paths) -> AiConfig:
    """Liest ``ai.toml``; fehlt die Datei, gilt der Standard (Anbieter aus)."""
    path = config_file(paths)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return AiConfig()
    except OSError as exc:
        raise ConfigError("ai.toml nicht lesbar") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError("ai.toml ist kein gültiges TOML") from exc
    provider = data.get("provider", "off")
    if provider not in PROVIDERS:
        raise ConfigError("provider in ai.toml muss off, cloud oder local sein")
    model = data.get("model", "")
    if not isinstance(model, str) or (model and not valid_model(model)):
        raise ConfigError("model in ai.toml enthält unzulässige Zeichen")
    p = data.get("prices") or {}
    if not isinstance(p, dict):
        raise ConfigError("[prices] in ai.toml ungültig")
    d = Prices()
    prices = Prices(
        input=_num(p.get("input"), d.input, lo=0, hi=1000),
        output=_num(p.get("output"), d.output, lo=0, hi=1000),
        cache_read=_num(p.get("cache_read"), d.cache_read, lo=0, hi=1000),
        cache_write=_num(p.get("cache_write"), d.cache_write, lo=0, hi=1000),
    )
    local = data.get("local") or {}
    port = local.get("port", 11434) if isinstance(local, dict) else 11434
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ConfigError("[local] port in ai.toml ungültig")
    max_out = data.get("max_output_tokens", 8000)
    if not isinstance(max_out, int) or isinstance(max_out, bool) or not 1000 <= max_out <= 64000:
        raise ConfigError("max_output_tokens in ai.toml muss zwischen 1000 und 64000 liegen")
    return AiConfig(
        provider=provider,
        model=model,
        monthly_limit_usd=_num(data.get("monthly_limit_usd"), DEFAULT_LIMIT_USD, lo=0, hi=100000),
        prices=prices,
        local_port=port,
        max_output_tokens=max_out,
    )


def _fmt(v: float) -> str:
    return repr(float(v))


def save_config(paths: Paths, cfg: AiConfig) -> Path:
    """Schreibt ``ai.toml`` atomar mit 0600. Nur Zahlen und geprüfte Kennungen, nie Secrets."""
    if cfg.provider not in PROVIDERS:
        raise ConfigError("provider ungültig")
    if cfg.model and not valid_model(cfg.model):
        raise ConfigError("Modell-ID enthält unzulässige Zeichen")
    ensure_private_dir(paths.config_dir)
    text = (
        "# Ariadne: KI-Gateway (ariadne ai setup). Keine Secrets in dieser Datei;\n"
        "# der API-Key liegt verschlüsselt im Operator-Tresor.\n"
        f'provider = "{cfg.provider}"\n'
        f'model = "{cfg.model}"\n'
        f"monthly_limit_usd = {_fmt(cfg.monthly_limit_usd)}\n"
        f"max_output_tokens = {int(cfg.max_output_tokens)}\n"
        "\n[prices]  # USD pro Million Tokens\n"
        f"input = {_fmt(cfg.prices.input)}\n"
        f"output = {_fmt(cfg.prices.output)}\n"
        f"cache_read = {_fmt(cfg.prices.cache_read)}\n"
        f"cache_write = {_fmt(cfg.prices.cache_write)}\n"
        "\n[local]  # Ollama, nur 127.0.0.1\n"
        f"port = {int(cfg.local_port)}\n"
    )
    path = config_file(paths)
    tmp = path.with_name(f".ai.toml.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return path
