"""Monatsbudget des KI-Gateways (E66: Schutz gegen Fehlbedienung, Standard 20 USD).

Der Verbrauch steht in ``~/.local/state/ariadne/ai-budget.json`` (0600, nur Zahlen, keine Inhalte):
``{"month": "2026-10", "used_microusd": 123456}``. Ein neuer Monat beginnt bei 0. Kosten sind
Token-Zahlen mal Preise aus der Konfiguration (:class:`~ariadne.ai.config.Prices`).

* ab 80 % des Limits: ``warn``;
* ab 100 %: ``over``; ein Auftrag braucht dann eine ausdrückliche Bestätigung.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ariadne.ai.config import Prices
from ariadne.paths import Paths, ensure_private_dir

__all__ = ["Usage", "Ledger", "BudgetState", "cost_microusd", "level_of", "month_of", "WARN_PCT"]

WARN_PCT = 80.0
Level = Literal["ok", "warn", "over"]
_LOCK = threading.Lock()


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


@dataclass(frozen=True)
class BudgetState:
    month: str
    used_microusd: int
    limit_usd: float

    @property
    def used_usd(self) -> float:
        return self.used_microusd / 1_000_000

    @property
    def pct(self) -> float:
        if self.limit_usd <= 0:
            return 100.0 if self.used_microusd > 0 else 0.0
        return self.used_usd / self.limit_usd * 100.0

    @property
    def level(self) -> Level:
        return level_of(self.used_microusd, self.limit_usd)

    def would_exceed(self, extra_microusd: int) -> bool:
        return (self.used_microusd + max(0, extra_microusd)) >= int(self.limit_usd * 1_000_000)

    def json(self) -> dict[str, object]:
        return {
            "month": self.month,
            "limit_usd": round(self.limit_usd, 2),
            "used_usd": round(self.used_usd, 4),
            "pct": round(self.pct, 1),
            "level": self.level,
        }


def level_of(used_microusd: int, limit_usd: float) -> Level:
    limit = int(limit_usd * 1_000_000)
    if limit <= 0 or used_microusd >= limit:
        return "over"
    if used_microusd * 100 >= limit * WARN_PCT:
        return "warn"
    return "ok"


def month_of(ts: float | None = None) -> str:
    return time.strftime("%Y-%m", time.gmtime(time.time() if ts is None else ts))


def cost_microusd(usage: Usage, prices: Prices) -> int:
    """Kosten in Mikro-USD (aufgerundet), Preise in USD pro Million Tokens."""
    total = (
        usage.input_tokens * prices.input
        + usage.output_tokens * prices.output
        + usage.cache_read_tokens * prices.cache_read
        + usage.cache_write_tokens * prices.cache_write
    )
    return int(math.ceil(total)) if total > 0 else 0


class Ledger:
    """Verbrauch pro Monat; Lesen und Schreiben unter einer Sperre, atomar."""

    def __init__(self, paths: Paths, clock: object = None) -> None:
        self.paths = paths
        self._clock = clock if callable(clock) else time.time

    @property
    def path(self) -> Path:
        return self.paths.state_dir / "ai-budget.json"

    def _read(self) -> tuple[str, int]:
        month = month_of(self._clock())  # type: ignore[operator]
        try:
            data = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return month, 0
        if not isinstance(data, dict) or data.get("month") != month:
            return month, 0
        used = data.get("used_microusd")
        return month, used if isinstance(used, int) and not isinstance(used, bool) and used >= 0 else 0

    def state(self, limit_usd: float) -> BudgetState:
        with _LOCK:
            month, used = self._read()
        return BudgetState(month, used, limit_usd)

    def add(self, microusd: int) -> int:
        """Bucht Kosten; gibt den neuen Monatsverbrauch zurück."""
        with _LOCK:
            month, used = self._read()
            used += max(0, int(microusd))
            ensure_private_dir(self.paths.state_dir)
            tmp = self.path.with_name(f".ai-budget.{os.getpid()}.tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps({"month": month, "used_microusd": used}).encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp, self.path)
            return used
