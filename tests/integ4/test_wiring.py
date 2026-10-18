"""Verdrahtung der Etappe 4 (Integration): SSE-Ereignis ``screenshot`` nur mit Kennungen, Fehlercodes
``shot_*`` im gemeinsamen Format, ``Status.llm`` aus ``ai.toml`` und dem Monatsbuch."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from ariadne.ai.budget import Ledger
from ariadne.ai.config import AiConfig, save_config
from ariadne.sources.screenshot import SHOT_ERRORS
from ariadne.web.api import errors
from ariadne.web.api.events import _Sources
from ariadne.web.api.status import _llm_view


class _Bus:
    def __init__(self) -> None:
        self.out: list[tuple[str, dict[str, Any]]] = []

    def publish(self, event: str, data: dict[str, Any]) -> None:
        self.out.append((event, data))


def test_screenshot_event_only_ids_and_fixed_words() -> None:
    bus = _Bus()
    src = _Sources(SimpleNamespace(daemon=SimpleNamespace(project=None), bus=bus))  # type: ignore[arg-type]
    src.on_daemon("screenshot", {"project_id": "p1", "id": "e1", "trigger": "hotkey", "title": "geheim"})
    src.on_daemon("screenshot", {"project_id": "p1", "id": "e2", "trigger": "\x1b[31mboese"})
    src.on_daemon("screenshot", {"project_id": "p1", "id": None, "trigger": "cli"})
    assert bus.out == [("screenshot", {"project_id": "p1", "id": "e1", "trigger": "hotkey"})]


def test_shot_codes_in_error_tables() -> None:
    for code, text in SHOT_ERRORS.items():
        assert errors.MESSAGES[code] == text and errors.STATUS[code] == 503
        assert errors.from_ctl({"code": code, "message": "x"}).code == code


def test_status_llm_from_ai_config(paths) -> None:
    d = SimpleNamespace(paths=paths)
    off = _llm_view(d, True)
    assert off["mode"] == "off" and off["model"] is None and off["available"] is False
    assert off["budget"] == {"month_limit_usd": 20.0, "month_used_usd": 0.0}
    assert _llm_view(d, False)["budget"] is None
    save_config(paths, AiConfig(provider="local", model="test-model", monthly_limit_usd=7.5))
    Ledger(paths).add(1_250_000)
    on = _llm_view(d, True)
    assert on == {
        "mode": "local",
        "model": "test-model",
        "available": True,
        "budget": {"month_limit_usd": 7.5, "month_used_usd": 1.25},
    }
