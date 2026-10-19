"""``ariadne ai``: setup, status, check, allow-cloud. API-Key nur per Deskriptor (statt getpass) und ctl;
nie in ai.toml, nie als Argument. Der Daemon ist durch eine Liste der ctl-Aufrufe ersetzt."""

from __future__ import annotations

import os
from typing import Any

import pytest

from ariadne.ai.config import load_config
from ariadne.cli import ai as ai_cli
from ariadne.cli.main import main
from ariadne.paths import default_paths

KEY = "sk-test-CLI-KEY-987654321"


@pytest.fixture
def env(tmp_path, monkeypatch):
    for k, v in {
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path / "c"),
        "XDG_STATE_HOME": str(tmp_path / "s"),
        "XDG_DATA_HOME": str(tmp_path / "d"),
        "XDG_RUNTIME_DIR": str(tmp_path / "r"),
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("ARIADNE_TERMINAL_ID", raising=False)
    calls: list[tuple[str, dict[str, Any]]] = []
    state = {"key": False}

    def fake_call(paths: Any, op: str, *, start: bool = True, **args: Any) -> Any:
        calls.append((op, args))
        if op == "ai.key.set":
            state["key"] = True
            return {"key_present": True}
        if op == "ai.status":
            return {
                "key_present": state["key"],
                "operator_unlocked": True,
                "budget": {"month": "2026-10", "used_usd": 0.0, "pct": 0.0, "level": "ok"},
                "project": None,
                "reason": None,
            }
        if op == "ai.allow_cloud":
            return {"already": False, "decision_id": "d1"}
        raise AssertionError(op)

    monkeypatch.setattr(ai_cli, "_call", fake_call)
    monkeypatch.setattr(ai_cli, "_client", lambda paths, **kw: None)
    return calls


def test_setup_cloud_key_via_fd_never_in_file(env, capsys):
    r, w = os.pipe()
    os.write(w, (KEY + "\n").encode())
    os.close(w)
    rc = main(
        ["ai", "setup", "--provider", "cloud", "--model", "test-model", "--limit", "15", "--key-fd", str(r)]
    )
    assert rc == 0
    cfg = load_config(default_paths())
    assert (cfg.provider, cfg.model, cfg.monthly_limit_usd) == ("cloud", "test-model", 15.0)
    text = (default_paths().config_dir / "ai.toml").read_text()
    assert KEY not in text
    assert ("ai.key.set", {"value": KEY, "provider": "cloud"}) in env
    out = capsys.readouterr().out
    assert KEY not in out and "allow-cloud" in out


def test_setup_rejects_bad_input_and_local_needs_no_key(env, capsys):
    assert main(["ai", "setup", "--provider", "local", "--model", "bad model"]) == 1
    assert main(["ai", "setup", "--provider", "cloud", "--model", ""]) == 1
    assert main(["ai", "setup", "--provider", "local", "--model", "test-model", "--limit", "nan"]) == 1
    assert main(["ai", "setup", "--provider", "local", "--model", "test-model"]) == 0
    assert not any(op == "ai.key.set" for op, _a in env)
    assert load_config(default_paths()).provider == "local"


def test_status_check_and_allow_cloud(env, capsys, monkeypatch):
    assert main(["ai", "setup", "--provider", "local", "--model", "test-model"]) == 0
    assert main(["ai", "status"]) == 0
    out = capsys.readouterr().out
    assert "Anbieter: local" in out and "Modell: test-model" in out
    monkeypatch.setattr("ariadne.ai.providers.LocalProvider.ping", lambda self: False)
    assert main(["ai", "check"]) == 1
    assert "Ollama" in capsys.readouterr().out
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["ai", "allow-cloud"]) == 1  # ohne --yes und ohne Terminal: keine stille Freigabe
    assert main(["ai", "allow-cloud", "--yes"]) == 0
    assert ("ai.allow_cloud", {}) in env
