"""Die CLI meldet ihr Terminal vor jeder Secret-Abfrage an (Vertrag 4.7, E26).

Sonst landet Ariadnes eigene Passphrase als ``term.input`` im Vorlauf oder im Journal.
Die interaktive Abfrage endet ausserdem, bevor die Anmeldung im Daemon abläuft.
"""

from __future__ import annotations

import signal
import time
from typing import Any

import pytest

from ariadne.cli import common
from ariadne.cli import main as cli
from ariadne.cli.common import SECRET_PROMPT_S, CliError


class _Vault:
    def __init__(self, path: Any) -> None:
        pass

    exists = True


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any]]:
    log: list[tuple[str, Any]] = []
    answers: dict[str, Any] = {
        "status": {"operator": {"unlocked": False}, "project": None, "active": {"slug": "lame",
                                                                              "stopped": False}},
        "preroll.info": {"terminals": 0, "seconds": 0},
        "start": {"slug": "lame", "profile": "lab", "workspace": "/x", "created": False, "preroll": {},
                  "recording": 1},
        "init": {"recovery_code": "CODE"},
        "unlock": {"already": False, "handle": "op"},
        "secrets.add": {"labels": ["db"]},
    }

    def fake_call(paths: Any, op: str, **args: Any) -> Any:
        log.append(("call", op, args))
        return answers.get(op, {})

    def fake_secret(prompt: str, fd: Any, **kw: Any) -> str:
        log.append(("secret", prompt, kw))
        return "lange-genug-passphrase"

    monkeypatch.setattr(cli, "_call", fake_call)
    monkeypatch.setattr(cli, "_client", lambda paths, **kw: None)
    monkeypatch.setattr(cli, "read_secret", fake_secret)
    monkeypatch.setattr(cli, "OperatorVault", _Vault)
    monkeypatch.setenv("ARIADNE_TERMINAL_ID", "term-0001")
    return log


@pytest.mark.parametrize("argv,vault", [
    (["init"], False), (["unlock"], True), (["start", "lame"], True), (["secrets", "add", "db"], True),
])
def test_pause_terminal_before_every_secret_prompt(calls, monkeypatch, argv, vault):
    _Vault.exists = vault
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    try:
        assert cli.main(argv) == 0
    finally:
        _Vault.exists = True
    kinds = [c[1] if c[0] == "call" else "SECRET" for c in calls]
    assert "SECRET" in kinds and "pause_terminal" in kinds, kinds
    assert kinds.index("pause_terminal") < kinds.index("SECRET"), kinds
    pause = next(c for c in calls if c[0] == "call" and c[1] == "pause_terminal")
    assert pause[2] == {"terminal_id": "term-0001", "seconds": SECRET_PROMPT_S + 60}


def test_secret_prompt_times_out_before_the_terminal_pause_ends():
    old = signal.getsignal(signal.SIGALRM)
    t0 = time.monotonic()
    with pytest.raises(CliError, match="abgelaufen"), common._deadline(1):
        time.sleep(5)
    assert time.monotonic() - t0 < 4
    assert signal.getsignal(signal.SIGALRM) is old and signal.alarm(0) == 0
    with common._deadline(None):
        pass
