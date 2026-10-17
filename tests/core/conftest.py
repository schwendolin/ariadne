"""Gemeinsame Fixtures für den Kern: isolierte XDG-Ordner, Operator-Vorlage.

age-scrypt ist absichtlich langsam (etwa 1 s pro Vorgang). Der Operator-Tresor
wird deshalb nur einmal pro Testlauf angelegt und für einzelne Tests kopiert.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from ariadne.crypto.vault import OperatorVault, UnlockedOperator
from ariadne.paths import Paths, default_paths

PASSPHRASE = "Korrekt-Pferd-Batterie-9"
OWN_SECRET = "Sudo-Geheim-4711"


def make_env(base: Path) -> dict[str, str]:
    home = base / "home"
    run = base / "r"
    home.mkdir(parents=True, exist_ok=True)
    run.mkdir(mode=0o700, exist_ok=True)
    return {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_RUNTIME_DIR": str(run),
        "ARIADNE_PROJECTS_ROOT": str(home / "ariadne"),
        "ARIADNE_WEB": "0",  # Daemon-Prozesse der Tests belegen nie Port 7330 (Vertrag v0.1-Server)
    }


@pytest.fixture
def xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    env = make_env(tmp_path)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("ARIADNE_TERMINAL_ID", raising=False)
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    return env


@pytest.fixture
def paths(xdg: dict[str, str]) -> Paths:
    return default_paths(xdg)


@dataclass
class OperatorTemplate:
    directory: Path
    recovery_code: str
    op: UnlockedOperator


@pytest.fixture(scope="session")
def operator_template(tmp_path_factory: pytest.TempPathFactory) -> OperatorTemplate:
    d = tmp_path_factory.mktemp("optpl") / "operator"
    code, op = OperatorVault(d).create_and_unlock(PASSPHRASE, handle="tester")
    op.add_secret("sudo", OWN_SECRET)
    op.save()
    return OperatorTemplate(d, code, op)


def clone_operator(tpl: OperatorTemplate, paths: Paths) -> UnlockedOperator:
    """Kopiert den Tresor nach ``paths`` und liefert einen entsperrten Operator dazu (ohne scrypt)."""
    shutil.copytree(tpl.directory, paths.operator_dir)
    os.chmod(paths.operator_dir.parent, 0o700)
    return dataclasses.replace(
        tpl.op, vault=OperatorVault(paths.operator_dir), _secrets=list(tpl.op.own_secrets),
        _api_keys={},
    )


@pytest.fixture
def operator(paths: Paths, operator_template: OperatorTemplate) -> UnlockedOperator:
    return clone_operator(operator_template, paths)
