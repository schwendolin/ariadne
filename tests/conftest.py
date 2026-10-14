"""Gemeinsame pytest-Einstellungen für alle Tests.

``--update-golden`` schreibt die erwarteten Ergebnisse der Golden-Tests neu
(Parser unter ``tests/golden``, Normalizer unter ``tests/ingest``) und zeigt
vorher den Diff. Gleichwertig: ``ARIADNE_UPDATE_GOLDEN=1``.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--update-golden",
        action="store_true",
        default=False,
        help="erwartete Ergebnisse der Golden-Fälle neu schreiben (zeigt vorher den Diff)",
    )


def pytest_configure(config: pytest.Config) -> None:
    # Der Normalizer-Test liest die Umgebungsvariable beim Import.
    if config.getoption("--update-golden"):
        os.environ["ARIADNE_UPDATE_GOLDEN"] = "1"


@pytest.fixture
def update_golden(request: pytest.FixtureRequest) -> bool:
    if request.config.getoption("--update-golden"):
        return True
    return os.environ.get("ARIADNE_UPDATE_GOLDEN") == "1"


@pytest.fixture(autouse=True)
def _close_sqlite_connections(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Schliesst alle im Test geöffneten ``sqlite3``-Verbindungen (auch die aus
    ``sqlite3.connect(...).execute(...)``). Sonst meldet der GC sie als
    ``ResourceWarning`` in einem fremden Test und verdeckt echte Lecks."""
    opened: list[sqlite3.Connection] = []
    real = sqlite3.connect

    def connect(*args, **kwargs):  # type: ignore[no-untyped-def]
        conn = real(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", connect)
    yield
    for conn in opened:
        conn.close()
