"""Gemeinsame pytest-Einstellungen für alle Tests.

``--update-golden`` schreibt die erwarteten Ergebnisse der Golden-Tests neu
(Parser unter ``tests/golden``, Normalizer unter ``tests/ingest``) und zeigt
vorher den Diff. Gleichwertig: ``ARIADNE_UPDATE_GOLDEN=1``.
"""

from __future__ import annotations

import os

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
