"""Option ``--update-golden`` für die Golden-Tests.

Aufruf: ``python -m pytest tests/golden --update-golden``. Die Option ist nur
bekannt, wenn ``tests/golden`` beim Start angegeben wird (pytest liest
``pytest_addoption`` nur aus Start-conftests). Als Ersatz gilt
``ARIADNE_UPDATE_GOLDEN=1``.
"""

from __future__ import annotations

import os

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--update-golden",
        action="store_true",
        default=False,
        help="expected.jsonl der Golden-Fälle neu schreiben (zeigt vorher den Diff)",
    )


@pytest.fixture
def update_golden(request: pytest.FixtureRequest) -> bool:
    try:
        if request.config.getoption("--update-golden"):
            return True
    except ValueError:
        pass
    return os.environ.get("ARIADNE_UPDATE_GOLDEN") == "1"
