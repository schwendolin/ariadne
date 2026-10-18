"""Gemeinsames der KI-Tests: echter Daemon (Routen) wie bei den Regel-Tests, Verbindungen schliessen."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests.core.conftest import operator, operator_template, paths, xdg  # noqa: F401 - echter Daemon (Routen)
from tests.projection import helpers


@pytest.fixture(autouse=True)
def _close_connections() -> Iterator[None]:
    yield
    while helpers.OPEN:
        helpers.OPEN.pop().close()
