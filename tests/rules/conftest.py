"""Gemeinsame Einstellungen der Regel-Tests: feste Zeitzone für Beleg-Labels, Verbindungen schliessen."""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest

from tests.core.conftest import operator, operator_template, paths, xdg  # noqa: F401 - echter Daemon (Routen)
from tests.projection import helpers


@pytest.fixture(autouse=True)
def _fixed_tz(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Die Tests rechnen in Mitteleuropa (wie das Design, «nmap -sV · 14:02»): Beleg-Labels sind ohne
    Uhrzeit (sie steht in ``ts``), die Zeitzone darf das Ergebnis also nicht ändern. POSIX-Schreibweise,
    damit keine Zeitzonen-Datenbank nötig ist."""
    monkeypatch.setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.fixture(autouse=True)
def _close_connections() -> Iterator[None]:
    yield
    while helpers.OPEN:
        helpers.OPEN.pop().close()
