"""Hermetische Tests (Befund F8): Die E2E-Tests überspringen, wenn der Testrechner selbst eine
Ziel-Adresse des Fixture-Netzes hat; sonst wäre das Ziel «eigene Adresse» (A5)."""

from __future__ import annotations

import pytest
from tests.e2e import helpers


def test_e2e_skips_when_test_machine_owns_fixture_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "read_local_addrs", lambda: ("127.0.0.1", "192.168.56.101"))
    with pytest.raises(pytest.skip.Exception, match="192.168.56.101"):
        helpers.skip_if_own_address("192.168.56.101")
    monkeypatch.setattr(helpers, "read_local_addrs", lambda: ("192.0.2.2",))
    helpers.skip_if_own_address("192.168.56.101")  # keine Überschneidung: läuft
    monkeypatch.setattr(helpers, "read_local_addrs", lambda: None)
    helpers.skip_if_own_address("192.168.56.101")
