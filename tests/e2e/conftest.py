"""Fixture ``lab``: isoliertes Lab unter einem kurzen ``tmp_path`` (AF_UNIX-Grenze)."""

from __future__ import annotations

import pytest

from tests.core.conftest import operator_template  # noqa: F401 - Operator-Tresor für test_dashboard (Weg B)
from tests.e2e.helpers import Lab


@pytest.fixture
def lab(tmp_path_factory: pytest.TempPathFactory):
    lab = Lab(tmp_path_factory.mktemp("e2e"))
    try:
        yield lab
    finally:
        lab.close_terminals()
        lab.stop_daemon()
