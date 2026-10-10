from __future__ import annotations

import pytest

from tests.projection import helpers


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    while helpers.OPEN:
        helpers.OPEN.pop().close()
