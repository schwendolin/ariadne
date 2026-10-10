from __future__ import annotations

import sqlite3

import pytest

from ariadne.scope.matcher import ScopeMatcher
from ariadne.store.memory import MemoryBlobStore, MemoryJournal
from tests.ingest.helpers import BASE_TS, StubHighParser, StubParser, StubProjector, TermSim


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    for var, sub in (("HOME", "home"), ("XDG_CONFIG_HOME", "cfg"), ("XDG_DATA_HOME", "data"),
                     ("XDG_STATE_HOME", "state"), ("XDG_RUNTIME_DIR", "run"), ("XDG_CACHE_HOME", "cache")):
        d = tmp_path / sub
        d.mkdir(exist_ok=True)
        monkeypatch.setenv(var, str(d))


class Env:
    def __init__(self, tmp_path):
        self.journal = MemoryJournal()
        self.blobs = MemoryBlobStore()
        self.db_path = tmp_path / "derived.db"
        self.conn = sqlite3.connect(self.db_path)
        self.projector = StubProjector(self.conn)
        self.scope = ScopeMatcher.from_settings({"scope": {"include": ["10.10.10.0/24", "lame.htb"]}}, 1)
        self.now = BASE_TS
        self.term = TermSim(self.journal)

    def clock(self) -> int:
        return self.now

    def pipeline(self, conn=None, **kw):
        from ariadne.ingest.pipeline import Pipeline
        from ariadne.ingest.runner import InProcessRunner

        kw.setdefault("runner", InProcessRunner())
        kw.setdefault("projector", self.projector)
        kw.setdefault("registry", [StubHighParser(), StubParser()])
        return Pipeline(self.journal, self.blobs, conn or self.conn, project_key=b"k" * 32, scope=self.scope,
                        clock=self.clock, **kw)

    def rows(self, sql, *args, conn=None):
        return (conn or self.conn).execute(sql, args).fetchall()


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.conn.close()
