"""Auswertung im Daemon: Pipeline in einem eigenen Thread (Architektur 5.4, 5.10).

* Pro offenem Projekt ein Thread (``ThreadPoolExecutor`` mit einem Arbeiter).
  Er besitzt alle Verbindungen der Auswertung: ``journal.db`` nur lesend
  (:class:`~ariadne.store.journal.JournalReader`), ``derived.db`` lesend und
  schreibend. Der Event-Loop blockiert nie; die Verbindungen des Writers
  bleiben im Loop-Thread.
* Nach Commits entprellt (Standard 500 ms) ``Pipeline.process_new``, dazu
  periodisch (Stille: offene Einheiten nach 10 Minuten vorläufig parsen).
* Parser laufen über :class:`~ariadne.ingest.runner.SubprocessRunner` in
  Worker-Prozessen ohne Schlüssel.
* Scope aus dem jüngsten ``d.scope.update`` (``OpenProject.settings``); nach
  einer Änderung neuer ``ScopeMatcher`` und vollständige Neuberechnung.
* ``system.redaction`` (FTS enthält Klartext) und ``ariadne reparse`` bauen eine
  neue ``derived.db`` und tauschen sie atomar.

Fehler werden nur mit ihrer Klasse geloggt und stoppen nie den Daemon.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from ariadne.ingest import queries
from ariadne.ingest.db import set_meta
from ariadne.ingest.pipeline import Pipeline, Stats
from ariadne.ingest.runner import Runner, SubprocessRunner
from ariadne.scope.matcher import ScopeMatcher
from ariadne.store.api import EventRecord
from ariadne.store.journal import JournalReader

if TYPE_CHECKING:
    from ariadne.project.service import OpenProject

__all__ = ["IngestService", "REPARSE_NAME"]

log = logging.getLogger("ariadne.ingest")

REPARSE_NAME = "derived.reparse.db"
T = TypeVar("T")


@dataclass
class _ThreadState:
    jconn: Any
    journal: JournalReader
    conn: Any
    pipeline: Pipeline
    scope_version: int


def _remove_db_files(vault: Any, name: str, *, main: bool = True) -> None:
    suffixes = ("", "-wal", "-shm", "-journal") if main else ("-wal", "-shm", "-journal")
    for suffix in suffixes:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(vault / f"{name}{suffix}")


class IngestService:
    """Hält die Auswertung eines offenen Projekts am Laufen."""

    def __init__(self, *, debounce: float = 0.5, periodic: float = 60.0,
                 runner_factory: Callable[[], Runner] = SubprocessRunner,
                 registry: Sequence[Any] | None = None) -> None:
        self.debounce = debounce
        self.periodic = periodic
        self._runner_factory = runner_factory
        self._registry = registry
        self.project: OpenProject | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._timer: asyncio.TimerHandle | None = None
        self._tick: asyncio.TimerHandle | None = None
        self._queued = False
        self._state: _ThreadState | None = None
        self._runner: Runner | None = None
        self.runs = 0
        self.last_error: str | None = None

    # ------------------------------------------------------------------ Lebenszyklus (Loop-Thread)
    def attach(self, project: OpenProject) -> None:
        self.detach()
        self.project = project
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ariadne-ingest")
        self._runner = self._runner_factory()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self.schedule(0.0)
        self._arm_tick()

    def detach(self) -> None:
        """Wartet auf den laufenden Durchgang, schliesst die Verbindungen im Thread."""
        for h in (self._timer, self._tick):
            if h is not None:
                h.cancel()
        self._timer = self._tick = None
        ex = self._executor
        self._executor = None
        if ex is not None:
            with contextlib.suppress(RuntimeError):
                ex.submit(self._drop_state)
            ex.shutdown(wait=True, cancel_futures=False)
        self.project = None
        self._queued = False

    @property
    def active(self) -> bool:
        return self._executor is not None and self.project is not None

    def _arm_tick(self) -> None:
        if self._loop is None or self.periodic <= 0:
            return

        def tick() -> None:
            self._tick = None
            if self.active:
                self.schedule(0.0)
                self._arm_tick()

        self._tick = self._loop.call_later(self.periodic, tick)

    def on_commit(self, records: list[EventRecord]) -> None:
        """Commit-Hook des Daemons: Einstellungen nachladen, Durchgang einplanen."""
        p = self.project
        if p is None:
            return
        if any(r.kind == "d.scope.update" for r in records):
            try:
                p.reload_settings()
            except Exception as exc:
                log.error("Einstellungen nicht neu ladbar (%s)", type(exc).__name__)
        self.schedule()

    def _snapshot(self) -> tuple[int, dict[str, Any]]:
        p = self.project
        assert p is not None
        return p.settings_version, p.settings

    def schedule(self, delay: float | None = None) -> None:
        """Entprellt: höchstens ein Durchgang wartet; weitere Aufrufe gehen darin auf."""
        if not self.active or self._timer is not None:
            return
        if self._loop is None:
            return
        self._timer = self._loop.call_later(self.debounce if delay is None else delay, self._fire)

    def _fire(self) -> None:
        self._timer = None
        if not self.active or self._queued:
            return
        self._queued = True
        assert self._executor is not None
        fut = self._executor.submit(self._job, self._snapshot())
        fut.add_done_callback(lambda f: f.exception())  # Fehler werden im Job geloggt

    async def _run(self, fn: Callable[..., T], *args: Any) -> T:
        if not self.active:
            raise RuntimeError("Auswertung nicht aktiv")
        loop = asyncio.get_running_loop()
        assert self._executor is not None
        return await loop.run_in_executor(self._executor, fn, *args)

    async def sync(self) -> Stats | None:
        """Verarbeitet alles bis jetzt Gespeicherte und wartet darauf."""
        return await self._run(self._job, self._snapshot())

    async def query(self, fn: Callable[[Any], T]) -> T:
        """Führt ``fn(conn)`` mit der ``derived.db``-Verbindung im Thread der Auswertung aus."""
        return await self._run(self._query, self._snapshot(), fn)

    async def reparse(self) -> dict[str, Any]:
        return await self._run(self._reparse_job, self._snapshot())

    # ------------------------------------------------------------------ im Thread
    def _ensure(self, snap: tuple[int, dict[str, Any]]) -> _ThreadState:
        version, settings = snap
        st = self._state
        if st is None:
            p = self.project
            if p is None:
                raise RuntimeError("kein Projekt")
            jconn = p.connect_journal()
            try:
                journal = JournalReader(jconn)
                blobs = p.blobs.with_connection(jconn)
                conn = p.connect_derived()
                try:
                    scope = ScopeMatcher.from_settings(settings, version)
                    assert self._runner is not None
                    pipe = Pipeline(journal, blobs, conn, project_key=p.project_key, scope=scope,
                                    runner=self._runner, registry=self._registry)
                except BaseException:
                    conn.close()
                    raise
            except BaseException:
                jconn.close()
                raise
            st = self._state = _ThreadState(jconn, journal, conn, pipe, version)
        elif st.scope_version != version:
            scope = ScopeMatcher.from_settings(settings, version)
            st.pipeline.scope = scope
            if st.pipeline.projector is not None:
                st.pipeline.projector.set_scope(scope)
            set_meta(st.conn, "rebuild_pending", "1")
            st.conn.commit()
            st.scope_version = version
        return st

    def _drop_state(self) -> None:
        st, self._state = self._state, None
        if st is None:
            return
        for c in (st.conn, st.jconn):
            with contextlib.suppress(Exception):
                c.close()

    def _job(self, snap: tuple[int, dict[str, Any]]) -> Stats | None:
        self._queued = False
        try:
            st = self._ensure(snap)
            stats = st.pipeline.process_new()
            self.runs += 1
            if st.pipeline.needs_reparse:
                log.info("Redaktion: derived.db wird neu aufgebaut")
                self._reparse_job(snap)
            self.last_error = None
            return stats
        except Exception as exc:
            self.last_error = type(exc).__name__
            log.error("Auswertung fehlgeschlagen (%s)", type(exc).__name__)
            self._drop_state()
            return None

    def _query(self, snap: tuple[int, dict[str, Any]], fn: Callable[[Any], T]) -> T:
        st = self._ensure(snap)
        try:
            return fn(st.conn)
        finally:
            if st.conn.in_transaction:
                st.conn.rollback()

    def _reparse_job(self, snap: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        """Neue ``derived.db`` aus dem Journal, Diff berechnen, Datei atomar tauschen."""
        st = self._ensure(snap)
        p = self.project
        assert p is not None
        vault = p.info.vault
        _remove_db_files(vault, REPARSE_NAME)
        new_conn = p.connect_derived(name=REPARSE_NAME)
        try:
            st.pipeline.reparse(new_conn)
            diff = queries.reparse_diff(st.conn, new_conn)
            new_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        except BaseException:
            with contextlib.suppress(Exception):
                new_conn.close()
            _remove_db_files(vault, REPARSE_NAME)
            raise
        new_conn.close()
        self._drop_state()
        # Reste der alten Datei dürfen nie auf die neue angewendet werden.
        _remove_db_files(vault, "derived.db", main=False)
        os.replace(vault / REPARSE_NAME, vault / "derived.db")
        _remove_db_files(vault, REPARSE_NAME, main=False)
        self._ensure(snap)
        log.info("derived.db neu aufgebaut")
        return diff
