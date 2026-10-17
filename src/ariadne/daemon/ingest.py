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
  neue ``derived.db`` und tauschen sie atomar. Ebenso eine ``derived.db`` mit
  älterem Schema (``ingest.db.schema_stale``), bevor die erste Abfrage läuft.
* Profil des Projekts (``project.info.profile``) geht an die Projektion
  (Drei-Spuren-Regel im Profil lab, E42).

* Listener (:meth:`IngestService.add_listener`): Nach jedem erfolgreichen Durchgang
  meldet die Auswertung im Loop-Thread ein :class:`IngestUpdate`, unter anderem die
  automatischen Kontexte aus dem ersten Callback (E23). Der Daemon setzt damit den
  Host der Stufe im Live-Stapel (``ContextStack.set_auto_host``); ins Journal kommt
  davon nichts.

Fehler werden nur mit ihrer Klasse geloggt und stoppen nie den Daemon.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from ariadne.ingest import queries
from ariadne.ingest.db import get_meta, schema_stale, set_meta
from ariadne.ingest.pipeline import REPARSE_PENDING, Interrupted, Pipeline, Stats
from ariadne.ingest.runner import Runner, SubprocessRunner
from ariadne.scope.matcher import ScopeMatcher
from ariadne.store.api import EventRecord
from ariadne.store.journal import JournalReader

if TYPE_CHECKING:
    from ariadne.project.service import OpenProject

__all__ = ["IngestService", "REPARSE_NAME", "AutoContext", "IngestUpdate", "Listener"]

log = logging.getLogger("ariadne.ingest")

REPARSE_NAME = "derived.reparse.db"
OLD_NAME = "derived.old.db"
T = TypeVar("T")


@dataclass(frozen=True)
class AutoContext:
    """Automatischer Kontext einer Stufe (E23): erster Callback auf eine Listener-Stufe,
    IP im Scope, nicht Loopback, kein Entscheid des Nutzers für diese Stufe."""

    terminal_id: str
    opened_at: int  # Offset, an dem die Stufe begann (wie Stage.opened_at)
    host: str  # Kennung "ip:default/<ip>"


@dataclass(frozen=True)
class IngestUpdate:
    """Ergebnis eines Durchgangs für Listener. ``auto_contexts`` ist jeweils die
    vollständige aktuelle Liste (nicht nur neue Einträge)."""

    generation: int | None
    auto_contexts: tuple[AutoContext, ...] = ()


Listener = Callable[[IngestUpdate], None]


@dataclass
class _ThreadState:
    jconn: Any
    journal: JournalReader
    conn: Any
    pipeline: Pipeline
    scope_version: int


def _shred(path: Any) -> None:
    """Datei mit Nullen überschreiben und löschen (nach bestem Bemühen; SSD, COW)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return
    try:
        size = os.fstat(fd).st_size
        zero = b"\0" * (1 << 20)
        done = 0
        while done < size:
            done += os.write(fd, zero[: min(len(zero), size - done)])
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def _shred_db_files(vault: Any, name: str, rename_to: str | None = None) -> None:
    """``rename_to``: Hauptdatei nur umbenennen (atomar), WAL/SHM überschreiben."""
    for suffix in ("-wal", "-shm", "-journal"):
        _shred(vault / f"{name}{suffix}")
    if rename_to is not None:
        with contextlib.suppress(FileNotFoundError):
            os.replace(vault / name, vault / rename_to)
    else:
        _shred(vault / name)


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
        self._stopping = threading.Event()
        self.runs = 0
        self.last_error: str | None = None
        self._listeners: list[Listener] = []

    # ------------------------------------------------------------------ Lebenszyklus (Loop-Thread)
    def attach(self, project: OpenProject) -> None:
        self.detach()
        self.project = project
        self._stopping = threading.Event()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ariadne-ingest")
        self._runner = self._runner_factory()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self.schedule(0.0)
        self._arm_tick()

    def detach(self) -> None:
        """Bricht den laufenden Durchgang vor der nächsten Einheit ab, schliesst die Verbindungen.

        Blockiert höchstens so lange, wie der gerade laufende Worker braucht.
        """
        self._stopping.set()
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

    def add_listener(self, fn: Listener) -> None:
        """``fn(update)`` nach jedem erfolgreichen Durchgang, im Loop-Thread aufgerufen."""
        self._listeners.append(fn)

    def _publish(self, update: IngestUpdate) -> None:
        """Aus dem Thread der Auswertung: Listener im Loop-Thread aufrufen."""
        loop = self._loop
        if loop is None or not self._listeners:
            return

        def call() -> None:
            for fn in list(self._listeners):
                try:
                    fn(update)
                except Exception as exc:  # ein Listener stoppt die Auswertung nie
                    log.error("Listener der Auswertung fehlgeschlagen (%s)", type(exc).__name__)

        try:
            loop.call_soon_threadsafe(call)
        except RuntimeError:
            pass  # Loop beendet

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

    async def query_journal(self, fn: Callable[[Any, Any], T]) -> T:
        """Führt ``fn(conn, journal)`` im Thread der Auswertung aus: ``conn`` ist ``derived.db``,
        ``journal`` der nur lesende :class:`~ariadne.store.journal.JournalReader` (Web-API,
        Eingaben nach E104, Belegzeilen). Die Verbindungen des Writers bleiben im Loop-Thread."""
        return await self._run(self._query_journal, self._snapshot(), fn)

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
                scope = ScopeMatcher.from_settings(settings, version)
                conn = p.connect_derived()
                try:
                    if schema_stale(conn):
                        conn.close()
                        self._rebuild_stale(p, journal, blobs, scope)
                        conn = p.connect_derived()
                    assert self._runner is not None
                    pipe = Pipeline(journal, blobs, conn, project_key=p.project_key, scope=scope,
                                    runner=self._runner, registry=self._registry,
                                    should_stop=self._stopping.is_set, profile=self._profile(p))
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

    @staticmethod
    def _profile(p: OpenProject) -> str:
        profile = getattr(p.info, "profile", "lab")
        return profile if profile in ("lab", "customer") else "lab"

    def _rebuild_stale(self, p: OpenProject, journal: Any, blobs: Any, scope: Any) -> None:
        """``derived.db`` mit älterem Schema: aus dem Journal neu bauen und atomar tauschen."""
        vault = p.info.vault
        _remove_db_files(vault, REPARSE_NAME)
        new_conn = p.connect_derived(name=REPARSE_NAME)
        try:
            assert self._runner is not None
            pipe = Pipeline(journal, blobs, new_conn, project_key=p.project_key, scope=scope,
                            runner=self._runner, registry=self._registry, should_stop=self._stopping.is_set,
                            profile=self._profile(p))
            pipe.process_new()
            set_meta(new_conn, REPARSE_PENDING, "0")
            new_conn.commit()
            new_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        except BaseException:
            with contextlib.suppress(Exception):
                new_conn.close()
            _remove_db_files(vault, REPARSE_NAME)
            raise
        new_conn.close()
        _shred_db_files(vault, "derived.db", OLD_NAME)
        os.replace(vault / REPARSE_NAME, vault / "derived.db")
        _remove_db_files(vault, REPARSE_NAME, main=False)
        _shred_db_files(vault, OLD_NAME)
        log.info("derived.db mit neuem Schema neu aufgebaut")

    def _publish_state(self, st: _ThreadState) -> None:
        """Meldet Generation und Auto-Kontexte an die Listener (aus dem Thread der Auswertung)."""
        if not self._listeners:
            return
        try:
            gen_raw = get_meta(st.conn, "generation")
            rows = queries.auto_contexts(st.conn)
        except Exception as exc:
            log.error("Auto-Kontexte nicht lesbar (%s)", type(exc).__name__)
            return
        gen = int(gen_raw) if gen_raw is not None and gen_raw.isdigit() else None
        self._publish(IngestUpdate(gen, tuple(AutoContext(t, o, h) for t, o, h in rows)))

    def _drop_state(self) -> None:
        st, self._state = self._state, None
        if st is None:
            return
        for c in (st.conn, st.jconn):
            with contextlib.suppress(Exception):
                c.close()

    def _job(self, snap: tuple[int, dict[str, Any]]) -> Stats | None:
        self._queued = False
        if self._stopping.is_set():
            return None
        try:
            st = self._ensure(snap)
            stats = st.pipeline.process_new()
            self.runs += 1
            if st.pipeline.needs_reparse:
                log.info("Redaktion: derived.db wird neu aufgebaut")
                self._reparse_job(snap)
            self.last_error = None
            if self._state is not None:
                self._publish_state(self._state)
            return stats
        except Interrupted:
            log.info("Auswertung abgebrochen (Projekt wird geschlossen)")
            return None
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

    def _query_journal(self, snap: tuple[int, dict[str, Any]], fn: Callable[[Any, Any], T]) -> T:
        st = self._ensure(snap)
        try:
            return fn(st.conn, st.journal)
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
        # Die alte Datei enthält den Klartext geschwärzter Werte (FTS): erst beiseite,
        # dann die neue an ihren Platz, dann die alte überschreiben und löschen. Bricht
        # der Ablauf dazwischen ab, fehlt derived.db höchstens und wird neu berechnet.
        _shred_db_files(vault, "derived.db", OLD_NAME)
        os.replace(vault / REPARSE_NAME, vault / "derived.db")
        _remove_db_files(vault, REPARSE_NAME, main=False)
        _shred_db_files(vault, OLD_NAME)
        st = self._ensure(snap)
        log.info("derived.db neu aufgebaut")
        self._publish_state(st)
        return diff
