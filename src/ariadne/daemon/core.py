"""Kern des Daemons ``ariadned`` (Architektur 3.6, 3.7, 8.6; Vertrag v0.1-Bedienung 3 bis 5).

Ein asyncio-Prozess mit zwei Unix-Sockets im Runtime-Ordner (0700):

``term.sock``
    Rahmenprotokoll der Shims (:mod:`ariadne._shim.protocol`, Version 1 und 2).
    Angenommen werden nur Verbindungen derselben UID (``SO_PEERCRED``), deren
    Prozess ``ariadne-shim`` heisst (abschaltbar für Tests).
``ctl.sock``
    Zeilenweises JSON ``{"op", "args"}`` -> ``{"ok", "result"|"error"}`` für die CLI.

**Daueraufnahme (E22).** Es gibt keinen REC-Schalter mehr. Solange ein Projekt
offen ist, nehmen alle Terminals auf. Zustand pro Terminal (Reihenfolge verbindlich,
:meth:`Daemon.state_of`):

1. ``paused``  Pause des Nutzers bis ``pause_until_ns`` (``F12 r``, ``ariadne pause``)
2. ``held``    an ein Projekt gebunden, das nicht das aktive ist (Remote-Sitzung beim
               alten Projekt, E28): nichts wird gespeichert, bis der Shim mit
               ``req.rebind`` an der lokalen Kali-Shell die Bindung löst
3. ``on``      Projekt offen: Aufnahme ins Journal
4. ``locked``  aktives Projekt laut ``active.json``, aber nicht offen (Tresor gesperrt)
5. ``preroll`` kein Projekt; der Vorlauf liegt nur im RAM (E95, :mod:`ariadne.daemon.preroll`)
6. ``off``     Vorlauf abgeschaltet

In ``locked`` und ``preroll`` hält der Daemon Rahmen und Events im Vorlauf und
bestätigt sie sofort. ``ariadne start`` übernimmt ihn auf Wunsch mit den
Original-Zeiten (``origin="preroll"``). In ``paused``, ``held`` und ``off`` werden
Rahmen bestätigt und verworfen.

**Ende eines Projekts:** ``stop``, Leerlauf (``idle_end_hours`` ohne Aktivität in
irgendeinem Terminal), Wechsel durch ``start <anderes>``, ``lock`` und Daemon-Ende.
Davor steht ``system.project_end``, danach der Checkpoint ``close``.

**Zeit (E96).** Rahmen tragen die Shim-Zeit (``t_shim_ns``, ``mono_ns``, Zeitindex
``tix``). Der Daemon setzt ``time_suspect``, wenn sie mehr als 5 s von der
Empfangszeit abweicht oder die monotone Uhr rückwärts läuft. Eigene ``term.*``-Events
tragen die Shim-Zeit, wenn der Daemon sie am Offset kennt.

**Eingaben (E26).** INPUT-Rahmen werden zu ``term.input`` (Body = Bytes). Nie in Logs.

**Schwärzen (E72).** Der Daemon schwärzt nichts mehr vor dem Speichern. Eigene
Secrets ersetzt :attr:`Daemon.redactor` an den Ausgängen
(``redact_for_exit``/``redact_json``).

Hotkey-Anfragen (EVENT ``req.*``): ``req.pause``, ``req.rebind``, ``req.status``,
``req.rec`` (v1, wie ``req.pause`` ohne Minuten), ``req.ctx.set``/``push``/``pop``,
``req.ctx.sync``, ``req.keystep``, ``req.shot`` (Protokoll-Docstring).

Kontext-Stapel: Der Shim sieht alle Marker; der Daemon übernimmt seinen Stapel
(HELLO bei einem neuen Terminal, ``req.ctx.sync``, ``term.ctx_snapshot``). Der
Shim übernimmt ``STATE.stack`` nur nach einem Kontext-Entscheid oder einem
automatischen Host aus der Auswertung (``ctx_version``). Automatische Hosts
(``host_source="auto"``, E23) kommen nie ins Journal.

Erweiterungen für die Auswertung:

* :meth:`Daemon.add_commit_hook` ``fn(records)`` nach jedem Commit.
* :meth:`Daemon.add_mark_hook` ``fn(record, ctx)`` für jedes gespeicherte ``term.mark``.
* Die ctl-Operationen der Auswertung liegen in :mod:`ariadne.daemon.ops_eval` und
  nutzen ``_require_project``, ``_sync_ingest``, ``_ingest_info``, ``submit``,
  ``writer.flush_now``, ``redactor``, ``project`` und ``ingest`` (stabile Schnittstelle).

Fehler in Hooks werden nur mit ihrer Klasse geloggt. Logs enthalten nie Inhalte.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import math
import os
import time
from collections.abc import Awaitable, Callable
from typing import Any

from ariadne import __version__, events
from ariadne._shim import protocol as P
from ariadne.crypto.db import WrongKeyError
from ariadne.crypto.vault import (
    InvalidRecoveryCode,
    OperatorVault,
    UnlockedOperator,
    VaultError,
    VaultExists,
    VaultMissing,
    WrongPassphrase,
    valid_label,
)
from ariadne.ctxrules import ContextStack
from ariadne.daemon import hardening, ops_eval
from ariadne.daemon.active import read_active, write_active
from ariadne.daemon.config import RecordingConfig, load_recording
from ariadne.daemon.ingest import IngestService, IngestUpdate
from ariadne.daemon.ops_util import OpError
from ariadne.daemon.ops_util import arg_int as _arg_int
from ariadne.daemon.ops_util import arg_str as _arg_str
from ariadne.daemon.preroll import Held, PrerollStore
from ariadne.daemon.sources import LocalSources
from ariadne.daemon.terminal import (
    STAGE_KINDS,
    AckEntry,
    MarkContext,
    Pause,
    Terminal,
    apply_stack_event,
    merge_auto_hosts,
    normalize_host,
    normalize_user,
    parse_hello,
    parse_stack,
)
from ariadne.daemon.writer import OutChunk, Writer
from ariadne.paths import Paths, ensure_private_dir
from ariadne.project.service import (
    GuardrailError,
    OpenProject,
    ProjectError,
    ProjectLocked,
    ProjectNotFound,
    ProjectService,
)
from ariadne.secrets.redactor import Redactor
from ariadne.sources.localaddr import read_local_addrs
from ariadne.sources.safeopen import UnsafeFile
from ariadne.store.api import AppendItem, EventRecord, JournalError

__all__ = ["Daemon", "OpError", "CommitHook", "MarkHook", "STATES"]

log = logging.getLogger("ariadne.daemon")

CommitHook = Callable[[list[EventRecord]], Any]
MarkHook = Callable[[EventRecord, MarkContext | None], Any]

STATES = ("paused", "held", "on", "locked", "preroll", "off")
TERM_EVENTS = frozenset({
    "term.mark", "term.resize", "term.ctx_snapshot", "term.gap", "term.close",
    "term.osc52_blocked", "term.marker_forged",
})
REQUESTS = frozenset({"req.rec", "req.pause", "req.rebind", "req.status", "req.ctx.set", "req.ctx.push",
                      "req.ctx.pop", "req.ctx.sync", "req.keystep", "req.shot"})
KEYSTEPS = frozenset({"foothold", "privesc", "pivot", "loot"})
DATA_FRAMES = (P.OUT, P.OUTX, P.INPUT)
SUSPECT_NS = 5_000_000_000  # Shim-Zeit weicht mehr als 5 s von der Empfangszeit ab
IDLE_CHECK_NS = 10_000_000_000
ADDR_CHECK_NS = 30_000_000_000
ADDR_MARK_NS = 1_000_000_000
MAX_PAUSE_MIN = 240
_V1_REC = {"on": "on", "preroll": "waiting", "locked": "waiting"}
# Grund einer Lücke, die der Daemon als Offset-Sprung sieht, nachdem die Aufnahme so endete.
# Was im Vorlauf lag und nicht übernommen wurde, fehlt wegen «kein Projekt».
_STOP_HINT = {"paused": "pause", "held": "project_switch", "locked": "no_project", "preroll": "no_project",
              "off": "no_project"}


def _plausible_mono(mono: int | None, now: int) -> int:
    """Monotone Shim-Zeit als Fensterschlüssel, sonst die eigene (gleicher Boot, gleiche Uhr)."""
    if isinstance(mono, int) and now - 3_600_000_000_000 <= mono <= now:
        return mono
    return now


def _cut_time(wall: int, mono: int | None, tix: tuple[tuple[int, int], ...],
              cut: int) -> tuple[int, int | None, tuple[tuple[int, int], ...]]:
    """Zeit und Zeitindex eines Rahmens, dessen erste ``cut`` Bytes wegfallen."""
    base = 0
    for rel, dt in tix:
        if rel > cut:
            break
        base = dt
    add = base * 1000
    rest = tuple((rel - cut, dt - base) for rel, dt in tix if rel > cut)
    return wall + add, (mono + add if mono is not None else None), rest


class Daemon:
    def __init__(
        self,
        paths: Paths,
        *,
        check_peer_comm: bool = True,
        operator: UnlockedOperator | None = None,
        batch_interval: float = 0.2,
        batch_bytes: int = 256 * 1024,
        pause_timeout: float = 120.0,
        clock_check: Callable[[], Awaitable[dict[str, Any]]] | None = None,
        ingest: IngestService | bool = True,
        sources: bool = True,
        config: RecordingConfig | None = None,
        local_addrs: Callable[[], tuple[str, ...] | None] | None | bool = True,
        wall_clock: Callable[[], int] | None = None,
        mono_clock: Callable[[], int] | None = None,
    ) -> None:
        self.paths = paths
        self.check_peer_comm = check_peer_comm
        self.vault = OperatorVault(paths.operator_dir)
        self.operator = operator
        self.project: OpenProject | None = None
        self.daemon_id = os.urandom(8).hex()  # STATE: der Shim erkennt daran einen Neustart
        self.terminals: dict[str, Terminal] = {}
        self.redactor = Redactor()
        self.writer = Writer(self, interval=batch_interval, max_bytes=batch_bytes)
        self.pause_timeout = pause_timeout
        self._wall = wall_clock or time.time_ns
        self._mono = mono_clock or time.monotonic_ns
        self.config = config if config is not None else load_recording(paths.config_file)
        self.preroll = PrerollStore(window_s=self.config.preroll_minutes * 60,
                                    terminal_bytes=self.config.preroll_terminal_mib << 20,
                                    total_bytes=self.config.preroll_total_mib << 20, clock=self._mono)
        self.active: dict[str, Any] | None = read_active(paths.active_file)
        self.last_activity = self._mono()
        self._idle_checked = self._mono()
        self._clock_check = clock_check or hardening.clock_status
        self._read_addrs: Callable[[], tuple[str, ...] | None] | None = (
            read_local_addrs if local_addrs is True else local_addrs or None)
        self._addrs_written: tuple[str, ...] | None = None
        self._addrs_checked = 0
        self._runtime_secrets: list[tuple[str, str]] = []
        self._pending_sensitive: dict[str, float] = {}  # Anmeldung vor dem ersten HELLO
        self._departed: dict[str, Terminal] = {}  # beendete Terminals mit Vorlauf
        self._commit_hooks: list[CommitHook] = []
        self._mark_hooks: list[MarkHook] = []
        self._servers: list[asyncio.base_events.Server] = []
        self._tasks: set[asyncio.Task[Any]] = set()
        self._writer_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._lock = hardening.InstanceLock(paths.runtime_dir / "daemon.lock")
        self._started = False
        self.ingest: IngestService | None = (IngestService() if ingest is True else
                                              ingest if isinstance(ingest, IngestService) else None)
        if self.ingest is not None:
            self.add_commit_hook(self.ingest.on_commit)
            self.ingest.add_listener(self._on_ingest_update)
        self.sources = LocalSources(self, routes=sources, companions=sources)
        self.add_commit_hook(self.sources.on_commit)
        self.add_mark_hook(self.sources.on_mark)
        self._update_redactor()

    # ================================================================== #
    # Erweiterungspunkte
    # ================================================================== #
    def add_commit_hook(self, fn: CommitHook) -> None:
        self._commit_hooks.append(fn)

    def add_mark_hook(self, fn: MarkHook) -> None:
        self._mark_hooks.append(fn)

    def _spawn(self, coro: Awaitable[Any]) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task[Any]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            log.error("Hintergrundaufgabe fehlgeschlagen (%s)", type(task.exception()).__name__)

    def _call_hook(self, fn: Callable[..., Any], *args: Any) -> None:
        try:
            res = fn(*args)
        except Exception as exc:
            log.error("Hook fehlgeschlagen (%s)", type(exc).__name__)
            return
        if inspect.isawaitable(res):
            self._spawn(res)

    def submit(self, item: AppendItem) -> None:
        """Reiht ein Event für den nächsten Commit ein (andere Quellen, Web-UI-Entscheide).

        Der Header wird sofort geprüft. Ohne offenes Projekt: :class:`OpError`.
        """
        if self.project is None:
            raise OpError("no_project", "kein Projekt offen")
        header = events.validate_header(item.kind, item.header)
        t = self.terminals.get(item.terminal_id) if item.terminal_id else None
        self.writer.add_event(AppendItem(item.kind, header, item.body, item.origin, item.terminal_id,
                                         item.stream_off, item.ts_utc_ns), t)

    def flush(self) -> list[EventRecord]:
        """Schreibt alles Eingereihte sofort und gibt die neuen Records zurück."""
        return self.writer.flush_now()

    def run_commit_hooks(self, records: list[EventRecord]) -> None:
        if not records:
            return
        for fn in list(self._commit_hooks):
            self._call_hook(fn, records)

    def run_mark_hooks(self, record: EventRecord, ctx: MarkContext | None) -> None:
        for fn in list(self._mark_hooks):
            self._call_hook(fn, record, ctx)

    # ================================================================== #
    # Lebenszyklus
    # ================================================================== #
    async def start(self) -> None:
        ensure_private_dir(self.paths.runtime_dir)
        self._lock.acquire()
        try:
            for sock in (self.paths.term_sock, self.paths.ctl_sock):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(sock)
            term = await asyncio.start_unix_server(self._handle_term, path=str(self.paths.term_sock))
            os.chmod(self.paths.term_sock, 0o600)
            ctl = await asyncio.start_unix_server(self._handle_ctl, path=str(self.paths.ctl_sock),
                                                  limit=1 << 20)
            os.chmod(self.paths.ctl_sock, 0o600)
        except BaseException:
            self._lock.release()
            raise
        self._servers = [term, ctl]
        self._writer_task = asyncio.ensure_future(self._writer_loop())
        self._started = True
        hardening.sd_notify("READY=1")
        log.info("ariadned %s bereit", __version__)

    async def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        hardening.sd_notify("STOPPING=1")
        for srv in self._servers:
            srv.close()
        for t in list(self.terminals.values()):
            if t.conn is not None:
                with contextlib.suppress(Exception):
                    t.conn.close()
        if self.project is not None:
            self._close_current("shutdown")
        self.preroll.discard()
        if self._writer_task is not None:
            self._writer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._writer_task
        for task in list(self._tasks):
            task.cancel()
        self._lock_operator()
        for sock in (self.paths.term_sock, self.paths.ctl_sock):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(sock)
        self._lock.release()
        log.info("ariadned beendet")

    async def run(self) -> None:
        """Startet, wartet auf ``shutdown`` (oder :meth:`request_stop`) und räumt auf."""
        await self.start()
        try:
            await self._stop.wait()
        finally:
            await self.stop()

    def request_stop(self) -> None:
        self._stop.set()

    async def _writer_loop(self) -> None:
        while True:
            await asyncio.sleep(self.writer.interval)
            try:
                self._tick()
            except Exception as exc:
                log.error("Writer-Takt fehlgeschlagen (%s)", type(exc).__name__)

    def _tick(self) -> None:
        now = time.monotonic()
        for t in list(self.terminals.values()):
            if t.pause is not None and now >= t.pause.deadline:
                self._end_pause(t, None)
            self._check_user_pause(t)
        for tid, deadline in list(self._pending_sensitive.items()):
            if now >= deadline:
                del self._pending_sensitive[tid]
        mono = self._mono()
        if mono - self._idle_checked >= IDLE_CHECK_NS:
            self._idle_checked = mono
            self._check_idle()
        if self.project is not None and mono - self._addrs_checked >= ADDR_CHECK_NS:
            self._check_local_addrs()
        self.preroll.expire()
        for tid in list(self._departed):
            if tid not in self.preroll.bufs:
                del self._departed[tid]
        if self.writer.busy:
            self.writer.flush_now()

    def _activity(self) -> None:
        self.last_activity = self._mono()

    def _check_idle(self) -> bool:
        """Leerlauf-Ende (E22): Projekt schliessen und sperren. Gibt zurück, ob es endete."""
        limit = self.config.idle_end_s
        if self.project is None or limit is None:
            return False
        idle_ns = self._mono() - self.last_activity
        if idle_ns < limit * 1_000_000_000:
            return False
        log.info("Leerlauf: Projekt wird beendet")
        self._end_project("idle", idle_s=idle_ns // 1_000_000_000)
        return True

    # ================================================================== #
    # Zustand
    # ================================================================== #
    def _update_redactor(self) -> None:
        secrets = list(self._runtime_secrets)
        use_global = True
        if self.project is not None:
            use_global = bool(self.project.settings.get("secrets", {}).get("use_global", True))
        if self.operator is not None and use_global:
            secrets.extend(self.operator.own_secrets)
        self.redactor.update_secrets(secrets)

    def _lock_operator(self) -> None:
        if self.operator is not None:
            self.operator.wipe()
        self.operator = None
        self._runtime_secrets = []
        self._update_redactor()

    def _active_id(self) -> str | None:
        """Aktives Projekt: das offene, sonst das nicht gestoppte aus ``active.json``."""
        if self.project is not None:
            return self.project.info.id
        a = self.active
        if a is not None and not a["stopped"]:
            return str(a["project_id"])
        return None

    def state_of(self, t: Terminal) -> str:
        """Zustand eines Terminals nach Vertrag 3.4 (Reihenfolge verbindlich)."""
        if t.pause_until_ns is not None and t.pause_until_ns > self._wall():
            return "paused"
        active = self._active_id()
        if t.bound_project_id is not None and t.bound_project_id != active:
            return "held"
        if self.project is not None:
            return "on"
        if active is not None:
            return "locked"
        if self.preroll.enabled:
            return "preroll"
        return "off"

    def status_of(self, t: Terminal) -> str:
        """Zustand, wie ihn der Shim sieht (v1: ``on``, ``waiting`` oder ``off``)."""
        state = self.state_of(t)
        return state if t.proto >= 2 else _V1_REC.get(state, "off")

    def _state(self, t: Terminal) -> dict[str, Any]:
        state = self.state_of(t)
        p = self.project
        extra = t.title_extra
        if extra is None and t.proto < 2:
            if state == "held":
                extra = f"nicht gespeichert: {t.bound_slug or '?'}"
            elif state == "paused":
                extra = "Pause"
        return {
            "rec": state if t.proto >= 2 else _V1_REC.get(state, "off"),
            "project": p.info.slug if p else None,
            "project_id": p.info.id if p else None,
            "profile": p.info.profile if p else None,
            "bound_project_id": t.bound_project_id,
            "bound_slug": t.bound_slug,
            "stack": t.stack.snapshot(),
            "ctx_version": t.ctx_version,
            "daemon_id": self.daemon_id,
            "pause_until_ns": t.pause_until_ns if state == "paused" else None,
            "preroll_minutes": self.config.preroll_minutes,
            "suggestion": None,
            "hosts": [],
            "title_extra": extra,
        }

    def _send(self, t: Terminal, frame: bytes) -> None:
        conn = t.conn
        if conn is None or conn.is_closing():
            return
        try:
            conn.write(frame)
        except (ConnectionError, RuntimeError):
            pass

    def _send_state(self, t: Terminal, force: bool = False) -> None:
        state = self._state(t)
        if force or state != t.last_state:
            t.last_state = state
            self._send(t, P.encode_json(P.STATE, state))

    def _flash(self, t: Terminal, text: str, seconds: float = 5.0) -> None:
        """Kurze Rückmeldung im Titel des Terminals."""
        t.title_extra = text
        self._send_state(t)

        def clear() -> None:
            if t.title_extra == text:
                t.title_extra = None
                self._send_state(t)

        with contextlib.suppress(RuntimeError):
            asyncio.get_running_loop().call_later(seconds, clear)

    def advance_acks(self) -> None:
        for t in self.terminals.values():
            self._advance_ack(t)

    def _advance_ack(self, t: Terminal) -> None:
        new = t.acked_seq
        q = t.ack_queue
        while q:
            e = q[0]
            if not e.ready or e.need_end > t.stored_end or e.need_gen > self.writer.committed_gen:
                break
            q.popleft()
            new = max(new, e.seq)
        if new > t.acked_seq:
            t.acked_seq = new
            self._send(t, P.encode_json(P.ACK, {"seq": new}))

    def _refresh(self, t: Terminal) -> None:
        """Bringt Aufnahme und Anzeige eines Terminals mit dem Zustand in Einklang."""
        state = self.state_of(t)
        if state == "on":
            if not t.recording:
                self._start_recording(t)
        elif t.recording:
            self._stop_recording(t, _STOP_HINT.get(state, "locked"))
        self._advance_ack(t)
        self._send_state(t)

    def _refresh_all(self) -> None:
        for t in list(self.terminals.values()):
            self._refresh(t)

    def _shim_time(self, t: Terminal, off: int | None) -> dict[str, int]:
        """``t_shim_ns``/``mono_ns`` für eigene Events, wenn die Shim-Zeit am Offset bekannt ist."""
        if off is None:
            return {}
        at = t.time_at(off)
        if at is None:
            return {}
        wall, mono, _recv = at
        return {"t_shim_ns": wall, "mono_ns": mono} if mono is not None else {"t_shim_ns": wall}

    def _start_recording(self, t: Terminal) -> None:
        p = self.project
        assert p is not None
        self.preroll.discard(t.terminal_id)
        if t.bound_project_id is None:
            t.bound_project_id = p.info.id
            t.bound_slug = p.info.slug
        t.recording = True
        if p.info.id not in t.opened_in:
            t.pending_open = True  # term.open folgt am ersten Offset des Shims
            return
        tid = t.terminal_id
        self.writer.add_event(AppendItem(
            "term.ctx_snapshot", {"terminal_id": tid, "stream_off": t.recv_end,
                                  "stack": t.stack.journal_snapshot(), **self._shim_time(t, t.recv_end)},
            origin="daemon", terminal_id=tid, stream_off=t.recv_end), t)
        t.gap_hint = t.gap_hint or "no_project"

    def _ensure_open(self, t: Terminal, off: int | None = None) -> None:
        """Erstes Event eines Terminals im Projekt: ``term.open``, ``term.bind``, Schnappschuss.

        Ein Terminal ohne übernommenen Vorlauf beginnt am aktuellen Offset; nahm es im
        selben Projekt schon auf, vermerkt ``term.gap`` (``no_project``) die Lücke.
        """
        if not t.pending_open:
            return
        p = self.project
        assert p is not None
        t.pending_open = False
        tid = t.terminal_id
        cur = t.shim_off if off is None else max(off, 0)
        end = p.journal.stream_end(tid)
        start = max(end, cur)
        t.recv_end = t.stored_end = start
        if end > 0 and cur > end:
            self.writer.add_event(AppendItem(
                "term.gap", {"terminal_id": tid, "stream_off": end, "reason": "no_project",
                             "bytes_lost": cur - end, **self._shim_time(t, cur)},
                origin="daemon", terminal_id=tid, stream_off=end), t)
        self._write_open(t, start, origin="daemon")

    def _write_open(self, t: Terminal, at: int, *, origin: str, stack: ContextStack | None = None,
                    ts: int | None = None) -> None:
        p = self.project
        assert p is not None
        tid = t.terminal_id
        if p.info.id not in t.opened_in:
            header = {
                "terminal_id": tid, "tty": t.tty, "shell": t.shell, "term": t.term, "rows": t.rows,
                "cols": t.cols, "tmux_pane": t.tmux_pane, "window_id": t.window_id,
                "shim_version": t.shim_version, **self._shim_time(t, at),
            }
            self.writer.add_event(AppendItem("term.open", {k: v for k, v in header.items() if v is not None},
                                             origin=origin, terminal_id=tid, stream_off=at, ts_utc_ns=ts), t)
            self.writer.add_event(AppendItem("term.bind", {"terminal_id": tid, "project_id": p.info.id},
                                             origin=origin, terminal_id=tid, stream_off=at, ts_utc_ns=ts), t)
            t.opened_in.add(p.info.id)
        st = stack if stack is not None else t.stack
        self.writer.add_event(AppendItem(
            "term.ctx_snapshot", {"terminal_id": tid, "stream_off": at, "stack": st.journal_snapshot(),
                                  **self._shim_time(t, at)},
            origin=origin, terminal_id=tid, stream_off=at, ts_utc_ns=ts), t)

    def _stop_recording(self, t: Terminal, hint: str) -> None:
        if t.pause is not None:
            self._end_pause(t, None)  # Lücke mit Grund sensitive_output zuerst vermerken
        t.recording = False
        t.pending_open = False
        t.gap_hint = hint

    # ================================================================== #
    # term.sock
    # ================================================================== #
    def _peer_ok(self, writer: asyncio.StreamWriter, *, shim: bool) -> int | None:
        sock = writer.get_extra_info("socket")
        try:
            pid, uid, _gid = hardening.peer_cred(sock)
        except OSError:
            return None
        if uid != os.getuid():
            log.warning("Verbindung einer fremden UID abgelehnt")
            return None
        if shim and self.check_peer_comm and hardening.proc_comm(pid) != "ariadne-shim":
            log.warning("Verbindung abgelehnt: Prozess ist kein ariadne-shim")
            return None
        return pid

    async def _handle_term(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        pid = self._peer_ok(writer, shim=True)
        if pid is None:
            writer.close()
            return
        dec = P.FrameDecoder()
        t: Terminal | None = None
        try:
            while True:
                data = await reader.read(1 << 16)
                if not data:
                    break
                for frame in dec.feed(data):
                    if t is None:
                        if frame.type != P.HELLO:
                            raise P.ProtocolError("HELLO erwartet")
                        t = self._on_hello(writer, P.decode_json(frame.payload), pid)
                        continue
                    if frame.type == P.BYE:
                        self._on_bye(t)
                        return
                    v2 = t.proto >= 2 and frame.type in DATA_FRAMES
                    if frame.type not in (P.OUT, P.EVENT) and not v2:
                        raise P.ProtocolError("unerwarteter Rahmentyp")
                    self._on_frame(t, frame.type, frame.payload)
                await writer.drain()
        except P.ProtocolError as exc:
            log.warning("Shim-Protokollfehler: %s", type(exc).__name__)
        except (ConnectionError, OSError):
            pass
        except Exception as exc:  # ein fehlerhafter Shim darf den Daemon nie stören
            log.error("Shim-Verbindung abgebrochen (%s)", type(exc).__name__)
        finally:
            if t is not None and t.conn is writer:
                t.conn = None
            writer.close()

    def _on_hello(self, writer: asyncio.StreamWriter, obj: dict[str, Any], pid: int) -> Terminal:
        h = parse_hello(obj)
        tid = h["terminal_id"]
        t = self.terminals.get(tid)
        if t is None:
            t = self._departed.pop(tid, None) or Terminal(tid)
            resume = h["resume_from_seq"]
            if resume:
                t.max_seq = t.acked_seq = max(t.acked_seq, resume - 1)
            # Neues Terminal-Objekt (erster Kontakt oder Daemon-Neustart): Stapel, Bindung und
            # Pause kennt nur der Shim. Ohne die Bindung landete eine laufende Sitzung zu
            # Projekt A nach dem Neustart in Projekt B (Architektur 3.6).
            if h["stack"] is not None:
                t.stack = ContextStack.from_snapshot(h["stack"])
            if h["bound_project_id"]:
                t.bound_project_id = h["bound_project_id"]
                t.bound_slug = h["bound_slug"]
            until = h["pause_until_ns"]
            if until is not None and until > self._wall() and t.pause_until_ns is None:
                t.pause_until_ns = min(until, self._wall() + MAX_PAUSE_MIN * 60_000_000_000)
            if self._pending_sensitive.pop(tid, None) is not None:
                t.pause = Pause(start=-1, end=-1, deadline=time.monotonic() + self.pause_timeout)
            self.terminals[tid] = t
        elif t.conn is not None and t.conn is not writer:
            with contextlib.suppress(Exception):
                t.conn.close()
        for k in ("tty", "shell", "term", "rows", "cols", "tmux_pane", "window_id", "shim_version",
                  "display", "proto", "mux"):
            setattr(t, k, h[k])
        t.pid = pid
        t.conn = writer
        t.closed = False
        t.last_state = None
        if h["gap_hint"]:
            t.gap_hint = h["gap_hint"]  # Grund einer Lücke, die gleich als Offset-Sprung kommt
        log.info("Terminal verbunden")
        self._refresh(t)
        if t.acked_seq:
            self._send(t, P.encode_json(P.ACK, {"seq": t.acked_seq}))
        return t

    def _on_bye(self, t: Terminal) -> None:
        p = self.project
        known = (t.recording or (p is not None and p.info.id in t.opened_in
                                 and t.bound_project_id == p.info.id))
        if known and not t.closed and not t.pending_open:
            # Auch ohne laufende Aufnahme: sonst bleibt die letzte Einheit offen und die
            # Auswertung lädt das Terminal bei jedem Start neu.
            if t.pause is not None:
                self._end_pause(t, None)
            self.writer.add_event(AppendItem(
                "term.close", {"terminal_id": t.terminal_id, "stream_off": t.recv_end,
                               **self._shim_time(t, t.recv_end)},
                origin="daemon", terminal_id=t.terminal_id, stream_off=t.recv_end), t)
        if known:
            self.writer.flush_now()
        self.terminals.pop(t.terminal_id, None)
        if t.terminal_id in self.preroll.bufs:
            t.conn = None
            self._departed[t.terminal_id] = t  # Vorlauf bleibt übernehmbar
        log.info("Terminal beendet")

    def _on_frame(self, t: Terminal, ftype: int, payload: bytes) -> None:
        obj: dict[str, Any] | None = None
        if ftype in DATA_FRAMES:
            seq = P.frame_seq(ftype, payload)
        else:
            obj = P.decode_json(payload)
            seq = obj.get("seq")
            if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
                raise P.ProtocolError("EVENT ohne gültige seq")
        if seq <= t.max_seq:
            # Wiederholung: schon empfangen. ACK erneut senden, sonst nichts.
            if t.acked_seq:
                self._send(t, P.encode_json(P.ACK, {"seq": t.acked_seq}))
            return
        t.max_seq = t.seen_seq = seq
        entry = AckEntry(seq)
        t.ack_queue.append(entry)
        self._check_user_pause(t)
        kind = obj.get("kind") if obj is not None else None
        if obj is not None and isinstance(kind, str) and kind in REQUESTS:
            self._on_request(t, kind, obj, entry)
        elif obj is not None:
            self._process_event(t, obj, entry)
        else:
            self._activity()
            self._process_data(t, ftype, payload, entry)
        self._advance_ack(t)

    # ---- Datenrahmen ------------------------------------------------------- #
    def _process_data(self, t: Terminal, ftype: int, payload: bytes, entry: AckEntry) -> None:
        entry.ready = True
        recv = self._wall()
        if ftype == P.INPUT:
            fr = P.decode_input(payload)
            t.note_off(fr.out_end)
            if t.pause is not None:
                return  # Schlüsselmaterial: auch Eingaben (Passphrase) verwerfen
            fields = {"out_end": fr.out_end, "wall": fr.t_wall_ns, "mono": fr.t_mono_ns, "tix": fr.tix,
                      "paste": fr.paste}
            if t.recording:
                self._rec_input(t, fr.stream_off, fields, fr.data, recv, "shim", entry)
            elif self.state_of(t) in ("preroll", "locked"):
                self._hold(t, "input", fr.stream_off, recv, fr.t_mono_ns, data=fr.data, fields=fields)
            return
        if ftype == P.OUTX:
            ox = P.decode_outx(payload)
            off, wall, mono, tix, data = ox.stream_off, ox.t_wall_ns, ox.t_mono_ns, ox.tix, ox.data
        else:
            _seq, off, wall, mono, data = P.decode_out(payload)
            tix = ()
        end = off + len(data)
        t.note_off(end)
        if t.pause is not None:
            if t.pause.start < 0:
                t.pause.start = t.recv_end if t.recording else off
            t.pause.end = max(t.pause.end, end)
            return
        if t.recording:
            self._rec_out(t, off, wall, mono, tix, data, recv, "shim", entry)
        elif self.state_of(t) in ("preroll", "locked"):
            self._hold(t, "out", off, recv, mono, data=data, fields={"wall": wall, "mono": mono, "tix": tix})

    def _suspect(self, t: Terminal, wall: int, mono: int | None, recv: int) -> bool:
        bad = abs(wall - recv) > SUSPECT_NS
        if mono is not None:
            if t.last_mono is not None and mono < t.last_mono:
                bad = True
            t.last_mono = max(mono, t.last_mono or mono)
        return bad

    def _jump(self, t: Terminal, off: int) -> None:
        """Offset springt nach vorn: Lücke mit dem bekannten Grund vermerken."""
        self.writer.add_event(AppendItem(
            "term.gap",
            {"terminal_id": t.terminal_id, "stream_off": t.recv_end, "reason": t.gap_hint or "shim_error",
             "bytes_lost": off - t.recv_end, **self._shim_time(t, t.recv_end)},
            origin="daemon", terminal_id=t.terminal_id, stream_off=t.recv_end), t)
        t.gap_hint = None  # gilt für den nächsten Sprung, nicht für den nächsten Rahmen

    def _rec_out(self, t: Terminal, off: int, wall: int, mono: int | None, tix: tuple[tuple[int, int], ...],
                 data: bytes, recv: int, origin: str, entry: AckEntry | None) -> None:
        self._ensure_open(t, off)
        end = off + len(data)
        if end <= t.recv_end:
            return
        if off < t.recv_end:
            cut = t.recv_end - off
            wall, mono, tix = _cut_time(wall, mono, tix, cut)
            data, off = data[cut:], t.recv_end
        elif off > t.recv_end:
            self._jump(t, off)
        t.recv_end = end
        suspect = self._suspect(t, wall, mono, recv)
        t.note_frame(off, wall, mono, recv)
        if entry is not None:
            entry.need_end = end
            entry.need_gen = self.writer.pending_gen
        self.writer.add_out(OutChunk(t, off, data, wall, mono, tuple(tix), recv, origin, suspect))

    def _rec_input(self, t: Terminal, off: int, f: dict[str, Any], data: bytes, recv: int, origin: str,
                   entry: AckEntry | None) -> None:
        self._ensure_open(t, off)
        mono = f.get("mono")
        header: dict[str, Any] = {
            "terminal_id": t.terminal_id, "stream_off": off, "out_end": f["out_end"], "length": len(data),
            "t_shim_ns": f["wall"], "mono_ns": mono, "tix": [list(x) for x in f.get("tix") or ()] or None,
            "paste": True if f.get("paste") else None,
            "time_suspect": True if abs(int(f["wall"]) - recv) > SUSPECT_NS else None,
        }
        try:
            header = events.validate_header("term.input", header)
        except ValueError:
            log.warning("Ungültiges term.input verworfen")
            return
        self.writer.add_event(AppendItem("term.input", header, bytes(data), origin=origin,
                                         terminal_id=t.terminal_id, stream_off=off, ts_utc_ns=recv), t)
        if entry is not None:
            entry.need_gen = self.writer.pending_gen

    def _hold(self, t: Terminal, kind: str, off: int, recv: int, mono: int | None, *,
              data: bytes | None = None, fields: dict[str, Any] | None = None,
              stack_before: ContextStack | None = None) -> None:
        """Eintrag im Vorlauf halten (nur RAM)."""
        held = Held(kind, off, recv, _plausible_mono(mono, self._mono()), t.bound_project_id,
                    bytearray(data) if data is not None else None, dict(fields or {}))
        self.preroll.add(t.terminal_id, held, stack_before or t.stack)

    # ---- Events vom Shim --------------------------------------------------- #
    def _process_event(self, t: Terminal, obj: dict[str, Any], entry: AckEntry) -> None:
        entry.ready = True
        kind = obj.get("kind")
        if not isinstance(kind, str) or kind not in TERM_EVENTS:
            log.warning("Unbekannte Event-Art vom Shim verworfen")
            return
        header = {k: v for k, v in obj.items() if k not in ("seq", "kind")}
        header["terminal_id"] = t.terminal_id
        if kind == "term.ctx_snapshot" and isinstance(header.get("stack"), list):
            # Automatische Hosts kommen nie ins Journal, auch nicht von einem fehlerhaften Shim.
            header["stack"] = [{k: v for k, v in st.items() if not (k in ("host", "host_source")
                                                                    and st.get("host_source") == "auto")}
                               if isinstance(st, dict) else st for st in header["stack"]]
        try:
            header = events.validate_header(kind, header)
        except ValueError:
            log.warning("Ungültiges %s vom Shim verworfen", kind)
            return
        off = header.get("stream_off")
        t.note_off(off + int(header.get("bytes_lost", 0) or 0) if kind == "term.gap" else off)
        state = self.state_of(t)
        before = t.stack.snapshot()
        stack_before = ContextStack.from_snapshot(before)
        local_before = t.stack.is_local()
        if kind != "term.ctx_snapshot" or state in ("on", "preroll", "locked"):
            t.stack = apply_stack_event(t.stack, kind, header)
        if kind == "term.mark":
            mark = header["mark"]
            if mark in ("A", "D") and header.get("fg_shell") and t.pause is not None:
                self._end_pause(t, off)
            if mark == "C" and local_before and t.recording:
                self._check_local_addrs(on_mark=True)
        elif kind == "term.resize":
            t.rows, t.cols = int(header["rows"]), int(header["cols"])
        elif kind == "term.close":
            t.closed = True
        if t.recording:
            mark_ctx: MarkContext | None = None
            if kind == "term.mark" and self.project is not None:
                mark_ctx = MarkContext(t.terminal_id, self.project.info.id, tuple(t.stack.snapshot()),
                                       t.stack.is_local(), local_before)
            self._store_event(t, kind, header, origin="shim", recv=self._wall(), mark_ctx=mark_ctx)
            entry.need_gen = self.writer.pending_gen
        elif state in ("preroll", "locked"):
            self._hold(t, "event", int(off or 0), self._wall(), header.get("mono_ns"),
                       fields={"kind": kind, **header}, stack_before=stack_before)
        if t.stack.snapshot() != before:
            self._send_state(t)

    def _store_event(self, t: Terminal, kind: str, header: dict[str, Any], *, origin: str, recv: int,
                     mark_ctx: MarkContext | None = None) -> None:
        """Ein ``term.*``-Event einer laufenden Aufnahme ins Journal (live und aus dem Vorlauf)."""
        off = header.get("stream_off")
        if kind == "term.gap":
            end = int(header["stream_off"]) + int(header.get("bytes_lost", 0))
            self._ensure_open(t, end)
            t.gap_hint = None
            if int(header.get("bytes_lost", 0)) > 0 and end <= t.recv_end:
                return  # Bereich schon gespeichert oder als Lücke vermerkt
            if int(header["stream_off"]) > t.recv_end:
                # Bytes zwischen dem gespeicherten Ende und dem Lückenbeginn des Shims hat der
                # Daemon verworfen (z. B. Rahmen unterwegs, als die Pause begann).
                header = dict(header, stream_off=t.recv_end, bytes_lost=end - t.recv_end)
                off = t.recv_end
            t.recv_end = max(t.recv_end, end)
        else:
            self._ensure_open(t, off)
        self.writer.add_event(AppendItem(kind, header, origin=origin, terminal_id=t.terminal_id,
                                         stream_off=off, ts_utc_ns=recv), t, mark_ctx)

    # ---- Pause bei Schlüsselmaterial -------------------------------------- #
    def _end_pause(self, t: Terminal, at_off: int | None) -> None:
        pause = t.pause
        if pause is None:
            return
        t.pause = None
        tid = t.terminal_id
        if t.recording:
            if pause.start < 0:
                return
            self._ensure_open(t, pause.start)
            start = min(pause.start, t.recv_end) if pause.start >= 0 else t.recv_end
            end = max(pause.end, at_off or 0, t.recv_end)
            self.writer.add_event(AppendItem(
                "term.gap",
                {"terminal_id": tid, "stream_off": start, "reason": "sensitive_output",
                 "bytes_lost": end - start, **self._shim_time(t, end)},
                origin="daemon", terminal_id=tid, stream_off=start), t)
            t.recv_end = end
        elif pause.start >= 0 and pause.end > pause.start and self.state_of(t) in ("preroll", "locked"):
            self._hold(t, "event", pause.start, self._wall(), None,
                       fields={"kind": "term.gap", "terminal_id": tid, "stream_off": pause.start,
                               "reason": "sensitive_output", "bytes_lost": pause.end - pause.start})

    # ---- Pause des Nutzers (E22) ------------------------------------------- #
    def _check_user_pause(self, t: Terminal) -> None:
        if t.pause_until_ns is not None and t.pause_until_ns <= self._wall():
            t.pause_until_ns = None
            self._refresh(t)

    def _set_pause(self, t: Terminal, minutes: int | None, source: str) -> int | None:
        """``None`` schaltet um, 0 setzt fort, sonst Pause (neu oder verlängert). Gibt das Ende zurück."""
        now = self._wall()
        paused = t.pause_until_ns is not None and t.pause_until_ns > now
        if minutes is None:
            minutes = 0 if paused else self.config.pause_minutes
        if minutes <= 0:
            t.pause_until_ns = None
            self._refresh(t)
            return None
        until = now + min(minutes, MAX_PAUSE_MIN) * 60_000_000_000
        if t.recording:
            self._ensure_open(t)
            self.writer.add_event(AppendItem(
                "term.pause", {"terminal_id": t.terminal_id, "stream_off": t.recv_end, "until_ns": until,
                               "source": source},
                origin=_origin(source), terminal_id=t.terminal_id, stream_off=t.recv_end), t)
        t.pause_until_ns = until
        t.pause_source = source
        self._refresh(t)
        return until

    # ---- Hotkey-Anfragen ----------------------------------------------------- #
    def _can_store_decision(self, t: Terminal) -> bool:
        p = self.project
        return p is not None and t.bound_project_id in (None, p.info.id)

    def _on_request(self, t: Terminal, kind: str, obj: dict[str, Any], entry: AckEntry) -> None:
        entry.ready = True
        t.note_off(obj.get("stream_off"))
        try:
            if kind in ("req.pause", "req.rec"):
                minutes = obj.get("minutes") if kind == "req.pause" else None
                if minutes is not None and (type(minutes) is not int or not 0 <= minutes <= MAX_PAUSE_MIN):
                    raise ValueError("minutes")
                if kind == "req.rec" and obj.get("on") is not None and not isinstance(obj.get("on"), bool):
                    raise ValueError("on")
                self._activity()
                until = self._set_pause(t, minutes, "hotkey")
                self._flash(t, f"Pause {self._minutes_left(until)} min" if until else "Aufnahme läuft weiter")
            elif kind == "req.rebind":
                if self.state_of(t) == "held":
                    t.bound_project_id = t.bound_slug = None
                    log.info("Terminal neu eingeordnet")
                    self._refresh(t)
            elif kind == "req.status":
                t.mux = obj.get("mux") is True
            elif kind == "req.ctx.sync":
                stack = parse_stack(obj.get("stack"))
                if stack is None:
                    raise ValueError("stack")
                if not t.recording:  # bei laufender Aufnahme führen die Marker den Stapel
                    t.stack = merge_auto_hosts(t.stack, ContextStack.from_snapshot(stack))
            elif kind in ("req.ctx.set", "req.ctx.push", "req.ctx.pop"):
                stage_kind = obj.get("stage_kind", obj.get("ctx_kind"))
                self._ctx_decision(t, kind.rsplit(".", 1)[1], host=obj.get("host"), user=obj.get("user"),
                                   stage_kind=stage_kind, origin="shim", source="hotkey",
                                   shim_off=obj.get("stream_off"))
            elif kind == "req.keystep":
                self._keystep(t, obj)
            elif kind == "req.shot":
                self._flash(t, "Screenshots kommen in einer späteren Version")
            if self.writer.pending:
                entry.need_gen = self.writer.pending_gen
        except (ValueError, TypeError, OpError):
            self._flash(t, "Eingabe ungültig")

    def _minutes_left(self, until: int | None) -> int:
        if until is None:
            return 0
        return max(1, math.ceil((until - self._wall()) / 60_000_000_000))

    def _ctx_decision(self, t: Terminal, op: str, *, host: Any = None, user: Any = None,
                      stage_kind: Any = None, origin: str, source: str,
                      shim_off: Any = None) -> dict[str, Any]:
        host_n = normalize_host(host) if isinstance(host, str) and host.strip() else None
        user_n = normalize_user(user) if isinstance(user, str) and user.strip() else None
        if stage_kind is not None and (not isinstance(stage_kind, str) or stage_kind not in STAGE_KINDS):
            raise ValueError("ungültige Stufe")
        if t.recording:
            self._ensure_open(t)
            off = t.recv_end
        elif isinstance(shim_off, int) and not isinstance(shim_off, bool) and shim_off >= 0:
            off = shim_off  # Stromposition des Shims; recv_end ist das Ende der letzten Aufnahme
        else:
            off = t.shim_off
        tid = t.terminal_id
        if op == "set":
            if host_n is None and user_n is None and stage_kind is None:
                raise ValueError("nichts zu setzen")
            t.stack.set_top(host=host_n, user=user_n, kind=stage_kind, source=source, offset=off)
            kind, header = "d.ctx.set", {"terminal_id": tid, "from_off": off, "host": host_n,
                                         "user": user_n, "kind": stage_kind}
        elif op == "push":
            t.stack.push(kind=stage_kind or "unknown", host=host_n, user=user_n, offset=off, source=source)
            kind, header = "d.ctx.push", {"terminal_id": tid, "stream_off": off,
                                          "kind": stage_kind or "unknown", "host": host_n, "user": user_n}
        elif op == "pop":
            if t.stack.pop() is None:
                self._flash(t, "Kontext: nichts zu schliessen")
                return {"stack": t.stack.snapshot(), "stored": False}
            kind, header = "d.ctx.pop", {"terminal_id": tid, "stream_off": off}
        else:
            raise ValueError("unbekannte Kontext-Operation")
        header = {k: v for k, v in header.items() if v is not None}
        t.ctx_version += 1
        stored = self._can_store_decision(t) and t.recording
        if stored:
            self.writer.add_event(AppendItem(kind, header, origin=origin, terminal_id=tid, stream_off=off), t)
        else:
            if self.state_of(t) in ("preroll", "locked"):
                # Im Vorlauf als Schnappschuss halten: bei der Übernahme gilt er ab dieser Stelle.
                self._hold(t, "event", off, self._wall(), None,
                           fields={"kind": "term.ctx_snapshot", "terminal_id": tid, "stream_off": off,
                                   "stack": t.stack.journal_snapshot()})
            if origin == "shim":
                self._flash(t, "Kontext gesetzt, gespeichert ab ariadne start")
        self._send_state(t)
        return {"stack": t.stack.snapshot(), "stored": stored}

    def _keystep(self, t: Terminal, obj: dict[str, Any]) -> None:
        step = obj.get("step")
        if not isinstance(step, str) or step not in KEYSTEPS:
            raise ValueError("step")
        note = obj.get("note")
        if note is not None and (not isinstance(note, str) or len(note) > 500):
            raise ValueError("note")
        host = obj.get("host")
        host_n = normalize_host(host) if isinstance(host, str) and host.strip() else t.stack.top().host
        if host_n == "local":
            host_n = None
        if not self._can_store_decision(t):
            self._flash(t, "Schlüsselschritt nicht gespeichert: kein Projekt offen")
            return
        # Ohne Aufnahme gibt es keine Stromposition: recv_end wäre das Ende der letzten Aufnahme.
        if t.recording:
            self._ensure_open(t)
        tid, off = (t.terminal_id, t.recv_end) if t.recording else (None, None)
        header = {"terminal_id": tid, "stream_off": off, "step": step, "host": host_n, "note": note}
        self.writer.add_event(AppendItem("d.keystep.mark", {k: v for k, v in header.items() if v is not None},
                                         origin="shim", terminal_id=tid, stream_off=off), t)
        self._flash(t, f"Schlüsselschritt: {step}")

    # ---- Auswertung -> Live-Stapel (E23) ------------------------------------ #
    def _on_ingest_update(self, update: IngestUpdate) -> None:
        for ac in update.auto_contexts:
            t = self.terminals.get(ac.terminal_id)
            if t is None or not isinstance(ac.host, str):
                continue
            if t.stack.set_auto_host(int(ac.opened_at), ac.host):
                t.ctx_version += 1
                self._send_state(t)

    # ---- Eigene Adressen (A5) ------------------------------------------------ #
    def _check_local_addrs(self, *, force: bool = False, on_mark: bool = False) -> None:
        p = self.project
        if p is None or self._read_addrs is None:
            return
        now = self._mono()
        if on_mark and now - self._addrs_checked < ADDR_MARK_NS:
            return
        self._addrs_checked = now
        try:
            addrs = self._read_addrs()
        except Exception as exc:
            log.warning("Eigene Adressen nicht lesbar (%s)", type(exc).__name__)
            return
        if addrs is None or (not force and addrs == self._addrs_written):
            return
        self._addrs_written = tuple(addrs)
        self.writer.add_event(AppendItem("net.local_addrs", {"addrs": list(addrs), "source": "proc"},
                                         origin="daemon"))

    # ================================================================== #
    # Projekte
    # ================================================================== #
    def _checkpoint(self, reason: str) -> None:
        p = self.project
        if p is None:
            return
        self.writer.flush_now()
        seq, h = p.journal.head()
        self.writer.add_event(AppendItem("system.checkpoint",
                                         {"reason": reason, "head_seq": seq, "head_hash": h.hex()}))
        self.writer.flush_now()

    async def _clock_task(self, project: OpenProject) -> None:
        try:
            info = await self._clock_check()
        except Exception:
            info = {"detail": "unbekannt"}
        if self.project is project:
            try:
                header = events.validate_header("clock.check", info)
            except ValueError:
                header = {"detail": "unbekannt"}
            self.writer.add_event(AppendItem("clock.check", header, origin="daemon"))

    def _service(self) -> ProjectService:
        return ProjectService(self.paths, self.operator)

    def _set_active(self, slug: str, project_id: str, *, stopped: bool) -> None:
        try:
            self.active = write_active(self.paths.active_file, slug, project_id, stopped=stopped)
        except OSError as exc:
            log.error("active.json nicht geschrieben (%s)", type(exc).__name__)
            self.active = {"slug": slug, "project_id": project_id, "stopped": stopped, "since_utc": None}

    def _open_project(self, slug: str, *, refresh: bool = True) -> OpenProject:
        """Öffnet ``slug`` (ein anderes offenes Projekt endet mit Grund ``switch``)."""
        if self.project is not None and self.project.info.slug == slug:
            return self.project
        if self.operator is None:
            raise OpError("locked", "Operator ist gesperrt (ariadne start)")
        new = self._service().open(slug)
        if not new.head_ok:
            log.warning("Kettenkopf beim Öffnen ungültig, ariadne verify ausführen")
        if self.project is not None:
            self._close_current("switch")
        self.project = new
        if self.ingest is not None:
            self.ingest.attach(new)
        self._update_redactor()
        self._set_active(new.info.slug, new.info.id, stopped=False)
        self._addrs_written = None
        self._check_local_addrs(force=True)
        self._spawn(self._clock_task(new))
        log.info("Projekt geöffnet")
        if refresh:
            self._refresh_all()
        return new

    def _close_current(self, reason: str, *, idle_s: int | None = None) -> tuple[int, str] | None:
        """Beendet das offene Projekt: ``system.project_end``, Checkpoint ``close``."""
        p = self.project
        if p is None:
            return None
        for t in self.terminals.values():
            if t.recording:
                if reason == "switch" and not t.pending_open:
                    self.writer.add_event(AppendItem(
                        "term.gap", {"terminal_id": t.terminal_id, "stream_off": t.recv_end,
                                     "reason": "project_switch", "bytes_lost": 0,
                                     **self._shim_time(t, t.recv_end)},
                        origin="daemon", terminal_id=t.terminal_id, stream_off=t.recv_end), t)
                self._stop_recording(t, "project_switch" if reason == "switch" else "no_project")
        header: dict[str, Any] = {"reason": reason}
        if idle_s is not None:
            header["idle_s"] = int(idle_s)
        self.writer.add_event(AppendItem("system.project_end", header, origin="daemon"))
        try:
            self.writer.flush_now()
        finally:
            self.writer.drop_carry()
            if self.ingest is not None:
                self.ingest.detach()
            self.project = None
            head = p.close()
            self._update_redactor()
        log.info("Projekt geschlossen")
        return head

    def _end_project(self, reason: str, *,
                     idle_s: int | None = None) -> tuple[str | None, tuple[int, str] | None]:
        """``stop`` und Leerlauf: schliessen, sperren, ``stopped: true``."""
        slug = self.project.info.slug if self.project else (self.active or {}).get("slug")
        head = self._close_current(reason, idle_s=idle_s)
        a = self.active
        if a is not None and not a["stopped"]:
            self._set_active(a["slug"], a["project_id"], stopped=True)
        self._lock_operator()
        self._refresh_all()
        return slug, head

    def _adopt_preroll(self, p: OpenProject) -> dict[str, Any]:
        """Vorlauf ins offene Projekt schreiben (E95). Gibt Terminals, Sekunden und Bytes zurück."""
        bufs = []
        for tid in list(self.preroll.terminals()):
            buf = self.preroll.take(tid)
            if buf is not None:
                bufs.append(buf)
        bufs.sort(key=lambda b: b.oldest_mono() or 0)
        done = {"terminals": 0, "seconds": 0, "bytes": 0}
        now = self._mono()
        for buf in bufs:
            tid = buf.terminal_id
            t = self.terminals.get(tid) or self._departed.get(tid)
            entries = [e for e in buf.entries if e.bound in (None, p.info.id)]
            departed = tid not in self.terminals
            if (t is None or not entries or t.recording
                    or (not departed and self.state_of(t) != "on")):
                buf.wipe()
                continue
            try:
                n = self._replay(t, p, buf, entries, departed)
            finally:
                buf.wipe()
            done["terminals"] += 1
            done["bytes"] += n
            done["seconds"] = max(done["seconds"], math.ceil((now - entries[0].mono) / 1e9))
            self._departed.pop(tid, None)
        return done

    def _replay(self, t: Terminal, p: OpenProject, buf: Any, entries: list[Held], departed: bool) -> int:
        tid = t.terminal_id
        first, last = entries[0], entries[-1]
        end_in_p = p.journal.stream_end(tid)
        start = max(first.stream_off, end_in_p)
        if t.bound_project_id is None:
            t.bound_project_id, t.bound_slug = p.info.id, p.info.slug
        t.recording, t.pending_open = True, False
        t.recv_end = t.stored_end = start
        if end_in_p > 0 and first.stream_off > end_in_p:
            self.writer.add_event(AppendItem(
                "term.gap", {"terminal_id": tid, "stream_off": end_in_p, "reason": "no_project",
                             "bytes_lost": first.stream_off - end_in_p},
                origin="daemon", terminal_id=tid, stream_off=end_in_p), t)
        win = ContextStack.from_snapshot(buf.start_stack.snapshot())
        self._write_open(t, start, origin="daemon", stack=win, ts=first.recv_ns)

        def t_of(e: Held) -> int:
            return int(e.fields.get("wall") or e.fields.get("t_shim_ns") or e.recv_ns)

        to_off = max(e.end for e in entries)
        self.writer.add_event(AppendItem(
            "term.preroll", {"terminal_id": tid, "from_off": start, "to_off": max(start, to_off),
                             "frames": len(entries), "t_first_ns": t_of(first), "t_last_ns": t_of(last),
                             "dropped_bytes": buf.dropped_bytes},
            origin="daemon", terminal_id=tid, stream_off=start, ts_utc_ns=first.recv_ns), t)
        nbytes = 0
        for e in entries:
            if e.kind == "out" and e.data is not None:
                f = e.fields
                nbytes += len(e.data)
                self._rec_out(t, e.stream_off, int(f["wall"]), f.get("mono"), tuple(f.get("tix") or ()),
                              bytes(e.data), e.recv_ns, "preroll", None)
            elif e.kind == "input" and e.data is not None:
                nbytes += len(e.data)
                self._rec_input(t, e.stream_off, e.fields, bytes(e.data), e.recv_ns, "preroll", None)
            elif e.kind == "event":
                kind = str(e.fields["kind"])
                header = {k: v for k, v in e.fields.items() if k != "kind"}
                local_before = win.is_local()
                win = apply_stack_event(win, kind, header)
                ctx = (MarkContext(tid, p.info.id, tuple(win.snapshot()), win.is_local(), local_before)
                       if kind == "term.mark" else None)
                self._store_event(t, kind, header, origin="preroll", recv=e.recv_ns, mark_ctx=ctx)
        if departed:
            t.recording = False
        return nbytes

    # ================================================================== #
    # ctl.sock
    # ================================================================== #
    async def _handle_ctl(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._peer_ok(writer, shim=False) is None:
            writer.close()
            return
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                resp = await self._dispatch_line(line)
                writer.write(json.dumps(resp, ensure_ascii=False).encode() + b"\n")
                await writer.drain()
        except (ConnectionError, ValueError, asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def _dispatch_line(self, line: bytes) -> dict[str, Any]:
        try:
            req = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            return {"ok": False, "error": {"code": "invalid", "message": "kein gültiges JSON"}}
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            return {"ok": False, "error": {"code": "invalid", "message": "op fehlt"}}
        args = req.get("args") or {}
        if not isinstance(args, dict):
            return {"ok": False, "error": {"code": "invalid", "message": "args muss ein Objekt sein"}}
        return await self.call(req["op"], args)

    async def call(self, op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """Führt eine ctl-Operation aus (auch direkt aus Tests oder der Web-API)."""
        fn = _OPS.get(op)
        if fn is None:
            return {"ok": False, "error": {"code": "unknown_op", "message": "unbekannte Operation"}}
        try:
            result = fn(self, args or {})
            if inspect.isawaitable(result):
                result = await result
            return {"ok": True, "result": result}
        except Exception as exc:
            return {"ok": False, "error": _error(exc)}

    # ---- Hilfen für Operationen ------------------------------------------- #
    def _require_operator(self) -> UnlockedOperator:
        if self.operator is None:
            raise OpError("locked", "Operator ist gesperrt (ariadne start)")
        return self.operator

    def _require_project(self) -> OpenProject:
        if self.project is None:
            raise OpError("no_project", "kein Projekt offen (ariadne start <slug>)")
        return self.project

    def _terminal(self, args: dict[str, Any]) -> Terminal:
        tid = _arg_str(args, "terminal_id", max_len=64)
        t = self.terminals.get(str(tid))
        if t is None:
            raise OpError("unknown_terminal", "Terminal unbekannt (läuft der Shim in diesem Terminal?)")
        return t

    def _targets(self, args: dict[str, Any], key: str = "targets") -> list[str] | None:
        targets = args.get(key)
        if targets is None:
            return None
        if (not isinstance(targets, list) or len(targets) > 256
                or not all(isinstance(x, str) and len(x) <= 512 for x in targets)):
            raise OpError("invalid", "targets muss eine Liste von Strings sein")
        return targets

    def _project_info(self) -> dict[str, Any] | None:
        p = self.project
        if p is None:
            return None
        return {"slug": p.info.slug, "id": p.info.id, "profile": p.info.profile,
                "workspace": str(p.info.workspace), "chain_head_ok": p.head_ok}

    def _preroll_info(self) -> dict[str, Any]:
        return self.preroll.info()

    def _terminal_state(self, t: Terminal) -> dict[str, Any]:
        state = self.state_of(t)
        return {"terminal_id": t.terminal_id, "tty": t.tty, "state": state,
                "pause_until_ns": t.pause_until_ns if state == "paused" else None,
                "bound_slug": t.bound_slug, "label": t.stack.label(), "mux": t.mux,
                "preroll_s": self.preroll.seconds(t.terminal_id), "proto": t.proto}

    def _connected(self) -> list[Terminal]:
        return [t for t in self.terminals.values() if t.conn is not None]

    # ---- Operationen ------------------------------------------------------- #
    def op_ping(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"pong": True, "pid": os.getpid(), "version": __version__}

    def op_status(self, args: dict[str, Any]) -> dict[str, Any]:
        connected = self._connected()
        a = self.active
        idle_s = max(0, (self._mono() - self.last_activity) // 1_000_000_000)
        res = {
            "version": __version__,
            "pid": os.getpid(),
            "operator": {
                "exists": self.vault.exists,
                "unlocked": self.operator is not None,
                "handle": self.operator.handle if self.operator else None,
            },
            "project": self._project_info(),
            "rec": self.project is not None,
            "terminals": len(connected),
            "recording": sum(1 for t in connected if t.recording),
            "waiting": 0,
            "active": {"slug": a["slug"], "stopped": a["stopped"]} if a else None,
            "locked": self.operator is None,
            "idle": {"last_activity_ns": self.last_activity, "idle_s": idle_s,
                     "end_after_s": self.config.idle_end_s},
            "preroll": self._preroll_info(),
            "terminal_states": [self._terminal_state(t) for t in connected],
            "ingest": self._ingest_info(),
        }
        return self.redactor.redact_json(res)[0]

    async def op_init(self, args: dict[str, Any]) -> dict[str, Any]:
        passphrase = _arg_str(args, "passphrase") or ""
        handle = _arg_str(args, "handle", required=False, max_len=64) or "operator"
        if self.vault.exists:
            raise VaultExists("Operator-Tresor existiert bereits")
        code, op = await asyncio.to_thread(self.vault.create_and_unlock, passphrase, handle=handle)
        op.add_secret("ariadne:recovery", code)
        await asyncio.to_thread(op.save)
        self.operator = op
        self._runtime_secrets = [("ariadne:passphrase", passphrase)]
        self._update_redactor()
        log.info("Operator-Tresor angelegt")
        self._refresh_all()
        return {"recovery_code": code, "operator_id": op.operator_id, "handle": op.handle}

    async def op_unlock(self, args: dict[str, Any]) -> dict[str, Any]:
        """Entsperrt nur; geöffnet wird mit ``start`` (``reopened`` ist immer ``None``)."""
        passphrase = _arg_str(args, "passphrase", required=False)
        recovery = _arg_str(args, "recovery_code", required=False, max_len=128)
        if self.operator is not None:
            return {"already": True, "handle": self.operator.handle, "operator_id": self.operator.operator_id,
                    "reopened": None}
        if (passphrase is None) == (recovery is None):
            raise OpError("invalid", "genau eines: passphrase oder recovery_code")
        op = await asyncio.to_thread(self.vault.unlock, passphrase, recovery_code=recovery)
        if self.operator is not None:  # gleichzeitiges Entsperren
            op.wipe()
            return {"already": True, "handle": self.operator.handle, "operator_id": self.operator.operator_id,
                    "reopened": None}
        self.operator = op
        self._runtime_secrets = [("ariadne:passphrase", passphrase)] if passphrase else []
        self._update_redactor()
        log.info("Operator entsperrt")
        self._refresh_all()
        return {"already": False, "handle": op.handle, "operator_id": op.operator_id, "reopened": None}

    def op_lock(self, args: dict[str, Any]) -> dict[str, Any]:
        head = self._close_current("lock")
        self._lock_operator()
        log.info("Operator gesperrt")
        self._refresh_all()
        return {"closed_project": head is not None}

    async def op_start(self, args: dict[str, Any]) -> dict[str, Any]:
        """``ariadne start``: entsperren, Projekt öffnen oder anlegen, Vorlauf übernehmen (E22, E95)."""
        passphrase = _arg_str(args, "passphrase", required=False)
        slug = _arg_str(args, "slug", required=False, max_len=64)
        targets = self._targets(args)
        name = _arg_str(args, "name", required=False, max_len=200)
        profile = _arg_str(args, "profile", required=False, max_len=16) or "lab"
        adopt = args.get("adopt_preroll") is True
        self._activity()
        if not slug:
            a = self.active
            if a is not None and not a["stopped"]:
                slug = str(a["slug"])
            elif self.project is not None:
                slug = self.project.info.slug
            else:
                raise OpError("no_active_project",
                              "Kein aktives Projekt. ariadne start <slug> --target <ziel>")
        unlocked = False
        if self.operator is None:
            if not passphrase:
                raise OpError("locked", "gesperrt: Passphrase nötig")
            await self.op_unlock({"passphrase": passphrase})
            unlocked = True
        try:
            return self._start_open(slug, targets, args, name, profile, adopt, unlocked)
        except BaseException:
            if unlocked and self.project is None:
                self._lock_operator()  # gescheiterter Start lässt den Tresor nicht offen
            raise

    def _start_open(self, slug: str, targets: list[str] | None, args: dict[str, Any], name: str | None,
                    profile: str, adopt: bool, unlocked: bool) -> dict[str, Any]:
        created = targets_ignored = False
        existing = {s.slug for s in ProjectService(self.paths).list()}
        if slug not in existing:
            if not targets:
                raise ProjectNotFound(f"Projekt {slug} existiert nicht (mit --target anlegen)")
            self._service().create(slug, targets, name=name, not_customer=bool(args.get("not_customer")),
                                   profile=profile, origin="cli")
            created = True
        elif targets:
            targets_ignored = True
        before = self.project.info.slug if self.project is not None else None
        p = self._open_project(slug, refresh=False)
        switched = before if before is not None and before != p.info.slug else None
        if adopt:
            pre = self._adopt_preroll(p)
            pre["adopted"] = pre["terminals"] > 0
        else:
            info = self.preroll.info()
            pre = {"terminals": 0, "seconds": 0, "bytes": 0, "adopted": False,
                   "discarded_terminals": info["terminals"]}
            self.preroll.discard()
            self._departed.clear()
        self._refresh_all()
        self.writer.flush_now()
        log.info("Projekt gestartet")
        res: dict[str, Any] = {
            "slug": p.info.slug, "id": p.info.id, "profile": p.info.profile,
            "workspace": str(p.info.workspace), "created": created, "switched_from": switched,
            "unlocked": unlocked, "preroll": pre,
            "recording": sum(1 for t in self._connected() if t.recording),
        }
        if targets_ignored:
            res["targets_ignored"] = True
        return res

    def op_stop(self, args: dict[str, Any]) -> dict[str, Any]:
        """``ariadne stop``: Projekt beenden und sperren (``stopped: true``)."""
        a = self.active
        was = self.project is not None or (a is not None and not a["stopped"])
        slug, head = self._end_project("stop")
        res: dict[str, Any] = {"stopped": was, "slug": slug if was else None, "head_seq": None,
                               "head_hash": None}
        if head is not None:
            res["head_seq"], res["head_hash"] = head
        return res

    def op_preroll_info(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._preroll_info()

    def _pause_targets(self, args: dict[str, Any]) -> list[Terminal]:
        if args.get("all") is True:
            return self._connected()
        return [self._terminal(args)]

    def op_term_pause(self, args: dict[str, Any]) -> dict[str, Any]:
        minutes = _arg_int(args, "minutes", 1, MAX_PAUSE_MIN, self.config.pause_minutes)
        source = args.get("source") if args.get("source") in ("cli", "webui") else "cli"
        self._activity()
        out = []
        for t in self._pause_targets(args):
            until = self._set_pause(t, minutes, str(source))
            self._flash(t, f"Pause {minutes} min")
            out.append({"terminal_id": t.terminal_id, "until_ns": until})
        return {"paused": out}

    def op_term_resume(self, args: dict[str, Any]) -> dict[str, Any]:
        self._activity()
        out = []
        for t in self._pause_targets(args):
            if t.pause_until_ns is not None:
                self._set_pause(t, 0, "cli")
                self._flash(t, "Aufnahme läuft weiter")
                out.append(t.terminal_id)
        return {"resumed": out}

    def op_project_new(self, args: dict[str, Any]) -> dict[str, Any]:
        self._require_operator()
        slug = _arg_str(args, "slug", max_len=64) or ""
        targets = self._targets(args)
        if targets is None:
            raise OpError("invalid", "targets muss eine Liste von Strings sein")
        name = _arg_str(args, "name", required=False, max_len=200)
        info = self._service().create(slug, targets, name=name, not_customer=bool(args.get("not_customer")),
                                      profile=str(args.get("profile", "lab")), origin="cli")
        opened = False
        if args.get("open", True):
            self.preroll.discard()
            self._departed.clear()
            self._open_project(info.slug)
            opened = True
        return {"slug": info.slug, "id": info.id, "profile": info.profile, "workspace": str(info.workspace),
                "opened": opened}

    def op_project_open(self, args: dict[str, Any]) -> dict[str, Any]:
        self.preroll.discard()
        self._departed.clear()
        p = self._open_project(_arg_str(args, "slug", max_len=64) or "")
        return {"slug": p.info.slug, "id": p.info.id, "profile": p.info.profile,
                "workspace": str(p.info.workspace)}

    def op_project_close(self, args: dict[str, Any]) -> dict[str, Any]:
        """Wie ``stop``, aber ohne zu sperren."""
        head = self._close_current("stop")
        a = self.active
        if a is not None and not a["stopped"]:
            self._set_active(a["slug"], a["project_id"], stopped=True)
        self._refresh_all()
        if head is None:
            return {"closed": False}
        return {"closed": True, "head_seq": head[0], "head_hash": head[1]}

    def op_project_list(self, args: dict[str, Any]) -> dict[str, Any]:
        active = self.project.info.slug if self.project else None
        return {"projects": [
            {"slug": s.slug, "id": s.project_id, "profile": s.profile, "created_utc": s.created_utc,
             "active": s.slug == active}
            for s in ProjectService(self.paths).list()
        ]}

    def op_rec_status(self, args: dict[str, Any]) -> dict[str, Any]:
        """Kompatibilität: ``state`` ist ``on`` genau bei offenem Projekt (es gibt keinen Schalter)."""
        on = self.project is not None
        return {"rec": on, "state": "on" if on else "off", "project": self._project_info(),
                "recording": sum(1 for t in self._connected() if t.recording)}

    def op_rec_removed(self, args: dict[str, Any]) -> dict[str, Any]:
        raise OpError("removed", "REC gibt es nicht mehr: ariadne pause oder ariadne stop")

    def op_ctx_show(self, args: dict[str, Any]) -> dict[str, Any]:
        t = self._terminal(args)
        return {"terminal_id": t.terminal_id, "stack": t.stack.snapshot(), "label": t.stack.label()}

    def _op_ctx(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        t = self._terminal(args)
        try:
            return self._ctx_decision(t, op, host=args.get("host"), user=args.get("user"),
                                      stage_kind=args.get("kind"), origin="cli", source="cli")
        except ValueError as exc:
            raise OpError("invalid", str(exc)) from None

    def op_ctx_set(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._op_ctx("set", args)

    def op_ctx_push(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._op_ctx("push", args)

    def op_ctx_pop(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._op_ctx("pop", args)

    def op_terminals(self, args: dict[str, Any]) -> dict[str, Any]:
        out = []
        for t in self.terminals.values():
            state = self.state_of(t)
            out.append({
                "terminal_id": t.terminal_id, "shell": t.shell, "tty": t.tty, "connected": t.conn is not None,
                "status": self.status_of(t), "state": state, "recording": t.recording,
                "bound_project_id": t.bound_project_id, "label": t.stack.label(), "stream_off": t.recv_end,
                "paused": t.pause is not None,
                "pause_until_ns": t.pause_until_ns if state == "paused" else None,
                "mux": t.mux,
            })
        return {"terminals": out}

    def op_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        p = self._require_project()
        self.writer.flush_now()
        rep = p.journal.verify()
        blob_problems = p.blobs.verify()
        problems = rep.problems + blob_problems
        return {"ok": rep.ok and not blob_problems, "events": rep.events, "head_seq": rep.head_seq,
                "head_hash": rep.head_hash, "problems": problems[:100], "problem_count": len(problems)}

    def op_redact(self, args: dict[str, Any]) -> dict[str, Any]:
        p = self._require_project()
        seq = args.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            raise OpError("invalid", "seq ungültig")
        label = _arg_str(args, "label", max_len=64) or ""
        if not valid_label(label):
            raise OpError("invalid", "ungültiges Label")
        reason = _arg_str(args, "reason", max_len=500) or ""
        self.writer.flush_now()
        rec = p.journal.get(seq)
        if rec is None or rec.body is None:
            raise OpError("invalid", "Event existiert nicht oder hat keinen Body")
        body = bytearray(rec.body)
        rng = args.get("range")
        if rng is not None:
            if (not isinstance(rng, list) or len(rng) != 2
                    or not all(isinstance(x, int) and not isinstance(x, bool) for x in rng)):
                raise OpError("invalid", "range muss [start, end] sein")
            base = (rec.stream_off or 0) if rec.kind == "term.out" else 0
            a, b = rng[0] - base, rng[1] - base
            if not 0 <= a < b <= len(body):
                raise OpError("invalid", "range liegt ausserhalb des Bodys")
            body[a:b] = b"*" * (b - a)
        else:
            body[:] = b"*" * len(body)
        red = p.journal.redact(seq, label=label, replacement=bytes(body), reason=reason)
        with contextlib.suppress(Exception):
            p.journal.checkpoint(vacuum=True)
        self.run_commit_hooks([red])
        log.info("Redaktion geschrieben")
        return {"redaction_seq": red.seq, "ref_seq": seq}

    async def op_secrets_add(self, args: dict[str, Any]) -> dict[str, Any]:
        op = self._require_operator()
        label = _arg_str(args, "label", max_len=64) or ""
        value = _arg_str(args, "value") or ""
        op.add_secret(label, value)
        await asyncio.to_thread(op.save)
        self._update_redactor()
        return {"labels": op.secret_labels()}

    def op_secrets_list(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"labels": self._require_operator().secret_labels()}

    async def op_secrets_remove(self, args: dict[str, Any]) -> dict[str, Any]:
        op = self._require_operator()
        removed = op.remove_secret(_arg_str(args, "label", max_len=64) or "")
        if removed:
            await asyncio.to_thread(op.save)
            self._update_redactor()
        return {"removed": removed, "labels": op.secret_labels()}

    def op_pause_terminal(self, args: dict[str, Any]) -> dict[str, Any]:
        """Verwirft Ausgaben und Eingaben eines Terminals bis zum nächsten Prompt (``sensitive_output``).

        Gilt in allen Zuständen (auch Vorlauf und gesperrt). Kennt der Daemon das Terminal
        noch nicht (gerade gestartet), gilt die Anmeldung für sein erstes HELLO.
        """
        tid = _arg_str(args, "terminal_id", max_len=64) or ""
        t = self.terminals.get(tid)
        if t is None:
            if len(self._pending_sensitive) < 256:
                self._pending_sensitive[tid] = time.monotonic() + self.pause_timeout
            return {"paused": True, "pending": True}
        if t.pause is None:
            start = t.recv_end if t.recording else t.shim_off
            t.pause = Pause(start=start, end=start, deadline=time.monotonic() + self.pause_timeout)
        return {"paused": True}

    def op_resume_terminal(self, args: dict[str, Any]) -> dict[str, Any]:
        t = self._terminal(args)
        was = t.pause is not None
        self._end_pause(t, None)
        return {"resumed": was}

    # ---- Auswertung: Grundlage für ops_eval (stabile Schnittstelle) ---------- #
    def _ingest_info(self) -> dict[str, Any] | None:
        ing = self.ingest
        if ing is None:
            return None
        return {"active": ing.active, "runs": ing.runs, "last_error": ing.last_error}

    async def _sync_ingest(self) -> IngestService:
        """Alles Eingereihte speichern und auswerten."""
        self._require_project()
        ing = self.ingest
        if ing is None or not ing.active:
            raise OpError("no_ingest", "Auswertung nicht aktiv")
        self.writer.flush_now()
        await ing.sync()
        return ing

    def op_keystep_mark(self, args: dict[str, Any]) -> dict[str, Any]:
        p = self._require_project()
        step = _arg_str(args, "step", max_len=16)
        if step not in KEYSTEPS:
            raise OpError("invalid", "Schritt: foothold, privesc, pivot oder loot")
        note = _arg_str(args, "note", required=False, max_len=500)
        raw_host = _arg_str(args, "host", required=False, max_len=253)
        try:
            host = normalize_host(raw_host) if raw_host and raw_host.strip() else None
        except ValueError as exc:
            raise OpError("invalid", str(exc)) from None
        tid = _arg_str(args, "terminal_id", required=False, max_len=64)
        t = self.terminals.get(tid) if tid else None
        header: dict[str, Any] = {"step": step}
        item_tid = item_off = None
        if t is not None and t.recording and t.bound_project_id in (None, p.info.id):
            self._ensure_open(t)
            item_tid, item_off = t.terminal_id, t.recv_end
            header.update(terminal_id=item_tid, stream_off=item_off)
            if host is None:
                top = t.stack.top().host
                host = top if top and top != "local" else None
        if host:
            header["host"] = host
        if note:
            header["note"] = note
        self.submit(AppendItem("d.keystep.mark", header, origin="cli", terminal_id=item_tid,
                               stream_off=item_off))
        self.writer.flush_now()
        return {"step": step, "host": host, "terminal": item_tid is not None}

    async def op_import(self, args: dict[str, Any]) -> dict[str, Any]:
        self._require_project()
        path = _arg_str(args, "path", max_len=4096) or ""
        raw_host = _arg_str(args, "host", required=False, max_len=253)
        try:
            host = normalize_host(raw_host) if raw_host and raw_host.strip() else None
        except ValueError as exc:
            raise OpError("invalid", str(exc)) from None
        try:
            res = await self.sources.import_file(path, host)
        except UnsafeFile as exc:
            raise OpError("unsafe_file", _UNSAFE.get(exc.reason, "Datei abgelehnt")) from None
        self.writer.flush_now()
        log.info("Datei importiert")
        return res

    def op_shutdown(self, args: dict[str, Any]) -> dict[str, Any]:
        asyncio.get_running_loop().call_soon(self._stop.set)
        return {"stopping": True}


_UNSAFE = {
    "path": "Pfad ungültig (absolut, ohne .. und ohne leere Teile)",
    "symlink": "Symlink im Pfad: Ariadne folgt nie Symlinks",
    "symlink_or_not_dir": "Symlink oder kein Ordner im Pfad",
    "missing": "Datei nicht gefunden",
    "permission": "keine Leserechte",
    "not_regular": "keine reguläre Datei",
    "hardlink": "Datei hat mehrere harte Links",
    "owner": "Datei gehört weder dir noch root",
    "other_fs": "Datei liegt auf einem anderen Dateisystem",
    "too_large": "Datei zu gross",
    "blocked": "Pfad liegt in der Sperrliste (~/.ssh, ~/.gnupg, ~/.config, Ariadne-Daten, Browser, Keyrings)",
    "vault": "Pfad liegt in einem .vault",
    "no_project": "kein Projekt offen",
    "project_changed": "Projekt wurde während des Imports gewechselt",
    "open_failed": "Datei lässt sich nicht öffnen",
}


def _origin(source: str) -> str:
    return {"hotkey": "shim", "webui": "webui", "cli": "cli"}.get(source, "daemon")


def _error(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, OpError):
        return {"code": exc.code, "message": str(exc)}
    if isinstance(exc, GuardrailError):
        return {"code": "guardrail", "message": str(exc), "outside": exc.outside}
    table: list[tuple[type[BaseException], str]] = [
        (WrongPassphrase, "wrong_passphrase"),
        (InvalidRecoveryCode, "invalid_recovery"),
        (VaultExists, "vault_exists"),
        (VaultMissing, "vault_missing"),
        (VaultError, "vault"),
        (ProjectLocked, "project_locked"),
        (ProjectNotFound, "project_not_found"),
        (ProjectError, "project"),
        (WrongKeyError, "wrong_key"),
        (JournalError, "journal"),
    ]
    for cls, code in table:
        if isinstance(exc, cls):
            return {"code": code, "message": str(exc)}
    log.error("Operation fehlgeschlagen (%s)", type(exc).__name__)
    return {"code": "internal", "message": f"interner Fehler ({type(exc).__name__})"}


_OPS: dict[str, Callable[[Daemon, dict[str, Any]], Any]] = {
    "ping": Daemon.op_ping,
    "status": Daemon.op_status,
    "init": Daemon.op_init,
    "unlock": Daemon.op_unlock,
    "lock": Daemon.op_lock,
    "start": Daemon.op_start,
    "stop": Daemon.op_stop,
    "preroll.info": Daemon.op_preroll_info,
    "term.pause": Daemon.op_term_pause,
    "term.resume": Daemon.op_term_resume,
    "project.new": Daemon.op_project_new,
    "project.open": Daemon.op_project_open,
    "project.close": Daemon.op_project_close,
    "project.list": Daemon.op_project_list,
    "rec.on": Daemon.op_rec_status,
    "rec.status": Daemon.op_rec_status,
    "rec.off": Daemon.op_rec_removed,
    "rec.toggle": Daemon.op_rec_removed,
    "ctx.show": Daemon.op_ctx_show,
    "ctx.set": Daemon.op_ctx_set,
    "ctx.push": Daemon.op_ctx_push,
    "ctx.pop": Daemon.op_ctx_pop,
    "terminals": Daemon.op_terminals,
    "verify": Daemon.op_verify,
    "redact": Daemon.op_redact,
    "secrets.add": Daemon.op_secrets_add,
    "secrets.list": Daemon.op_secrets_list,
    "secrets.remove": Daemon.op_secrets_remove,
    "pause_terminal": Daemon.op_pause_terminal,
    "resume_terminal": Daemon.op_resume_terminal,
    "keystep.mark": Daemon.op_keystep_mark,
    "import": Daemon.op_import,
    "shutdown": Daemon.op_shutdown,
}
# Operationen der Auswertung (Ansichten, Suche, Claims, Reparse) liegen in ops_eval.
_OPS.update(ops_eval.OPS)
