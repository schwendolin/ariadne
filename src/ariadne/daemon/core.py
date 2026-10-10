"""Kern des Daemons ``ariadned`` (Architektur 3.6, 3.7, 8.6).

Ein asyncio-Prozess mit zwei Unix-Sockets im Runtime-Ordner (0700):

``term.sock``
    Rahmenprotokoll der Shims (:mod:`ariadne._shim.protocol`). Angenommen
    werden nur Verbindungen derselben UID (``SO_PEERCRED``), deren Prozess
    ``ariadne-shim`` heisst (abschaltbar für Tests).
``ctl.sock``
    Zeilenweises JSON ``{"op", "args"}`` -> ``{"ok", "result"|"error"}`` für die CLI.

REC-Zustand pro Terminal:

* ``off``: REC aus, oder das Terminal ist an ein anderes Projekt gebunden
  (Projektwechsel, Titel ``REC pausiert``). Rahmen werden verworfen und bestätigt.
* ``waiting``: REC an, aber kein Projekt offen (gesperrt). Rahmen bleiben
  unbestätigt im RAM, bis ein Projekt offen ist.
* ``on``: Aufnahme. Beim ersten REC bindet der Daemon das Terminal an das
  aktive Projekt (``term.open``, ``term.bind``, ``term.ctx_snapshot``).

Hotkey-Anfragen (EVENT ``req.*``, Felder neben ``seq`` und ``kind``):

* ``req.rec``      ``{"on": true | false | null}`` (null schaltet um)
* ``req.ctx.set``  ``{"host"?, "user"?, "stage_kind"?}`` setzt die oberste Stufe
* ``req.ctx.push`` ``{"host"?, "user"?, "stage_kind"?}`` legt eine Stufe an
* ``req.ctx.pop``  ``{}`` schliesst die oberste Stufe
* ``req.keystep``  ``{"step": foothold|privesc|pivot|loot, "host"?, "note"?}``
* ``req.shot``     ``{}`` (v0.1: nur Rückmeldung im Titel)

Hosts werden als ``ip:default/<ip>`` oder ``name:<name>`` gespeichert, nie
aufgelöst. Rückmeldungen kommen als ``STATE.title_extra`` (5 s).

Erweiterungen für die Auswertung:

* :meth:`Daemon.add_commit_hook` ``fn(records)`` nach jedem Commit, ausserhalb der
  Schreibtransaktion. Darf eine Coroutine zurückgeben (läuft dann als Task).
* :meth:`Daemon.add_mark_hook` ``fn(record, ctx)`` für jedes gespeicherte
  ``term.mark``, ``ctx`` ist ein :class:`~ariadne.daemon.terminal.MarkContext`.

Fehler in Hooks werden nur mit ihrer Klasse geloggt. Logs enthalten nie Inhalte.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
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
from ariadne.ctxrules import ContextStack, context_argv
from ariadne.daemon import hardening
from ariadne.daemon.terminal import (
    STAGE_KINDS,
    AckEntry,
    MarkContext,
    Pause,
    Terminal,
    normalize_host,
    normalize_user,
    parse_hello,
)
from ariadne.daemon.writer import Writer
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
from ariadne.store.api import AppendItem, EventRecord, JournalError

__all__ = ["Daemon", "OpError", "CommitHook", "MarkHook"]

log = logging.getLogger("ariadne.daemon")

CommitHook = Callable[[list[EventRecord]], Any]
MarkHook = Callable[[EventRecord, MarkContext | None], Any]

TERM_EVENTS = frozenset({
    "term.mark", "term.resize", "term.ctx_snapshot", "term.gap", "term.close",
    "term.osc52_blocked", "term.marker_forged",
})
REQUESTS = frozenset({"req.rec", "req.ctx.set", "req.ctx.push", "req.ctx.pop", "req.keystep", "req.shot"})
KEYSTEPS = frozenset({"foothold", "privesc", "pivot", "loot"})
_MARK_TEXT_FIELDS = ("cmd_typed", "cmd_expanded", "cwd", "user")


class OpError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _arg_str(args: dict[str, Any], key: str, *, required: bool = True, max_len: int = 4096) -> str | None:
    v = args.get(key)
    if v is None:
        if required:
            raise OpError("invalid", f"Argument fehlt: {key}")
        return None
    if not isinstance(v, str) or len(v) > max_len:
        raise OpError("invalid", f"Argument ungültig: {key}")
    return v


class Daemon:
    def __init__(
        self,
        paths: Paths,
        *,
        check_peer_comm: bool = True,
        operator: UnlockedOperator | None = None,
        batch_interval: float = 0.2,
        batch_bytes: int = 256 * 1024,
        idle_flush: float = 10.0,
        pause_timeout: float = 120.0,
        buffer_limit: int = 16 << 20,
        clock_check: Callable[[], Awaitable[dict[str, Any]]] | None = None,
    ) -> None:
        self.paths = paths
        self.check_peer_comm = check_peer_comm
        self.vault = OperatorVault(paths.operator_dir)
        self.operator = operator
        self.project: OpenProject | None = None
        self.rec_on = False
        self.terminals: dict[str, Terminal] = {}
        self.redactor = Redactor()
        self.writer = Writer(self, interval=batch_interval, max_bytes=batch_bytes)
        self.idle_flush = idle_flush
        self.pause_timeout = pause_timeout
        self.buffer_limit = buffer_limit
        self._clock_check = clock_check or hardening.clock_status
        self._runtime_secrets: list[tuple[str, str]] = []
        self._commit_hooks: list[CommitHook] = []
        self._mark_hooks: list[MarkHook] = []
        self._servers: list[asyncio.base_events.Server] = []
        self._tasks: set[asyncio.Task[Any]] = set()
        self._writer_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._lock = hardening.InstanceLock(paths.runtime_dir / "daemon.lock")
        self._last_slug: str | None = None
        self._started = False
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
            self._close_current("daemon_down")
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
            if (t.recording and t.last_out and now - t.last_out >= self.idle_flush
                    and self.redactor.pending(t.terminal_id) is not None):
                self.writer.add_flush(t)
        if self.writer.pending or self.writer._carry:
            self.writer.flush_now()

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

    def status_of(self, t: Terminal) -> str:
        if not self.rec_on:
            return "off"
        if self.project is None:
            return "waiting"
        if t.bound_project_id is None or t.bound_project_id == self.project.info.id:
            return "on"
        return "off"

    def _state(self, t: Terminal) -> dict[str, Any]:
        status = self.status_of(t)
        p = self.project
        extra = t.title_extra
        if (extra is None and self.rec_on and p is not None and t.bound_project_id
                and t.bound_project_id != p.info.id):
            extra = f"REC pausiert: {t.bound_slug}"
        return {
            "rec": status,
            "project": p.info.slug if p else None,
            "project_id": p.info.id if p else None,
            "profile": p.info.profile if p else None,
            "bound_project_id": t.bound_project_id,
            "stack": t.stack.snapshot(),
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
        """Bringt Aufnahmezustand und Puffer eines Terminals mit dem globalen Zustand in Einklang."""
        status = self.status_of(t)
        if status == "on":
            if not t.recording:
                self._start_recording(t)
            while t.buffer:
                ftype, payload, entry = t.buffer.popleft()
                t.buffer_bytes -= len(payload)
                self._process_frame(t, ftype, payload, entry)
        elif status == "off":
            if t.recording:
                self._stop_recording(t, "rec_off" if not self.rec_on else "project_switch")
            while t.buffer:
                _, payload, entry = t.buffer.popleft()
                entry.ready = True
            t.buffer_bytes = 0
        self._advance_ack(t)
        self._send_state(t)

    def _refresh_all(self) -> None:
        for t in list(self.terminals.values()):
            self._refresh(t)

    def _start_recording(self, t: Terminal) -> None:
        p = self.project
        assert p is not None
        if t.bound_project_id is None:
            t.bound_project_id = p.info.id
            t.bound_slug = p.info.slug
        tid = t.terminal_id
        if p.info.id not in t.opened_in:
            end = p.journal.stream_end(tid)
            t.recv_end = max(t.recv_end, end)
            t.stored_end = max(t.stored_end, end)
            header = {
                "terminal_id": tid, "tty": t.tty, "shell": t.shell, "term": t.term, "rows": t.rows,
                "cols": t.cols, "tmux_pane": t.tmux_pane, "window_id": t.window_id,
                "shim_version": t.shim_version,
            }
            self.writer.add_event(AppendItem("term.open", {k: v for k, v in header.items() if v is not None},
                                             origin="daemon", terminal_id=tid, stream_off=t.recv_end), t)
            self.writer.add_event(AppendItem("term.bind", {"terminal_id": tid, "project_id": p.info.id},
                                             origin="daemon", terminal_id=tid, stream_off=t.recv_end), t)
            t.opened_in.add(p.info.id)
        self.writer.add_event(AppendItem(
            "term.ctx_snapshot", {"terminal_id": tid, "stream_off": t.recv_end, "stack": t.stack.snapshot()},
            origin="daemon", terminal_id=tid, stream_off=t.recv_end), t)
        t.gap_hint = t.gap_hint or "rec_off"
        t.recording = True

    def _stop_recording(self, t: Terminal, hint: str) -> None:
        if t.pause is not None:
            self._end_pause(t, None)  # Lücke mit Grund sensitive_output zuerst vermerken
        self.writer.add_flush(t)
        t.recording = False
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
                    if frame.type not in (P.OUT, P.EVENT):
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
            t = Terminal(tid)
            resume = h["resume_from_seq"]
            if resume:
                t.max_seq = t.acked_seq = max(0, resume - 1)
            self.terminals[tid] = t
        elif t.conn is not None and t.conn is not writer:
            with contextlib.suppress(Exception):
                t.conn.close()
        for k in ("tty", "shell", "term", "rows", "cols", "tmux_pane", "window_id", "shim_version",
                  "display"):
            setattr(t, k, h[k])
        t.pid = pid
        t.conn = writer
        t.closed = False
        t.last_state = None
        log.info("Terminal verbunden")
        self._refresh(t)
        if t.acked_seq:
            self._send(t, P.encode_json(P.ACK, {"seq": t.acked_seq}))
        return t

    def _on_bye(self, t: Terminal) -> None:
        if t.recording and not t.closed:
            self.writer.add_event(AppendItem(
                "term.close", {"terminal_id": t.terminal_id, "stream_off": t.recv_end},
                origin="daemon", terminal_id=t.terminal_id, stream_off=t.recv_end), t)
        if t.recording:
            self.writer.add_flush(t)
            self.writer.flush_now()
        self.terminals.pop(t.terminal_id, None)
        log.info("Terminal beendet")

    def _on_frame(self, t: Terminal, ftype: int, payload: bytes) -> None:
        obj: dict[str, Any] | None = None
        if ftype == P.OUT:
            seq = P.decode_out(payload)[0]
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
        t.max_seq = seq
        entry = AckEntry(seq)
        t.ack_queue.append(entry)
        kind = obj.get("kind") if obj is not None else None
        if obj is not None and isinstance(kind, str) and kind in REQUESTS:
            self._on_request(t, kind, obj, entry)
            self._advance_ack(t)
            return
        if self.status_of(t) == "waiting":
            t.buffer.append((ftype, payload, entry))
            t.buffer_bytes += len(payload)
            while t.buffer_bytes > self.buffer_limit and t.buffer:
                _, old, old_entry = t.buffer.popleft()
                t.buffer_bytes -= len(old)
                old_entry.ready = True
                t.gap_hint = "buffer_overflow"
            return
        self._process_frame(t, ftype, payload, entry)
        self._advance_ack(t)

    def _process_frame(self, t: Terminal, ftype: int, payload: bytes, entry: AckEntry) -> None:
        if ftype == P.OUT:
            _seq, off, wall, mono, data = P.decode_out(payload)
            self._process_out(t, off, wall, mono, data, entry)
        else:
            obj = P.decode_json(payload)
            self._process_event(t, obj, entry)

    def _process_out(self, t: Terminal, off: int, wall: int, mono: int, data: bytes, entry: AckEntry) -> None:
        entry.ready = True
        if not t.recording:
            return
        end = off + len(data)
        if t.pause is not None:
            t.pause.end = max(t.pause.end, end)
            return
        if end <= t.recv_end:
            return
        if off < t.recv_end:
            data = data[t.recv_end - off:]
            off = t.recv_end
        elif off > t.recv_end:
            self.writer.add_event(AppendItem(
                "term.gap",
                {"terminal_id": t.terminal_id, "stream_off": t.recv_end,
                 "reason": t.gap_hint or "shim_error", "bytes_lost": off - t.recv_end},
                origin="daemon", terminal_id=t.terminal_id, stream_off=t.recv_end), t)
        t.gap_hint = None
        t.recv_end = end
        t.note_frame(off, wall, mono)
        t.last_out = time.monotonic()
        entry.need_end = end
        entry.need_gen = self.writer.pending_gen
        self.writer.add_out(t, off, data)

    def _process_event(self, t: Terminal, obj: dict[str, Any], entry: AckEntry) -> None:
        entry.ready = True
        kind = obj.get("kind")
        if not isinstance(kind, str) or kind not in TERM_EVENTS:
            log.warning("Unbekannte Event-Art vom Shim verworfen")
            return
        header = {k: v for k, v in obj.items() if k not in ("seq", "kind")}
        header["terminal_id"] = t.terminal_id
        labels: list[str] = []
        if kind == "term.mark":
            for key in _MARK_TEXT_FIELDS:
                if isinstance(header.get(key), str):
                    header[key], hit = self.redactor.redact_text(header[key])
                    labels += hit
            if isinstance(header.get("cmd_vars"), dict):
                cleaned = {}
                for k, v in header["cmd_vars"].items():
                    cleaned[k], hit = self.redactor.redact_text(v) if isinstance(v, str) else (v, [])
                    labels += hit
                header["cmd_vars"] = cleaned
        try:
            header = events.validate_header(str(kind), header)
        except ValueError:
            log.warning("Ungültiges %s vom Shim verworfen", kind)
            return
        off = header.get("stream_off")
        mark_ctx: MarkContext | None = None
        before = t.stack.snapshot()
        local_before = t.stack.is_local()
        if kind == "term.mark":
            mark = header["mark"]
            if mark == "C":
                cmd = header.get("cmd_expanded") or header.get("cmd_typed") or ""
                t.stack.on_command_start(context_argv(cmd), int(off or 0))
            elif mark == "D" and header.get("fg_shell"):
                t.stack.on_command_end(header.get("exit"), int(off or 0))
            if mark in ("A", "D") and header.get("fg_shell") and t.pause is not None:
                self._end_pause(t, off)
            if self.project is not None:
                mark_ctx = MarkContext(t.terminal_id, self.project.info.id, tuple(t.stack.snapshot()),
                                       t.stack.is_local(), local_before)
        elif kind == "term.ctx_snapshot":
            t.stack = ContextStack.from_snapshot(header["stack"])
        elif kind == "term.resize":
            t.rows, t.cols = int(header["rows"]), int(header["cols"])
        elif kind == "term.gap" and t.recording:
            t.recv_end = max(t.recv_end, int(header["stream_off"]) + int(header.get("bytes_lost", 0)))
        elif kind == "term.close":
            t.closed = True
        if t.recording:
            self.writer.add_event(AppendItem(str(kind), header, origin="shim", terminal_id=t.terminal_id,
                                             stream_off=off), t, mark_ctx)
            entry.need_gen = self.writer.pending_gen
        if labels:
            log.info("Redaktor: %d Treffer in Marker-Feldern", len(labels))
        if t.stack.snapshot() != before:
            self._send_state(t)

    # ---- Pause bei Schlüsselmaterial -------------------------------------- #
    def _end_pause(self, t: Terminal, at_off: int | None) -> None:
        pause = t.pause
        if pause is None:
            return
        t.pause = None
        if not t.recording:
            return
        end = max(pause.end, at_off or 0, t.recv_end)
        self.writer.add_event(AppendItem(
            "term.gap",
            {"terminal_id": t.terminal_id, "stream_off": pause.start, "reason": "sensitive_output",
             "bytes_lost": end - pause.start},
            origin="daemon", terminal_id=t.terminal_id, stream_off=pause.start), t)
        t.recv_end = end

    # ---- Hotkey-Anfragen ----------------------------------------------------- #
    def _can_store_decision(self, t: Terminal) -> bool:
        p = self.project
        return p is not None and t.bound_project_id in (None, p.info.id)

    def _on_request(self, t: Terminal, kind: str, obj: dict[str, Any], entry: AckEntry) -> None:
        entry.ready = True
        try:
            if kind == "req.rec":
                on = obj.get("on")
                if on is not None and not isinstance(on, bool):
                    raise ValueError("on")
                self._set_rec(not self.rec_on if on is None else on, source="hotkey",
                              terminal_id=t.terminal_id)
            elif kind in ("req.ctx.set", "req.ctx.push", "req.ctx.pop"):
                stage_kind = obj.get("stage_kind", obj.get("ctx_kind"))
                self._ctx_decision(t, kind.rsplit(".", 1)[1], host=obj.get("host"), user=obj.get("user"),
                                   stage_kind=stage_kind, origin="shim", source="hotkey")
            elif kind == "req.keystep":
                self._keystep(t, obj)
            elif kind == "req.shot":
                self._flash(t, "Screenshots kommen in einer späteren Version")
            if self.writer.pending:
                entry.need_gen = self.writer.pending_gen
        except (ValueError, TypeError, OpError):
            self._flash(t, "Eingabe ungültig")

    def _ctx_decision(self, t: Terminal, op: str, *, host: Any = None, user: Any = None,
                      stage_kind: Any = None, origin: str, source: str) -> dict[str, Any]:
        host_n = normalize_host(host) if isinstance(host, str) and host.strip() else None
        user_n = normalize_user(user) if isinstance(user, str) and user.strip() else None
        if stage_kind is not None and (not isinstance(stage_kind, str) or stage_kind not in STAGE_KINDS):
            raise ValueError("ungültige Stufe")
        off = t.recv_end
        tid = t.terminal_id
        if op == "set":
            if host_n is None and user_n is None and stage_kind is None:
                raise ValueError("nichts zu setzen")
            t.stack.set_top(host=host_n, user=user_n, kind=stage_kind, source=source)
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
        stored = self._can_store_decision(t)
        if stored:
            self.writer.add_event(AppendItem(kind, header, origin=origin, terminal_id=tid, stream_off=off), t)
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
        header = {"terminal_id": t.terminal_id, "stream_off": t.recv_end, "step": step, "host": host_n,
                  "note": note}
        self.writer.add_event(AppendItem("d.keystep.mark", {k: v for k, v in header.items() if v is not None},
                                         origin="shim", terminal_id=t.terminal_id, stream_off=t.recv_end), t)
        self._flash(t, f"Schlüsselschritt: {step}")

    # ================================================================== #
    # REC und Projekte
    # ================================================================== #
    def _set_rec(self, on: bool, *, source: str, terminal_id: str | None = None) -> None:
        if on == self.rec_on:
            self._refresh_all()
            return
        p = self.project
        header: dict[str, Any] = {"on": on, "source": source}
        if terminal_id:
            header["terminal_id"] = terminal_id
        if not on:
            self.rec_on = False
            for t in self.terminals.values():
                if t.recording:
                    self._stop_recording(t, "rec_off")
            if p is not None:
                self.writer.add_event(AppendItem("rec.set", header, origin=_origin(source)))
                self._checkpoint("rec_off")
        else:
            self.rec_on = True
            if p is not None:
                self.writer.add_event(AppendItem("rec.set", header, origin=_origin(source)))
                self._spawn(self._clock_task(p))
        log.info("REC %s (%s)", "an" if on else "aus", source)
        self._refresh_all()

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

    def _open_project(self, slug: str) -> OpenProject:
        if self.project is not None and self.project.info.slug == slug:
            return self.project
        if self.operator is None:
            raise OpError("locked", "Operator ist gesperrt (ariadne unlock)")
        new = self._service().open(slug)
        if not new.head_ok:
            log.warning("Kettenkopf beim Öffnen ungültig, ariadne verify ausführen")
        if self.project is not None:
            self._close_current("project_switch")
        self.project = new
        self._last_slug = slug
        self._update_redactor()
        if self.rec_on:  # REC lief schon (wartend): im neuen Journal vermerken
            self.writer.add_event(AppendItem("rec.set", {"on": True, "source": "system"}, origin="daemon"))
        self._spawn(self._clock_task(new))
        log.info("Projekt geöffnet")
        self._refresh_all()
        return new

    def _close_current(self, hint: str) -> tuple[int, str] | None:
        p = self.project
        if p is None:
            return None
        for t in self.terminals.values():
            if t.recording:
                if hint == "project_switch":
                    self.writer.add_event(AppendItem(
                        "term.gap", {"terminal_id": t.terminal_id, "stream_off": t.recv_end,
                                     "reason": "project_switch", "bytes_lost": 0},
                        origin="daemon", terminal_id=t.terminal_id, stream_off=t.recv_end), t)
                self._stop_recording(t, "project_switch" if hint == "project_switch" else "locked")
        try:
            self.writer.flush_now()
        finally:
            self.writer.drop_carry()
            self.project = None
            head = p.close()
            self._update_redactor()
        log.info("Projekt geschlossen")
        return head

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
            raise OpError("locked", "Operator ist gesperrt (ariadne unlock)")
        return self.operator

    def _require_project(self) -> OpenProject:
        if self.project is None:
            raise OpError("no_project", "kein Projekt offen (ariadne project open <slug>)")
        return self.project

    def _terminal(self, args: dict[str, Any]) -> Terminal:
        tid = _arg_str(args, "terminal_id", max_len=64)
        t = self.terminals.get(str(tid))
        if t is None:
            raise OpError("unknown_terminal", "Terminal unbekannt (läuft der Shim in diesem Terminal?)")
        return t

    def _project_info(self) -> dict[str, Any] | None:
        p = self.project
        if p is None:
            return None
        return {"slug": p.info.slug, "id": p.info.id, "profile": p.info.profile,
                "workspace": str(p.info.workspace), "chain_head_ok": p.head_ok}

    # ---- Operationen ------------------------------------------------------- #
    def op_ping(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"pong": True, "pid": os.getpid(), "version": __version__}

    def op_status(self, args: dict[str, Any]) -> dict[str, Any]:
        connected = [t for t in self.terminals.values() if t.conn is not None]
        return {
            "version": __version__,
            "pid": os.getpid(),
            "operator": {
                "exists": self.vault.exists,
                "unlocked": self.operator is not None,
                "handle": self.operator.handle if self.operator else None,
            },
            "project": self._project_info(),
            "rec": self.rec_on,
            "terminals": len(connected),
            "recording": sum(1 for t in connected if t.recording),
            "waiting": sum(1 for t in connected if self.status_of(t) == "waiting"),
        }

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
        passphrase = _arg_str(args, "passphrase", required=False)
        recovery = _arg_str(args, "recovery_code", required=False, max_len=128)
        if self.operator is not None:
            return {"already": True, "handle": self.operator.handle, "operator_id": self.operator.operator_id}
        if (passphrase is None) == (recovery is None):
            raise OpError("invalid", "genau eines: passphrase oder recovery_code")
        op = await asyncio.to_thread(self.vault.unlock, passphrase, recovery_code=recovery)
        if self.operator is not None:  # gleichzeitiges Entsperren
            op.wipe()
            return {"already": True, "handle": self.operator.handle, "operator_id": self.operator.operator_id}
        self.operator = op
        self._runtime_secrets = [("ariadne:passphrase", passphrase)] if passphrase else []
        self._update_redactor()
        log.info("Operator entsperrt")
        reopened = None
        if self.rec_on and self._last_slug and self.project is None:
            with contextlib.suppress(ProjectError, OpError, WrongKeyError):
                reopened = self._open_project(self._last_slug).info.slug
        self._refresh_all()
        return {"already": False, "handle": op.handle, "operator_id": op.operator_id, "reopened": reopened}

    def op_lock(self, args: dict[str, Any]) -> dict[str, Any]:
        head = self._close_current("locked")
        self._lock_operator()
        log.info("Operator gesperrt")
        self._refresh_all()
        return {"closed_project": head is not None}

    def op_project_new(self, args: dict[str, Any]) -> dict[str, Any]:
        self._require_operator()
        slug = _arg_str(args, "slug", max_len=64) or ""
        targets = args.get("targets")
        if (not isinstance(targets, list) or len(targets) > 256
                or not all(isinstance(x, str) for x in targets)):
            raise OpError("invalid", "targets muss eine Liste von Strings sein")
        name = _arg_str(args, "name", required=False, max_len=200)
        info = self._service().create(slug, targets, name=name, not_customer=bool(args.get("not_customer")),
                                      profile=str(args.get("profile", "lab")), origin="cli")
        opened = False
        if args.get("open", True):
            self._open_project(info.slug)
            opened = True
        return {"slug": info.slug, "id": info.id, "profile": info.profile, "workspace": str(info.workspace),
                "opened": opened}

    def op_project_open(self, args: dict[str, Any]) -> dict[str, Any]:
        p = self._open_project(_arg_str(args, "slug", max_len=64) or "")
        return {"slug": p.info.slug, "id": p.info.id, "profile": p.info.profile,
                "workspace": str(p.info.workspace)}

    def op_project_close(self, args: dict[str, Any]) -> dict[str, Any]:
        head = self._close_current("locked")
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

    def op_rec_on(self, args: dict[str, Any]) -> dict[str, Any]:
        self._set_rec(True, source=_rec_source(args))
        return self.op_rec_status(args)

    def op_rec_off(self, args: dict[str, Any]) -> dict[str, Any]:
        self._set_rec(False, source=_rec_source(args))
        return self.op_rec_status(args)

    def op_rec_toggle(self, args: dict[str, Any]) -> dict[str, Any]:
        self._set_rec(not self.rec_on, source=_rec_source(args))
        return self.op_rec_status(args)

    def op_rec_status(self, args: dict[str, Any]) -> dict[str, Any]:
        connected = [t for t in self.terminals.values() if t.conn is not None]
        state = "off"
        if self.rec_on:
            state = "on" if self.project is not None else "waiting"
        return {"rec": self.rec_on, "state": state, "project": self._project_info(),
                "recording": sum(1 for t in connected if t.recording)}

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
        return {"terminals": [
            {"terminal_id": t.terminal_id, "shell": t.shell, "tty": t.tty, "connected": t.conn is not None,
             "status": self.status_of(t), "recording": t.recording, "bound_project_id": t.bound_project_id,
             "label": t.stack.label(), "stream_off": t.recv_end, "paused": t.pause is not None}
            for t in self.terminals.values()
        ]}

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
        """Pausiert die Aufnahme eines Terminals bis zum nächsten Prompt (``sensitive_output``)."""
        tid = _arg_str(args, "terminal_id", max_len=64)
        t = self.terminals.get(str(tid))
        if t is None or not t.recording:
            return {"paused": False}
        if t.pause is None:
            self.writer.add_flush(t)
            t.pause = Pause(start=t.recv_end, end=t.recv_end, deadline=time.monotonic() + self.pause_timeout)
        return {"paused": True}

    def op_resume_terminal(self, args: dict[str, Any]) -> dict[str, Any]:
        t = self._terminal(args)
        was = t.pause is not None
        self._end_pause(t, None)
        return {"resumed": was}

    def op_shutdown(self, args: dict[str, Any]) -> dict[str, Any]:
        asyncio.get_running_loop().call_soon(self._stop.set)
        return {"stopping": True}


def _origin(source: str) -> str:
    return {"hotkey": "shim", "webui": "webui", "cli": "cli"}.get(source, "daemon")


def _rec_source(args: dict[str, Any]) -> str:
    src = args.get("source", "cli")
    return src if src in ("cli", "webui") else "cli"


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
    "project.new": Daemon.op_project_new,
    "project.open": Daemon.op_project_open,
    "project.close": Daemon.op_project_close,
    "project.list": Daemon.op_project_list,
    "rec.on": Daemon.op_rec_on,
    "rec.off": Daemon.op_rec_off,
    "rec.toggle": Daemon.op_rec_toggle,
    "rec.status": Daemon.op_rec_status,
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
    "shutdown": Daemon.op_shutdown,
}
