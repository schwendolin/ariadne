"""PTY-Relay und Hauptschleife des Shims (Architektur 3.1, 3.2, 3.6).

Nur Standardbibliothek. Eine ``selectors``-Schleife ohne Threads:

* stdin -> Hotkey-Filter -> Master (nur echte Nutzertasten)
* Master -> Scanner -> Anzeige (stdout) und Aufnahme (Transport)
* Rückstau: Kommt das Terminal nicht nach, liest der Shim den Master nicht
  weiter, stdin aber schon (Ctrl-C geht sofort durch).
* Signale über ``set_wakeup_fd``: SIGWINCH, SIGCHLD, SIGHUP, SIGTERM.

Der Start (Prüfungen, PTY, fork) liegt in :mod:`ariadne._shim.launch`; dieses
Modul lädt erst danach. Ein Fehler im Aufnahmecode schaltet nur die Aufnahme
ab; stürzt die Schleife selbst, übernimmt ein einfaches Relay.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import re
import selectors
import signal
import termios
import time
from typing import Any

from ariadne import __version__
from ariadne._shim.hotkey import Armed, Cancelled, Forward, InputFilter, Key, describe_prefix, parse_hotkey
from ariadne._shim.launch import Spawned, exit_code, make_raw, set_winsize, winsize
from ariadne._shim.markers import MarkerValidator, mark_event
from ariadne._shim.miniprompt import LinePrompt, parse_user_host
from ariadne._shim.ringbuf import FrameRing, capacity_from_env
from ariadne._shim.scanner import AltScreen, Forged, Marker, Osc52, OutputScanner, ScanResult, Title
from ariadne._shim.title import Link, TitleWriter, compose_title
from ariadne._shim.transport import Transport
from ariadne.ctxrules import ContextStack, Stage, context_argv
from ariadne.paths import default_paths

__all__ = ["Shim"]

READ_SIZE = 65536
DISP_HIGH = 256 * 1024
DELAY_MAX = 4 << 20
CHILD_HIGH = 1 << 20
DRAIN_IDLE_S = 0.1
DRAIN_MAX_S = 2.0
HUP_WAIT_S = 1.0
NOTICE_S = 3.0
PROMPT_IDLE_S = 120.0
TITLE_FIRST_S = 0.3
CPR_SWALLOW_S = 0.5
DISPLAY_KEYS = ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR")
_CPR = re.compile(rb"\x1b\[\d{1,4};\d{1,4}R")
_REC_STATES = ("on", "off", "waiting", "offline")
_STAGE_KINDS = {"local", "su", "ssh", "winrm", "remote", "revshell", "msf", "meterpreter", "db", "unknown"}
_HELP = ("r REC, h Host, b Stufe zurück, k Schlüsselschritt, s Screenshot, "
         "2x Präfix sendet ihn durch. Taste schliesst.")
_KEYSTEPS = {"f": "foothold", "p": "privesc", "v": "pivot", "l": "loot"}


# --------------------------------------------------------------------------- #
# Hilfen
# --------------------------------------------------------------------------- #


def _set_nonblock(fd: int, on: bool) -> int:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, (flags | os.O_NONBLOCK) if on else (flags & ~os.O_NONBLOCK))
    return flags


def _clean_stack(data: Any) -> list[dict] | None:
    """``STATE.stack`` vom Daemon prüfen; nur saubere Stufen übernehmen."""
    if not isinstance(data, list) or not data or len(data) > 64:
        return None
    out: list[dict] = []
    for d in data:
        if not isinstance(d, dict) or d.get("kind") not in _STAGE_KINDS:
            return None
        st: dict[str, Any] = {"kind": d["kind"]}
        for key in ("host", "user", "candidate"):
            v = d.get(key)
            if isinstance(v, str) and len(v) <= 255:
                st[key] = v
        st["opened_at"] = d["opened_at"] if type(d.get("opened_at")) is int else 0
        st["state"] = "suspended" if d.get("state") == "suspended" else "active"
        src = d.get("source")
        st["source"] = src if src in ("auto", "hotkey", "webui", "cli", "suggestion") else "auto"
        out.append(st)
    return out


def _noop(_sig: int, _frame: object) -> None:
    return None


# --------------------------------------------------------------------------- #
# Shim
# --------------------------------------------------------------------------- #


class Shim:
    def __init__(self, sp: Spawned) -> None:
        self.sp = sp
        self.argv = sp.argv
        self.env = sp.env
        self.hotkey_name, prefix = parse_hotkey(self.env.get("ARIADNE_HOTKEY"))
        self.input = InputFilter(prefix)
        self.terminal_id = sp.terminal_id
        self.nonce = sp.nonce
        self.scanner: OutputScanner | None = OutputScanner()
        self.stack = ContextStack()
        self.titles = TitleWriter()
        self.transport: Transport | None = None
        self.validator: MarkerValidator | None = None
        self.child = sp.child
        self.master = sp.master
        self.tty_name = sp.tty_name
        self.rows, self.cols = sp.rows, sp.cols
        self.exit_code = 0
        # Laufzeitzustand
        self.capture = False
        self.inner_title: str | None = None
        self.hosts: list[str] = []
        self._rec: str | None = None
        self._last_rec: str | None = None
        self._drop_from: int | None = None
        self._lost_since: int | None = 0
        self._lost_reason = "daemon_down"
        self._rec_broken = False
        self._ctx_version: int | None = None  # STATE.ctx_version, zuletzt übernommen
        self._daemon_id: str | None = None
        self._bound_id: str | None = None
        self._bound_slug: str | None = None
        self._disp = bytearray()
        self._delayed = bytearray()
        self._to_child = bytearray()
        self._notice: str | None = None
        self._notice_until = 0.0
        self._title_due = 0.0
        self._title_live = False
        self.prompt: LinePrompt | None = None
        self._prompt_kind = ""
        self._prompt_t = 0.0
        self._keystep: str | None = None
        self._cpr_until = 0.0
        self._sig_r = -1
        self._sig_w = -1
        self._saved_attrs: list[Any] | None = None
        self._saved_flags: dict[int, int] = {}
        self._master_eof = False
        self._master_eof_t = 0.0
        self._last_master = 0.0
        self._child_status: int | None = None
        self._child_exit_t = 0.0
        self._hup = False
        self._sel: selectors.BaseSelector | None = None
        self._reg: dict[int, int] = {}
        self._reg_sock: object | None = None

    # ------------------------------------------------------------ Start

    def setup(self) -> None:
        """Nach dem fork: Signale, Raw-Mode, Transport. Wirft bei Fehlern (dann Notfall-Relay)."""
        try:
            self._setup()
        except BaseException:
            self._restore_tty()
            with contextlib.suppress(OSError, ValueError):
                signal.set_wakeup_fd(-1)
            raise

    def _setup(self) -> None:
        self._sig_r, self._sig_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        signal.set_wakeup_fd(self._sig_w, warn_on_full_buffer=False)
        for sig in (signal.SIGWINCH, signal.SIGCHLD, signal.SIGHUP, signal.SIGTERM):
            signal.signal(sig, _noop)
        for sig in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU):
            signal.signal(sig, signal.SIG_IGN)
        self.validator = MarkerValidator(self.nonce, self.child, self.master)
        self._saved_attrs = self.sp.attrs
        for fd in (0, 1, self.master):
            self._saved_flags.setdefault(fd, _set_nonblock(fd, True))
        termios.tcsetattr(0, termios.TCSANOW, make_raw(self.sp.attrs))
        # Was vor dem Installieren der Handler geschah, nicht verpassen.
        now = time.monotonic()
        self._reap(now)
        if winsize(0) != (self.rows, self.cols):
            self._resize(now)
        self._open_transport()

    def _open_transport(self) -> None:
        try:
            sock = str(default_paths(self.env).term_sock)
            ring = FrameRing(capacity_from_env(self.env.get("ARIADNE_SHIM_BUFFER_MB")))
            self.transport = Transport(sock, self.terminal_id, self._hello, ring,
                                       on_state=self._on_state_cb, on_disconnect=self._on_disconnect_cb)
            self.transport.try_connect(time.monotonic())
            self._update_capture(time.monotonic())
        except Exception:
            self.transport = None
            self._rec_broken = True

    def _hello(self) -> dict[str, Any]:
        return {
            "proto": 1,
            "terminal_id": self.terminal_id,
            "tty": self.tty_name,
            "shell": self.argv[0],
            "term": self.env.get("TERM"),
            "rows": self.rows,
            "cols": self.cols,
            "tmux_pane": self.env.get("TMUX_PANE"),
            "window_id": self.env.get("WINDOWID"),
            "shim_version": __version__,
            "pid": os.getpid(),
            "display": {k: self.env.get(k) for k in DISPLAY_KEYS},
            # Nach einem Daemon-Neustart kennt nur der Shim Stapel und Projektbindung.
            "stack": self.stack.snapshot(),
            "bound_project_id": self._bound_id,
            "bound_slug": self._bound_slug,
        }

    # --------------------------------------------------------- Schleife

    def serve(self) -> int:
        try:
            try:
                self._loop()
            except Exception:
                self._broken()
                self._plain_loop()
        finally:
            self._shutdown()
        return self.exit_code

    def _loop(self) -> None:
        sel = selectors.DefaultSelector()
        self._sel = sel
        sel.register(self._sig_r, selectors.EVENT_READ, "sig")
        now = time.monotonic()
        self._title_due = now + TITLE_FIRST_S
        self._last_master = now
        while not self._finished(now):
            self._sync(sel)
            try:
                events = sel.select(self._timeout(now))
            except InterruptedError:
                events = []
            now = time.monotonic()
            for key, mask in events:
                tag = key.data
                if tag == "sig":
                    self._on_signals(now)
                elif tag == "stdin":
                    self._on_stdin(now)
                elif tag == "stdout":
                    self._on_stdout(now)
                elif tag == "master":
                    if mask & selectors.EVENT_READ:
                        self._on_master(now)
                    if mask & selectors.EVENT_WRITE:
                        self._write_child()
                elif tag == "sock":
                    self._on_sock(mask, now)
            self._tick(now)

    def _desired(self) -> dict[int, tuple[int, str]]:
        want: dict[int, tuple[int, str]] = {}
        if not self._hup and len(self._to_child) < CHILD_HIGH:
            want[0] = (selectors.EVENT_READ, "stdin")
        if self._disp and not self._hup:
            want[1] = (selectors.EVENT_WRITE, "stdout")
        m = 0
        paused = len(self._disp) > DISP_HIGH or len(self._delayed) > DELAY_MAX
        if not self._master_eof and not paused:
            m |= selectors.EVENT_READ
        if self._to_child and not self._master_eof:
            m |= selectors.EVENT_WRITE
        if m:
            want[self.master] = (m, "master")
        return want

    def _sync(self, sel: selectors.BaseSelector) -> None:
        want = self._desired()
        for fd in list(self._reg):
            if fd not in want:
                sel.unregister(fd)
                del self._reg[fd]
        for fd, (mask, tag) in want.items():
            old = self._reg.get(fd)
            if old is None:
                sel.register(fd, mask, tag)
            elif old != mask:
                sel.modify(fd, mask, tag)
            self._reg[fd] = mask
        t = self.transport
        sock = t.sock if t is not None else None
        if sock is not self._reg_sock:
            if self._reg_sock is not None:
                with contextlib.suppress(KeyError, ValueError, OSError):
                    sel.unregister(self._reg_sock)  # type: ignore[arg-type]
            self._reg_sock = None
            if sock is not None:
                sel.register(sock, selectors.EVENT_READ, "sock")
                self._reg_sock = sock
        if sock is not None and t is not None:
            mask = selectors.EVENT_READ | (selectors.EVENT_WRITE if t.wants_write() else 0)
            if sel.get_key(sock).events != mask:
                sel.modify(sock, mask, "sock")

    def _timeout(self, now: float) -> float | None:
        cands: list[float | None] = [
            self.input.deadline(),
            self.titles.deadline(),
            self._notice_until if self._notice else None,
            None if self._title_live else self._title_due,
            (self._prompt_t + PROMPT_IDLE_S) if self.prompt is not None else None,
        ]
        if self.scanner is not None:
            cands.append(self.scanner.deadline())
        if self.transport is not None and not self._rec_broken:
            cands.append(self.transport.deadline())
        if self._child_status is not None or self._master_eof:
            cands.append(now + 0.05)
        ds = [d for d in cands if d is not None]
        if not ds:
            return None
        return max(0.0, min(ds) - now)

    def _finished(self, now: float) -> bool:
        if self._hup:
            return True
        if self._child_status is None:
            if self._master_eof and now - self._master_eof_t > DRAIN_MAX_S:
                return True
            return False
        if self._master_eof:
            return True
        paused = len(self._disp) > DISP_HIGH or len(self._delayed) > DELAY_MAX
        if now - self._child_exit_t > DRAIN_MAX_S:
            return True
        return not paused and now - self._last_master > DRAIN_IDLE_S

    # ------------------------------------------------------ Ereignisse

    def _on_signals(self, now: float) -> None:
        try:
            data = os.read(self._sig_r, 512)
        except OSError:
            return
        sigs = set(data)
        if signal.SIGCHLD in sigs:
            self._reap(now)
        if signal.SIGWINCH in sigs:
            self._resize(now)
        if signal.SIGHUP in sigs or signal.SIGTERM in sigs:
            self._hup = True

    def _reap(self, now: float) -> None:
        if self._child_status is not None:
            return
        try:
            pid, status = os.waitpid(self.child, os.WNOHANG)
        except ChildProcessError:
            pid, status = self.child, 0
        if pid == self.child:
            self._child_status = status
            self._child_exit_t = now

    def _resize(self, now: float) -> None:
        rows, cols = winsize(0)
        self.rows, self.cols = rows, cols
        set_winsize(self.master, rows, cols)
        self._emit("term.resize", {"stream_off": self._offset(), "rows": min(rows, 1000),
                                   "cols": min(cols, 1000)})

    def _on_stdin(self, now: float) -> None:
        try:
            data = os.read(0, READ_SIZE)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._hup = True
            return
        if not data:
            self._hup = True
            return
        if self.prompt is not None:
            self._prompt_input(data, now)
            return
        if now < self._cpr_until and _CPR.fullmatch(data):
            self._cpr_until = 0.0
            return
        for act in self.input.feed(data, now):
            self._on_action(act, now)

    def _on_stdout(self, now: float) -> None:
        if not self._disp:
            return
        try:
            n = os.write(1, self._disp[:READ_SIZE])
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._hup = True
            return
        del self._disp[:n]

    def _write_child(self) -> None:
        if not self._to_child:
            return
        try:
            n = os.write(self.master, self._to_child[:READ_SIZE])
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._to_child.clear()
            return
        del self._to_child[:n]

    def _on_master(self, now: float) -> None:
        try:
            data = os.read(self.master, READ_SIZE)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
            data = b""
        if not data:
            self._master_eof = True
            self._master_eof_t = now
            return
        self._last_master = now
        self._on_output(data, now)

    def _on_sock(self, mask: int, now: float) -> None:
        t = self.transport
        if t is None or self._rec_broken:
            return
        try:
            if mask & selectors.EVENT_READ:
                t.on_readable()
            if mask & selectors.EVENT_WRITE and t.sock is not None:
                t.on_writable()
        except Exception:
            self._broken()

    def _tick(self, now: float) -> None:
        if self.scanner is not None and self.scanner.deadline() is not None:
            off0 = self.scanner.offset
            try:
                res = self.scanner.expire(now)
            except Exception:
                self.scanner = None
                self._broken()
            else:
                self._apply_scan(res, off0, now)
        t = self.transport
        if t is not None and not self._rec_broken:
            try:
                t.tick(now)
                if t.sock is not None and t.wants_write():
                    t.on_writable()
            except Exception:
                self._broken()
        for act in self.input.expire(now):
            self._on_action(act, now)
        if self.prompt is not None and now >= self._prompt_t + PROMPT_IDLE_S:
            self.prompt.cancelled = self.prompt.done = True
            self._prompt_done(now)
        if self._notice and now >= self._notice_until:
            self._notice = None
            self._refresh_title(now)
        if not self._title_live and now >= self._title_due:
            self._title_live = True
            self._refresh_title(now)
        out = self.titles.expire(now)
        if out:
            self._disp += out

    # --------------------------------------------------- Ausgabe, Aufnahme

    def _offset(self) -> int:
        return self.scanner.offset if self.scanner is not None else 0

    def _show(self, data: bytes) -> None:
        if data:
            if self.prompt is not None:
                self._delayed += data
            else:
                self._disp += data

    def _on_output(self, data: bytes, now: float) -> None:
        if self.scanner is None:
            self._show(data)
            return
        off0 = self.scanner.offset
        try:
            res = self.scanner.feed(data, now)
        except Exception:
            self.scanner = None
            self._broken()
            self._show(data)
            return
        self._apply_scan(res, off0, now)

    def _apply_scan(self, res: ScanResult, off0: int, now: float) -> None:
        self._show(res.display)
        if self._rec_broken:
            return
        try:
            if res.record and self.capture and self.transport is not None:
                self.transport.add_out(res.record, off0, time.time_ns(), time.monotonic_ns(), now)
            for item in res.items:
                self._on_item(item, now)
        except Exception:
            self._broken()

    def _on_item(self, item: object, now: float) -> None:
        if isinstance(item, Marker):
            self._on_marker(item, now)
        elif isinstance(item, Forged):
            self._emit("term.marker_forged", {"stream_off": item.stream_off, "reason": item.reason})
        elif isinstance(item, Title):
            self.inner_title = item.text.decode("utf-8", "replace")[:400]
            self._refresh_title(now)
        elif isinstance(item, Osc52):
            self._emit("term.osc52_blocked", {"stream_off": item.stream_off, "length": item.length})
        elif isinstance(item, AltScreen):
            self._refresh_title(now)

    def _on_marker(self, item: Marker, now: float) -> None:
        if self.validator is None:
            return
        v = self.validator.check(item.payload)
        if not v.ok or v.marker is None:
            reason = v.reason or "malformed"
            self._emit("term.marker_forged", {"stream_off": item.stream_off, "reason": reason})
            return
        ev = mark_event(v.marker, terminal_id=self.terminal_id, stream_off=item.stream_off,
                        fg_shell=v.fg_shell)
        self._emit("term.mark", ev)
        before = self.stack.snapshot()
        label = self.stack.label()
        cmd = ev.get("cmd_expanded") or ev.get("cmd_typed")  # wie Daemon und Segmenter (Aliase)
        if v.marker.mark == "C" and cmd:
            self.stack.on_command_start(context_argv(cmd), item.stream_off)
        elif v.marker.mark == "D" and v.fg_shell:
            self.stack.on_command_end(ev.get("exit"), item.stream_off)
        if self.stack.snapshot() != before and not self.capture:
            self._sync_stack()
        if self.stack.label() != label:
            self._refresh_title(now)

    def _sync_stack(self) -> None:
        """Ohne Aufnahme sieht der Daemon keine Marker: Stapel nachführen (``req.ctx.sync``)."""
        t = self.transport
        if t is None or not t.ready or self._rec_broken:
            return
        try:
            t.add_event("req.ctx.sync", {"terminal_id": self.terminal_id, "stream_off": self._offset(),
                                         "stack": self.stack.snapshot()})
        except Exception:
            self._broken()

    def _emit(self, kind: str, fields: dict[str, Any]) -> None:
        t = self.transport
        if not self.capture or t is None or self._rec_broken:
            return
        fields = dict(fields)
        fields.setdefault("terminal_id", self.terminal_id)
        t.add_event(kind, fields)

    def _broken(self) -> None:
        """Fehler im Aufnahmecode: Aufnahme aus, Relay läuft weiter."""
        self._rec_broken = True
        self.capture = False
        t, self.transport = self.transport, None
        if t is not None:
            with contextlib.suppress(Exception):
                t.close()
        self._refresh_title(time.monotonic())

    # ------------------------------------------------------- REC-Zustand

    def _want_capture(self) -> bool:
        t = self.transport
        if t is None or self._rec_broken:
            return False
        if t.ready:
            return self._rec in ("on", "waiting")
        if t.connected:  # vorläufig, bis der erste STATE kommt
            return self._last_rec in (None, "on", "waiting")
        return self._last_rec in ("on", "waiting")

    def _update_capture(self, now: float, reason: str | None = None) -> None:
        want = self._want_capture()
        if want == self.capture:
            return
        off = self._offset()
        t = self.transport
        if want:
            self.capture = True
            if self._lost_since is not None and off > self._lost_since:
                self._emit("term.gap", {"stream_off": self._lost_since, "reason": self._lost_reason,
                                        "bytes_lost": off - self._lost_since})
            self._lost_since = None
            self._emit("term.resize", {"stream_off": off, "rows": min(self.rows, 1000),
                                       "cols": min(self.cols, 1000)})
            self._emit("term.ctx_snapshot", {"stream_off": off, "stack": self.stack.snapshot()})
        else:
            if t is not None:
                t.flush_out()
            self.capture = False
            lost = off if self._drop_from is None else min(off, self._drop_from)
            self._drop_from = None
            self._lost_since = lost
            ready_off = t is not None and t.ready and self._rec == "off"
            self._lost_reason = reason or ("rec_off" if ready_off else "daemon_down")

    def _on_state_cb(self, st: dict[str, Any], first: bool) -> None:
        now = time.monotonic()
        t = self.transport
        rec = st.get("rec")
        if rec not in _REC_STATES:
            rec = "off"
        prev = self._rec
        if rec == "offline":
            rec = self._last_rec or "off"
        self._rec = rec
        self._last_rec = rec
        reason = None
        if first:
            did = st.get("daemon_id") if isinstance(st.get("daemon_id"), str) else None
            if self._daemon_id is not None and did != self._daemon_id and self.capture:
                reason = "daemon_down"  # Daemon neu gestartet (gesperrt, REC aus): Puffer verloren
            self._daemon_id = did
        if first and rec not in ("on", "waiting") and t is not None:
            self._drop_from = t.drop_unacked()
        if prev == "waiting" and rec == "on" and t is not None:
            t.rewind()
        # Den Stapel führt der Shim selbst (er sieht alle Marker, auch bei REC aus). Vom
        # Daemon kommt er nur nach einem Kontext-Entscheid (neue ctx_version).
        ver = st.get("ctx_version")
        ver = ver if type(ver) is int else None
        if first:
            self._ctx_version = ver
        elif ver is not None and ver != self._ctx_version:
            self._ctx_version = ver
            stack = _clean_stack(st.get("stack"))
            if stack is not None:
                with contextlib.suppress(Exception):
                    self.stack = ContextStack([Stage.from_dict(d) for d in stack])
        bound = st.get("bound_project_id")
        if isinstance(bound, str) and 0 < len(bound) <= 64:
            self._bound_id = bound
            slug = st.get("project")
            if st.get("project_id") == bound and isinstance(slug, str) and len(slug) <= 64:
                self._bound_slug = slug
        hosts = st.get("hosts")
        if isinstance(hosts, list):
            self.hosts = [h for h in hosts[:500] if isinstance(h, str) and len(h) <= 255]
        self._update_capture(now, reason)
        if first and not self.capture:
            self._sync_stack()
        self._refresh_title(now)

    def _on_disconnect_cb(self) -> None:
        now = time.monotonic()
        self._rec = None
        self._update_capture(now)
        self._refresh_title(now)

    # ------------------------------------------------------------ Titel

    def _note(self, text: str, now: float, dur: float = NOTICE_S) -> None:
        self._notice = text
        self._notice_until = now + dur
        self._refresh_title(now)

    def _refresh_title(self, now: float) -> None:
        t = self.transport
        ready = t is not None and t.ready
        if not self._title_live and not ready:
            return
        self._title_live = True
        if self._rec_broken:
            link = Link.BROKEN
        elif t is None or not t.connected:
            link = Link.OFFLINE
        elif not ready:
            link = Link.CONNECTING
        else:
            link = Link.READY
        st = t.state if (t is not None and ready) else {}
        bound, proj_id = st.get("bound_project_id"), st.get("project_id")
        project = st.get("project")
        extra = st.get("title_extra")
        text = compose_title(
            link=link,
            rec=self._rec,
            project=project if isinstance(project, str) else None,
            paused=bool(bound and proj_id and bound != proj_id),
            label=self.stack.label(),
            suggestion=bool(st.get("suggestion")),
            extra=extra if isinstance(extra, str) else None,
            inner=self.inner_title,
            notice=self._notice if now < self._notice_until else None,
        )
        out = self.titles.request(text, now)
        if out:
            self._disp += out

    # ----------------------------------------------------------- Hotkeys

    def _on_action(self, act: object, now: float) -> None:
        if isinstance(act, Forward):
            self._to_child += act.data
        elif isinstance(act, Armed):
            self._note(f"{describe_prefix(self.hotkey_name)}: Taste r h b k s ?", now, 5.0)
        elif isinstance(act, Key):
            self._hotkey(act.key, now)
        elif isinstance(act, Cancelled):
            if act.reason in ("esc", "abort", "timeout"):
                self._note("abgebrochen", now, 1.5)
            else:
                self._notice = None
                self._refresh_title(now)

    def _request(self, kind: str, fields: dict[str, Any], now: float) -> bool:
        t = self.transport
        if t is None or not t.ready or self._rec_broken:
            self._note("Daemon nicht erreichbar", now)
            return False
        try:
            t.add_event(kind, {"terminal_id": self.terminal_id, "stream_off": self._offset(), **fields})
        except Exception:
            self._broken()
            return False
        return True

    def _alt(self) -> bool:
        return self.scanner is not None and self.scanner.alt_screen

    def _hotkey(self, key: str, now: float) -> None:
        if key == "r":
            if self._request("req.rec", {"on": None}, now):
                self._note("REC umschalten", now)
        elif key == "b":
            self.stack.pop()
            self._request("req.ctx.pop", {}, now)
            self._note("Stufe geschlossen", now)
        elif key == "s":
            if self._request("req.shot", {"mode": "window"}, now):
                self._note("Screenshot angefordert", now)
        elif key in ("h", "k", "?"):
            if self._alt():
                self._note("im Vollbild nur r b s" if key != "?" else _HELP, now, 5.0)
                return
            if key == "h":
                p = LinePrompt("[ariadne] Host (user@host, Tab ergänzt): ", completions=self.hosts,
                               width=self.cols)
                self._open_prompt("host", p, now)
            elif key == "k":
                p = LinePrompt("[ariadne] Schlüsselschritt: f foothold, p privesc, v pivot, l loot: ",
                               mode="choice", choices=_KEYSTEPS, width=self.cols)
                self._open_prompt("keystep", p, now)
            else:
                p = LinePrompt(f"[ariadne] {describe_prefix(self.hotkey_name)} dann: " + _HELP,
                               mode="message", width=self.cols)
                self._open_prompt("help", p, now)
        else:
            self._note("unbekannte Taste", now)

    def _open_prompt(self, kind: str, prompt: LinePrompt, now: float, new_line: bool = True) -> None:
        self.prompt = prompt
        self._prompt_kind = kind
        self._prompt_t = now
        self._disp += prompt.open(new_line=new_line)

    def _prompt_input(self, data: bytes, now: float) -> None:
        p = self.prompt
        if p is None:
            return
        self.input.observe(data, now)
        self._prompt_t = now
        out = p.feed(data)
        if out:
            self._disp += out
        if p.done:
            self._prompt_done(now)

    def _prompt_done(self, now: float) -> None:
        p, kind = self.prompt, self._prompt_kind
        if p is None:
            return
        if kind == "keystep" and not p.cancelled and p.result:
            self._keystep = p.result
            nxt = LinePrompt("[ariadne] Notiz (optional, Enter): ", allowed=None, max_len=200,
                             width=self.cols, cursor=p.cursor)
            self._open_prompt("note", nxt, now, new_line=False)
            return
        self._disp += p.close_bytes(self.rows)
        self.prompt = None
        self._disp += self._delayed
        self._delayed = bytearray()
        if p.cursor is None:
            self._cpr_until = now + CPR_SWALLOW_S
        if p.cancelled:
            self._note("abgebrochen", now, 1.5)
            return
        if kind == "host":
            user, host = parse_user_host(p.result or "")
            if host is None:
                self._note("kein Host angegeben", now)
                return
            self.stack.set_top(host=host, user=user, source="hotkey", offset=self._offset())
            self._request("req.ctx.set", {"host": host, "user": user}, now)
            self._note(f"Host {host}", now)
        elif kind == "note" and self._keystep:
            note = (p.result or "").strip() or None
            if self._request("req.keystep", {"step": self._keystep, "note": note}, now):
                self._note(f"Schlüsselschritt {self._keystep}", now)
            self._keystep = None

    # -------------------------------------------------------- Abschluss

    def _plain_loop(self) -> None:
        """Notfall-Relay ohne Scanner, Hotkeys und Aufnahme."""
        self.scanner = None
        self.prompt = None
        with contextlib.suppress(Exception):
            if self._sel is not None:
                self._sel.close()
        sel = selectors.DefaultSelector()
        try:
            sel.register(self._sig_r, selectors.EVENT_READ, "sig")
            sel.register(0, selectors.EVENT_READ, "stdin")
            sel.register(self.master, selectors.EVENT_READ, "master")
            self._disp += self._delayed
            self._delayed = bytearray()
            while not self._hup and not self._master_eof:
                for key, _mask in sel.select(0.2):
                    if key.data == "sig":
                        self._on_signals(time.monotonic())
                    elif key.data == "stdin":
                        with contextlib.suppress(BlockingIOError):
                            data = os.read(0, READ_SIZE)
                            if not data:
                                self._hup = True
                            self._to_child += data
                    else:
                        self._on_master(time.monotonic())
                self._flush_blocking(self._to_child, self.master, 1.0)
                self._flush_blocking(self._disp, 1, 1.0)
                if self._child_status is not None and time.monotonic() - self._last_master > DRAIN_IDLE_S:
                    break
        except OSError:
            return
        finally:
            sel.close()

    @staticmethod
    def _flush_blocking(buf: bytearray, fd: int, timeout: float) -> None:
        end = time.monotonic() + timeout
        while buf and time.monotonic() < end:
            try:
                n = os.write(fd, buf[:READ_SIZE])
            except (BlockingIOError, InterruptedError):
                time.sleep(0.005)
                continue
            except OSError:
                buf.clear()
                return
            del buf[:n]

    def _drain_master(self, limit_s: float) -> None:
        end = time.monotonic() + limit_s
        while not self._master_eof and time.monotonic() < end:
            try:
                data = os.read(self.master, READ_SIZE)
            except BlockingIOError:
                return
            except OSError:
                return
            if not data:
                return
            self._on_output(data, time.monotonic())
            self._flush_blocking(self._disp, 1, 0.5)

    def _shutdown(self) -> None:
        now = time.monotonic()
        if self.prompt is not None:
            self._disp += self.prompt.close_bytes(self.rows)
            self.prompt = None
        self._disp += self._delayed
        self._delayed = bytearray()
        if self._child_status is not None and not self._hup:
            self._drain_master(0.5)
        if self._child_status is None:
            self._close_master()
            end = now + HUP_WAIT_S
            while self._child_status is None and time.monotonic() < end:
                try:
                    pid, status = os.waitpid(self.child, os.WNOHANG)
                except ChildProcessError:
                    break
                if pid == self.child:
                    self._child_status = status
                    break
                time.sleep(0.01)
        self.exit_code = exit_code(self._child_status) if self._child_status is not None else 129
        if self.scanner is not None:
            with contextlib.suppress(Exception):
                res = self.scanner.expire(float("inf"))
                self._apply_scan(res, self.scanner.offset - len(res.record), now)
        t = self.transport
        if t is not None and not self._rec_broken:
            with contextlib.suppress(Exception):
                self._emit("term.close", {"stream_off": self._offset(), "exit_code": self.exit_code})
                t.bye(self.exit_code)
            with contextlib.suppress(Exception):
                t.ring.close()
        if not self._hup:
            self._flush_blocking(self._disp, 1, 1.0)
        self._restore_tty()
        with contextlib.suppress(OSError, ValueError):
            signal.set_wakeup_fd(-1)
        self._close_master()

    def _close_master(self) -> None:
        """Master genau einmal schliessen (die Nummer könnte sonst neu vergeben sein)."""
        self._master_eof = True
        if self.master >= 0:
            with contextlib.suppress(OSError):
                os.close(self.master)
            self.master = -1

    def _restore_tty(self) -> None:
        if self._saved_attrs is not None:
            with contextlib.suppress(termios.error, OSError):
                termios.tcsetattr(0, termios.TCSADRAIN, self._saved_attrs)
        for fd, flags in self._saved_flags.items():
            if fd in (0, 1):
                with contextlib.suppress(OSError):
                    fcntl.fcntl(fd, fcntl.F_SETFL, flags)
