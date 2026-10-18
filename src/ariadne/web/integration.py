"""Einbindung des Web-Servers in den Daemon (Vertrag v0.1-Server, Abschnitt 3.3).

``WebExtension.start(daemon)`` (Reihenfolge verbindlich):

1. ``[ui]`` aus ``config.toml`` lesen. Nicht-Loopback, ungültiger Port oder ``enabled = false``:
   kein Server, ``ui.status`` nennt den Grund; die Aufnahme läuft weiter (fail-closed, R1).
2. ctl-Operationen ``ui.code``, ``ui.sessions``, ``ui.revoke``, ``ui.status`` anmelden (immer).
3. Sitzungen, Bus, :class:`~ariadne.web.ctx.WebContext` und App bauen; Socket selbst anlegen,
   ``getsockname()`` prüfen, uvicorn als Aufgabe im Loop des Daemons starten.
4. ``daemon.add_listener``: alle Sitzungen widerrufen und ihre SSE-Ströme schliessen bei
   ``locked``, ``stopping`` und ``project`` mit ``change = closed`` und ``reason`` in ``stop``,
   ``idle``, ``lock``, ``shutdown`` (ein Projektwechsel, ``switch``, beendet nichts).
5. ``detach = api.attach_sources(ctx)``.
6. Alle 2 s: gebundene Prozesse prüfen (PID lebt, Startzeit gleich), sonst Sitzung beenden
   (Tunnelende, R6); Ablauf nach höchstens 12 h. Zusätzlich: Wird der Tresor ohne Ereignis
   gesperrt (``stop`` ohne offenes Projekt), endet ebenfalls alles.

``stop()``: Listener ab, ``detach()``, alle Sitzungen widerrufen, Ströme schliessen, uvicorn
beenden (höchstens 2 s), Socket schliessen. Nichts davon hält die Aufnahme auf.

Die ctl-Operationen erreicht nur derselbe Benutzer (``ctl.sock``, ``SO_PEERCRED``, R5). Codes
stehen nie in Logs; das Ergebnis von ``ui.code`` geht nur an den Aufrufer.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ariadne.daemon.ops_util import OpError
from ariadne.paths import Paths
from ariadne.web import api as api_mod
from ariadne.web.app import build_app
from ariadne.web.config import UiConfigError, load_ui
from ariadne.web.ctx import WebContext
from ariadne.web.peer import sshd_ancestor
from ariadne.web.server import BindError, PeerGate, Resolver, WebServer
from ariadne.web.sessions import Clock, SessionStore, format_typed
from ariadne.web.sse import EventBus
from ariadne.web.static import STATIC_DIR

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon

__all__ = ["WebExtension", "STUB"]

log = logging.getLogger("ariadne.web")

STUB = False

CHECK_INTERVAL_S = 2.0
START_WAIT_S = 5.0
_END_REASONS = frozenset({"stop", "idle", "lock", "shutdown"})
_BIND_ERRORS = {
    98: "Port belegt (läuft ein anderes Programm auf diesem Port?)",
    99: "Adresse nicht verfügbar (ist IPv6 abgeschaltet?)",
    97: "Adressfamilie nicht verfügbar (ist IPv6 abgeschaltet?)",
    13: "Port nicht erlaubt",
}


class WebExtension:
    """Web-Server als Erweiterung des Daemons (:class:`ariadne.daemon.core.DaemonExtension`)."""

    name = "web"

    def __init__(
        self,
        paths: Paths,
        *,
        peer_resolver: Resolver | None = None,
        clock: Clock | None = None,
        static_root: Path = STATIC_DIR,
        check_interval: float = CHECK_INTERVAL_S,
        bus_factory: Callable[[], EventBus] | None = None,
        sshd_lookup: Callable[[int], Any] | None = None,
    ) -> None:
        self.paths = paths
        self.daemon: Daemon | None = None
        self._resolver = peer_resolver
        self._clock = clock
        self._static_root = static_root
        self._check_interval = check_interval
        self._bus_factory = bus_factory or EventBus
        self._sshd_lookup = sshd_lookup or (lambda pid: sshd_ancestor(pid))
        self.error: str | None = None
        self.running = False
        self.host: str | None = None
        self.sessions: SessionStore | None = None
        self.bus: EventBus | None = None
        self.ctx: WebContext | None = None
        self.server: WebServer | None = None
        self.gate: PeerGate | None = None
        self._detach: Callable[[], None] | None = None
        self._task: asyncio.Task[None] | None = None
        self._was_unlocked = False
        # gesetzt, sobald start() fertig ist (mit oder ohne Server): ctl.sock antwortet schon vorher
        self._ready: asyncio.Event | None = None

    # ------------------------------------------------------------------ #
    # Lebenszyklus
    # ------------------------------------------------------------------ #
    async def start(self, daemon: Daemon) -> None:
        self._ready = asyncio.Event()
        try:
            await self._start(daemon)
        finally:
            self._ready.set()

    async def _wait_ready(self) -> None:
        """``ui.code`` und ``ui.status`` kurz nach dem Start des Daemons: auf den Server warten."""
        if self._ready is not None and not self._ready.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._ready.wait(), START_WAIT_S)

    async def _start(self, daemon: Daemon) -> None:
        self.daemon = daemon
        self.error = None
        self.running = False
        try:
            cfg = load_ui(self.paths)
        except UiConfigError as exc:
            cfg = None
            self.error = str(exc)
        if "ui.status" not in daemon.extra_ops:
            daemon.add_ops({"ui.code": self._op_code, "ui.sessions": self._op_sessions,
                            "ui.revoke": self._op_revoke, "ui.status": self._op_status})
        if cfg is None:
            log.error("Web-Server nicht gestartet: Konfiguration [ui] ungültig")
            return
        if not cfg.enabled:
            self.error = "abgeschaltet ([ui] enabled = false in config.toml)"
            log.info("Web-Server abgeschaltet")
            return
        self.host = cfg.bind
        self.sessions = SessionStore(session_hours=cfg.session_hours, clock=self._clock)
        self.bus = self._bus_factory()
        self.gate = PeerGate(self._resolver)
        server = WebServer(self.gate)
        try:
            port = server.bind(cfg.bind, cfg.port)
        except OSError as exc:
            self.error = _BIND_ERRORS.get(exc.errno or 0, "Socket nicht anlegbar")
            log.error("Web-Server nicht gestartet (%s)", type(exc).__name__)
            self.gate.close()
            return
        except BindError as exc:
            self.error = str(exc)
            log.error("Web-Server nicht gestartet (Bindung)")
            self.gate.close()
            return
        self.ctx = WebContext(daemon, self.bus, host=cfg.bind, port=port)
        try:
            webapp = build_app(self.ctx, self.sessions, self.bus, uid=self.gate.uid,
                               static_root=self._static_root)
            await server.start(webapp.asgi)
        except Exception as exc:
            self.error = "Web-Server nicht gestartet (interner Fehler)"
            log.error("Web-Server nicht gestartet (%s)", type(exc).__name__)
            await server.stop()
            return
        self.server = server
        self.sessions.add_revoke_listener(self.bus.close_session)
        daemon.add_listener(self._on_event)
        try:
            self._detach = api_mod.attach_sources(self.ctx)
        except Exception as exc:  # Server läuft, nur ohne Ereignisse der API
            log.error("Ereignisquellen der API nicht angemeldet (%s)", type(exc).__name__)
            self._detach = None
        self._was_unlocked = daemon.operator is not None
        self._task = asyncio.ensure_future(self._watch())
        self.running = True
        log.info("Web-Server läuft auf Loopback")

    async def stop(self) -> None:
        daemon = self.daemon
        self.running = False
        if daemon is not None:
            daemon.remove_listener(self._on_event)
        if self._detach is not None:
            try:
                self._detach()
            except Exception as exc:
                log.error("Ereignisquellen nicht abgemeldet (%s)", type(exc).__name__)
            self._detach = None
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self.sessions is not None:
            self.sessions.clear()
        if self.bus is not None:
            self.bus.close_all()
        if self.server is not None:
            await self.server.stop()
            self.server = None

    # ------------------------------------------------------------------ #
    # Sitzungsende
    # ------------------------------------------------------------------ #
    def end_all(self) -> int:
        """Alle Sitzungen und offenen Codes verwerfen (Ströme schliessen sich mit)."""
        return self.sessions.clear() if self.sessions is not None else 0

    def _on_event(self, kind: str, data: dict[str, Any]) -> None:
        if kind in ("locked", "stopping") or (
                kind == "project" and data.get("change") == "closed" and data.get("reason") in _END_REASONS):
            n = self.end_all()
            if n:
                log.info("Web-Sitzungen beendet (%s)", kind)
        if kind == "unlocked":
            self._was_unlocked = True
        elif kind == "locked":
            # schon erledigt: die 2-s-Prüfung darf Codes und Sitzungen danach nicht noch einmal
            # verwerfen (sonst gilt ein Code nicht, der kurz nach lock geholt wurde)
            self._was_unlocked = False

    def check_now(self) -> None:
        """Eine Runde der Prüfung (sonst alle 2 s)."""
        if self.sessions is None:
            return
        ended = self.sessions.check()
        if ended:
            log.info("Web-Sitzungen beendet: Prozess weg oder abgelaufen (%d)", len(ended))
        unlocked = self.daemon is not None and self.daemon.operator is not None
        if self._was_unlocked and not unlocked:
            self.end_all()
        self._was_unlocked = unlocked

    async def _watch(self) -> None:
        while True:
            await asyncio.sleep(self._check_interval)
            try:
                self.check_now()
            except Exception as exc:  # die Prüfung darf nie still sterben
                log.error("Prüfung der Web-Sitzungen fehlgeschlagen (%s)", type(exc).__name__)
                self.end_all()

    # ------------------------------------------------------------------ #
    # ctl-Operationen (nur über ctl.sock, gleicher Benutzer)
    # ------------------------------------------------------------------ #
    def _require_running(self) -> tuple[SessionStore, WebContext]:
        if not self.running or self.sessions is None or self.ctx is None:
            raise OpError("ui_off", f"Web-Oberfläche aus: {self.error or 'nicht gestartet'}")
        return self.sessions, self.ctx

    async def _op_code(self, daemon: Daemon, args: dict[str, Any]) -> dict[str, Any]:
        typed = args.get("typed", False)
        via = args.get("via", "local")
        if not isinstance(typed, bool) or via not in ("local", "sshd"):
            raise OpError("invalid", "typed muss true oder false sein, via local oder sshd")
        from ariadne.daemon.core import ctl_peer_pid

        pid = ctl_peer_pid()  # vor dem Warten lesen (gilt nur während dieser Operation)
        await self._wait_ready()
        sessions, ctx = self._require_running()
        sshd = None
        if via == "sshd":
            sshd = self._sshd_lookup(pid) if pid else None
            if sshd is None:
                raise OpError("not_sshd", "Aufrufer stammt nicht von einer SSH-Verbindung ab")
        code, ttl = sessions.issue_code(typed=typed, via=via, sshd=sshd)
        res: dict[str, Any] = {"code": code, "display": format_typed(code) if typed else code,
                               "expires_in": ttl, "url": None if typed else f"{ctx.origin}/#c={code}",
                               "port": ctx.port, "via": via}
        if sshd is not None:
            # damit remote serve code bei seinem Ende genau diese Bindung widerrufen kann (SEC-R1)
            res["bound"] = {"pid": sshd.pid, "start": sshd.start}
        return res

    def _op_sessions(self, daemon: Daemon, args: dict[str, Any]) -> dict[str, Any]:
        if self.sessions is None:
            return {"sessions": []}
        self.sessions.check()
        return {"sessions": self.sessions.listing()}

    def _op_revoke(self, daemon: Daemon, args: dict[str, Any]) -> dict[str, Any]:
        """``session_id``: eine Sitzung; ``bound_pid`` mit ``bound_start``: alle Sitzungen und Codes,
        die an diesen sshd-Prozess gebunden sind (Ende von ``remote serve code``); sonst alle."""
        sid = args.get("session_id")
        if sid is not None and (not isinstance(sid, str) or not 1 <= len(sid) <= 32):
            raise OpError("invalid", "session_id ungültig")
        if "bound_pid" in args or "bound_start" in args:
            pid, start = args.get("bound_pid"), args.get("bound_start")
            if (sid is not None or type(pid) is not int or type(start) is not int or pid <= 0
                    or start < 0):
                raise OpError("invalid", "bound_pid und bound_start müssen Zahlen sein")
            n = self.sessions.revoke_bound(pid, start) if self.sessions is not None else 0
            if n:
                log.info("Web-Sitzungen beendet: remote serve code endete (%d)", n)
            return {"revoked": n}
        if self.sessions is None:
            if sid is not None:
                raise OpError("not_found", "Sitzung unbekannt")
            return {"revoked": 0}
        if sid is None:
            return {"revoked": self.sessions.clear()}
        n = self.sessions.revoke(sid)
        if n == 0:
            raise OpError("not_found", "Sitzung unbekannt")
        return {"revoked": n}

    async def _op_status(self, daemon: Daemon, args: dict[str, Any]) -> dict[str, Any]:
        await self._wait_ready()
        srv = self.server
        return {
            "running": self.running,
            "host": self.host or "127.0.0.1",
            "port": srv.port if (srv is not None and self.running) else None,
            "error": self.error,
            "sessions": len(self.sessions) if self.sessions is not None else 0,
            "inode": srv.inode if (srv is not None and self.running) else None,
            "pid": os.getpid(),
        }
