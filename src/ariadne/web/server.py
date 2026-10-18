"""uvicorn im Loop des Daemons, nur auf Loopback (R1, E89, Vertrag v0.1-Server 3.3).

* :func:`bind_socket` legt den Socket selbst an (``AF_INET`` bzw. ``AF_INET6`` mit
  ``IPV6_V6ONLY``), bindet nur an ``127.0.0.1`` oder ``::1`` und prüft danach
  ``getsockname()``; jede Abweichung schliesst den Socket (fail-closed).
* :class:`PeerCheckedProtocol` (Unterklasse des h11-Protokolls von uvicorn) liest beim Annehmen
  einer Verbindung nichts, bis der Peer feststeht: Client-Socket in ``/proc/net/tcp(6)`` mit
  der eigenen UID, sonst Verbindung ohne Antwort zu (R2). Der Peer (:class:`PeerInfo`) gilt
  für die ganze Verbindung und steht in jedem ``scope["state"]``. Die Suche läuft in einem
  eigenen kleinen Thread-Pool, nie im Loop. Höchstens :data:`MAX_PENDING_LOOKUPS` Suchen warten
  gleichzeitig; jede weitere neue Verbindung wird sofort geschlossen, und Ablehnungen meldet das
  Log nur zusammengefasst (Befund SEC-W2: eine Flut eines fremden Benutzers darf den Loop, der
  auch ``ctl.sock`` und die Shims bedient, nicht aufhalten).
* Der Socket ist ausdrücklich ``IPPROTO_TCP``; nur dann setzt asyncio ``TCP_NODELAY`` auf die
  angenommenen Verbindungen (sonst wartet jede Keep-alive-Antwort etwa 40 ms, Befund RT-1).
* :class:`WebServer` startet uvicorn mit ``sockets=[sock]`` als Aufgabe im Loop
  (``lifespan="off"``, kein Access-Log, keine eigene Logging-Konfiguration, keine
  Proxy-Header, kein WebSocket, keine Signal-Handler) und beendet es in höchstens 2 s.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import ipaddress
import logging
import os
import socket
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import h11
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from ariadne.web.config import ALLOWED_BINDS
from ariadne.web.peer import DiagUnavailable, PeerInfo, diag_lookup, resolve_peer
from ariadne.web.security import _STATIC_HEADERS, OTHER_CSP, PEER_KEY, ASGIApp, error_body

__all__ = [
    "BindError",
    "bind_socket",
    "check_sockname",
    "PeerGate",
    "WebServer",
    "MAX_CONNECTIONS",
    "MAX_PENDING_LOOKUPS",
]

log = logging.getLogger("ariadne.web")

MAX_CONNECTIONS = 128
MAX_PENDING_LOOKUPS = 16  # gleichzeitig wartende Peer-Suchen; darüber wird sofort geschlossen
PEER_TIMEOUT_S = 5.0
WARN_EVERY_S = 10.0  # Ablehnungen höchstens so oft ins Log, mit Zahl

Resolver = Callable[[tuple[str, int], tuple[str, int]], PeerInfo | None]


class BindError(RuntimeError):
    """Bindung nicht wie verlangt (R1). Meldung ohne fremde Werte."""


def check_sockname(name: Any, host: str, port: int) -> int:
    """Prüft das Ergebnis von ``getsockname()``; gibt den Port zurück."""
    try:
        got_host = str(ipaddress.ip_address(str(name[0]).split("%", 1)[0]))
        got_port = int(name[1])
    except (ValueError, TypeError, IndexError):
        raise BindError("Adresse des Sockets unlesbar") from None
    if got_host != host or got_host not in ALLOWED_BINDS:
        raise BindError("Socket nicht auf der verlangten Loopback-Adresse")
    if port != 0 and got_port != port:
        raise BindError("Socket nicht auf dem verlangten Port")
    return got_port


def bind_socket(host: str, port: int) -> socket.socket:
    """Neuer lauschender Socket auf ``host:port`` (nur Loopback), geprüft mit ``getsockname``."""
    if host not in ALLOWED_BINDS:
        raise BindError("nur 127.0.0.1 oder ::1")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    # IPPROTO_TCP ausdrücklich: asyncio setzt TCP_NODELAY nur bei sock.proto == IPPROTO_TCP (RT-1)
    sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        sock.set_inheritable(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        check_sockname(sock.getsockname(), host, port)
        sock.listen(64)
        sock.setblocking(False)
    except BaseException:
        sock.close()
        raise
    return sock


class PeerGate:
    """Bestimmt den Peer einer neuen Verbindung (austauschbarer Resolver für Tests)."""

    def __init__(self, resolver: Resolver | None = None, *, uid: int | None = None) -> None:
        self.uid = os.getuid() if uid is None else uid
        self._default: Resolver = functools.partial(_default_resolve, uid=self.uid)
        self.resolver: Resolver = resolver or self._default
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ariadne-peer")
        self.tasks: set[asyncio.Task[None]] = set()
        self.closed = False
        self.pending = 0  # laufende Peer-Suchen
        self.rejected_total = 0
        self._unreported = 0
        self._last_warn = -WARN_EVERY_S
        self._clock = time.monotonic

    def quick_reject(self, client: Any, server: Any) -> bool:
        """Sofort im Loop: gehört der Client-Socket einem fremden Benutzer oder gibt es ihn nicht?

        Eine gezielte Netlink-Abfrage (etwa 15 µs, kein Thread) weist eine Flut fremder
        Verbindungen ab, bevor eine Suche in den fd-Tabellen beginnt. Mit einem eigenen Resolver
        (Tests) oder ohne Netlink entscheidet erst :meth:`lookup`."""
        if self.resolver is not self._default or client is None or server is None or server[1] is None:
            return False
        try:
            entry = diag_lookup((client[0], client[1]), (server[0], int(server[1])))
        except DiagUnavailable:
            return False
        except (ValueError, TypeError, OSError):
            return True
        return entry is None or entry.uid != self.uid

    def busy(self) -> bool:
        """Zu viele Suchen warten schon: neue Verbindungen sofort schliessen (Überlast)."""
        return self.pending >= MAX_PENDING_LOOKUPS

    def rejected(self, why: str) -> None:
        """Eine Verbindung wurde abgewiesen; das Log bekommt höchstens alle 10 s eine Zeile."""
        self.rejected_total += 1
        self._unreported += 1
        now = self._clock()
        if now - self._last_warn >= WARN_EVERY_S:
            log.warning("%d Verbindung(en) ohne passenden Peer geschlossen (zuletzt: %s)",
                        self._unreported, why)
            self._unreported = 0
            self._last_warn = now

    async def lookup(self, client: tuple[str, int], server: tuple[str, int]) -> PeerInfo | None:
        loop = asyncio.get_running_loop()
        self.pending += 1
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(self._pool, self.resolver, client, server), PEER_TIMEOUT_S)
        except Exception as exc:
            self.rejected(f"Peer nicht bestimmbar, {type(exc).__name__}")
            return None
        finally:
            self.pending -= 1

    def close(self) -> None:
        self.closed = True
        for t in list(self.tasks):
            t.cancel()
        self._pool.shutdown(wait=False, cancel_futures=True)


def _default_resolve(client: tuple[str, int], server: tuple[str, int], *, uid: int) -> PeerInfo | None:
    return resolve_peer(client, server, uid=uid)


def make_protocol(gate: PeerGate) -> type[H11Protocol]:
    """Protokollklasse, die vor dem ersten gelesenen Byte den Peer prüft."""

    class PeerCheckedProtocol(H11Protocol):
        def __init__(self, config: Any, server_state: Any, app_state: dict[str, Any],
                     _loop: asyncio.AbstractEventLoop | None = None) -> None:
            # eigener Zustand pro Verbindung (der Peer), nie geteilt
            super().__init__(config, server_state, dict(app_state), _loop)

        def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
            super().connection_made(transport)
            if gate.closed or len(self.connections) > MAX_CONNECTIONS:
                transport.close()
                return
            if gate.quick_reject(self.client, self.server):
                transport.close()  # fremder Benutzer oder kein Eintrag: ohne Antwort (R2)
                gate.rejected("fremder Benutzer oder kein Eintrag")
                return
            if gate.busy():
                transport.close()
                gate.rejected("Überlast")
                return
            transport.pause_reading()  # nichts lesen, bevor der Peer feststeht
            task = self.loop.create_task(self._check_peer(transport))
            gate.tasks.add(task)
            task.add_done_callback(gate.tasks.discard)

        async def _check_peer(self, transport: asyncio.Transport) -> None:
            peer = None
            client, server = self.client, self.server
            if client is not None and server is not None and server[1] is not None:
                peer = await gate.lookup((client[0], client[1]), (server[0], int(server[1])))
            if transport.is_closing():
                return
            if peer is None or peer.uid != gate.uid:
                transport.close()  # ohne Antwort (R2)
                gate.rejected("fremder Benutzer" if peer is not None else "kein Eintrag")
                return
            self.app_state[PEER_KEY] = peer
            transport.resume_reading()

        def send_400_response(self, msg: str) -> None:
            """Kaputte Anfrage: 400 mit den üblichen Sicherheits-Headern, dann schliessen."""
            body = error_body("validation")
            headers = [(b"content-type", b"application/json; charset=utf-8"), (b"connection", b"close"),
                       *_STATIC_HEADERS, (b"content-security-policy", OTHER_CSP.encode("ascii"))]
            try:
                for event in (h11.Response(status_code=400, headers=headers, reason=b"Bad Request"),
                              h11.Data(data=body), h11.EndOfMessage()):
                    out = self.conn.send(event)
                    if out:
                        self.transport.write(out)
            except h11.LocalProtocolError:
                pass
            self.transport.close()

    return PeerCheckedProtocol


class _QuietServer(uvicorn.Server):
    """uvicorn ohne eigene Signal-Handler: Signale gehören dem Daemon."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield

    def install_signal_handlers(self) -> None:  # ältere uvicorn-Versionen
        return None


class WebServer:
    """Ein uvicorn-Server auf einem selbst gebundenen Loopback-Socket."""

    def __init__(self, gate: PeerGate) -> None:
        self.gate = gate
        self.sock: socket.socket | None = None
        self.host: str | None = None
        self.port: int | None = None
        self.inode: int | None = None
        self._server: _QuietServer | None = None
        self._task: asyncio.Task[None] | None = None

    def bind(self, host: str, port: int) -> int:
        self.sock = bind_socket(host, port)
        self.host = host
        self.port = check_sockname(self.sock.getsockname(), host, port)
        self.inode = os.fstat(self.sock.fileno()).st_ino
        return self.port

    async def start(self, app: ASGIApp, *, timeout: float = 5.0) -> None:
        if self.sock is None:
            raise BindError("Socket fehlt")
        config = uvicorn.Config(
            app, http=make_protocol(self.gate), ws="none", lifespan="off", interface="asgi3",
            access_log=False, log_config=None, proxy_headers=False, server_header=False,
            date_header=True, timeout_keep_alive=5, timeout_graceful_shutdown=1,
            h11_max_incomplete_event_size=64 * 1024,
            # uvicorn ruft listen() erneut auf; 64 statt 2048 hält auch die Zahl der pro Durchgang
            # angenommenen Verbindungen klein (asyncio nimmt bis zu ``backlog`` auf einmal an)
            backlog=64,
        )
        server = _QuietServer(config)
        self._server = server
        self._task = asyncio.ensure_future(server.serve(sockets=[self.sock]))
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while not server.started:
            if self._task.done():
                exc = self._task.exception() if not self._task.cancelled() else None
                raise BindError(f"Web-Server nicht gestartet ({type(exc).__name__ if exc else 'Abbruch'})")
            if loop.time() > end:
                raise BindError("Web-Server startet nicht")
            await asyncio.sleep(0.01)
        # erneut prüfen, nachdem uvicorn den Socket übernommen hat
        check_sockname(self.sock.getsockname(), self.host or "", self.port or 0)

    async def stop(self, timeout: float = 2.0) -> None:
        """Beendet uvicorn (höchstens ``timeout`` s, dann hart) und schliesst den Socket."""
        self.gate.close()
        server, task = self._server, self._task
        if server is not None and task is not None and not task.done():
            server.should_exit = True
            done, _ = await asyncio.wait({task}, timeout=timeout)
            if not done:
                server.force_exit = True
                done, _ = await asyncio.wait({task}, timeout=0.5)
            if not done:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        if task is not None and task.done() and not task.cancelled() and task.exception() is not None:
            log.error("Web-Server endete mit Fehler (%s)", type(task.exception()).__name__)
        if server is not None:  # Verbindungen, die noch offen sind, hart schliessen
            for conn in list(server.server_state.connections):
                with contextlib.suppress(Exception):
                    conn.transport.close()
        if self.sock is not None:
            self.sock.close()
        self._server = self._task = None
