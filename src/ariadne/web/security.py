"""Äusserste Schicht des Web-Servers: Prüfungen und Header vor jeder Route (R2, R3, R5 bis R8, R12).

Prüfreihenfolge (web-api.md 1.1, verbindlich; T3 und T4 hängen daran):

1. Peer: Die Verbindung gehört einem Socket der eigenen UID. Das prüft schon das Protokoll
   beim Annehmen (``server.py``, Verbindung ohne Antwort zu); hier nur noch als zweite Schicht.
2. ``Host`` exakt ``127.0.0.1:PORT``, ``localhost:PORT`` oder ``[::1]:PORT``, sonst 421.
3. ``Sec-Fetch-Site`` nur ``same-origin`` oder ``none`` (oder fehlend), sonst 403, auch für
   statische Dateien. **Einzige Ausnahme (E115):** ein ``GET`` der SPA-Shell (``/``,
   ``/index.html`` oder eine Route ohne Dateiendung, nie ``/api/`` oder ``/assets/``) als
   Navigation (``Sec-Fetch-Mode: navigate``, ``Sec-Fetch-Dest: document``) auch von
   ``cross-site`` oder ``same-site``. So lädt die Startdatei aus ``ariadne ui`` bzw.
   ``ariadne-mac start`` (``file://``, für den Browser eine fremde Herkunft) die Shell. Liefert
   die innere App dafür etwas anderes als die Shell, wird daraus 403. Die Shell enthält keine
   Daten; Rahmen (``frame-ancestors``, ``X-Frame-Options``), COOP und alle API-Regeln bleiben.
4. ``OPTIONS`` ergibt 405 (kein CORS).
5. ``Origin`` bei ``POST``, ``PUT``, ``PATCH``, ``DELETE`` Pflicht und genau ``http://<Host>``;
   ein fremder ``Origin`` ergibt auch bei anderen Methoden 403.
6. Anfragen über 1 MiB: 413.
7. Unter ``/api/`` (ausser ``POST /api/v1/session``): ``Authorization: Bearer <token>``, das
   Token muss gelten und die Verbindung vom gebundenen Prozess kommen, sonst 401. Danach steht
   :class:`~ariadne.web.ctx.SessionInfo` in ``request.state.session``. Ein Token in der URL wird
   nie gelesen.

Erst danach zählen Fehlversuche (der Tausch Code gegen Token liegt in der Route): Eine Anfrage,
die hier scheitert, kann keine Codes sperren (R5).

Jede Antwort, auch Fehler, statische Dateien und SSE, bekommt die Header aus web-api.md 1.1;
was die innere App an solchen Headern setzt, wird ersetzt. Ausnahmen der App erreichen den
Browser nie (500 mit festem Text), ins Log kommt nur ihre Klasse (Architektur 8.6).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any

from ariadne.web.peer import PeerInfo
from ariadne.web.sessions import SessionStore

__all__ = [
    "SecurityMiddleware",
    "ERROR_TEXT",
    "error_body",
    "error_message",
    "allowed_hosts",
    "SHELL_CSP",
    "OTHER_CSP",
    "PEER_KEY",
    "SHELL_MARKER",
    "SESSION_PATH",
    "MAX_BODY",
    "shell_navigation",
]

log = logging.getLogger("ariadne.web")

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

PEER_KEY = "ariadne_peer"  # vom Protokoll pro Verbindung in scope["state"] gesetzt
SHELL_MARKER = b"x-ariadne-csp"  # interner Header der Statik: Antwort ist die SPA-Shell
SESSION_PATH = "/api/v1/session"
MAX_BODY = 1 << 20

SHELL_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; "
             "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
OTHER_CSP = "default-src 'none'; frame-ancestors 'none'; sandbox"

_STATIC_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-frame-options", b"DENY"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
]
# Diese Header setzt nur diese Schicht; was die innere App dazu sendet, fällt weg.
_OWNED = frozenset({h for h, _ in _STATIC_HEADERS} | {
    b"content-security-policy", b"content-security-policy-report-only", b"server", b"set-cookie",
    b"x-powered-by", b"pragma", b"expires", SHELL_MARKER,
})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_FETCH_SITE_OK = frozenset({b"same-origin", b"none"})
_FETCH_SITE_NAV = frozenset({b"cross-site", b"same-site"})  # nur Navigation zur Shell (E115)
_TOKEN_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

# Feste deutsche Texte pro Code (web-api.md 1.5); nie Zieldaten, nie Text aus Ausnahmen.
ERROR_TEXT: dict[str, str] = {
    "unauthorized": "Nicht angemeldet oder Sitzung beendet. Neu anmelden: ariadne ui.",
    "forbidden": "Anfrage abgelehnt.",
    "policy": "Im Terminal erledigen; über das Web nicht erlaubt.",
    "not_found": "Nicht gefunden.",
    "method": "Methode nicht erlaubt.",
    "no_project": "Kein Projekt offen.",
    "project_mismatch": "Das Projekt ist nicht mehr offen.",
    "conflict": "Der Stand hat sich geändert.",
    "too_large": "Anfrage zu gross.",
    "host": "Host nicht erlaubt.",
    "validation": "Eingabe ungültig.",
    "locked": "Gesperrt: im Terminal ariadne start oder ariadne unlock.",
    "rate_limited": "Zu viele Fehlversuche. Neuen Code holen: ariadne ui.",
    "not_implemented": "Kommt in einer späteren Version.",
    "unavailable": "Auswertung nicht bereit, später erneut versuchen.",
    "internal": "Interner Fehler.",
}
_STATUS_CODE = {401: "unauthorized", 403: "forbidden", 404: "not_found", 405: "method", 409: "conflict",
                413: "too_large", 421: "host", 422: "validation", 423: "locked", 429: "rate_limited",
                501: "not_implemented", 503: "unavailable"}


def error_message(code: str) -> str:
    return ERROR_TEXT.get(code, ERROR_TEXT["internal"])


def code_for_status(status: int) -> str:
    return _STATUS_CODE.get(status, "internal")


def error_body(code: str, detail: list[dict[str, Any]] | None = None) -> bytes:
    err: dict[str, Any] = {"code": code, "message": error_message(code)}
    if detail is not None:
        err["detail"] = detail
    return json.dumps({"error": err}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def allowed_hosts(port: int) -> frozenset[bytes]:
    """Erlaubte ``Host``-Werte (R3, Vertrag 1.4 Punkt 1)."""
    return frozenset(f"{h}:{int(port)}".encode("ascii") for h in ("127.0.0.1", "localhost", "[::1]"))


def _headers(scope: Scope) -> dict[bytes, list[bytes]]:
    out: dict[bytes, list[bytes]] = {}
    for k, v in scope.get("headers") or []:
        out.setdefault(bytes(k).lower(), []).append(bytes(v))
    return out


def _one(headers: dict[bytes, list[bytes]], name: bytes) -> bytes | None:
    """Genau ein Wert; fehlt der Header: ``None``; mehrfach: ``b"\\0"`` (immer ungültig)."""
    vals = headers.get(name)
    if not vals:
        return None
    return vals[0] if len(vals) == 1 else b"\0"


def shell_navigation(method: str, path: str, headers: dict[bytes, list[bytes]]) -> bool:
    """Fremde Navigation, die nur die SPA-Shell laden darf (E115, Startdatei über ``file://``).

    ``GET`` mit ``Sec-Fetch-Mode: navigate`` und ``Sec-Fetch-Dest: document`` auf ``/``,
    ``/index.html`` oder eine Route ohne Dateiendung ausserhalb von ``/api/`` und ``/assets/``.
    """
    if method != "GET":
        return False
    site = _one(headers, b"sec-fetch-site")
    if site is None or site.lower() not in _FETCH_SITE_NAV:
        return False
    if (_one(headers, b"sec-fetch-mode") or b"").lower() != b"navigate":
        return False
    if (_one(headers, b"sec-fetch-dest") or b"").lower() != b"document":
        return False
    if path in ("/", "/index.html"):
        return True
    if not path.startswith("/") or path == "/api" or path.startswith(("/api/", "/assets/")):
        return False
    last = path.rstrip("/").rsplit("/", 1)[-1]
    return bool(last) and "." not in last and "\\" not in path and "\0" not in path


def bearer_token(headers: dict[bytes, list[bytes]]) -> str | None:
    raw = _one(headers, b"authorization")
    if raw is None or raw == b"\0":
        return None
    scheme, _, token = raw.strip().partition(b" ")
    token = token.strip()
    if scheme.lower() != b"bearer" or not 16 <= len(token) <= 128 or not set(token) <= _TOKEN_CHARS:
        return None
    return token.decode("ascii")


class _GuardedSend:
    """Setzt die Sicherheits-Header auf jede Antwort und merkt sich den Status."""

    def __init__(self, send: Send, extra: Iterable[tuple[bytes, bytes]] = ()) -> None:
        self._send = send
        self.started = False
        self.status = 0
        self._extra = list(extra)
        # E115: eine fremde Navigation darf nur die Shell bekommen, alles andere wird 403.
        self.shell_only = False
        self._swallow = False

    async def __call__(self, message: Message) -> None:
        if self._swallow:
            return
        if message["type"] == "http.response.start":
            shell = any(bytes(k).lower() == SHELL_MARKER and bytes(v) == b"shell"
                        for k, v in message.get("headers") or [])
            if self.shell_only and not shell:
                self.shell_only = False
                await send_error(self, 403, "forbidden")
                self._swallow = True  # Rest der ursprünglichen Antwort verwerfen
                return
            self.started = True
            self.status = int(message.get("status", 500))
            headers: list[tuple[bytes, bytes]] = []
            for k, v in message.get("headers") or []:
                k = bytes(k).lower()
                v = bytes(v)
                if k in _OWNED or k.startswith(b"access-control-"):
                    continue
                if k == b"content-type" and v.lower() == b"application/json":
                    v = b"application/json; charset=utf-8"
                headers.append((k, v))
            headers += _STATIC_HEADERS
            headers.append((b"content-security-policy", (SHELL_CSP if shell else OTHER_CSP).encode("ascii")))
            headers += self._extra
            message = dict(message)
            message["headers"] = headers
        await self._send(message)


async def send_error(send: Send, status: int, code: str, *, extra: Iterable[tuple[bytes, bytes]] = (),
                     detail: list[dict[str, Any]] | None = None) -> None:
    body = error_body(code, detail)
    headers = [(b"content-type", b"application/json; charset=utf-8"),
               (b"content-length", str(len(body)).encode("ascii")), *extra]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


class SecurityMiddleware:
    """ASGI-Middleware als äusserste Schicht vor FastAPI und Statik."""

    def __init__(self, app: ASGIApp, *, hosts: frozenset[bytes], sessions: SessionStore, uid: int,
                 max_body: int = MAX_BODY) -> None:
        self.app = app
        self.hosts = hosts
        self.sessions = sessions
        self.uid = uid
        self.max_body = max_body

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return  # kein WebSocket, keine Lifespan-Ereignisse (uvicorn mit lifespan="off", ws="none")
        t0 = time.monotonic()
        guard = _GuardedSend(send)
        kind = "?"
        try:
            kind = await self._handle(scope, receive, guard)
        except Exception as exc:  # nie Ausnahmetext an den Browser oder ins Log
            log.error("Web-Anfrage fehlgeschlagen (%s)", type(exc).__name__)
            if not guard.started:
                try:
                    await send_error(guard, 500, "internal")
                except Exception as exc2:  # Verbindung schon weg
                    log.debug("Fehlerantwort nicht gesendet (%s)", type(exc2).__name__)
        finally:
            log.debug("web %s %s %d %.1f ms", scope.get("method", "?"), kind, guard.status,
                      (time.monotonic() - t0) * 1000)

    async def _handle(self, scope: Scope, receive: Receive, send: _GuardedSend) -> str:
        state = scope.setdefault("state", {})
        state.pop("session", None)  # nie einen Wert von aussen übernehmen
        peer = state.get(PEER_KEY)
        if not isinstance(peer, PeerInfo) or peer.uid != self.uid:
            await send_error(send, 403, "forbidden")
            return "peer"
        headers = _headers(scope)
        host = _one(headers, b"host")
        if host is None or host not in self.hosts:
            await send_error(send, 421, "host")
            return "host"
        method = str(scope.get("method", "")).upper()
        path = str(scope.get("path", ""))
        site = _one(headers, b"sec-fetch-site")
        if site is not None and site.lower() not in _FETCH_SITE_OK:
            if not shell_navigation(method, path, headers):
                await send_error(send, 403, "forbidden")
                return "fetch-site"
            send.shell_only = True
        if method == "OPTIONS":
            await send_error(send, 405, "method", extra=[(b"allow", b"GET, HEAD, POST, PUT, DELETE")])
            return "options"
        origin = _one(headers, b"origin")
        own_origin = b"http://" + host
        if origin != own_origin and (method in _WRITE_METHODS or origin is not None):
            await send_error(send, 403, "forbidden")
            return "origin"
        body = await self._read_body(headers, receive, send)
        if body is None:
            return "body"
        is_api = path == "/api" or path.startswith("/api/")
        if is_api and not (method == "POST" and path == SESSION_PATH):
            info = self.sessions.authenticate(bearer_token(headers) or "", peer)
            if info is None:
                await send_error(send, 401, "unauthorized", extra=[(b"www-authenticate", b"Bearer")])
                return "auth"
            state["session"] = info
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
        if not send.started:
            await send_error(send, 500, "internal")
        return "api" if is_api else "static"

    async def _read_body(self, headers: dict[bytes, list[bytes]], receive: Receive,
                         send: Send) -> bytes | None:
        length = _one(headers, b"content-length")
        if length is not None:
            if length == b"\0" or not length.isdigit():  # h11 lehnt das meist schon vorher ab
                await send_error(send, 400, "validation")
                return None
            if int(length) > self.max_body:
                await send_error(send, 413, "too_large")
                return None
        buf = bytearray()
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return None
            buf += msg.get("body", b"")
            if len(buf) > self.max_body:
                await send_error(send, 413, "too_large")
                return None
            if not msg.get("more_body", False):
                return bytes(buf)
