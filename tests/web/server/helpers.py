"""Hilfen für Tests mit echtem Web-Server im Daemon auf einem freien Loopback-Port.

Der Daemon läuft im Testprozess (``tests.core.test_daemon.run``) mit der echten
:class:`~ariadne.web.integration.WebExtension`. Die API ist durch eine kleine Test-API ersetzt
(eine Route, die die Sitzung zurückgibt, und eine 501-Route), damit diese Tests nur den
Server-Kern prüfen und nicht vom Stand des Teils «api» abhängen.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse

from ariadne.web import api as api_mod
from ariadne.web.ctx import session_of
from ariadne.web.integration import WebExtension
from ariadne.web.peer import PeerInfo
from tests.core.test_daemon import run

WRITE = {"POST", "PUT", "PATCH", "DELETE"}
AUTO = object()


def fake_api_register(app: Any, ctx: Any) -> None:
    """Ersatz für ``ariadne.web.api.register`` in den Server-Tests."""

    async def whoami(request: Request) -> JSONResponse:
        s = session_of(request)
        return JSONResponse({"session_id": s.session_id, "origin": s.origin})

    async def later(request: Request) -> JSONResponse:
        err = {"code": "not_implemented", "message": "Kommt in einer späteren Version."}
        return JSONResponse({"error": err}, status_code=501)

    async def boom(request: Request) -> JSONResponse:
        raise RuntimeError("Zieldaten <script>alert(1)</script> im Fehlertext")

    app.add_api_route("/api/v1/test/whoami", whoami, methods=["GET"])
    app.add_api_route("/api/v1/test/later", later, methods=["GET", "POST"])
    app.add_api_route("/api/v1/test/boom", boom, methods=["GET"])



def no_sources(ctx: Any) -> Callable[[], None]:
    return lambda: None


def use_test_api(monkeypatch: Any) -> None:
    monkeypatch.setattr(api_mod, "register", fake_api_register)
    monkeypatch.setattr(api_mod, "attach_sources", no_sources)


def write_config(paths: Any, text: str) -> None:
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(text, encoding="utf-8")


class Web:
    def __init__(self, daemon: Any, ext: WebExtension, paths: Any) -> None:
        self.d = daemon
        self.ext = ext
        self.paths = paths
        self.port: int = ext.server.port if ext.server is not None else 0

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def code(self, *, typed: bool = False) -> str:
        res = await self.d.call("ui.code", {"typed": typed, "via": "local"})
        assert res["ok"], res
        return res["result"]["code"]

    async def req(self, method: str, path: str, *, token: str | None = None,
                  headers: dict[str, str] | None = None, json_body: Any = None, content: Any = None,
                  host: str | None = None, origin: Any = AUTO) -> httpx.Response:
        h = {"Host": host if host is not None else f"127.0.0.1:{self.port}"}
        if token is not None:
            h["Authorization"] = f"Bearer {token}"
        if origin is AUTO:
            if method in WRITE:
                h["Origin"] = self.base
        elif origin is not None:
            h["Origin"] = origin
        h.update(headers or {})
        async with httpx.AsyncClient(base_url=self.base, timeout=10) as c:
            return await c.request(method, path, headers=h, json=json_body, content=content)

    async def login(self, *, typed: bool = False) -> str:
        r = await self.req("POST", "/api/v1/session", json_body={"code": await self.code(typed=typed)})
        assert r.status_code == 200, r.text
        return r.json()["token"]

    async def raw(self, data: bytes, timeout: float = 5.0) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        out = b""
        try:
            writer.write(data)
            await writer.drain()
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout)
                if not chunk:
                    break
                out += chunk
        except ConnectionError:  # ohne Antwort geschlossen (RST, weil ungelesene Daten anstanden)
            pass
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
        return out

    def unreadable(self) -> None:
        """Resolver liefert für neue Verbindungen «nicht lesbar» (wie bei sshd-session)."""
        uid = os.getuid()
        self.ext.gate.resolver = lambda client, server: PeerInfo(uid=uid, inode=1, pids=())

    def real_resolver(self) -> None:
        from ariadne.web.peer import resolve_peer

        uid = os.getuid()
        self.ext.gate.resolver = lambda client, server: resolve_peer(client, server, uid=uid)


class Stream:
    """Offener SSE-Strom; ``ended`` wird gesetzt, sobald der Server ihn schliesst."""

    def __init__(self, web: Web, token: str, last_event_id: str | None = None) -> None:
        self.web = web
        self.token = token
        self.chunks: list[bytes] = []
        self.status = 0
        self.headers: dict[str, str] = {}
        self.opened = asyncio.Event()
        self.ended = asyncio.Event()
        self._last = last_event_id
        self.task = asyncio.ensure_future(self._run())

    async def _run(self) -> None:
        h = {"Authorization": f"Bearer {self.token}", "Accept": "text/event-stream"}
        if self._last is not None:
            h["Last-Event-ID"] = self._last
        try:
            async with httpx.AsyncClient(base_url=self.web.base, timeout=None) as c:
                async with c.stream("GET", "/api/v1/events", headers=h) as r:
                    self.status = r.status_code
                    self.headers = dict(r.headers)
                    self.opened.set()
                    async for chunk in r.aiter_bytes():
                        self.chunks.append(chunk)
        except (httpx.HTTPError, ConnectionError):
            pass
        finally:
            self.opened.set()
            self.ended.set()

    async def wait_open(self) -> None:
        await asyncio.wait_for(self.opened.wait(), 5)
        for _ in range(100):
            if self.chunks or self.ended.is_set():
                return
            await asyncio.sleep(0.01)

    async def ends_within(self, seconds: float) -> bool:
        try:
            await asyncio.wait_for(self.ended.wait(), seconds)
            return True
        except TimeoutError:
            return False

    async def close(self) -> None:
        self.task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self.task

    @property
    def text(self) -> str:
        return b"".join(self.chunks).decode("utf-8", "replace")


CLIENT_SCRIPT = r"""
import http.client, json, sys
port = int(sys.argv[1])
for line in sys.stdin:
    cmd = json.loads(line)
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = cmd.get("body")
    c.request(cmd["method"], cmd["path"], body=None if body is None else json.dumps(body),
              headers=cmd.get("headers") or {})
    r = c.getresponse()
    data = r.read()
    c.close()
    print(json.dumps({"status": r.status, "body": data.decode("utf-8", "replace")}), flush=True)
"""

CODE_VIA_CTL = r"""
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(json.dumps({"op": "ui.code", "args": {"via": "sshd", "typed": False}}).encode() + b"\n")
buf = b""
while not buf.endswith(b"\n"):
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
s.close()
print(buf.decode().strip(), flush=True)
"""


class ClientProc:
    """Hilfsprozess X, der HTTP-Anfragen aus einem eigenen Prozess stellt (T6)."""

    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self.proc = proc

    @classmethod
    async def start(cls, port: int) -> ClientProc:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-I", "-c", CLIENT_SCRIPT, str(port),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        return cls(proc)

    async def request(self, method: str, path: str, *, port: int, token: str | None = None,
                      body: Any = None) -> tuple[int, str]:
        headers = {"Host": f"127.0.0.1:{port}"}
        if method in WRITE:
            headers["Origin"] = f"http://127.0.0.1:{port}"
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps({"method": method, "path": path, "headers": headers,
                                          "body": body}).encode() + b"\n")
        await self.proc.stdin.drain()
        line = await asyncio.wait_for(self.proc.stdout.readline(), 15)
        res = json.loads(line)
        return res["status"], res["body"]

    async def stop(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        with contextlib.suppress(ProcessLookupError):
            self.proc.kill()
        await self.proc.wait()


class FakeSshd:
    """Attrappe für einen sshd-Prozess (Vertrag 4): ``sh`` unter dem Namen ``sshd``, dessen Kind
    ``ui.code`` mit ``via = sshd`` über ``ctl.sock`` holt und danach schläft."""

    def __init__(self, proc: asyncio.subprocess.Process, result: dict[str, Any]) -> None:
        self.proc = proc
        self.result = result

    @classmethod
    async def start(cls, tmp: Path, ctl_sock: Path) -> FakeSshd:
        link = tmp / "sshd"
        if not link.exists():
            link.symlink_to("/bin/sh")
        proc = await asyncio.create_subprocess_exec(
            str(link), "-c", '"$1" -I -c "$2" "$3"; sleep 60', "sshd", sys.executable, CODE_VIA_CTL,
            str(ctl_sock), stdout=asyncio.subprocess.PIPE, start_new_session=True)
        assert proc.stdout is not None
        line = await asyncio.wait_for(proc.stdout.readline(), 15)
        return cls(proc, json.loads(line))

    async def stop(self) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.proc.pid, signal.SIGKILL)
        await self.proc.wait()


def run_web(paths: Any, operator: Any, scenario: Callable[[Web], Awaitable[None]], *,
            config: str = "[ui]\nport = 0\n", ext_kw: dict[str, Any] | None = None,
            **daemon_kw: Any) -> WebExtension:
    write_config(paths, config)
    ext = WebExtension(paths, **(ext_kw or {}))
    daemon_kw.setdefault("ingest", False)

    async def inner(d: Any) -> None:
        await scenario(Web(d, ext, paths))

    run(paths, operator, inner, extensions=[ext], **daemon_kw)
    return ext
