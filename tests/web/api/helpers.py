"""Hilfen für die API-Tests: Test-App nach Vertrag v0.1-Server 4 (FastAPI, eine kleine Middleware,
die die Sitzung setzt, und ein Bus als Liste), echter Daemon mit Fake-Shim und das MS2-Fixture mit
feindlichen Werten (HTML, Steuerzeichen, Bidi), einem bekannten Secret und dem eigenen Secret."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI

from ariadne._shim import protocol as P
from ariadne.web.api import register
from ariadne.web.ctx import SSE_EVENTS, SessionInfo, WebContext
from tests.core.conftest import OWN_SECRET
from tests.core.fakeshim import FakeShim, ctl_ok
from tests.integration.helpers import TARGET, Term, ms2
from tests.integration.test_daemon_ingest import run

__all__ = [
    "FakeBus",
    "make_app",
    "client",
    "Fixture",
    "build_fixture",
    "HOSTILE",
    "CRYPT",
    "OWN_SECRET",
    "TARGET",
    "BASE",
    "all_strings",
    "SESSION",
    "run_api",
    "sync",
    "REMOTE_PW",
    "NMAP2",
    "clean",
]

BASE = "/api/v1"
HOSTILE = "<script>alert(1)</script>\u202eevil\u200bx"  # HTML, Bidi, Zero-Width (XML erlaubt kein ESC)
CRYPT = "$1$abcdefgh$0123456789abcdefghijkl"  # md5crypt: Secret der Art «crypt» (regex.net)
REMOTE_PW = "remote-pw-123"  # Eingabe ohne Echo in einer «Remote-Shell» (E104)
NMAP2 = (
    b"Starting Nmap 7.94 ( https://nmap.org )\r\nNmap scan report for 10.10.10.3\r\n"
    b"Host is up (0.0010s latency).\r\nPORT    STATE SERVICE     VERSION\r\n"
    b"21/tcp  open  ftp         ProFTPD 1.3.1\r\n"
    b"445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)\r\n\r\n"
    b"Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds\r\n"
)
_UNSAFE = (
    [chr(c) for c in range(0x20)]
    + ["\x7f"]
    + [chr(c) for c in range(0x80, 0xA0)]
    + [
        "\u202e",
        "\u202d",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\u200b",
        "\u200e",
        "\u200f",
        "\ufeff",
        "\u2028",
        "\u2029",
    ]
)
SESSION = SessionInfo("s-test01", "sshd", time.time_ns(), time.time_ns() + 3600 * 10**9, os.getpid(), "sshd")


class FakeBus:
    """Bus als Liste; prüft wie der echte Bus Ereignisnamen und JSON-Tauglichkeit."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def publish(self, event: str, data: Mapping[str, Any]) -> None:
        if event not in SSE_EVENTS:
            raise ValueError(event)
        json.dumps(dict(data))
        self.events.append((event, dict(data)))

    def kinds(self) -> list[str]:
        return [e for e, _ in self.events]


class _SessionMiddleware:
    """Ersatz für die Middleware des Servers: setzt nur die Sitzung."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            scope.setdefault("state", {})["session"] = SESSION
        await self.app(scope, receive, send)


def make_app(daemon: Any, bus: Any | None = None) -> tuple[FastAPI, WebContext]:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    ctx = WebContext(daemon, bus or FakeBus(), port=7330)
    register(app, ctx)
    app.add_middleware(_SessionMiddleware)
    return app, ctx


def client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:7330",
        headers={"Origin": "http://127.0.0.1:7330"},
    )


def all_strings(obj: Any) -> list[str]:
    """Alle Strings einer JSON-Antwort (Werte und Schlüssel)."""
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            out.append(str(k))
            out.extend(all_strings(v))
    elif isinstance(obj, list | tuple):
        for v in obj:
            out.extend(all_strings(v))
    return out


def clean(text: str) -> bool:
    """Kein Steuer-, Bidi- oder Zero-Width-Zeichen im Text."""
    return not any(ch in text for ch in _UNSAFE)


@dataclass
class Fixture:
    pid: str
    ws: Path
    term: Term
    shim: FakeShim
    shim2: FakeShim | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    shims: list[FakeShim] = field(default_factory=list)


def hostile_xml() -> bytes:
    data = ms2("xml")
    esc = HOSTILE.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    esc = esc.replace("\u202e", "&#x202E;").replace("\u200b", "&#x200B;")
    # Produkt des Dienstes auf Port 21 durch einen feindlichen Banner ersetzen
    return data.replace(b'product="vsftpd"', f'product="{esc}"'.encode(), 1)


async def _input(s: FakeShim, seq: int, off: int, data: bytes, *, no_echo: bool = False) -> None:
    await s.send(P.encode_input(seq, off, off, time.time_ns(), time.monotonic_ns(), data, no_echo=no_echo))


async def sync(d: Any) -> None:
    """Alles Eingereihte schreiben und auswerten (wie ``_sync_ingest`` des Daemons)."""
    d.writer.flush_now()
    await d.ingest.sync()


async def build_fixture(d: Any, paths: Any, *, inputs: bool = True, extra: bool = False) -> Fixture:
    """Projekt «lame» mit nmap MS2 (feindlicher Banner), Hash, eigenem Secret, Callback und Eingaben.

    ``extra``: dazu ein zweiter nmap-Lauf (Widersprüche auf tcp/21, Verlauf auf tcp/445) und ein
    Callback von ausserhalb des Scopes (Kontextvorschlag)."""
    res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=[TARGET])
    ws = Path(res["workspace"])
    shim = await FakeShim(paths.term_sock).connect(proto=2)
    await shim.wait_state(rec="on")
    term = Term(shim)
    (ws / "scans").mkdir(exist_ok=True)
    (ws / "scans" / "lame.xml").write_bytes(hostile_xml())
    await term.command(f"nmap -sV -oA scans/lame {TARGET}", ms2("text").replace(b"\n", b"\r\n"), cwd=str(ws))
    await term.command(
        "cat loot.txt",
        f"admin:{CRYPT}:18000:0:99999:7:::\r\nsudo {OWN_SECRET}\r\nbanner {HOSTILE}\r\n".encode(),
        cwd=str(ws),
    )
    # C1-Steuerzeichen (U+009B als UTF-8), einzelnes ESC, Bidi und Zero-Width direkt aus der Ausgabe
    await term.command(
        "cat c1.txt", b"c1 \xc2\x9b31mrot \x1bZ esc \xe2\x80\xaeltr \xe2\x80\x8bzw\r\n", cwd=str(ws)
    )
    await term.command(
        "nc -lvnp 4444",
        b"listening on [any] 4444 ...\r\n"
        b"connect to [10.10.14.5] from (UNKNOWN) [10.10.10.3] 51234\r\n"
        b"id\r\nuid=0(root) gid=0(root)\r\n",
        cwd=str(ws),
        end=False,
    )
    await term.acked()
    fx = Fixture(res["id"], ws, term, shim)
    if inputs:
        s2 = await FakeShim(paths.term_sock).connect(proto=2)
        await s2.wait_state(rec="on")
        await s2.outx(1, 0, b"$ ")
        await _input(s2, 2, 2, b"id\r")
        await s2.outx(3, 2, b"id\r\nuid=0(root)\r\n[sudo] Passwort: ")
        await _input(s2, 4, 36, OWN_SECRET.encode() + b"\r", no_echo=True)
        await s2.outx(5, 36, b"\r\nPassword: ")
        await _input(s2, 6, 48, REMOTE_PW.encode() + b"\r")
        await s2.outx(7, 48, b"\r\n$ ")
        await s2.wait_ack(7)
        fx.shim2 = s2
        fx.shims.append(s2)
    fx.shims.insert(0, shim)
    if extra:
        s3 = await FakeShim(paths.term_sock).connect(proto=2)
        await s3.wait_state(rec="on")
        t3 = Term(s3)
        await t3.command("nmap -sV -p21,445 10.10.10.3", NMAP2, cwd=str(ws))
        await t3.acked()
        s4 = await FakeShim(paths.term_sock).connect(proto=2)
        await s4.wait_state(rec="on")
        t4 = Term(s4)
        await t4.command(
            "nc -lvnp 4445",
            b"listening on [any] 4445 ...\r\n"
            b"connect to [10.10.14.5] from (UNKNOWN) [10.10.10.99] 40000\r\n"
            b"whoami\r\nwww-data\r\n",
            cwd=str(ws),
            end=False,
        )
        await t4.acked()
        fx.shims += [s3, s4]
        fx.extra.update(nmap2=s3.terminal_id, callback=s4.terminal_id)
    await sync(d)
    return fx


Body = Callable[[Any, httpx.AsyncClient, Fixture | None, FakeBus, WebContext], Awaitable[None]]


def run_api(
    paths: Any, operator: Any, body: Body, *, fixture: bool = True, extra: bool = False, **kw: Any
) -> None:
    """Echter Daemon mit Auswertung, Test-App mit der echten API, Fixture nach Wunsch."""

    async def scenario(d: Any) -> None:
        bus = FakeBus()
        fx = await build_fixture(d, paths, extra=extra) if fixture else None
        app, ctx = make_app(d, bus)
        try:
            async with client(app) as c:
                await body(d, c, fx, bus, ctx)
        finally:
            for s in fx.shims if fx else []:
                await s.close()

    run(paths, operator, scenario, **kw)
