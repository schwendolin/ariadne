"""Auslieferung der gebauten SPA aus ``src/ariadne/web/static/`` (web-api.md 1.7).

* Nur ``GET`` und ``HEAD``; andere Methoden 405.
* Pfade mit ``..``, ``.``, versteckten Teilen, leeren Teilen, Backslash oder NUL: 404.
  Symlinks, die aus ``static/`` hinausführen, und Ordner: 404 (keine Verzeichnislisten).
* Unbekannte Pfade **ohne** Dateiendung ergeben die SPA-Shell ``index.html`` (History-Router);
  unbekannte Pfade mit Endung 404. Fehler sind JSON wie überall.
* Content-Type nur aus einer festen Tabelle, sonst ``application/octet-stream``.
* Die Shell trägt den internen Marker für ihre CSP (die Middleware setzt sie und entfernt den
  Marker); alles andere bekommt die strenge CSP mit ``sandbox``.

Gelesen wird in einem Thread, damit der Loop des Daemons nie auf die Platte wartet.
"""

from __future__ import annotations

import asyncio
import os
import stat
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any

from ariadne.web.security import SHELL_MARKER, Receive, Send, send_error

__all__ = ["StaticApp", "STATIC_DIR", "CONTENT_TYPES", "safe_segments"]

STATIC_DIR = Path(__file__).resolve().parent / "static"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".woff2": "font/woff2",
    ".json": "application/json; charset=utf-8",
}
MAX_FILE = 32 << 20


def safe_segments(path: str) -> list[str] | None:
    """Teile eines URL-Pfads oder ``None``, wenn er unsicher oder ungültig ist."""
    if not path.startswith("/") or "\\" in path or "\0" in path or len(path) > 1024:
        return None
    segs = path.split("/")[1:]
    if segs and segs[-1] == "":
        segs = segs[:-1]  # abschliessender Schrägstrich
    for seg in segs:
        if seg == "" or seg.startswith(".") or any(ord(c) < 0x20 or ord(c) == 0x7F for c in seg):
            return None
    return segs


def _read_regular(path: str, root_real: str) -> bytes | None:
    """Inhalt einer regulären Datei innerhalb von ``root_real`` oder ``None``."""
    real = os.path.realpath(path)
    if not real.startswith(root_real + os.sep):
        return None
    try:
        fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
            return None
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


class StaticApp:
    """ASGI-App für alles ausserhalb von ``/api/``."""

    def __init__(self, root: Path = STATIC_DIR) -> None:
        self.root = Path(root)
        self._root_real = os.path.realpath(self.root)

    async def __call__(self, scope: MutableMapping[str, Any], receive: Receive, send: Send) -> None:
        method = str(scope.get("method", "")).upper()
        if method not in ("GET", "HEAD"):
            await send_error(send, 405, "method", extra=[(b"allow", b"GET, HEAD")])
            return
        segs = safe_segments(str(scope.get("path", "")))
        if segs is None:
            await send_error(send, 404, "not_found")
            return
        found = await asyncio.to_thread(self._lookup, segs)
        if found is None:
            await send_error(send, 404, "not_found")
            return
        body, ctype, shell = found
        headers = [(b"content-type", ctype.encode("ascii")),
                   (b"content-length", str(len(body)).encode("ascii"))]
        if shell:
            headers.append((SHELL_MARKER, b"shell"))
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    def _shell(self) -> tuple[bytes, str, bool] | None:
        body = _read_regular(os.path.join(self._root_real, "index.html"), self._root_real)
        return None if body is None else (body, CONTENT_TYPES[".html"], True)

    def _lookup(self, segs: list[str]) -> tuple[bytes, str, bool] | None:
        if not segs or segs == ["index.html"]:
            return self._shell()
        body = _read_regular(os.path.join(self._root_real, *segs), self._root_real)
        ext = os.path.splitext(segs[-1])[1].lower()
        if body is not None:
            return body, CONTENT_TYPES.get(ext, "application/octet-stream"), False
        if ext:
            return None
        return self._shell()  # Route der SPA (/karte, /terminals, ...)
