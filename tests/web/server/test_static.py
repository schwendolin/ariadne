"""Statik (web-api.md 1.7): Traversal, Symlinks, Endungen, SPA-Fallback, Methoden."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from ariadne.web.static import STATIC_DIR, StaticApp, safe_segments


def _site(tmp_path: Path) -> Path:
    root = tmp_path / "static"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>Ariadne</title>")
    (root / "assets" / "app.js").write_text("console.log(1)")
    (root / "assets" / "app.css").write_text("body{}")
    (root / "assets" / "daten.bin").write_bytes(b"\x00\x01")
    (root / "assets" / "seite.html").write_text("<p>kein Shell</p>")
    secret = tmp_path / "geheim.txt"
    secret.write_text("GEHEIM")
    (root / "assets" / "raus.js").symlink_to(secret)
    (root / "assets" / "drin.js").symlink_to(root / "assets" / "app.js")
    return root


def _call(app: StaticApp, path: str, method: str = "GET") -> tuple[int, dict[bytes, bytes], bytes]:
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    asyncio.run(app({"type": "http", "method": method, "path": path, "headers": []}, receive, send))
    start = sent[0]
    body = b"".join(m.get("body", b"") for m in sent[1:])
    return start["status"], dict(start["headers"]), body


@pytest.mark.parametrize("path", ["/../geheim.txt", "/assets/../../geheim.txt", "/assets/./app.js",
                                  "//etc/passwd", "/assets//app.js", "/.hidden", "/assets/raus.js",
                                  "/a\\b", "/x\x00y", "/assets/fehlt.js", "relativ"])
def test_unsafe_or_missing_paths_are_404_json(tmp_path, path):
    status, headers, body = _call(StaticApp(_site(tmp_path)), path)
    assert status == 404, path
    assert json.loads(body)["error"]["code"] == "not_found"
    assert b"GEHEIM" not in body


def test_assets_types_and_shell_marker(tmp_path):
    app = StaticApp(_site(tmp_path))
    status, h, body = _call(app, "/assets/app.js")
    assert status == 200 and h[b"content-type"] == b"text/javascript; charset=utf-8"
    assert b"x-ariadne-csp" not in h
    assert _call(app, "/assets/app.css")[1][b"content-type"] == b"text/css; charset=utf-8"
    assert _call(app, "/assets/daten.bin")[1][b"content-type"] == b"application/octet-stream"
    assert _call(app, "/assets/drin.js")[0] == 200  # Symlink innerhalb von static/
    s, h, _ = _call(app, "/assets/seite.html")
    assert s == 200 and b"x-ariadne-csp" not in h  # nur index.html ist die Shell
    for spa in ("/", "/index.html", "/karte", "/zeitachse/", "/terminals/abc", "/assets"):
        s, h, body = _call(app, spa)
        assert s == 200 and h[b"x-ariadne-csp"] == b"shell" and body.startswith(b"<!doctype html>"), spa
    s, h, body = _call(app, "/", "HEAD")
    assert s == 200 and h[b"content-length"] == str(len(b"<!doctype html><title>Ariadne</title>")).encode()


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_only_get_and_head(tmp_path, method):
    status, headers, body = _call(StaticApp(_site(tmp_path)), "/", method)
    assert status == 405 and json.loads(body)["error"]["code"] == "method"


def test_safe_segments():
    assert safe_segments("/") == []
    assert safe_segments("/a/b/") == ["a", "b"]
    assert safe_segments("/a/../b") is None
    assert safe_segments("/a/\x1b[31m") is None


def test_shipped_build_is_served_unchanged():
    """Der heutige Build in src/ariadne/web/static bleibt, wie er ist (Mock-Modus)."""
    app = StaticApp(STATIC_DIR)
    status, h, body = _call(app, "/")
    assert status == 200 and body == (STATIC_DIR / "index.html").read_bytes()
    for asset in sorted((STATIC_DIR / "assets").iterdir()):
        s, _, b = _call(app, f"/assets/{asset.name}")
        assert s == 200 and b == asset.read_bytes()
