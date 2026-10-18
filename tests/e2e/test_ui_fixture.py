"""Rauchtest für den Fixture-Daemon der Browsertests (``tests/e2e/ui_fixture.py``).

Startet ihn als eigenen Prozess wie ``webui/playwright.config.ts``, wartet auf ``READY`` und prüft:
Zustandsdatei, Web-Server mit der Shell-CSP, Anmeldung nötig, Code über ``ctl.sock``, die
vorbereiteten Daten über die echte API (Finding F1, «Neu seit», Scope-Warnung), sauberes Ende auf
SIGTERM (Zustandsdatei weg, Wegwerf-Ordner gelöscht). Besitzer ab Phase 2: «backend-ui».
"""

from __future__ import annotations

import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]

pytestmark = [pytest.mark.e2e, pytest.mark.slow]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_ready(proc: subprocess.Popen[bytes], timeout: float = 90.0) -> str:
    assert proc.stdout is not None
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    out = b""
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if not sel.select(timeout=0.5):
                if proc.poll() is not None:
                    break
                continue
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            out += chunk
            if b"READY" in out:
                return out.decode(errors="replace")
    finally:
        sel.close()
    raise AssertionError(f"Fixture nicht bereit: {out.decode(errors='replace')[-2000:]}")


def _ctl(sock: str, op: str, args: dict[str, object]) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
        c.settimeout(10)
        c.connect(sock)
        c.sendall(json.dumps({"op": op, "args": args}).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = c.recv(65536)
            if not chunk:
                break
            buf += chunk
    res = json.loads(buf)
    assert res.get("ok"), res
    return dict(res["result"])


def _api(base: str, method: str, path: str, token: str | None = None, body: object = None) -> dict[str, Any]:
    req = urllib.request.Request(
        base + path, method=method, data=json.dumps(body).encode() if body is not None else None
    )
    req.add_header("Content-Type", "application/json")
    if method != "GET":
        req.add_header("Origin", base)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return dict(json.loads(resp.read()))


def test_ui_fixture_starts_serves_and_cleans_up(tmp_path: Path) -> None:
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text(
        '<!doctype html><html lang="de-CH"><head><meta charset="utf-8"><title>Ariadne</title>'
        '<script type="module" src="/assets/x.js"></script></head><body><div id="app"></div></body></html>',
        encoding="utf-8",
    )
    state_file = tmp_path / "state" / "daemon.json"
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARIADNE_")}
    proc = subprocess.Popen(
        [sys.executable, "-m", "tests.e2e.ui_fixture", "--port", str(port), "--static", str(static),
         "--state-file", str(state_file)],
        cwd=REPO, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        _wait_ready(proc)
        state = json.loads(state_file.read_text(encoding="utf-8"))
        assert state["port"] == port and state["base"] == f"http://127.0.0.1:{port}"
        assert state["scenario"] == "ms2" and state["project_id"]
        home = Path(state["home"])  # Wegwerf-Ordner, nie das echte HOME
        assert home.is_dir() and Path(tempfile.gettempdir()).resolve() in home.resolve().parents

        with urllib.request.urlopen(f"{state['base']}/karte", timeout=10) as resp:
            assert resp.status == 200
            csp = resp.headers["Content-Security-Policy"]
            assert "default-src 'none'" in csp and "style-src 'self'" in csp
            assert b'id="app"' in resp.read()
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(f"{state['base']}/api/v1/status", timeout=10)
        assert err.value.code == 401
        err.value.close()

        code = _ctl(state["ctl"], "ui.code", {"via": "local", "typed": False})
        assert isinstance(code.get("code"), str) and len(str(code["code"])) >= 8

        # vorbereitete Daten des Teils «backend-ui»: Finding F1, «Neu seit», Scope-Warnung
        base, pid = state["base"], state["project_id"]
        token = _api(base, "POST", "/api/v1/session", body={"code": code["code"]})["token"]
        (f1,) = _api(base, "GET", f"/api/v1/p/{pid}/findings", token)["findings"]
        assert f1["ordinal"] == 1 and f1["severity"] == "critical" and f1["title"] == "vsftpd 2.3.4 Backdoor"
        assert f1["evidence_count"] == 1 and f1["warnings"] == []
        seen = _api(base, "GET", f"/api/v1/p/{pid}/ui/seen", token)
        assert seen["seen_at"] and seen["new"]["count"] > 0 and seen["new"]["keysteps"]
        warning = _api(base, "GET", "/api/v1/status", token)["scope_warning"]
        assert warning["text"] == "ping -c1 10.66.66.66" and warning["acked"] is False
        assert warning["targets"][0]["value"] == "10.66.66.66"
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            rc = proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if proc.stdout is not None:
                proc.stdout.close()
    assert rc == 0
    assert not state_file.exists()
    assert not home.exists()
