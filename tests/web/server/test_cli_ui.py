"""``ariadne ui`` (Vertrag 3.4, web-api.md 3): Startdatei 0600 mit dem Code nur im Fragment, Code
nie in argv, Löschen nach der Frist, Tippcode, Sitzungen, Widerruf, kein Daemon-Start."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ariadne.cli import ui as ui_cli
from ariadne.cli.common import CliError
from ariadne.daemon.client import CtlClient
from ariadne.paths import default_paths
from tests.core.conftest import make_env
from tests.web.server.helpers import Web, run_web, use_test_api

pytestmark = pytest.mark.web

URL_IN_FILE = re.compile(r'url=(http://127\.0\.0\.1:\d+/#c=([A-Za-z0-9_-]+))"')


@pytest.fixture(autouse=True)
def _api(monkeypatch):
    use_test_api(monkeypatch)


@pytest.fixture
def fake_open(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "xdg-open.log"
    script = bindir / "xdg-open"
    script.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> "{log}"\nexit 0\n')
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    return log


def _args(**kw) -> argparse.Namespace:
    base = {"code": False, "sessions": False, "revoke": None, "no_open": False}
    base.update(kw)
    return argparse.Namespace(**base)


async def _cli(paths, **kw) -> int:
    return await asyncio.to_thread(ui_cli.cmd_ui, paths, _args(**kw))


def test_ui_opens_start_file_with_code_only_in_fragment(paths, operator, fake_open, monkeypatch, capsys):
    monkeypatch.setattr(ui_cli, "START_TTL_S", 0.5)

    async def scenario(web: Web) -> None:
        assert await _cli(paths) == 0
        opened = fake_open.read_text().splitlines()
        assert len(opened) == 1
        start = Path(opened[0])
        assert start.parent == paths.runtime_dir and start.name.startswith("ui-start-")
        assert stat.S_IMODE(start.stat().st_mode) == 0o600
        text = start.read_text()
        url, code = URL_IN_FILE.search(text).groups()
        assert url == f"http://127.0.0.1:{web.port}/#c={code}" and len(code) == 22
        assert code not in fake_open.read_text()  # nie in argv
        assert code not in capsys.readouterr().out  # nie im Terminal
        r = await web.req("POST", "/api/v1/session", json_body={"code": code})
        assert r.status_code == 200 and r.json()["session"]["origin"] == "local"
        for _ in range(60):  # nach der Frist gelöscht
            if not start.exists():
                break
            await asyncio.sleep(0.05)
        assert not start.exists()

    run_web(paths, operator, scenario)


def test_ui_no_open_code_sessions_and_revoke(paths, operator, fake_open, monkeypatch, capsys):
    monkeypatch.setattr(ui_cli, "START_TTL_S", 0.3)

    async def scenario(web: Web) -> None:
        assert await _cli(paths, no_open=True) == 0
        out = capsys.readouterr().out
        assert not fake_open.exists()
        path = Path(re.search(r"Startdatei: file://(\S+)", out).group(1))
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert URL_IN_FILE.search(path.read_text()).group(2) not in out
        assert await _cli(paths, code=True) == 0
        out = capsys.readouterr().out
        typed = re.search(r"Tippcode: ([0-9A-Z]{5}-[0-9A-Z]{5})", out).group(1)
        assert f"http://127.0.0.1:{web.port}/" in out
        r = await web.req("POST", "/api/v1/session", json_body={"code": typed})
        assert r.status_code == 200
        assert await _cli(paths, sessions=True) == 0
        out = capsys.readouterr().out
        sid = r.json()["session"]["session_id"]
        assert "Sitzungen (1)" in out and sid in out and "lokal" in out and r.json()["token"] not in out
        assert await _cli(paths, revoke=sid) == 0
        assert "1 Sitzung widerrufen" in capsys.readouterr().out
        with pytest.raises(CliError, match="unbekannt"):
            await _cli(paths, revoke=sid)
        assert await _cli(paths, revoke="all") == 0
        assert "Keine Sitzung offen" in capsys.readouterr().out
        assert await _cli(paths, sessions=True) == 0
        assert "Keine Sitzungen" in capsys.readouterr().out

    run_web(paths, operator, scenario)


def test_ui_refuses_when_the_port_is_not_the_daemons(paths, operator, fake_open, monkeypatch):
    monkeypatch.setattr(ui_cli, "listener_matches", lambda host, port, inode, **kw: False)

    async def scenario(web: Web) -> None:
        with pytest.raises(CliError, match="gehört nicht dem Daemon"):
            await _cli(paths)
        assert not fake_open.exists()
        assert not list(paths.runtime_dir.glob("ui-start-*"))
        assert (await web.d.call("ui.sessions"))["result"] == {"sessions": []}

    run_web(paths, operator, scenario)


def test_listener_check_against_the_real_socket(paths, operator):
    async def scenario(web: Web) -> None:
        srv = web.ext.server
        assert ui_cli.listener_matches("127.0.0.1", srv.port, srv.inode)
        assert not ui_cli.listener_matches("127.0.0.1", srv.port, srv.inode + 1)
        assert not ui_cli.listener_matches("127.0.0.1", srv.port + 1 if srv.port < 65535 else 1, srv.inode)

    run_web(paths, operator, scenario)


def test_ui_with_server_off_explains_why(paths, operator, fake_open):
    async def scenario(web: Web) -> None:
        with pytest.raises(CliError, match="Web-Oberfläche aus: .*Loopback"):
            await _cli(paths)
        assert not fake_open.exists()

    run_web(paths, operator, scenario, config='[ui]\nbind = "0.0.0.0"\n')


def test_start_file_refuses_unexpected_urls(paths):
    for url in ("http://evil.example/#c=AAAAAAAAAAAAAAAAAAAAAA", "javascript:alert(1)",
                'http://127.0.0.1:7330/#c=AAAAAAAAAAAAAAAA"><script>'):
        with pytest.raises(CliError):
            ui_cli.write_start_file(paths, url)


def test_old_start_files_are_cleaned_up(paths):
    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    old = paths.runtime_dir / "ui-start-alt.html"
    old.write_text("x")
    os.utime(old, (time.time() - 3600, time.time() - 3600))
    new = ui_cli.write_start_file(paths, "http://127.0.0.1:7330/#c=AAAAAAAAAAAAAAAAAAAAAA")
    assert new.exists() and not old.exists()
    new.unlink()


# --------------------------------------------------------------------------- #
# als Prozess
# --------------------------------------------------------------------------- #


def _run_cli(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "ariadne.cli.main", *args], env=env, capture_output=True,
                          text=True, timeout=60, stdin=subprocess.DEVNULL, check=False)


def test_ui_without_daemon_starts_none(tmp_path):
    env = make_env(tmp_path)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    res = _run_cli(env, "ui", "--no-open")
    assert res.returncode == 1 and "ariadne start" in res.stderr and "Traceback" not in res.stderr
    assert not Path(env["XDG_RUNTIME_DIR"], "ariadne", "ctl.sock").exists()
    for extra in (["--sessions"], ["--revoke"], ["--code"]):
        res = _run_cli(env, "ui", *extra)
        assert res.returncode == 1 and "ariadne start" in res.stderr


def test_ui_against_a_real_daemon_process(tmp_path_factory):
    base = tmp_path_factory.mktemp("uiproc")
    env = make_env(base)
    env.pop("ARIADNE_WEB")  # dieser Daemon startet den Web-Server (auf einem freien Port)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    paths = default_paths(env)
    paths.config_dir.mkdir(parents=True)
    paths.config_file.write_text("[ui]\nport = 0\n")
    try:
        res = _run_cli(env, "daemon", "run", "--detach")
        assert res.returncode == 0, res.stderr
        st = CtlClient(paths.ctl_sock, timeout=5).call("ui.status")
        assert st["running"] is True and st["host"] == "127.0.0.1" and st["port"] > 0
        res = _run_cli(env, "ui", "--no-open")
        assert res.returncode == 0, res.stderr
        start = Path(re.search(r"Startdatei: file://(\S+)", res.stdout).group(1))
        assert stat.S_IMODE(start.stat().st_mode) == 0o600
        code = URL_IN_FILE.search(start.read_text()).group(2)
        assert code not in res.stdout and code not in res.stderr
        import httpx

        r = httpx.post(f"http://127.0.0.1:{st['port']}/api/v1/session", json={"code": code},
                       headers={"Origin": f"http://127.0.0.1:{st['port']}"}, timeout=10)
        assert r.status_code == 200, r.text
        res = _run_cli(env, "ui", "--sessions")
        assert res.returncode == 0 and "Sitzungen (1)" in res.stdout and r.json()["token"] not in res.stdout
        res = _run_cli(env, "ui", "--revoke")
        assert res.returncode == 0 and "1 Sitzung widerrufen" in res.stdout
        log = paths.daemon_log.read_text()
        assert code not in log and r.json()["token"] not in log  # nie in Logs
    finally:
        with contextlib.suppress(Exception):
            CtlClient(paths.ctl_sock, timeout=5).call("shutdown")
        end = time.monotonic() + 10
        while time.monotonic() < end and CtlClient(paths.ctl_sock, timeout=1).ping():
            time.sleep(0.05)


def test_status_line_names_web_address_or_reason(monkeypatch, paths):
    """Befund F11: ``ariadne status`` zeigt die Web-Oberfläche (Adresse oder Grund, warum aus)."""
    from ariadne.cli import main as cli_main

    answers = iter([
        {"running": True, "host": "127.0.0.1", "port": 7330, "error": None, "sessions": 1},
        {"running": True, "host": "::1", "port": 7444, "error": None, "sessions": 2},
        {"running": False, "host": "127.0.0.1", "port": None, "error": "Port belegt \x1b[2J", "sessions": 0},
    ])
    monkeypatch.setattr(cli_main, "_call", lambda paths, op, **kw: next(answers))
    assert cli_main._web_line(paths) == "Web:      läuft auf http://127.0.0.1:7330 (1 Sitzung)"
    assert cli_main._web_line(paths) == "Web:      läuft auf http://[::1]:7444 (2 Sitzungen)"
    line = cli_main._web_line(paths)
    assert line.startswith("Web:      aus (Port belegt") and "\x1b" not in line

    def boom(paths, op, **kw):
        raise CliError("Daemon läuft nicht")

    monkeypatch.setattr(cli_main, "_call", boom)
    assert cli_main._web_line(paths).startswith("Web:      aus (im Daemon nicht geladen")
