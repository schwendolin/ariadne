"""Installation aus dem Wheel (Etappe 4, Paket): Wheel offline bauen, in ein frisches venv installieren,
``ariadne setup`` in einem isolierten HOME, Daemon starten; der Webserver liefert ``index.html`` und
die Assets aus dem installierten Paket (nicht aus dem Checkout), ``ariadne doctor`` meldet die
Oberfläche als vorhanden.

Abhängigkeiten kommen über eine ``.pth``-Datei aus dem venv des Checkouts (kein Netz, keine
Installation von Paketen); das Paket selbst kommt nur aus dem Wheel. Braucht ``uv``.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import sysconfig
import time
import zipfile
from pathlib import Path

import httpx
import pytest

from ariadne.cli.doctor import UI_MANIFEST

pytestmark = pytest.mark.slow

ROOT = Path(__file__).resolve().parents[2]
UV = shutil.which("uv")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _env(tmp: Path) -> dict[str, str]:
    home = tmp / "home"
    run = tmp / "run"
    home.mkdir()
    run.mkdir(mode=0o700)
    keep = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "TZ")}
    return {
        **keep,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_RUNTIME_DIR": str(run),
        "SHELL": "/bin/bash",
        "UV_OFFLINE": "1",
        "UV_NO_CACHE": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> Path:
    if UV is None:
        pytest.skip("uv fehlt (Wheel-Bau offline)")
    out = tmp_path_factory.mktemp("dist")
    res = subprocess.run(
        [UV, "build", "--wheel", "--offline", "-o", str(out), str(ROOT)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if res.returncode != 0 and "offline" in (res.stderr or "").lower():
        pytest.skip("Build-Backend nicht im Offline-Cache")
    assert res.returncode == 0, res.stderr[-2000:]
    (whl,) = out.glob("ariadne_recon-*.whl")
    return whl


def test_wheel_contains_built_ui(wheel):
    names = set(zipfile.ZipFile(wheel).namelist())
    static = ROOT / "src" / "ariadne" / "web" / "static"
    want = {
        "ariadne/web/static/" + p.relative_to(static).as_posix()
        for p in static.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    assert f"ariadne/web/static/{UI_MANIFEST}" in want and "ariadne/web/static/index.html" in want
    assert want <= names, sorted(want - names)
    assert not any(n.endswith(".pyc") or "/node_modules/" in n or n.startswith("webui/") for n in names)


def test_fresh_venv_setup_and_webserver_serves_index(wheel, tmp_path):
    env = _env(tmp_path)
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True, timeout=120)
    py = venv / "bin" / "python"
    site = Path(
        subprocess.run(
            [str(py), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    )
    # Abhängigkeiten aus dem Checkout-venv, aber ohne dessen .pth (editierbare Installation)
    (site / "zz_deps.pth").write_text(sysconfig.get_paths()["purelib"] + "\n", encoding="utf-8")
    res = subprocess.run(
        [UV, "pip", "install", "--offline", "--no-deps", "--python", str(py), str(wheel)],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
        check=False,
    )
    assert res.returncode == 0, res.stderr[-2000:]
    ariadne = venv / "bin" / "ariadne"
    where = subprocess.run(
        [str(py), "-c", "import ariadne, sys; print(ariadne.__file__)"],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        check=True,
    ).stdout.strip()
    assert where.startswith(str(site)), where  # aus dem Wheel, nicht aus dem Checkout

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(ariadne), *args],
            capture_output=True,
            text=True,
            env=env,
            cwd=tmp_path,
            timeout=60,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    home = Path(env["HOME"])
    (home / ".zshrc").write_text("# Original\n", encoding="utf-8")
    r = run("setup", "--no-systemd")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Setup abgeschlossen" in r.stdout
    assert (home / ".zshrc").read_text(encoding="utf-8").startswith("# >>> ariadne")
    doc = run("doctor")
    assert re.search(r"Weboberfläche vorhanden \(Quellstand [0-9a-f]{12}\)", doc.stdout), doc.stdout

    port = _free_port()
    cfg = Path(env["XDG_CONFIG_HOME"]) / "ariadne"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "config.toml").write_text(f"[ui]\nport = {port}\n", encoding="utf-8")
    proc = subprocess.Popen(
        [str(ariadne), "daemon", "run"],
        env=env,
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 30
        body = None
        while time.monotonic() < deadline and proc.poll() is None:
            try:
                r2 = httpx.get(f"{base}/", timeout=2.0)
            except httpx.HTTPError:
                time.sleep(0.2)
                continue
            body = r2
            break
        assert body is not None, "Webserver nicht erreichbar"
        assert body.status_code == 200 and body.headers["content-type"].startswith("text/html")
        assert '<div id="app">' in body.text
        assert "Content-Security-Policy" in body.headers
        for ref in re.findall(r'(?:src|href)="(/assets/[^"]+)"', body.text):
            a = httpx.get(f"{base}{ref}", timeout=5.0)
            assert a.status_code == 200 and len(a.content) > 0, ref
        # der Build-Vermerk ist versteckt (Punktdatei)
        assert httpx.get(f"{base}/{UI_MANIFEST}", timeout=5.0).status_code == 404
    finally:
        run("daemon", "stop")
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()
