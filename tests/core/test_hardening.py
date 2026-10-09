"""Daemon-Prozess: sd_notify, RLIMIT_CORE, Rechte von Runtime-Ordner und Sockets, Single-Instance."""

from __future__ import annotations

import os
import socket
import stat
import subprocess
import sys

from ariadne.daemon import hardening
from ariadne.daemon.client import CtlClient
from ariadne.paths import default_paths
from tests.core.conftest import make_env


def test_sd_notify(tmp_path, monkeypatch):
    path = tmp_path / "notify"
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as srv:
        srv.bind(str(path))
        monkeypatch.setenv("NOTIFY_SOCKET", str(path))
        assert hardening.sd_notify("READY=1")
        assert srv.recv(64) == b"READY=1"
    monkeypatch.delenv("NOTIFY_SOCKET")
    assert not hardening.sd_notify("READY=1")


def test_daemon_process_is_hardened(tmp_path):
    env = make_env(tmp_path)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    notify = tmp_path / "n"
    paths = default_paths(env)
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as srv:
        srv.bind(str(notify))
        srv.settimeout(15)
        env["NOTIFY_SOCKET"] = str(notify)
        proc = subprocess.Popen([sys.executable, "-m", "ariadne.daemon"], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            assert srv.recv(64) == b"READY=1"
            limits = open(f"/proc/{proc.pid}/limits").read()
            core = next(line for line in limits.splitlines() if line.startswith("Max core file size"))
            assert core.split()[4:6] == ["0", "0"]
            assert stat.S_IMODE(os.stat(paths.runtime_dir).st_mode) == 0o700
            for sock in (paths.term_sock, paths.ctl_sock):
                assert stat.S_IMODE(os.stat(sock).st_mode) == 0o600
            # zweite Instanz verweigert den Start
            second = subprocess.run([sys.executable, "-m", "ariadne.daemon"], env=env, capture_output=True,
                                    text=True, timeout=20, check=False)
            assert second.returncode == 1 and "läuft bereits" in second.stderr
            CtlClient(paths.ctl_sock).call("shutdown")
            assert proc.wait(timeout=10) == 0
            assert not paths.ctl_sock.exists() and not paths.term_sock.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        err = proc.stderr.read().decode() if proc.stderr else ""
        assert "bereit" in err and "beendet" in err


def test_clock_status_without_timedatectl(monkeypatch):
    import asyncio

    monkeypatch.setattr(hardening.shutil, "which", lambda name: None)
    assert asyncio.run(hardening.clock_status()) == {"detail": "unbekannt"}
