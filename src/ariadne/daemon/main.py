"""Start des Daemons: Vordergrund (systemd) oder abgekoppelt (CLI bei Bedarf)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import subprocess
import sys
import time

from ariadne.daemon.client import CtlClient
from ariadne.daemon.core import Daemon
from ariadne.daemon.hardening import AlreadyRunning, harden_process
from ariadne.paths import Paths, default_paths, ensure_private_dir

__all__ = ["run_foreground", "spawn_detached", "wait_ready"]


def _setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s ariadned %(levelname)s %(message)s")


def run_foreground(paths: Paths | None = None) -> int:
    """Läuft bis SIGTERM/SIGINT oder ``shutdown``. Gibt den Exit-Code zurück."""
    harden_process()
    _setup_logging()
    paths = paths or default_paths()
    daemon = Daemon(paths)

    async def main() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, daemon.request_stop)
        await daemon.run()

    try:
        asyncio.run(main())
    except AlreadyRunning:
        print("ariadned läuft bereits", file=sys.stderr)
        return 1
    return 0


def wait_ready(paths: Paths, timeout: float = 3.0) -> bool:
    client = CtlClient(paths.ctl_sock)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if paths.ctl_sock.exists() and client.ping():
            return True
        time.sleep(0.05)
    return client.ping()


def spawn_detached(paths: Paths | None = None, timeout: float = 3.0) -> bool:
    """Startet den Daemon im Hintergrund (eigene Session) und wartet bis ``timeout``."""
    paths = paths or default_paths()
    if CtlClient(paths.ctl_sock).ping():
        return True
    ensure_private_dir(paths.state_dir)
    log_path = paths.daemon_log
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    env = {k: v for k, v in os.environ.items() if k not in ("ARIADNE_TERMINAL_ID", "NOTIFY_SOCKET")}
    try:
        subprocess.Popen(
            [sys.executable, "-m", "ariadne.daemon"],
            stdin=subprocess.DEVNULL, stdout=fd, stderr=fd, close_fds=True,
            start_new_session=True, env=env, cwd="/",
        )
    finally:
        os.close(fd)
    return wait_ready(paths, timeout)
