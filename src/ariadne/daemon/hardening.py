"""Prozess-Härtung und Betriebshilfen des Daemons (Architektur 8.4, 8.6).

umask 077, keine Coredumps, ``PR_SET_DUMPABLE 0``, Single-Instance per flock,
Peer-Prüfung über ``SO_PEERCRED``, sd_notify, Zeitstatus für ``clock.check``.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import ctypes.util
import fcntl
import os
import resource
import shutil
import socket
import struct
from pathlib import Path
from typing import Any

__all__ = [
    "AlreadyRunning",
    "InstanceLock",
    "harden_process",
    "set_dumpable",
    "peer_cred",
    "proc_comm",
    "sd_notify",
    "clock_status",
]

PR_SET_DUMPABLE = 4


class AlreadyRunning(RuntimeError):
    pass


def set_dumpable(flag: bool) -> bool:
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        return libc.prctl(PR_SET_DUMPABLE, 1 if flag else 0, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def harden_process() -> None:
    """umask 077, RLIMIT_CORE 0, PR_SET_DUMPABLE 0. Nur im Daemon-Prozess aufrufen."""
    os.umask(0o077)
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    set_dumpable(False)


class InstanceLock:
    """Genau ein Daemon pro Benutzer: flock auf ``daemon.lock`` im Runtime-Ordner."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    def acquire(self) -> None:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise AlreadyRunning("ariadned läuft bereits") from None
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        self._fd = fd

    def release(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None


def peer_cred(sock: Any) -> tuple[int, int, int]:
    """``(pid, uid, gid)`` der Gegenseite eines Unix-Sockets."""
    data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", data)
    return pid, uid, gid


def proc_comm(pid: int) -> str | None:
    try:
        with open(f"/proc/{int(pid)}/comm", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def sd_notify(state: str) -> bool:
    """Meldet einen Zustand an systemd (``READY=1``), falls ``NOTIFY_SOCKET`` gesetzt ist."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as s:
            s.connect(addr)
            s.sendall(state.encode())
        return True
    except OSError:
        return False


async def _run(*argv: str, timeout: float = 3.0) -> str | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        return None
    if proc.returncode != 0:
        return None
    return out.decode("utf-8", "replace")


async def clock_status() -> dict[str, Any]:
    """Zeitstatus aus ``timedatectl`` für ``clock.check``. Ohne timedatectl: ``detail='unbekannt'``."""
    exe = shutil.which("timedatectl")
    if not exe:
        return {"detail": "unbekannt"}
    out = await _run(exe, "show", "-p", "NTPSynchronized", "-p", "Timezone")
    if out is None:
        return {"detail": "unbekannt"}
    values = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    info: dict[str, Any] = {"detail": "timedatectl"}
    if "NTPSynchronized" in values:
        info["synced"] = values["NTPSynchronized"].strip() == "yes"
    tz = values.get("Timezone", "").strip()
    if tz:
        info["timezone"] = tz[:64]
    server = await _run(exe, "show-timesync", "-p", "ServerName", "--value")
    if server and server.strip():
        info["ntp_server"] = server.strip()[:253]
    return info
