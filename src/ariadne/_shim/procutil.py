"""Prozess-Hilfen für den Shim: ``/proc``, ``prctl``, Härtung. Nur Standardbibliothek."""

from __future__ import annotations

import contextlib
import os
import resource

__all__ = [
    "SHIM_NAME",
    "SHELLS",
    "read_comm",
    "read_ppid",
    "has_ancestor_named",
    "descends_from",
    "set_process_name",
    "harden_parent",
]

SHIM_NAME = "ariadne-shim"
SHELLS = frozenset({"zsh", "bash", "fish", "sh", "dash"})

_PR_SET_DUMPABLE = 4
_PR_SET_NAME = 15
_MAX_DEPTH = 64


def read_comm(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/comm", "rb") as fh:
            return fh.read(64).rstrip(b"\n").decode("utf-8", "replace")
    except OSError:
        return None


def read_ppid(pid: int) -> int | None:
    """Elternprozess aus ``/proc/<pid>/stat`` (Feld 4, nach dem letzten ``)``)."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read(4096)
    except OSError:
        return None
    rest = data.rpartition(b")")[2].split()
    try:
        return int(rest[1])
    except (IndexError, ValueError):
        return None


def has_ancestor_named(name: str, start: int | None = None) -> bool:
    """Liegt ein Vorfahre mit ``comm == name`` in der Kette (ab dem Elternprozess)?"""
    pid = os.getppid() if start is None else start
    for _ in range(_MAX_DEPTH):
        if pid is None or pid <= 1:
            return False
        if read_comm(pid) == name:
            return True
        pid = read_ppid(pid)
    return False


def descends_from(pid: int, ancestor: int) -> bool:
    """``pid`` ist ``ancestor`` oder ein Nachfahre davon."""
    cur: int | None = pid
    for _ in range(_MAX_DEPTH):
        if cur is None or cur <= 1:
            return False
        if cur == ancestor:
            return True
        cur = read_ppid(cur)
    return False


def _prctl(option: int, arg: int | bytes) -> bool:
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        if isinstance(arg, bytes):
            buf = ctypes.create_string_buffer(arg[:15])
            return libc.prctl(option, buf, 0, 0, 0) == 0
        return libc.prctl(option, ctypes.c_ulong(arg), 0, 0, 0) == 0
    except Exception:  # nur nach bestem Bemühen
        return False


def set_process_name(name: str = SHIM_NAME) -> bool:
    """Setzt ``comm`` per ``prctl(PR_SET_NAME)``, sonst über ``/proc/self/comm``."""
    raw = name.encode()[:15]
    if _prctl(_PR_SET_NAME, raw):
        return True
    try:
        with open("/proc/self/comm", "wb") as fh:
            fh.write(raw)
        return True
    except OSError:
        return False


def harden_parent() -> None:
    """Keine Coredumps, kein ptrace durch andere Prozesse (nur für den Shim selbst)."""
    with contextlib.suppress(OSError, ValueError):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    _prctl(_PR_SET_DUMPABLE, 0)
