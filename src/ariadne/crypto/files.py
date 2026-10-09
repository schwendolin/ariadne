"""Dateihilfen für Schlüsselmaterial und Chiffrate.

Schreiben immer atomar (temporäre Datei, fsync, rename, fsync des Ordners) mit
Rechten 0600. Lesen nur reguläre Dateien des Benutzers, ohne Symlinks.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
from pathlib import Path

from ariadne.paths import UnsafePathError

__all__ = ["write_private", "read_private", "fsync_dir"]


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Schreibt ``data`` atomar nach ``path`` (Rechte 0600, nie über Symlinks)."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(tmp, flags, mode)
    try:
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    fsync_dir(path.parent)


def read_private(path: Path, max_size: int = 64 << 20) -> bytes:
    """Liest eine reguläre Datei des Benutzers. Symlinks und fremde Dateien werden abgelehnt."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePathError(f"keine reguläre Datei: {path}")
        if st.st_uid != os.getuid():
            raise UnsafePathError(f"gehört nicht dem Benutzer: {path}")
        if st.st_size > max_size:
            raise UnsafePathError(f"Datei zu gross: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)
