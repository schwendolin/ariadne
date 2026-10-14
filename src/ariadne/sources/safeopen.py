"""Dateien sicher öffnen und lesen (Architektur 4.1).

Loot und Tool-Ausgaben sind feindliche Eingaben: ``tar``, ``git clone`` oder
``smbclient mget`` legen Symlinks mit absolutem Ziel an. Darum:

* Geöffnet wird Komponente für Komponente relativ zu einem Verzeichnis-fd, jede
  Komponente mit ``O_NOFOLLOW`` (Verzeichnisse mit ``O_DIRECTORY``), die Datei
  zusätzlich mit ``O_NONBLOCK | O_NOCTTY``. Ein Symlink irgendwo im Pfad ergibt
  :class:`UnsafeFile`. ``..`` und leere Komponenten sind verboten.
* ``fstat`` auf dem fd: nur reguläre Dateien, ``st_nlink == 1``, Eigentümer
  Operator oder root, optional dasselbe Dateisystem. Gelesen wird nur über
  dieses fd und nur bis zu einer Grenze.
* Nie gelesen wird aus der Sperrliste (``~/.ssh``, ``~/.gnupg``, ``~/.config``,
  Ariadnes eigene Daten, Browser-Profile, Keyrings, jedes ``.vault``).

Nur Standardbibliothek. Dieses Modul liest Bytes, es parst sie nicht.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "UnsafeFile",
    "FileData",
    "MAX_STORE",
    "MAX_HASH",
    "blocked_reason",
    "open_beneath",
    "open_absolute",
    "check_fd",
    "read_fd",
    "read_absolute",
    "read_beneath",
    "inside",
    "sniff",
]

MAX_STORE = 100 << 20  # bis hier landet eine Datei im Blob-Store (Architektur 4.1)
MAX_HASH = 16 << 30  # grössere Dateien werden gar nicht gelesen

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC

# relativ zu HOME, immer gesperrt
_BLOCKED_HOME = (
    ".ssh", ".gnupg", ".config", ".local/share/ariadne", ".local/share/keyrings", ".mozilla",
    ".thunderbird", ".password-store", ".pki", ".aws", ".kube", ".docker",
)


class UnsafeFile(Exception):
    """Datei wird nicht gelesen. ``reason`` ist ein kurzer Code (ohne Pfad und Inhalt)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class FileData:
    data: bytes | None  # None: grösser als die Grenze, nur Metadaten und Hash
    size: int
    sha256: str
    mtime_ns: int


def _parts(rel: str) -> list[str]:
    if not rel or "\0" in rel or rel.startswith("/"):
        raise UnsafeFile("path")
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise UnsafeFile("path")
    return parts


def _os_reason(exc: OSError) -> str:
    if exc.errno in (errno.ELOOP, errno.EMLINK):
        return "symlink"
    if exc.errno == errno.ENOTDIR:
        return "symlink_or_not_dir"
    if exc.errno == errno.ENOENT:
        return "missing"
    if exc.errno in (errno.EACCES, errno.EPERM):
        return "permission"
    return "open_failed"


def open_beneath(dir_fd: int, rel: str) -> int:
    """Öffnet ``rel`` unterhalb von ``dir_fd`` ohne je einem Symlink zu folgen. Gibt ein fd zurück."""
    parts = _parts(rel)
    fd = os.dup(dir_fd)
    try:
        for name in parts[:-1]:
            nfd = os.open(name, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return os.open(parts[-1], _FILE_FLAGS, dir_fd=fd)
    except OSError as exc:
        raise UnsafeFile(_os_reason(exc)) from None
    finally:
        os.close(fd)


def open_absolute(path: str) -> int:
    """Öffnet einen absoluten Pfad ab ``/`` ohne Symlinks (auch nicht in Verzeichnissen)."""
    if not os.path.isabs(path) or "\0" in path:
        raise UnsafeFile("path")
    norm = os.path.normpath(path)
    root = os.open("/", _DIR_FLAGS)
    try:
        return open_beneath(root, norm.lstrip("/"))
    finally:
        os.close(root)


def check_fd(fd: int, *, dev: int | None = None) -> os.stat_result:
    """Prüft das geöffnete fd: reguläre Datei, ein Link, Eigentümer Operator oder root."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise UnsafeFile("not_regular")
    if st.st_nlink != 1:
        raise UnsafeFile("hardlink")
    if st.st_uid not in (os.getuid(), 0):
        raise UnsafeFile("owner")
    if dev is not None and st.st_dev != dev:
        raise UnsafeFile("other_fs")
    return st


def read_fd(fd: int, limit: int, *, hard_limit: int = MAX_HASH) -> tuple[bytes | None, int, str]:
    """Liest über das fd und hasht alles (SHA-256). Inhalt nur, wenn höchstens ``limit`` Bytes.

    Gibt ``(daten oder None, grösse, sha256)`` zurück. Über ``hard_limit``: ``too_large``.
    """
    h = hashlib.sha256()
    chunks: list[bytes] | None = []
    total = 0
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        total += len(chunk)
        if total > hard_limit:
            raise UnsafeFile("too_large")
        h.update(chunk)
        if chunks is not None:
            if total > limit:
                chunks = None
            else:
                chunks.append(chunk)
    return (b"".join(chunks) if chunks is not None else None), total, h.hexdigest()


def _read(fd: int, *, limit: int, dev: int | None) -> FileData:
    try:
        st = check_fd(fd, dev=dev)
        data, size, sha = read_fd(fd, limit)
        return FileData(data, size, sha, st.st_mtime_ns)
    finally:
        os.close(fd)


def _canon(path: str) -> str:
    """``normpath`` plus POSIX-Sonderfall: ``//home`` ist ``/home`` (normpath lässt ``//`` stehen)."""
    norm = os.path.normpath(path)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return norm


def blocked_reason(path: str, home: Path | str, extra: tuple[Path, ...] = ()) -> str | None:
    """Grund, warum ein (absoluter, normalisierter) Pfad nie gelesen wird, sonst ``None``."""
    norm = _canon(path)
    if ".vault" in norm.split("/"):
        return "vault"
    roots = [os.path.join(str(home), b) for b in _BLOCKED_HOME] + [str(e) for e in extra]
    for r in roots:
        r = _canon(r)
        if norm == r or norm.startswith(r + "/"):
            return "blocked"
    return None


def inside(path: str, root: Path | str) -> str | None:
    """Pfad relativ zu ``root``, wenn ``path`` (lexikalisch) darin liegt, sonst ``None``."""
    norm = _canon(path)
    base = _canon(str(root))
    if not norm.startswith(base + "/"):
        return None
    return norm[len(base) + 1:]


def read_absolute(path: str, *, home: Path | str, limit: int = MAX_STORE,
                  extra_blocked: tuple[Path, ...] = ()) -> FileData:
    """Ausdrücklicher Import: absoluter Pfad, ohne Symlinks, nicht aus der Sperrliste."""
    reason = blocked_reason(path, home, extra_blocked)
    if reason is not None:
        raise UnsafeFile(reason)
    return _read(open_absolute(path), limit=limit, dev=None)


def read_beneath(root: Path, rel: str, *, home: Path | str, limit: int = MAX_STORE,
                 extra_blocked: tuple[Path, ...] = ()) -> FileData:
    """Datei im Arbeitsbereich ``root`` (gleiches Dateisystem, ohne Symlinks)."""
    reason = blocked_reason(os.path.join(str(root), rel), home, extra_blocked)
    if reason is not None:
        raise UnsafeFile(reason)
    try:
        rfd = os.open(root, _DIR_FLAGS)
    except OSError as exc:
        raise UnsafeFile(_os_reason(exc)) from None
    try:
        dev = os.fstat(rfd).st_dev
        fd = open_beneath(rfd, rel)
    finally:
        os.close(rfd)
    return _read(fd, limit=limit, dev=dev)


def sniff(data: bytes | None, path: str) -> tuple[str | None, str | None]:
    """Grobe Einordnung über Magic-Bytes und Endung: ``(mime, sniff)``. Liest nur den Anfang."""
    lower = path.lower()
    if data is None:
        return None, None
    head = data[:4096]
    if b"<nmaprun" in head:
        return "application/xml", "nmaprun"
    if head.lstrip().startswith(b"<?xml") or lower.endswith(".xml"):
        return "application/xml", None
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", None
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", None
    if b"\0" in head:
        return "application/octet-stream", None
    return "text/plain", None
