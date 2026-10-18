"""Was in die Sicherung kommt: Auswahl, Sperren der Projekte, erster Durchgang mit Hashes.

Auswahl (Konzept Fernzugriff 6.1, Vertrag 3.5):

* ``operator/``: der ganze Operator-Tresor (``Paths.operator_dir``), immer;
* ``config/``: ``~/.config/ariadne`` (ohne Sockets, FIFOs, Geräte und Links);
* ``projects/<slug>/``: der Projektordner mit Arbeitsbereich und ``.vault/``, in ``.vault/`` ohne
  ``derived*`` (wird nach dem Zurückspielen neu gebaut), ohne ``*-shm`` und ``.lock``, aber mit
  ``*-wal`` (nach einem Absturz stehen dort bestätigte Einträge der Kette).

Überall ausgelassen: Symlinks (nie folgen), Sockets, FIFOs und Geräte, ausserhalb des
Arbeitsbereichs auch liegengebliebene temporäre Dateien von ``write_private``
(``.<name>.<16 hex>.tmp``). Ihre Zahl steht als ``skipped`` im Manifest, Namen nie (sie können
aus Zieldaten stammen).

Ein offenes Projekt wird nicht gesichert: Wie der Daemon nimmt die Sicherung ``flock`` auf
``.vault/.lock`` und hält ihn bis zum Ende (sonst ``project_open``). Datenbanken öffnet sie nie.
Solange sie ihn hält, liegt ``.vault/.backup-running`` mit ihrer PID daneben; ein ``start`` oder
``unlock`` in dieser Zeit nennt dann den richtigen Grund (Befund RT-7).

Strenge Regeln gelten für ``operator/``, ``config/`` und ``.vault/``: Jede Datei gehört dem
Benutzer, jeder Ordner ist lesbar, und eine Datei ändert sich zwischen den beiden Durchgängen nicht
(sonst Abbruch mit ``io``). Im **Arbeitsbereich** (``projects/<slug>/`` ausser ``.vault/``) liegen
Dateien der Werkzeuge: Dateien von root (``sudo nmap -oA``) werden mitgesichert, Dateien anderer
Benutzer und nicht lesbare Dateien oder Ordner übersprungen und gezählt (``unreadable``, ohne
Namen; Befund F1). Wächst dort eine Datei während der Sicherung (``tee -a``, ``tcpdump``, ein Scan),
kommt genau der Anfang mit der Länge und dem Hash aus dem ersten Durchgang in die Sicherung
(``grown``); abgebrochen wird nur, wenn sie ersetzt, kürzer oder am Anfang geändert wurde (Befund
RT-2), und die Meldung nennt dann das Projekt.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ariadne.backup.model import BackupError
from ariadne.crypto.files import read_private
from ariadne.crypto.vault import OperatorVault, VaultError
from ariadne.paths import Paths, UnsafePathError
from ariadne.project.service import BACKUP_MARKER, HEAD_FORMAT, MANIFEST_FORMAT, valid_slug

__all__ = ["Entry", "ProjectMeta", "Selection", "select", "hash_file", "open_checked", "CHUNK"]

CHUNK = 1 << 20
_TMP_RE = re.compile(r"^\..+\.[0-9a-f]{16}\.tmp$")
_DERIVED_RE = re.compile(r"^derived(\.[a-z0-9-]{1,32})?\.db(-wal|-shm|-journal)?$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Entry:
    arc: str  # Pfad im Strom, z. B. ``projects/lame/scans/a.xml``
    src: Path
    is_dir: bool
    mode: int
    mtime: int
    dev: int = 0
    ino: int = 0
    size: int = 0
    sha256: str = ""
    workspace: bool = False  # im Arbeitsbereich: Wachstum erlaubt, Fremdes wird übersprungen
    grew: bool = False  # beim zweiten Durchgang länger als im Manifest (nur Arbeitsbereich)

    @property
    def slug(self) -> str | None:
        parts = self.arc.split("/")
        return parts[1] if len(parts) > 1 and parts[0] == "projects" else None


@dataclass(frozen=True)
class ProjectMeta:
    slug: str
    project_id: str
    profile: str
    head: dict[str, Any] | None  # {head_seq, head_hash, closed_utc} oder None


@dataclass
class Selection:
    operator_recipient: str
    projects: list[ProjectMeta]
    entries: list[Entry]
    skipped: int = 0
    unreadable: int = 0  # Arbeitsbereich: fremde oder nicht lesbare Dateien und Ordner
    lock_fds: list[int] = field(default_factory=list)
    markers: list[Path] = field(default_factory=list)

    @property
    def files(self) -> list[Entry]:
        return [e for e in self.entries if not e.is_dir]

    @property
    def grown(self) -> int:
        return sum(1 for e in self.entries if e.grew)

    def release(self) -> None:
        for marker in self.markers:
            with contextlib.suppress(OSError):
                marker.unlink()
        self.markers.clear()
        for fd in self.lock_fds:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(fd)
        self.lock_fds.clear()


def _io(message: str) -> BackupError:
    return BackupError("io", message)


def open_checked(path: Path) -> int:
    """Öffnet eine reguläre Datei ohne Symlinks zum Lesen (blockiert nie an einer FIFO)."""
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK)


def _changed(e: Entry) -> BackupError:
    if e.workspace and e.slug:
        return _io(f"Eine Datei im Arbeitsbereich von {e.slug} wurde während der Sicherung ersetzt, "
                   f"gekürzt oder am Anfang geändert (Werkzeug noch aktiv?). Werkzeug beenden, dann neu "
                   f"sichern.")
    return _io("Eine Datei änderte sich während der Sicherung; bitte neu starten.")


def hash_file(e: Entry) -> bool:
    """Erster Durchgang: Grösse und SHA-256 bestimmen (zweiter Durchgang prüft beides erneut).

    Gehasht werden genau die ``st_size`` Bytes beim Öffnen; wächst die Datei dabei, zählt das
    Spätere nicht. Im Arbeitsbereich gibt eine nicht lesbare Datei ``False`` (überspringen)."""
    try:
        fd = open_checked(e.src)
    except PermissionError as exc:
        if e.workspace:
            return False
        raise _io("Eine Datei ist nicht lesbar; die Sicherung wurde abgebrochen.") from exc
    except OSError as exc:
        raise _io("Eine Datei verschwand während der Sicherung; bitte neu starten.") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (e.dev, e.ino):
            raise _changed(e)
        h = hashlib.sha256()
        left = st.st_size
        while left > 0:
            chunk = os.read(fd, min(CHUNK, left))
            if not chunk:
                raise _changed(e)  # kürzer geworden
            h.update(chunk)
            left -= len(chunk)
        if not e.workspace and os.read(fd, 1):
            raise _changed(e)  # ausserhalb des Arbeitsbereichs ändert sich nichts
        e.size, e.sha256 = st.st_size, h.hexdigest()
    finally:
        os.close(fd)
    return True


def _real_dir(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise BackupError("io", "Ein Ordner der Installation ist ein Symlink oder keine Ordner; "
                                "Ariadne folgt keinen Links (ariadne doctor).")
    if st.st_uid != os.getuid():
        raise BackupError("io", "Ein Ordner der Installation gehört nicht dem Benutzer.")
    return True


class _Walker:
    def __init__(self, exclude: set[tuple[int, int]]) -> None:
        self.entries: list[Entry] = []
        self.skipped = 0
        self.unreadable = 0
        self.exclude = exclude
        self.uid = os.getuid()

    def walk(self, root: Path, arc: str) -> None:
        """Rekursiv, ohne Links zu folgen, sortiert (stabile Reihenfolge im Strom)."""
        parts = arc.split("/")
        in_vault = len(parts) >= 3 and parts[0] == "projects" and parts[2] == ".vault"
        vault_top = in_vault and len(parts) == 3
        # Reste von write_private gibt es nur, wo Ariadne selbst schreibt (nicht im Arbeitsbereich)
        skip_tmp = in_vault or parts[0] in ("operator", "config")
        workspace = parts[0] == "projects" and len(parts) >= 2 and not in_vault
        try:
            with os.scandir(root) as it:
                items = sorted(it, key=lambda d: d.name)
        except PermissionError as exc:
            if workspace:
                self.unreadable += 1  # z. B. ein Ordner von root mit 0700
                return
            raise _io("Ein Ordner ist nicht lesbar; die Sicherung wurde abgebrochen.") from exc
        except OSError as exc:
            raise _io("Ein Ordner ist nicht lesbar; die Sicherung wurde abgebrochen.") from exc
        for d in items:
            name = d.name
            if skip_tmp and _TMP_RE.match(name):
                self.skipped += 1
                continue
            if vault_top and (name in (".lock", BACKUP_MARKER) or _DERIVED_RE.match(name)):
                continue
            if in_vault and name.endswith("-shm"):
                continue
            try:
                st = d.stat(follow_symlinks=False)
            except OSError as exc:
                if workspace and isinstance(exc, PermissionError):
                    self.unreadable += 1
                    continue
                raise _io("Eine Datei ist nicht lesbar; die Sicherung wurde abgebrochen.") from exc
            if (st.st_dev, st.st_ino) in self.exclude:
                continue
            sub = f"{arc}/{name}"
            if stat.S_ISDIR(st.st_mode):
                self.entries.append(Entry(sub, Path(d.path), True, st.st_mode & 0o7777, int(st.st_mtime),
                                          st.st_dev, st.st_ino))
                self.walk(Path(d.path), sub)
            elif stat.S_ISREG(st.st_mode):
                if workspace and st.st_uid not in (self.uid, 0):
                    self.unreadable += 1  # Datei eines anderen Benutzers: nicht mitsichern
                    continue
                if not workspace and st.st_uid != self.uid:
                    raise _io("Eine Datei gehört nicht dem Benutzer; die Sicherung wurde abgebrochen.")
                self.entries.append(Entry(sub, Path(d.path), False, st.st_mode & 0o7777, int(st.st_mtime),
                                          st.st_dev, st.st_ino, st.st_size, workspace=workspace))
            else:
                self.skipped += 1  # Symlink, Socket, FIFO, Gerät


def _project_manifest(vault: Path, slug: str) -> dict[str, Any]:
    try:
        data = json.loads(read_private(vault / "manifest.json", max_size=1 << 20).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, UnsafePathError) as exc:
        raise _io(f"Projekt {slug}: .vault/manifest.json fehlt oder ist unlesbar. Ohne dieses Projekt "
                  f"sichern: --project für die übrigen angeben.") from exc
    if not isinstance(data, dict) or data.get("format") != MANIFEST_FORMAT or data.get("slug") != slug:
        raise _io(f"Projekt {slug}: .vault/manifest.json passt nicht zum Ordner.")
    pid = data.get("project_id")
    if not isinstance(pid, str) or not 8 <= len(pid) <= 64:
        raise _io(f"Projekt {slug}: Projekt-ID fehlt im Manifest.")
    return data


def _read_head(vault: Path, project_id: str) -> dict[str, Any] | None:
    """Kettenkopf aus ``.vault/head.json`` (Vertrag 1.2); ``None``, wenn er fehlt oder nicht passt."""
    try:
        data = json.loads(read_private(vault / "head.json", max_size=4096).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, UnsafePathError):
        return None
    if not isinstance(data, dict) or data.get("format") != HEAD_FORMAT:
        return None
    if data.get("project_id") != project_id:
        return None
    seq, h = data.get("head_seq"), data.get("head_hash")
    if type(seq) is not int or seq < 0 or not isinstance(h, str) or not _HEX64.match(h):
        return None
    closed = data.get("closed_utc")
    return {"head_seq": seq, "head_hash": h, "closed_utc": closed if isinstance(closed, str) else None}


def _lock_project(vault: Path, slug: str) -> int:
    try:
        fd = os.open(vault / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise _io(f"Projekt {slug}: Sperrdatei nicht verfügbar.") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise BackupError("project_open", f"Projekt {slug} ist offen. Zuerst ariadne lock oder ariadne stop "
                                          f"(vom Mac: ariadne-mac stop), dann sichern.") from None
    except OSError as exc:
        os.close(fd)
        raise _io(f"Projekt {slug}: Sperrdatei nicht verfügbar.") from exc
    return fd


def _candidate_projects(paths: Paths) -> list[str]:
    root = paths.projects_root
    if not _real_dir(root):
        return []
    out = []
    for entry in sorted(root.iterdir()):
        if not valid_slug(entry.name) or entry.is_symlink() or not entry.is_dir():
            continue
        vault = entry / ".vault"
        if vault.is_symlink() or not vault.is_dir():
            continue  # kein Projekt (eigene Ordner unter ~/ariadne bleiben aussen vor)
        out.append(entry.name)
    return out


def select(paths: Paths, projects: list[str] | None = None, *,
           exclude: set[tuple[int, int]] | None = None) -> Selection:
    """Sperrt die Projekte, sammelt Ordner und Dateien und hasht jede Datei (erster Durchgang).

    Bei einem Fehler sind alle Sperren wieder frei. Sonst gibt ``Selection.release`` sie frei.
    """
    vault = OperatorVault(paths.operator_dir)
    if not vault.exists or not _real_dir(paths.operator_dir):
        raise BackupError("no_vault", "Kein Operator-Tresor (ariadne init). Ohne Tresor ist keine "
                                      "Sicherung sinnvoll, denn er schliesst alle Projekte auf.")
    try:
        recipient = vault.recipient()
    except (VaultError, OSError, UnsafePathError, KeyError) as exc:
        raise _io("vault.json des Operator-Tresors ist unlesbar.") from exc

    available = _candidate_projects(paths)
    if projects is None:
        chosen = available
    else:
        chosen = []
        for slug in projects:
            if not valid_slug(slug) or slug not in available:
                raise BackupError("not_found", f"Projekt nicht gefunden: {slug if valid_slug(slug) else '?'}")
            if slug not in chosen:
                chosen.append(slug)

    sel = Selection(recipient, [], [])
    walker = _Walker(exclude or set())
    try:
        metas: list[ProjectMeta] = []
        for slug in chosen:
            pvault = paths.projects_root / slug / ".vault"
            sel.lock_fds.append(_lock_project(pvault, slug))
            marker = pvault / BACKUP_MARKER
            with contextlib.suppress(OSError):
                flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
                fd = os.open(marker, flags, 0o600)
                try:
                    os.write(fd, f"{os.getpid()}\n".encode("ascii"))
                finally:
                    os.close(fd)
                sel.markers.append(marker)
            m = _project_manifest(pvault, slug)
            pid = str(m["project_id"])
            metas.append(ProjectMeta(slug, pid, str(m.get("profile", "")), _read_head(pvault, pid)))
        sel.projects = metas

        walker.walk(paths.operator_dir, "operator")
        if _real_dir(paths.config_dir):
            walker.walk(paths.config_dir, "config")
        for meta in metas:
            proot = paths.projects_root / meta.slug
            st = os.lstat(proot)
            walker.entries.append(Entry(f"projects/{meta.slug}", proot, True, st.st_mode & 0o7777,
                                        int(st.st_mtime), st.st_dev, st.st_ino))
            walker.walk(proot, f"projects/{meta.slug}")
        unreadable = walker.unreadable
        kept: list[Entry] = []
        for e in walker.entries:
            if e.is_dir or hash_file(e):
                kept.append(e)
            else:
                unreadable += 1
        sel.entries = kept
        sel.skipped = walker.skipped
        sel.unreadable = unreadable
    except BaseException:
        sel.release()
        raise
    return sel


def iter_file(e: Entry) -> Iterator[bytes]:
    """Zweiter Durchgang: genau ``e.size`` Bytes in Blöcken; prüft Datei, Grösse und Hash erneut
    (sonst ``io``). Im Arbeitsbereich darf die Datei gewachsen sein (``e.grew``): Der Anfang muss
    dann denselben Hash haben, das Angehängte kommt nicht mit."""
    try:
        fd = open_checked(e.src)
    except OSError as exc:
        raise _io("Eine Datei verschwand während der Sicherung; bitte neu starten.") from exc
    try:
        st = os.fstat(fd)
        same = stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) == (e.dev, e.ino)
        if not same or st.st_size < e.size or (st.st_size != e.size and not e.workspace):
            raise _changed(e)
        h = hashlib.sha256()
        left = e.size
        while left > 0:
            chunk = os.read(fd, min(CHUNK, left))
            if not chunk:
                raise _changed(e)  # während des Lesens kürzer geworden
            h.update(chunk)
            left -= len(chunk)
            yield chunk
        if h.hexdigest() != e.sha256:
            raise _changed(e)
        if os.read(fd, 1):
            if not e.workspace:
                raise _changed(e)
            e.grew = True
    finally:
        os.close(fd)
