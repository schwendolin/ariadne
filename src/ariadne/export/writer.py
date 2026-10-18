"""Export sicher auf die Platte schreiben (Architektur 8.7 Punkte 1, 3, 8).

* Ziel ist immer ``<projekt>/exports/<UTC>-<vorlage>/``. Ordner und Dateien entstehen per
  ``openat`` relativ zum Export-Ordner mit ``O_NOFOLLOW | O_EXCL``; Symlinks im Weg führen zum Abbruch.
* Jede Datei geht vor dem Schreiben noch einmal durch ``redact_for_exit`` (E72, letzte Schicht).
* ``_ariadne/manifest.json`` nennt Exportzeit, Vorlage, Kettenkopf des Journals, die Kettenköpfe der
  Belege und SHA-256 und Grösse jeder Datei.
* Liegt der Projektordner in einem Sync-Ordner (Obsidian-Vault, Nextcloud, ownCloud, Dropbox,
  Syncthing, OneDrive, Google Drive), kommt die Warnung ``sync_folder``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = ["ExportError", "write_export", "list_exports", "sync_folder", "EXPORT_RE", "MANIFEST_FORMAT"]

MANIFEST_FORMAT = "ariadne-export/1"
EXPORT_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-(cys|htb)(-[0-9]{1,3})?$")
_PATH_RE = re.compile(
    r"^(?:[A-Za-z0-9ÄÖÜäöü][A-Za-z0-9ÄÖÜäöü ._-]{0,80}/){0,3}[A-Za-z0-9ÄÖÜäöü][A-Za-z0-9ÄÖÜäöü ._-]{0,80}$"
)
_SYNC_MARKERS = (
    ".obsidian",
    ".nextcloudsync.log",
    ".owncloudsync.log",
    ".sync_",
    ".dropbox",
    ".dropbox.cache",
    ".stfolder",
    ".sync-exclude.lst",
)
_SYNC_NAMES = (
    "dropbox",
    "nextcloud",
    "owncloud",
    "onedrive",
    "google drive",
    "googledrive",
    "mega",
    "icloud",
    "seafile",
    "pcloud",
    "syncthing",
)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class ExportError(RuntimeError):
    """Export nicht möglich (fester Text, ohne Pfade aus Zieldaten)."""


def sync_folder(path: Path) -> bool:
    """Liegt ``path`` in einem Sync-Ordner? Prüft Namen und Marker in ``path`` und allen Eltern."""
    p = Path(path)
    for d in [p, *p.parents]:
        name = d.name.lower()
        if any(name == n or name.startswith(n + " ") or name.startswith(n + "-") for n in _SYNC_NAMES):
            return True
        for marker in _SYNC_MARKERS:
            with contextlib.suppress(OSError):
                if marker.endswith("_"):
                    if any(e.name.startswith(marker) for e in os.scandir(d) if not e.is_symlink()):
                        return True
                elif os.path.lexists(d / marker):
                    return True
    return False


def _mkdir_at(parent_fd: int, name: str) -> int:
    with contextlib.suppress(FileExistsError):
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise ExportError("Export-Ordner ist kein Ordner oder ein Symlink") from exc


def _open_exports(workspace: Path) -> int:
    try:
        ws_fd = os.open(str(workspace), _DIR_FLAGS)
    except OSError as exc:
        raise ExportError("Projektordner nicht gefunden oder ein Symlink") from exc
    try:
        return _mkdir_at(ws_fd, "exports")
    finally:
        os.close(ws_fd)


def _write_at(dir_fd: int, name: str, data: bytes) -> None:
    fd = os.open(name, _FILE_FLAGS, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _stamp(now_ns: int) -> str:
    return datetime.fromtimestamp(now_ns // 1_000_000_000, tz=UTC).strftime("%Y%m%dT%H%M%SZ")


def write_export(
    workspace: Path,
    files: Mapping[str, str | bytes],
    *,
    template: str,
    now_ns: int,
    redactor: Any,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Schreibt alle Dateien in einen neuen Export-Ordner und das Manifest. Gibt Kennung, relativen
    Pfad, Zahl der Dateien und das Manifest zurück."""
    if template not in ("cys", "htb"):
        raise ExportError("unbekannte Vorlage")
    for rel in files:
        if not _PATH_RE.match(rel) or ".." in rel.split("/"):
            raise ExportError("ungültiger Dateiname im Export")
    exp_fd = _open_exports(workspace)
    try:
        base = f"{_stamp(now_ns)}-{template}"
        export_id = None
        for i in range(0, 100):
            name = base if i == 0 else f"{base}-{i + 1}"
            try:
                os.mkdir(name, 0o700, dir_fd=exp_fd)
            except FileExistsError:
                continue
            export_id = name
            break
        if export_id is None:
            raise ExportError("zu viele Exporte in derselben Sekunde")
        root_fd = os.open(export_id, _DIR_FLAGS, dir_fd=exp_fd)
    finally:
        os.close(exp_fd)
    entries: list[dict[str, Any]] = []
    dirs: dict[str, int] = {"": root_fd}
    try:
        for rel in sorted(files):
            content = files[rel]
            raw = content.encode("utf-8") if isinstance(content, str) else bytes(content)
            if isinstance(content, str) and redactor is not None:
                red, _labels = redactor.redact_for_exit(raw)
                raw = bytes(red)
            parent, _, fname = rel.rpartition("/")
            fd = dirs.get(parent)
            if fd is None:
                fd = root_fd
                acc = ""
                for part in parent.split("/"):
                    acc = f"{acc}/{part}" if acc else part
                    if acc not in dirs:
                        dirs[acc] = _mkdir_at(fd, part)
                    fd = dirs[acc]
            _write_at(fd, fname, raw)
            entries.append({"path": rel, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
        man = dict(manifest)
        man.update({"format": MANIFEST_FORMAT, "export_id": export_id, "files": entries})
        if redactor is not None:
            man, _labels = redactor.redact_json(man)
        ariadne_fd = _mkdir_at(root_fd, "_ariadne")
        dirs["_ariadne"] = ariadne_fd
        body = json.dumps(man, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        _write_at(ariadne_fd, "manifest.json", body)
    finally:
        for fd in dirs.values():
            with contextlib.suppress(OSError):
                os.close(fd)
    return {
        "export_id": export_id,
        "path": f"exports/{export_id}",
        "files": len(entries) + 1,
        "manifest_sha256": hashlib.sha256(body).hexdigest(),
    }


def _read_manifest(exp_fd: int, name: str) -> dict[str, Any] | None:
    try:
        d = os.open(name, _DIR_FLAGS, dir_fd=exp_fd)
    except OSError:
        return None
    try:
        a = os.open("_ariadne", _DIR_FLAGS, dir_fd=d)
    except OSError:
        os.close(d)
        return None
    try:
        f = os.open("manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=a)
    except OSError:
        os.close(a)
        os.close(d)
        return None
    try:
        data = os.read(f, 4 << 20)
    finally:
        os.close(f)
        os.close(a)
        os.close(d)
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) and obj.get("format") == MANIFEST_FORMAT else None


def list_exports(workspace: Path, limit: int = 100) -> list[dict[str, Any]]:
    """Exporte im Projektordner, neueste zuerst (nur Ordner mit gültigem Namen und Manifest)."""
    try:
        exp_fd = os.open(str(Path(workspace) / "exports"), _DIR_FLAGS)
    except OSError:
        return []
    try:
        names = sorted((n for n in os.listdir(exp_fd) if EXPORT_RE.match(n)), reverse=True)[: int(limit)]
        out = []
        for n in names:
            man = _read_manifest(exp_fd, n)
            if man is None:
                continue
            chain = man.get("chain") if isinstance(man.get("chain"), dict) else {}
            files = man.get("files") if isinstance(man.get("files"), list) else []
            warnings = man.get("warnings") if isinstance(man.get("warnings"), list) else []
            out.append(
                {
                    "export_id": n,
                    "template": man.get("template") if man.get("template") in ("cys", "htb") else None,
                    "created_at": man.get("created_at") if isinstance(man.get("created_at"), str) else None,
                    "path": f"exports/{n}",
                    "files": len(files) + 1,
                    "klartext": man.get("klartext") is True,
                    "warnings": [
                        w for w in warnings if isinstance(w, str) and re.fullmatch(r"[a-z_]{1,32}", w)
                    ],
                    "chain": {
                        "seq": chain.get("seq") if isinstance(chain.get("seq"), int) else None,
                        "hash": chain.get("hash")
                        if isinstance(chain.get("hash"), str)
                        and re.fullmatch(r"[0-9a-f]{0,128}", chain["hash"])
                        else None,
                    },
                }
            )
        return out
    finally:
        os.close(exp_fd)


def warning_codes(items: Iterable[str]) -> list[str]:
    return sorted(set(items))
