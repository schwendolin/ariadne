"""Registry der Sicherungen (``Paths.registry_file``, Vertrag v0.1-Server 3.5, Architektur 8.9).

JSON-Datei mit Rechten 0600, atomar geschrieben, höchstens :data:`MAX_ENTRIES` Einträge (die
ältesten fallen weg)::

    {"format": "ariadne.backup-registry/1",
     "backups": [{"id", "ts_utc", "projects": [slug, …], "manifest_sha256",
                  "target": "stdout" | "file", "path"?: str}]}

Wozu: Der Hinweis nach ``ariadne stop`` vergleicht die jüngste Sicherung mit dem Beginn der
Session, und ``purge`` (später) findet darüber Sicherungen in Dateien. Keine Secrets, keine
Zieldaten; ``path`` ist der vom Benutzer gewählte Zielpfad von ``--to-file``.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from ariadne.crypto.files import read_private, write_private
from ariadne.paths import Paths, ensure_private_dir

__all__ = ["REGISTRY_FORMAT", "MAX_ENTRIES", "read_entries", "add_entry", "latest", "parse_utc"]

REGISTRY_FORMAT = "ariadne.backup-registry/1"
MAX_ENTRIES = 500
MAX_SIZE = 4 << 20
_UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
_TARGETS = ("stdout", "file")


def parse_utc(text: Any) -> datetime | None:
    """``YYYY-MM-DDTHH:MM:SSZ`` als aware ``datetime``; sonst ``None``."""
    if not isinstance(text, str) or not _UTC.match(text):
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _valid(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    if not isinstance(entry.get("id"), str) or parse_utc(entry.get("ts_utc")) is None:
        return False
    projects = entry.get("projects")
    if not isinstance(projects, list) or not all(isinstance(p, str) for p in projects):
        return False
    if entry.get("target") not in _TARGETS:
        return False
    return isinstance(entry.get("manifest_sha256", ""), str)


def read_entries(paths: Paths) -> list[dict[str, Any]]:
    """Alle gültigen Einträge, älteste zuerst. Fehlende oder kaputte Datei: leere Liste."""
    try:
        data = json.loads(read_private(paths.registry_file, max_size=MAX_SIZE).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict) or data.get("format") != REGISTRY_FORMAT:
        return []
    backups = data.get("backups")
    if not isinstance(backups, list):
        return []
    return [e for e in backups if _valid(e)]


@contextlib.contextmanager
def _locked(paths: Paths) -> Iterator[None]:
    """Serialisiert gleichzeitige Sicherungen (zwei ``ariadne backup`` verlieren keinen Eintrag)."""
    ensure_private_dir(paths.state_dir)
    fd = os.open(paths.state_dir / "registry.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def add_entry(paths: Paths, *, entry_id: str, ts_utc: str, projects: list[str], manifest_sha256: str,
              target: str, path: str | None = None) -> dict[str, Any]:
    """Hängt einen Eintrag an (atomar, 0600) und gibt ihn zurück. Wirft ``OSError`` beim Schreiben."""
    if target not in _TARGETS:
        raise ValueError("target muss stdout oder file sein")
    entry: dict[str, Any] = {"id": entry_id, "ts_utc": ts_utc, "projects": list(projects),
                             "manifest_sha256": manifest_sha256, "target": target}
    if path is not None:
        entry["path"] = path
    with _locked(paths):
        entries = read_entries(paths)
        entries.append(entry)
        entries = entries[-MAX_ENTRIES:]
        body = {"format": REGISTRY_FORMAT, "backups": entries}
        write_private(paths.registry_file, json.dumps(body, indent=1, sort_keys=True).encode() + b"\n")
    return entry


def latest(paths: Paths, slug: str | None = None) -> dict[str, Any] | None:
    """Jüngster Eintrag (nach ``ts_utc``), mit ``slug`` nur Sicherungen, die das Projekt enthalten."""
    best: dict[str, Any] | None = None
    best_ts: datetime | None = None
    for e in read_entries(paths):
        if slug is not None and slug not in e["projects"]:
            continue
        ts = parse_utc(e["ts_utc"])
        if ts is not None and (best_ts is None or ts >= best_ts):
            best, best_ts = e, ts
    return best
