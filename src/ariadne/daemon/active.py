"""Zuletzt aktives Projekt (``Paths.active_file``, Vertrag v0.1-Bedienung 4.2).

JSON ``{"slug", "project_id", "stopped", "since_utc"}``, 0600, atomar geschrieben,
nur vom Daemon. Keine Secrets. ``ariadne start`` ohne Slug öffnet das hier
genannte Projekt, solange es nicht gestoppt ist; ``lock`` und Daemon-Ende lassen
die Datei unverändert (Zustand ``locked``).
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from ariadne.crypto.files import read_private, write_private
from ariadne.paths import ensure_private_dir

__all__ = ["read_active", "write_active"]

log = logging.getLogger("ariadne.daemon")

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_ID_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z-]{7,63}$")


def read_active(path: Path) -> dict[str, Any] | None:
    """Liest und prüft die Datei; ``None`` bei fehlender oder ungültiger Datei."""
    try:
        data = json.loads(read_private(path, max_size=4096).decode())
    except FileNotFoundError:
        return None
    except (OSError, ValueError, UnicodeDecodeError):
        log.warning("active.json ungültig, wird ignoriert")
        return None
    if not isinstance(data, dict):
        return None
    slug, pid, stopped = data.get("slug"), data.get("project_id"), data.get("stopped")
    if (not isinstance(slug, str) or not _SLUG_RE.match(slug) or not isinstance(pid, str)
            or not _ID_RE.match(pid) or not isinstance(stopped, bool)):
        log.warning("active.json ungültig, wird ignoriert")
        return None
    since = data.get("since_utc")
    return {"slug": slug, "project_id": pid, "stopped": stopped,
            "since_utc": since if isinstance(since, str) and len(since) <= 40 else None}


def write_active(path: Path, slug: str, project_id: str, *, stopped: bool,
                 since_utc: str | None = None) -> dict[str, Any]:
    data = {"slug": slug, "project_id": project_id, "stopped": stopped,
            "since_utc": since_utc or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    ensure_private_dir(path.parent)
    write_private(path, json.dumps(data, sort_keys=True).encode() + b"\n")
    return data
