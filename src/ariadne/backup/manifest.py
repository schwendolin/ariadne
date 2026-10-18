"""Manifest der Sicherung (Format ``ariadne.backup/1``) und Pfadregeln.

Der innere Strom ist ein gewöhnlicher Tar-Strom (PAX). Erstes Mitglied ist
:data:`MANIFEST_NAME` (JSON, UTF-8), danach Ordner und Dateien unter genau drei Präfixen:

* ``operator/`` = ``~/.local/share/ariadne/operator`` (Operator-Tresor, immer dabei),
* ``config/`` = ``~/.config/ariadne``,
* ``projects/<slug>/`` = ``~/ariadne/<slug>`` (``.vault/`` und Arbeitsbereich).

Im Notfall lässt sich der Strom ohne Ariadne lesen (``age -d … | tar -t``). Das Manifest::

    {"format": "ariadne.backup/1", "backup_id", "created_utc", "ariadne_version",
     "operator": {"recipient": "age1…"},          # öffentlich, aus vault.json
     "projects": [{"slug", "project_id", "profile",
                   "head": {"head_seq", "head_hash", "closed_utc"} | null}],
     "dirs":  [{"path", "mode"}],
     "files": [{"path", "size", "sha256", "mode", "mtime"}],
     "skipped": 0}

``head`` stammt aus ``.vault/head.json`` (Kettenkopf beim letzten Schliessen, Vertrag 1.2) und
ist ``null`` bei einem Projekt, das nie mit dieser Version geschlossen wurde. Pfade sind
Zeichenketten; Dateinamen, die kein UTF-8 sind, stehen mit ``surrogateescape`` darin (JSON
``\\udcXX``). Nie stehen Dateiinhalte, Secrets oder Schlüssel im Manifest.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from ariadne.backup.model import BackupError
from ariadne.project.service import valid_slug

__all__ = [
    "FORMAT", "FORMAT_PREFIX", "FORMAT_MAJOR", "MANIFEST_NAME", "MAX_MANIFEST", "PREFIXES",
    "parse_version", "version_newer", "check_path", "encode_manifest", "decode_manifest",
]

FORMAT_PREFIX = "ariadne.backup/"
FORMAT_MAJOR = 1
FORMAT = f"{FORMAT_PREFIX}{FORMAT_MAJOR}"
MANIFEST_NAME = "ariadne-backup.json"
MAX_MANIFEST = 64 << 20
PREFIXES = ("operator", "config", "projects")
MAX_PATH_BYTES = 4096
MAX_COMPONENT_BYTES = 255
MAX_ENTRIES = 2_000_000

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
_VERSION = re.compile(
    r"^v?(?P<release>\d+(?:\.\d+){0,5})"
    r"(?:[-_.]?(?P<pre_l>a|b|rc|alpha|beta|c)[-_.]?(?P<pre_n>\d+)?)?"
    r"(?:[-_.]?post[-_.]?(?P<post>\d+))?"
    r"(?P<dev_seg>[-_.]?dev[-_.]?(?P<dev>\d+)?)?"
    r"(?:\+[a-z0-9.]+)?$",
    re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2}
_INF = float("inf")


# --------------------------------------------------------------------------- #
# Versionen (PEP 440, das Nötige ohne Fremdpaket)
# --------------------------------------------------------------------------- #


def parse_version(text: str) -> tuple[Any, ...]:
    """Sortierschlüssel einer Ariadne-Version nach PEP 440 (``0.1.0.dev0`` < ``0.1.0rc1`` < ``0.1.0``).

    Wirft :class:`ValueError` bei einer unbekannten Form.
    """
    if not isinstance(text, str) or len(text) > 64:
        raise ValueError("Version ungültig")
    m = _VERSION.match(text.strip())
    if not m:
        raise ValueError("Version ungültig")
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_l, post = m.group("pre_l"), m.group("post")
    has_dev = m.group("dev_seg") is not None
    if pre_l is None and post is None and has_dev:
        pre: tuple[float, float] = (-_INF, 0)  # 1.0.dev0 vor 1.0a1
    elif pre_l is None:
        pre = (_INF, 0)
    else:
        pre = (_PRE_RANK[pre_l.lower()], int(m.group("pre_n") or 0))
    post_k: float = -_INF if post is None else int(post)
    dev_k: float = int(m.group("dev") or 0) if has_dev else _INF
    return (tuple(release), pre, post_k, dev_k)


def version_newer(candidate: str, installed: str) -> bool:
    """Ist ``candidate`` neuer als ``installed``? Unbekannte Formen gelten als neuer (fail-closed)."""
    try:
        return parse_version(candidate) > parse_version(installed)
    except ValueError:
        return True


# --------------------------------------------------------------------------- #
# Pfade
# --------------------------------------------------------------------------- #


def check_path(path: Any, *, slugs: set[str] | None = None, is_dir: bool = False) -> str:
    """Prüft einen Pfad aus Manifest oder Tar-Strom und gibt ihn zurück.

    Erlaubt: relativ, ohne leere Teile, ohne ``.`` und ``..``, ohne NUL, Präfix ``operator/``,
    ``config/`` oder ``projects/<slug>/`` (Slug aus dem Manifest). Eine Datei liegt immer
    unterhalb des Präfixes (``projects/<slug>`` selbst ist nur als Ordner erlaubt). Wirft
    ``unsafe_path`` ohne den Pfad in der Meldung (er kann aus Zieldaten stammen).
    """
    def bad() -> BackupError:
        return BackupError("unsafe_path", "Unzulässiger Pfad in der Sicherung (absolut, «..», "
                                          "unbekannter Bereich oder zu lang); nichts geschrieben.")

    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("/"):
        raise bad()
    try:
        raw = os.fsencode(path)
    except (UnicodeError, ValueError):
        raise bad() from None
    if len(raw) > MAX_PATH_BYTES:
        raise bad()
    parts = path.split("/")
    for part in parts:
        if part in ("", ".", "..") or len(os.fsencode(part)) > MAX_COMPONENT_BYTES:
            raise bad()
    head = parts[0]
    if head not in PREFIXES:
        raise bad()
    if head == "projects":
        if len(parts) < 2 or not valid_slug(parts[1]):
            raise bad()
        if slugs is not None and parts[1] not in slugs:
            raise bad()
        min_parts = 2 if is_dir else 3
    else:
        min_parts = 1 if is_dir else 2
    if len(parts) < min_parts:
        raise bad()
    return path


# --------------------------------------------------------------------------- #
# Kodieren und Prüfen
# --------------------------------------------------------------------------- #


def encode_manifest(doc: dict[str, Any]) -> bytes:
    """JSON mit festen Schlüsseln (sortiert), ASCII (Nicht-UTF-8-Namen als ``\\udcXX``)."""
    return json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def _bad(reason: str) -> BackupError:
    return BackupError("bad_manifest", f"Manifest der Sicherung ungültig: {reason}")


def _int(v: Any, lo: int = 0, hi: int = 1 << 62) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise _bad("Zahl ausserhalb des Bereichs")
    return v


def decode_manifest(data: bytes, installed_version: str) -> dict[str, Any]:
    """Prüft Format, Version und Struktur. Gibt das Manifest mit geprüften Feldern zurück.

    ``version``: neueres Format (``ariadne.backup/2``) oder neuere Ariadne als ``installed``
    (Migrationen gehen nur vorwärts, Konzept 6.5). ``bad_manifest``: alles andere.
    """
    if len(data) > MAX_MANIFEST:
        raise _bad("zu gross")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _bad("kein JSON") from None
    if not isinstance(doc, dict):
        raise _bad("kein Objekt")
    fmt = doc.get("format")
    if not isinstance(fmt, str) or not fmt.startswith(FORMAT_PREFIX):
        raise _bad("unbekanntes Format")
    try:
        major = int(fmt[len(FORMAT_PREFIX):])
    except ValueError:
        raise _bad("unbekanntes Format") from None
    if major > FORMAT_MAJOR:
        raise BackupError("version", "Die Sicherung hat ein neueres Format, als diese Ariadne kennt. "
                                     "Zuerst Ariadne aktualisieren (pipx upgrade ariadne-recon).")
    if major != FORMAT_MAJOR:
        raise _bad("unbekanntes Format")
    version = doc.get("ariadne_version")
    if not isinstance(version, str):
        raise _bad("Version fehlt")
    if version_newer(version, installed_version):
        raise BackupError("version", "Die Sicherung stammt von einer neueren Ariadne-Version. Zuerst "
                                     "Ariadne aktualisieren (Migrationen gehen nur vorwärts).")
    for key in ("backup_id", "created_utc"):
        if not isinstance(doc.get(key), str) or len(doc[key]) > 64:
            raise _bad(f"{key} fehlt")
    if not _UTC.match(doc["created_utc"]):
        raise _bad("created_utc ungültig")
    op = doc.get("operator")
    if not isinstance(op, dict) or not isinstance(op.get("recipient"), str) or len(op["recipient"]) > 100:
        raise _bad("Operator-Recipient fehlt")

    projects = doc.get("projects")
    if not isinstance(projects, list) or len(projects) > 10_000:
        raise _bad("Projektliste fehlt")
    slugs: set[str] = set()
    ids: set[str] = set()
    for p in projects:
        if not isinstance(p, dict):
            raise _bad("Projekteintrag")
        slug, pid = p.get("slug"), p.get("project_id")
        if not isinstance(slug, str) or not valid_slug(slug) or slug in slugs:
            raise _bad("Slug ungültig oder doppelt")
        if not isinstance(pid, str) or not 8 <= len(pid) <= 64 or pid in ids:
            raise _bad("Projekt-ID ungültig oder doppelt")
        if not isinstance(p.get("profile", ""), str):
            raise _bad("Profil ungültig")
        head = p.get("head")
        if head is not None:
            if not isinstance(head, dict):
                raise _bad("Kettenkopf ungültig")
            _int(head.get("head_seq"))
            if not isinstance(head.get("head_hash"), str) or not _HEX64.match(head["head_hash"]):
                raise _bad("Kettenkopf ungültig")
        slugs.add(slug)
        ids.add(pid)

    dirs = doc.get("dirs")
    files = doc.get("files")
    if not isinstance(dirs, list) or not isinstance(files, list) or len(dirs) + len(files) > MAX_ENTRIES:
        raise _bad("Datei- oder Ordnerliste fehlt")
    seen: set[str] = set()
    for d in dirs:
        if not isinstance(d, dict):
            raise _bad("Ordnereintrag")
        path = check_path(d.get("path"), slugs=slugs, is_dir=True)
        _int(d.get("mode", 0o700), 0, 0o7777)
        if path in seen:
            raise _bad("Pfad doppelt")
        seen.add(path)
    for f in files:
        if not isinstance(f, dict):
            raise _bad("Dateieintrag")
        path = check_path(f.get("path"), slugs=slugs)
        _int(f.get("size"))
        _int(f.get("mode", 0o600), 0, 0o7777)
        if not isinstance(f.get("sha256"), str) or not _HEX64.match(f["sha256"]):
            raise _bad("Hash ungültig")
        if path in seen:
            raise _bad("Pfad doppelt")
        seen.add(path)
    for p in projects:  # jedes Projekt bringt seinen Tresor-Ordner mit
        if f"projects/{p['slug']}/.vault/manifest.json" not in seen:
            raise _bad("Projekt ohne .vault/manifest.json")
    if "operator/vault.json" not in seen:
        raise _bad("Operator-Tresor fehlt")
    _int(doc.get("skipped", 0))
    return doc
