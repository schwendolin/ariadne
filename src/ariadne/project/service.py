"""Projekte anlegen, öffnen, schliessen, auflisten (Architektur 4.1, 5.1, 8.1-8.3).

Layout::

    <projects_root>/<slug>/          0700, Arbeitsbereich (Profil lab: Klartext)
      scans/ loot/ imports/ screenshots/ exports/
      .vault/                         0700
        manifest.json                 Klartext, ohne Kundendaten
        slots/operator.age            Projektschlüssel, versiegelt an den Operator
        journal.db derived.db state.db
        blobs/
        .lock                         flock, solange das Projekt offen ist

Nur das Profil lab gibt es in v0.1. Schlüssel liegen nur im Speicher des
Prozesses, der das Projekt geöffnet hat (dem Daemon).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import secrets
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import sqlcipher3

from ariadne.crypto import age
from ariadne.crypto.db import new_key, open_db
from ariadne.crypto.files import read_private, write_private
from ariadne.crypto.vault import UnlockedOperator
from ariadne.ids import new_id
from ariadne.paths import Paths, UnsafePathError, ensure_private_dir
from ariadne.project.guardrails import LabAllowlist, split_targets
from ariadne.project.settings import SettingsError, default_settings, parse_settings
from ariadne.store.blobs import AgeBlobStore
from ariadne.store.journal import SCHEMA_VERSION, SqlCipherJournal, read_boot_id

__all__ = [
    "SLUG_RE",
    "WORKSPACE_DIRS",
    "ProjectError",
    "ProjectExists",
    "ProjectNotFound",
    "ProjectLocked",
    "GuardrailError",
    "ProjectInfo",
    "ProjectSummary",
    "OpenProject",
    "ProjectService",
    "valid_slug",
]

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
WORKSPACE_DIRS = ("scans", "loot", "imports", "screenshots", "exports")
MANIFEST_FORMAT = "ariadne.project-manifest/1"
SLOT_FORMAT = "ariadne.project-slot/1"


class ProjectError(RuntimeError):
    pass


class ProjectExists(ProjectError):
    pass


class ProjectNotFound(ProjectError):
    pass


class ProjectLocked(ProjectError):
    """Das Projekt ist bereits von einem anderen Prozess geöffnet."""


class GuardrailError(ProjectError):
    def __init__(self, message: str, outside: list[str]) -> None:
        super().__init__(message)
        self.outside = outside


def valid_slug(slug: str) -> bool:
    return bool(SLUG_RE.match(slug))


@dataclass(frozen=True)
class ProjectInfo:
    id: str
    slug: str
    profile: str
    workspace: Path
    vault: Path


@dataclass(frozen=True)
class ProjectSummary:
    slug: str
    project_id: str
    profile: str
    created_utc: str


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _touch_db(path: Path, key: bytes, project_id: str) -> None:
    """Legt eine leere, verschlüsselte Datenbank an (Schemas legen andere Teilsysteme an)."""
    conn = open_db(path, key)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS _vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT OR IGNORE INTO _vault_meta(key, value) VALUES ('project_id', ?)", (project_id,))
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    finally:
        conn.close()


class OpenProject:
    """Ein geöffnetes Projekt. Hält Schlüssel und den flock bis :meth:`close`."""

    def __init__(self, info: ProjectInfo, journal: SqlCipherJournal, blobs: AgeBlobStore, *,
                 db_key: bytes, project_key: bytes, lock_fd: int) -> None:
        self.info = info
        self.journal = journal
        self.blobs = blobs
        self._db_key = bytearray(db_key)
        self._project_key = bytearray(project_key)
        self._lock_fd = lock_fd
        self.settings: dict[str, Any] = {}
        self.settings_version = 0
        self.closed = False
        self.head_ok = journal.verify_head()
        self.reload_settings()

    @property
    def project_key(self) -> bytes:
        """32 Byte für HMACs (z. B. ``chain.secret_key``)."""
        return bytes(self._project_key)

    def _db(self, name: str, readonly: bool) -> sqlcipher3.Connection:
        if self.closed:
            raise ProjectError("Projekt ist geschlossen")
        return open_db(self.info.vault / name, bytes(self._db_key), readonly=readonly)

    def connect_derived(self, readonly: bool = False) -> sqlcipher3.Connection:
        return self._db("derived.db", readonly)

    def connect_state(self, readonly: bool = False) -> sqlcipher3.Connection:
        return self._db("state.db", readonly)

    def connect_journal(self) -> sqlcipher3.Connection:
        """Eigene, nur lesende Verbindung auf journal.db (z. B. für Reparse in einem Thread).

        Geschrieben wird nur über :attr:`journal` bzw. den Writer des Daemons.
        """
        return self._db("journal.db", True)

    def reload_settings(self) -> dict[str, Any]:
        last = None
        for rec in self.journal.iter_events(kinds=["d.scope.update"]):
            last = rec
        if last is None:
            raise ProjectError("Projekt ohne Einstellungen (d.scope.update fehlt)")
        self.settings = parse_settings(str(last.header["toml"]))
        self.settings_version = int(last.header["version"])
        return self.settings

    def close(self, reason: str = "close") -> tuple[int, str]:
        """Checkpoint-Event, WAL kürzen, Schlüssel verwerfen, flock lösen. Gibt den Kettenkopf zurück."""
        if self.closed:
            seq, h = self.journal.head()
            return seq, h.hex()
        try:
            head_seq, head_hash = self.journal.head()
            self.journal.append("system.checkpoint",
                                {"reason": reason, "head_seq": head_seq, "head_hash": head_hash.hex()})
            final = self.journal.head()
            self.journal.checkpoint()
        finally:
            self.journal.close()
            self.blobs.close()
            for buf in (self._db_key, self._project_key):
                for i in range(len(buf)):
                    buf[i] = 0
            with contextlib.suppress(OSError):
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(self._lock_fd)
            self.closed = True
        return final[0], final[1].hex()


class ProjectService:
    def __init__(self, paths: Paths, operator: UnlockedOperator | None = None,
                 allowlist: LabAllowlist | None = None) -> None:
        self.paths = paths
        self.operator = operator
        self.allowlist = allowlist or LabAllowlist.from_config(paths.config_file)

    # ------------------------------------------------------------------ #
    def _require_operator(self) -> UnlockedOperator:
        if self.operator is None:
            raise ProjectError("Operator ist gesperrt (ariadne unlock)")
        return self.operator

    def workspace(self, slug: str) -> Path:
        if not valid_slug(slug):
            raise ProjectError("ungültiger Slug (erlaubt: a-z 0-9 -, höchstens 40 Zeichen)")
        return self.paths.projects_root / slug

    @staticmethod
    def _read_manifest(vault: Path) -> dict[str, Any]:
        try:
            data = json.loads(read_private(vault / "manifest.json", max_size=1 << 20).decode())
        except FileNotFoundError:
            raise ProjectNotFound("kein Projekt (manifest.json fehlt)") from None
        except (ValueError, UnicodeDecodeError) as exc:
            raise ProjectError("manifest.json unlesbar") from exc
        if not isinstance(data, dict) or data.get("format") != MANIFEST_FORMAT:
            raise ProjectError("unbekanntes Manifest-Format")
        return data

    # ------------------------------------------------------------------ #
    def create(self, slug: str, targets: list[str], *, name: str | None = None,
               not_customer: bool = False, profile: str = "lab", origin: str = "cli") -> ProjectInfo:
        if profile == "customer":
            raise ProjectError("Profil customer kommt ab v0.3; bis dahin nur lab und nie für Kundendaten")
        if profile != "lab":
            raise ProjectError("unbekanntes Profil")
        op = self._require_operator()
        ws = self.workspace(slug)
        name = name if name is not None else slug
        if len(name) > 100 or any(ord(c) < 0x20 or ord(c) == 0x7F or 0x80 <= ord(c) <= 0x9F for c in name):
            raise ProjectError("ungültiger Projektname")
        if not targets:
            raise ProjectError("mindestens ein Ziel nötig (--target)")
        parsed, outside = split_targets(targets, self.allowlist)
        if outside and not not_customer:
            raise GuardrailError(
                "Ziele ausserhalb der Lab-Allowlist. Nur erlaubt mit der Bestätigung, dass es "
                "kein Kundenauftrag ist (--not-customer).",
                [t.value for t in outside],
            )
        ensure_private_dir(self.paths.projects_root)
        try:
            os.mkdir(ws, 0o700)
        except FileExistsError:
            raise ProjectExists(f"Projekt existiert bereits: {slug}") from None
        try:
            return self._create_in(ws, slug, op, name=name, profile=profile,
                                   include=[t.value for t in parsed], not_customer=not_customer,
                                   origin=origin)
        except BaseException:
            shutil.rmtree(ws, ignore_errors=True)
            raise

    def _create_in(self, ws: Path, slug: str, op: UnlockedOperator, *, name: str, profile: str,
                   include: list[str], not_customer: bool, origin: str) -> ProjectInfo:
        for d in WORKSPACE_DIRS:
            ensure_private_dir(ws / d)
        vault = ensure_private_dir(ws / ".vault")
        ensure_private_dir(vault / "slots")
        ensure_private_dir(vault / "blobs")
        project_id = new_id()
        db_key = new_key()
        identity, recipient = age.generate_identity()
        hmac_key = secrets.token_bytes(32)
        slot = op.seal({
            "format": SLOT_FORMAT,
            "project_id": project_id,
            "db_key": db_key.hex(),
            "age_identity": identity,
            "hmac_key": hmac_key.hex(),
        })
        write_private(vault / "slots" / "operator.age", slot)
        manifest = {
            "format": MANIFEST_FORMAT,
            "project_id": project_id,
            "slug": slug,
            "profile": profile,
            "schema_version": SCHEMA_VERSION,
            "created_utc": _now_utc(),
            "crypto": {"db": "sqlcipher4-raw-256", "files": "age-x25519", "slots": "age-x25519+hmac"},
            "slots": [{"type": "operator", "file": "slots/operator.age", "recipient": op.recipient}],
        }
        write_private(vault / "manifest.json", json.dumps(manifest, indent=2).encode() + b"\n")
        _touch_db(vault / "derived.db", db_key, project_id)
        _touch_db(vault / "state.db", db_key, project_id)
        journal = SqlCipherJournal.open(vault / "journal.db", db_key, project_id=project_id,
                                        operator_id=op.operator_id, boot_id=read_boot_id())
        try:
            journal.append("system.project_created", {
                "project_id": project_id, "slug": slug, "profile": profile,
                "schema_version": SCHEMA_VERSION,
            }, origin=origin)
            journal.append("d.scope.update",
                           {"version": 1, "toml": default_settings(name=name, profile=profile,
                                                                   include=include)},
                           origin=origin)
            if not_customer:
                journal.append("d.lab.not_customer", {"scope_version": 1}, origin=origin)
            journal.checkpoint()
        finally:
            journal.close()
        return ProjectInfo(project_id, slug, profile, ws, vault)

    # ------------------------------------------------------------------ #
    def open(self, slug: str) -> OpenProject:
        op = self._require_operator()
        ws = self.workspace(slug)
        if ws.is_symlink() or not ws.is_dir():
            raise ProjectNotFound(f"Projekt nicht gefunden: {slug}")
        vault = ws / ".vault"
        if vault.is_symlink() or not vault.is_dir():
            raise ProjectNotFound(f"Projekt nicht gefunden: {slug}")
        ensure_private_dir(vault)
        lock_fd = os.open(vault / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProjectLocked(f"Projekt ist bereits geöffnet: {slug}") from None
            manifest = self._read_manifest(vault)
            if manifest.get("slug") != slug:
                raise ProjectError("Manifest passt nicht zum Ordner")
            slot = op.unseal(read_private(vault / "slots" / "operator.age", max_size=1 << 20))
            if slot.get("format") != SLOT_FORMAT or slot.get("project_id") != manifest.get("project_id"):
                raise ProjectError("Schlüsselslot passt nicht zum Projekt")
            db_key = bytes.fromhex(str(slot["db_key"]))
            identity = str(slot["age_identity"])
            info = ProjectInfo(str(manifest["project_id"]), slug, str(manifest["profile"]), ws, vault)
            journal = SqlCipherJournal.open(vault / "journal.db", db_key, project_id=info.id,
                                            operator_id=op.operator_id, boot_id=read_boot_id())
            try:
                blobs = AgeBlobStore(vault / "blobs", journal.conn, recipient=age.recipient_of(identity),
                                     identity=identity)
                project = OpenProject(info, journal, blobs, db_key=db_key,
                                      project_key=bytes.fromhex(str(slot["hmac_key"])), lock_fd=lock_fd)
            except BaseException:
                journal.close()
                raise
        except (SettingsError, UnsafePathError, KeyError, ValueError) as exc:
            with contextlib.suppress(OSError):
                os.close(lock_fd)
            raise ProjectError(f"Projekt lässt sich nicht öffnen: {type(exc).__name__}") from exc
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(lock_fd)
            raise
        return project

    def list(self) -> list[ProjectSummary]:
        """Alle Projekte nach Manifest, ohne zu entsperren."""
        root = self.paths.projects_root
        if not root.is_dir():
            return []
        out: list[ProjectSummary] = []
        for entry in sorted(root.iterdir()):
            if entry.is_symlink() or not entry.is_dir() or not valid_slug(entry.name):
                continue
            vault = entry / ".vault"
            if vault.is_symlink() or not vault.is_dir():
                continue
            try:
                m = self._read_manifest(vault)
            except (ProjectError, OSError, UnsafePathError):
                continue
            out.append(ProjectSummary(entry.name, str(m.get("project_id", "")), str(m.get("profile", "")),
                                      str(m.get("created_utc", ""))))
        return out
