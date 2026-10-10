"""Blob-Store mit age (Architektur 5.1).

* Dateien unter ``blobs/<xx>/<blob_id>.age``, ``blob_id`` ist eine zufällige
  UUIDv4. Der Name verrät weder Inhalt noch Hash.
* Atomar geschrieben (temporäre Datei, fsync, rename), Rechte 0600.
* Verschlüsselt an den Projekt-Recipient.
* Der SHA-256 des Klartexts steht nur im Index ``blob`` in ``journal.db``
  (verschlüsselt). Gleicher Inhalt wird nur einmal gespeichert.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import time
import uuid
from pathlib import Path

import sqlcipher3

from ariadne.crypto import age
from ariadne.crypto.files import read_private, write_private
from ariadne.paths import ensure_private_dir
from ariadne.store.api import BlobRef

__all__ = ["AgeBlobStore", "BlobCorrupt"]

MAX_BLOB = 256 << 20


class BlobCorrupt(RuntimeError):
    pass


def _check_id(blob_id: str) -> str:
    try:
        u = uuid.UUID(blob_id)
    except (ValueError, TypeError, AttributeError):
        raise KeyError(blob_id) from None
    if str(u) != blob_id:
        raise KeyError(blob_id)
    return blob_id


class AgeBlobStore:
    """Implementiert :class:`ariadne.store.api.BlobStore`.

    ``conn`` ist die Verbindung zu ``journal.db`` (Tabelle ``blob``), in der
    Regel ``SqlCipherJournal.conn``. Nicht threadsicher.
    """

    def __init__(self, root: Path, conn: sqlcipher3.Connection, *, recipient: str, identity: str) -> None:
        self.root = ensure_private_dir(Path(root))
        self.conn = conn
        self._recipient = recipient
        self._identity = identity

    def with_connection(self, conn: sqlcipher3.Connection) -> AgeBlobStore:
        """Gleicher Store über eine andere Verbindung (z. B. nur lesend in einem anderen Thread)."""
        return AgeBlobStore(self.root, conn, recipient=self._recipient, identity=self._identity)

    def _path(self, blob_id: str) -> Path:
        return self.root / blob_id[:2] / f"{blob_id}.age"

    def _commit(self) -> None:
        if self.conn.in_transaction:
            self.conn.commit()

    def put_bytes(self, data: bytes, *, kind: str = "file") -> BlobRef:
        if len(data) > MAX_BLOB:
            raise ValueError("Blob zu gross")
        sha = hashlib.sha256(data).hexdigest()
        existing = self.find_by_sha256(sha)
        if existing is not None:
            return existing
        blob_id = str(uuid.uuid4())
        path = self._path(blob_id)
        ensure_private_dir(path.parent)
        write_private(path, age.encrypt(data, [self._recipient]))
        try:
            self.conn.execute(
                "INSERT INTO blob(blob_id, sha256, size, kind, created_ns) VALUES (?,?,?,?,?)",
                (blob_id, sha, len(data), kind, time.time_ns()),
            )
            self._commit()
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
            raise
        return BlobRef(blob_id, sha, len(data))

    def _row(self, blob_id: str) -> tuple[str, int]:
        row = self.conn.execute("SELECT sha256, size FROM blob WHERE blob_id = ?",
                                (_check_id(blob_id),)).fetchone()
        if row is None:
            raise KeyError(blob_id)
        return str(row[0]), int(row[1])

    def open_bytes(self, blob_id: str) -> bytes:
        sha, _size = self._row(blob_id)
        data = age.decrypt(read_private(self._path(blob_id), max_size=MAX_BLOB + (1 << 20)),
                           [self._identity])
        if hashlib.sha256(data).hexdigest() != sha:
            raise BlobCorrupt(f"Blob {blob_id} passt nicht zum Index")
        return data

    def find_by_sha256(self, sha256: str) -> BlobRef | None:
        row = self.conn.execute("SELECT blob_id, size FROM blob WHERE sha256 = ?",
                                (sha256.lower(),)).fetchone()
        if row is None:
            return None
        return BlobRef(str(row[0]), sha256.lower(), int(row[1]))

    def delete(self, blob_id: str) -> None:
        self._row(blob_id)
        path = self._path(blob_id)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        self.conn.execute("DELETE FROM blob WHERE blob_id = ?", (blob_id,))
        self._commit()

    def verify(self) -> list[str]:
        """Prüft jeden Blob: Datei vorhanden, entschlüsselbar, SHA-256 wie im Index."""
        problems: list[str] = []
        for blob_id, _sha, _size in self.conn.execute("SELECT blob_id, sha256, size FROM blob").fetchall():
            try:
                self.open_bytes(str(blob_id))
            except FileNotFoundError:
                problems.append(f"Blob {blob_id}: Datei fehlt")
            except (BlobCorrupt, age.DecryptionFailed, OSError) as exc:
                problems.append(f"Blob {blob_id}: {type(exc).__name__}")
        return problems

    def close(self) -> None:
        self._identity = ""
