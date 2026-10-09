"""SQLCipher-Verbindungen (Architektur 5.1, 8.4).

Alle drei Datenbanken eines Projekts öffnet nur :func:`open_db`: zufälliger
256-Bit-Schlüssel als Raw Key, ``journal_mode=WAL``, ``secure_delete=ON``,
``temp_store=MEMORY``, ``foreign_keys=ON``. Ein falscher Schlüssel ergibt
:class:`WrongKeyError`, nie eine leere Datenbank.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import sqlcipher3

__all__ = ["KEY_LEN", "CryptoError", "WrongKeyError", "new_key", "open_db"]

KEY_LEN = 32


class CryptoError(RuntimeError):
    pass


class WrongKeyError(CryptoError):
    """Der Schlüssel passt nicht zur Datenbank (oder die Datei ist keine)."""


def new_key() -> bytes:
    return secrets.token_bytes(KEY_LEN)


def open_db(path: str | os.PathLike[str], key: bytes, readonly: bool = False) -> sqlcipher3.Connection:
    """Öffnet eine SQLCipher-Datenbank mit Raw Key.

    ``readonly`` öffnet per URI mit ``mode=ro`` (ohne WAL-Umstellung). Die
    Verbindung verhält sich wie ``sqlite3`` (implizite Transaktionen); wer
    selbst steuern will, setzt ``isolation_level = None``.
    """
    if not isinstance(key, bytes | bytearray) or len(key) != KEY_LEN:
        raise ValueError("Schlüssel muss 32 Byte lang sein")
    p = Path(path)
    created = not readonly and not p.exists()
    if readonly:
        conn = sqlcipher3.connect(p.absolute().as_uri() + "?mode=ro", uri=True)
    else:
        conn = sqlcipher3.connect(str(p))
    try:
        conn.execute("PRAGMA cipher_log_level = NONE")
        conn.execute(f"PRAGMA key = \"x'{bytes(key).hex()}'\"")
        try:
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlcipher3.DatabaseError:
            raise WrongKeyError(f"Schlüssel passt nicht: {p.name}") from None
        if not readonly:
            conn.execute("PRAGMA journal_mode=WAL").fetchone()
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA foreign_keys=ON")
        if created:
            os.chmod(p, 0o600)
    except BaseException:
        conn.close()
        raise
    return conn
