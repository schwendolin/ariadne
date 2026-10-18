"""SQLCipher-Verbindungen (Architektur 5.1, 8.4).

Alle drei Datenbanken eines Projekts öffnet nur :func:`open_db`: zufälliger
256-Bit-Schlüssel als Raw Key, ``journal_mode=WAL``, ``secure_delete=ON``,
``temp_store=MEMORY``, ``foreign_keys=ON``. Ein falscher Schlüssel ergibt
:class:`WrongKeyError`, nie eine leere Datenbank.

Öffnen und Schliessen laufen prozessweit nacheinander (:data:`_OPEN_CLOSE`). Die mit sqlcipher3
gelieferte SQLite nimmt beim Öffnen einer Datei die globale Sperre der Unix-VFS und dann die Sperre
der Datei (``findReusableFd``), beim Schliessen einer WAL-Verbindung umgekehrt (``unixLock`` mit
``unixIsSharingShmNode``). Öffnet ein Thread ``state.db``, während ein anderer eine Verbindung auf
dieselbe Datei schliesst, hängen beide für immer (beobachtet im Fixture-Daemon der Browsertests,
Integration v0.1-Oberfläche). Die Sperre hier schliesst genau diese Überschneidung aus.
"""

from __future__ import annotations

import os
import secrets
import threading
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


_OPEN_CLOSE = threading.RLock()


class _Connection(sqlcipher3.Connection):
    """Verbindung, deren ``close()`` die Sperre für Öffnen und Schliessen hält (siehe oben)."""

    def close(self) -> None:
        with _OPEN_CLOSE:
            super().close()


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
    with _OPEN_CLOSE:
        if readonly:
            conn = sqlcipher3.connect(p.absolute().as_uri() + "?mode=ro", uri=True, factory=_Connection)
        else:
            conn = sqlcipher3.connect(str(p), factory=_Connection)
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
