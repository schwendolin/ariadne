"""Hash-Kette des Journals (Architektur 5.2). Gemeinsam für echte und Test-Stores.

* ``hash`` läuft über eine kanonische, längenpräfixierte Serialisierung aller
  Spalten ausser ``hash``, mit Domänentrennung ``ariadne-event-v1``.
* Bodies werden über ``body_commit = sha256(salt || body)`` gebunden. Der Salt
  (16 Byte) wird mit dem Body gespeichert und bei einer Redaktion mit gelöscht.
  So lässt sich ein kurzer Klartext nach der Redaktion nicht zurückrechnen.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

__all__ = [
    "DOMAIN",
    "SALT_LEN",
    "genesis_hash",
    "new_salt",
    "body_commit",
    "event_hash",
]

DOMAIN = b"ariadne-event-v1"
SALT_LEN = 16


def genesis_hash(project_id: str) -> bytes:
    return hashlib.sha256(b"ariadne-genesis:" + project_id.encode()).digest()


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def body_commit(salt: bytes, body: bytes) -> bytes:
    if len(salt) != SALT_LEN:
        raise ValueError("Salt hat falsche Länge")
    return hashlib.sha256(salt + body).digest()


def _field(value: object) -> bytes:
    """Längenpräfixierte Kodierung eines Feldes; None ist von b'' unterscheidbar."""
    if value is None:
        return b"\x00"
    if isinstance(value, bool):
        raw = b"1" if value else b"0"
        tag = b"\x03"
    elif isinstance(value, int):
        raw = str(value).encode()
        tag = b"\x02"
    elif isinstance(value, bytes):
        raw = value
        tag = b"\x04"
    elif isinstance(value, str):
        raw = value.encode()
        tag = b"\x01"
    else:
        raise TypeError(f"nicht serialisierbar: {type(value)!r}")
    return tag + struct.pack(">Q", len(raw)) + raw


def event_hash(
    prev_hash: bytes,
    *,
    seq: int,
    event_id: str,
    layer: str,
    kind: str,
    ts_utc_ns: int,
    mono_ns: int | None,
    boot_id: str | None,
    operator_id: str,
    origin: str,
    terminal_id: str | None,
    stream_off: int | None,
    header_json: bytes,
    body_commit: bytes | None,
) -> bytes:
    parts = [
        DOMAIN,
        prev_hash,
        seq,
        event_id,
        layer,
        kind,
        ts_utc_ns,
        mono_ns,
        boot_id,
        operator_id,
        origin,
        terminal_id,
        stream_off,
        header_json,
        body_commit,
    ]
    h = hashlib.sha256()
    for p in parts:
        h.update(_field(p))
    return h.digest()


def secret_key(project_key: bytes, kind: str, value: str | bytes) -> str:
    """HMAC-Schlüssel für Secrets und daraus abgeleitete Kennungen (Architektur 5.7).

    Ein ungesalzener SHA-256 eines schwachen Passworts wäre in Sekunden umkehrbar.
    """
    raw = value.encode() if isinstance(value, str) else value
    mac = hmac.new(project_key, kind.encode() + b"\x00" + raw, hashlib.sha256)
    return mac.hexdigest()


__all__.append("secret_key")
