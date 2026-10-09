"""Bezeichner. Nur Standardbibliothek, wird auch vom Shim importiert."""

from __future__ import annotations

import os
import secrets
import time
import uuid

__all__ = ["uuid7", "new_id", "new_nonce", "cmd_id"]


def uuid7() -> uuid.UUID:
    """UUIDv7 (RFC 9562): 48 Bit Unix-Millisekunden, danach Zufall.

    Ab Python 3.14 gibt es ``uuid.uuid7``; bis dahin diese Implementierung.
    """
    native = getattr(uuid, "uuid7", None)
    if native is not None:
        return native()
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")  # 80 Bit
    rand_a = (rand >> 62) & 0xFFF  # 12 Bit
    rand_b = rand & ((1 << 62) - 1)  # 62 Bit
    value = (
        ((ms & ((1 << 48) - 1)) << 80)
        | (0x7 << 76)
        | (rand_a << 64)
        | (0b10 << 62)
        | rand_b
    )
    return uuid.UUID(int=value)


def new_id() -> str:
    """Neue ID als String (UUIDv7)."""
    return str(uuid7())


def new_nonce(nbytes: int = 16) -> str:
    """Zufällige Nonce als Hex-String (Standard 128 Bit)."""
    return secrets.token_hex(nbytes)


def cmd_id(terminal_id: str, c_marker_offset: int) -> str:
    """Deterministische Befehls-ID: ``<terminal_id>@<stream_off des C-Markers>``.

    Siehe Architektur 5.3. Rohereignisse und Entscheide verweisen nur auf diesen
    Schlüssel, nie auf Zeilen-IDs in ``derived.db``.
    """
    return f"{terminal_id}@{c_marker_offset}"
