"""Dünne Hülle um ``pyrage`` (age): X25519-Identitäten, Recipients, Passphrasen.

Keine eigene Kryptografie. Alle Formate lassen sich im Notfall mit dem
``age``-Kommando öffnen.
"""

from __future__ import annotations

from collections.abc import Sequence

import pyrage
from pyrage import passphrase as _passphrase
from pyrage import x25519

from ariadne.crypto.db import CryptoError

__all__ = [
    "DecryptionFailed",
    "generate_identity",
    "recipient_of",
    "encrypt",
    "decrypt",
    "encrypt_with_passphrase",
    "decrypt_with_passphrase",
]


class DecryptionFailed(CryptoError):
    """Entschlüsseln fehlgeschlagen (falscher Schlüssel, falsche Passphrase, defekt)."""


def generate_identity() -> tuple[str, str]:
    """Neue X25519-Identität: ``(identity, recipient)`` als age-Strings."""
    ident = x25519.Identity.generate()
    return str(ident), str(ident.to_public())


def _identity(s: str) -> x25519.Identity:
    try:
        return x25519.Identity.from_str(s)
    except Exception as exc:  # pyrage.IdentityError und Verwandte
        raise CryptoError("ungültige age-Identität") from exc


def recipient_of(identity: str) -> str:
    return str(_identity(identity).to_public())


def encrypt(data: bytes, recipients: Sequence[str]) -> bytes:
    if not recipients:
        raise ValueError("mindestens ein Recipient nötig")
    try:
        recips = [x25519.Recipient.from_str(r) for r in recipients]
    except Exception as exc:
        raise CryptoError("ungültiger age-Recipient") from exc
    return pyrage.encrypt(bytes(data), recips)


def decrypt(data: bytes, identities: Sequence[str]) -> bytes:
    idents = [_identity(i) for i in identities]
    try:
        return pyrage.decrypt(bytes(data), idents)
    except pyrage.DecryptError as exc:
        raise DecryptionFailed("Entschlüsseln fehlgeschlagen") from exc


def encrypt_with_passphrase(data: bytes, passphrase: str) -> bytes:
    """age-scrypt. Langsam (Arbeitsfaktor etwa 1 s), gewollt."""
    if not passphrase:
        raise ValueError("leere Passphrase")
    return _passphrase.encrypt(bytes(data), passphrase)


def decrypt_with_passphrase(data: bytes, passphrase: str) -> bytes:
    try:
        return _passphrase.decrypt(bytes(data), passphrase)
    except pyrage.DecryptError as exc:
        raise DecryptionFailed("Passphrase passt nicht") from exc
