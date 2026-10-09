"""Versiegelte JSON-Nutzlasten: age an einen Recipient plus HMAC mit der Identität.

age authentisiert den Absender nicht: Jeder kann an einen öffentlichen
Recipient verschlüsseln. Damit ein fremder Prozess keine Nutzlast (Slot,
Operator-Daten) unterschieben kann, trägt sie ein HMAC-SHA256, dessen Schlüssel
die private Identität ist. Nur wer die Identität hält, kann gültig versiegeln.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from ariadne.crypto import age
from ariadne.crypto.db import CryptoError

__all__ = ["TamperedError", "seal", "unseal"]

_DOMAIN = b"ariadne-seal-v1\x00"


class TamperedError(CryptoError):
    """Nutzlast ist nicht von dieser Identität versiegelt oder beschädigt."""


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _mac(identity: str, body: dict[str, Any]) -> str:
    return hmac.new(identity.encode(), _DOMAIN + _canon(body), hashlib.sha256).hexdigest()


def seal(body: dict[str, Any], recipient: str, identity: str) -> bytes:
    envelope = {"v": 1, "body": body, "mac": _mac(identity, body)}
    return age.encrypt(_canon(envelope), [recipient])


def unseal(data: bytes, identity: str) -> dict[str, Any]:
    raw = age.decrypt(data, [identity])
    try:
        envelope = json.loads(raw.decode())
        body = envelope["body"]
        mac = envelope["mac"]
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
        raise TamperedError("Nutzlast unlesbar") from exc
    if envelope.get("v") != 1 or not isinstance(body, dict) or not isinstance(mac, str):
        raise TamperedError("Nutzlast unbekannt")
    if not hmac.compare_digest(mac, _mac(identity, body)):
        raise TamperedError("Siegel ungültig")
    return body
