"""Operator-Tresor (Architektur 8.4).

Unter ``paths.operator_dir`` (0700):

``vault.json``
    Klartext: Format, öffentlicher Operator-Recipient, Slot-Liste. Wird zuletzt
    geschrieben und markiert einen vollständig angelegten Tresor.
``slots/passphrase.age``, ``slots/recovery.age``
    Die age-X25519-Identität des Operators, per age-scrypt mit Passphrase bzw.
    Recovery-Code verschlüsselt.
``payload.age``
    Versiegelt an den Operator-Recipient (:mod:`ariadne.crypto.seal`):
    ``operator_id`` (UUIDv7), ``handle``, eigene Secrets, API-Keys.

Der Recovery-Code hat 130 Bit Zufall in Crockford-Base32 plus 2 Prüfzeichen,
angezeigt als 7 Gruppen à 4 Zeichen. Tippfehler fallen sofort auf, ohne die
langsame scrypt-Ableitung.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ariadne.crypto import age
from ariadne.crypto.db import CryptoError
from ariadne.crypto.files import read_private, write_private
from ariadne.crypto.seal import seal, unseal
from ariadne.ids import new_id
from ariadne.paths import ensure_private_dir

__all__ = [
    "VAULT_FORMAT",
    "MIN_PASSPHRASE",
    "VaultError",
    "VaultExists",
    "VaultMissing",
    "WrongPassphrase",
    "InvalidRecoveryCode",
    "OperatorVault",
    "UnlockedOperator",
    "new_recovery_code",
    "normalize_recovery_code",
    "format_recovery_code",
    "valid_label",
]

VAULT_FORMAT = "ariadne.operator/1"
PAYLOAD_FORMAT = "ariadne.operator-payload/1"
MIN_PASSPHRASE = 8
MAX_SECRET_LEN = 4096

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford, ohne I L O U
_CODE_RANDOM = 26  # 26 * 5 = 130 Bit
_CODE_CHECK = 2
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


class VaultError(CryptoError):
    pass


class VaultExists(VaultError):
    pass


class VaultMissing(VaultError):
    pass


class WrongPassphrase(VaultError):
    pass


class InvalidRecoveryCode(VaultError):
    pass


def valid_label(label: str) -> bool:
    return bool(_LABEL_RE.match(label))


# --------------------------------------------------------------------------- #
# Recovery-Code
# --------------------------------------------------------------------------- #


def _check_chars(body: str) -> str:
    n = int.from_bytes(hashlib.sha256(b"ariadne-recovery:" + body.encode()).digest()[:2], "big") >> 6
    return _ALPHABET[(n >> 5) & 31] + _ALPHABET[n & 31]


def new_recovery_code() -> str:
    body = "".join(secrets.choice(_ALPHABET) for _ in range(_CODE_RANDOM))
    return format_recovery_code(body + _check_chars(body))


def normalize_recovery_code(code: str) -> str:
    """Grossschreibung, Trenner weg, O->0, I/L->1. Prüft Länge und Prüfzeichen."""
    s = re.sub(r"[\s\-_.]", "", code).upper().replace("O", "0").replace("I", "1").replace("L", "1")
    if len(s) != _CODE_RANDOM + _CODE_CHECK or any(c not in _ALPHABET for c in s):
        raise InvalidRecoveryCode("Recovery-Code hat ein ungültiges Format")
    if _check_chars(s[:_CODE_RANDOM]) != s[_CODE_RANDOM:]:
        raise InvalidRecoveryCode("Recovery-Code enthält einen Tippfehler")
    return s


def format_recovery_code(normalized: str) -> str:
    return "-".join(normalized[i : i + 4] for i in range(0, len(normalized), 4))


# --------------------------------------------------------------------------- #
# Tresor
# --------------------------------------------------------------------------- #


class OperatorVault:
    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    @property
    def meta_file(self) -> Path:
        return self.directory / "vault.json"

    @property
    def payload_file(self) -> Path:
        return self.directory / "payload.age"

    def slot_file(self, name: str) -> Path:
        return self.directory / "slots" / f"{name}.age"

    @property
    def exists(self) -> bool:
        return self.meta_file.is_file()

    def meta(self) -> dict[str, Any]:
        if not self.exists:
            raise VaultMissing("kein Operator-Tresor angelegt (ariadne init)")
        try:
            meta = json.loads(read_private(self.meta_file).decode())
        except ValueError as exc:
            raise VaultError("vault.json unlesbar") from exc
        if meta.get("format") != VAULT_FORMAT:
            raise VaultError("unbekanntes Tresor-Format")
        return meta

    def recipient(self) -> str:
        return str(self.meta()["recipient"])

    # ------------------------------------------------------------------ #
    def create(self, passphrase: str, *, handle: str = "operator") -> str:
        """Legt den Tresor an und gibt den Recovery-Code zurück (nur dieses eine Mal)."""
        code, op = self.create_and_unlock(passphrase, handle=handle)
        op.wipe()
        return code

    def create_and_unlock(self, passphrase: str, *, handle: str = "operator") -> tuple[str, UnlockedOperator]:
        if self.exists:
            raise VaultExists("Operator-Tresor existiert bereits")
        if len(passphrase) < MIN_PASSPHRASE:
            raise VaultError(f"Passphrase zu kurz (mindestens {MIN_PASSPHRASE} Zeichen)")
        if not valid_label(handle):
            raise VaultError("ungültiger Handle")
        ensure_private_dir(self.directory)
        ensure_private_dir(self.directory / "slots")
        identity, recipient = age.generate_identity()
        code = new_recovery_code()
        write_private(self.slot_file("passphrase"),
                      age.encrypt_with_passphrase(identity.encode(), passphrase))
        write_private(self.slot_file("recovery"),
                      age.encrypt_with_passphrase(identity.encode(), normalize_recovery_code(code)))
        op = UnlockedOperator(
            vault=self, operator_id=new_id(), handle=handle, recipient=recipient, _identity=identity,
            created_utc=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        op.save()
        meta = {
            "format": VAULT_FORMAT,
            "recipient": recipient,
            "slots": ["passphrase", "recovery"],
            "kdf": "age-scrypt",
            "created_utc": op.created_utc,
        }
        write_private(self.meta_file, json.dumps(meta, indent=2).encode() + b"\n")
        return code, op

    def unlock(self, passphrase: str | None = None, *, recovery_code: str | None = None) -> UnlockedOperator:
        """Entsperrt mit Passphrase oder Recovery-Code (genau eines von beiden)."""
        if (passphrase is None) == (recovery_code is None):
            raise ValueError("genau eines: passphrase oder recovery_code")
        meta = self.meta()
        if recovery_code is not None:
            secret = normalize_recovery_code(recovery_code)
            slot = "recovery"
        else:
            secret = passphrase or ""
            slot = "passphrase"
        if not secret:
            raise WrongPassphrase("leere Passphrase")
        blob = read_private(self.slot_file(slot))
        try:
            identity = age.decrypt_with_passphrase(blob, secret).decode()
        except age.DecryptionFailed:
            raise WrongPassphrase(
                "Recovery-Code passt nicht" if slot == "recovery" else "Passphrase passt nicht"
            ) from None
        if age.recipient_of(identity) != meta.get("recipient"):
            raise VaultError("Tresor inkonsistent: Identität passt nicht zum Recipient")
        body = unseal(read_private(self.payload_file), identity)
        if body.get("format") != PAYLOAD_FORMAT:
            raise VaultError("unbekanntes Nutzlast-Format")
        return UnlockedOperator(
            vault=self,
            operator_id=str(body["operator_id"]),
            handle=str(body.get("handle", "operator")),
            recipient=str(meta["recipient"]),
            _identity=identity,
            created_utc=str(body.get("created_utc", "")),
            _secrets=[(str(s["label"]), str(s["value"])) for s in body.get("secrets", [])],
            _api_keys={str(k): str(v) for k, v in body.get("api_keys", {}).items()},
        )


@dataclass
class UnlockedOperator:
    """Entsperrter Operator. Hält die Identität nur im Speicher (nach bestem Bemühen)."""

    vault: OperatorVault
    operator_id: str
    handle: str
    recipient: str
    _identity: str = field(repr=False)
    created_utc: str = ""
    _secrets: list[tuple[str, str]] = field(default_factory=list, repr=False)
    _api_keys: dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def identity(self) -> str:
        if not self._identity:
            raise VaultError("Operator ist gesperrt")
        return self._identity

    # ---- eigene Secrets -------------------------------------------------- #
    @property
    def own_secrets(self) -> list[tuple[str, str]]:
        return list(self._secrets)

    def secret_labels(self) -> list[str]:
        return [label for label, _ in self._secrets]

    def add_secret(self, label: str, value: str) -> None:
        """Fügt ein Secret hinzu oder ersetzt das mit gleichem Label. Danach :meth:`save`."""
        if not valid_label(label):
            raise VaultError("ungültiges Label (erlaubt: A-Z a-z 0-9 . _ : -, höchstens 64)")
        if not value or len(value) > MAX_SECRET_LEN:
            raise VaultError("Secret leer oder zu lang")
        self._secrets = [(lb, v) for lb, v in self._secrets if lb != label] + [(label, value)]

    def remove_secret(self, label: str) -> bool:
        before = len(self._secrets)
        self._secrets = [(lb, v) for lb, v in self._secrets if lb != label]
        return len(self._secrets) != before

    # ---- API-Keys -------------------------------------------------------- #
    def set_api_key(self, name: str, value: str | None) -> None:
        if not valid_label(name):
            raise VaultError("ungültiger Name für API-Key")
        if value is None:
            self._api_keys.pop(name, None)
        else:
            if not value or len(value) > MAX_SECRET_LEN:
                raise VaultError("API-Key leer oder zu lang")
            self._api_keys[name] = value

    def get_api_key(self, name: str) -> str | None:
        return self._api_keys.get(name)

    def api_key_names(self) -> list[str]:
        return sorted(self._api_keys)

    # ---- Schlüsselmaterial ----------------------------------------------- #
    def seal(self, body: dict[str, Any]) -> bytes:
        """Versiegelt eine Nutzlast an den eigenen Recipient (z. B. Projekt-Slots)."""
        return seal(body, self.recipient, self.identity)

    def unseal(self, data: bytes) -> dict[str, Any]:
        return unseal(data, self.identity)

    def change_passphrase(self, new_passphrase: str) -> None:
        if len(new_passphrase) < MIN_PASSPHRASE:
            raise VaultError(f"Passphrase zu kurz (mindestens {MIN_PASSPHRASE} Zeichen)")
        blob = age.encrypt_with_passphrase(self.identity.encode(), new_passphrase)
        write_private(self.vault.slot_file("passphrase"), blob)

    def save(self) -> None:
        body = {
            "format": PAYLOAD_FORMAT,
            "operator_id": self.operator_id,
            "handle": self.handle,
            "created_utc": self.created_utc,
            "secrets": [{"label": lb, "value": v} for lb, v in self._secrets],
            "api_keys": dict(self._api_keys),
        }
        write_private(self.vault.payload_file, self.seal(body))

    def wipe(self) -> None:
        """Verwirft Schlüssel und Secrets (Python kann Strings nicht sicher löschen)."""
        self._identity = ""
        self._secrets = []
        self._api_keys = {}
