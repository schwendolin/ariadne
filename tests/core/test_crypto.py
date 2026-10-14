"""SQLCipher-Verbindungen, age-Hülle, Siegel, Operator-Tresor."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import time

import pytest

from ariadne.crypto import age
from ariadne.crypto.db import WrongKeyError, new_key, open_db
from ariadne.crypto.files import read_private, write_private
from ariadne.crypto.seal import TamperedError, seal, unseal
from ariadne.crypto.vault import (
    InvalidRecoveryCode,
    OperatorVault,
    VaultError,
    VaultExists,
    WrongPassphrase,
    format_recovery_code,
    new_recovery_code,
    normalize_recovery_code,
)
from ariadne.paths import UnsafePathError
from tests.core.conftest import OWN_SECRET, PASSPHRASE

# --------------------------------------------------------------------- open_db


def test_open_db_encrypts_and_rejects_wrong_key(tmp_path):
    p = tmp_path / "x.db"
    key = new_key()
    conn = open_db(p, key)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
    assert conn.execute("PRAGMA temp_store").fetchone()[0] == 2
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.execute("INSERT INTO t VALUES ('KANARIENVOGEL-DB')")
    conn.commit()
    # Datei und WAL sind Chiffrat
    for f in tmp_path.iterdir():
        assert b"KANARIENVOGEL-DB" not in f.read_bytes(), f.name
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(p).execute("SELECT * FROM sqlite_master").fetchall()
    with pytest.raises(WrongKeyError):
        open_db(p, new_key())
    ro = open_db(p, key, readonly=True)
    assert ro.execute("SELECT v FROM t").fetchone()[0] == "KANARIENVOGEL-DB"
    ro.close()
    conn.close()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    with pytest.raises(ValueError):
        open_db(p, b"zu kurz")


def test_age_roundtrip_and_errors():
    ident, recip = age.generate_identity()
    assert recip.startswith("age1") and age.recipient_of(ident) == recip
    ct = age.encrypt(b"daten", [recip])
    assert b"daten" not in ct and age.decrypt(ct, [ident]) == b"daten"
    other, _ = age.generate_identity()
    with pytest.raises(age.DecryptionFailed):
        age.decrypt(ct, [other])


def test_seal_detects_forgery():
    ident, recip = age.generate_identity()
    data = seal({"a": 1}, recip, ident)
    assert unseal(data, ident) == {"a": 1}
    attacker, _ = age.generate_identity()
    forged = seal({"a": 2}, recip, attacker)  # an den echten Recipient, falsches Siegel
    with pytest.raises(TamperedError):
        unseal(forged, ident)


def test_private_files(tmp_path):
    p = tmp_path / "f"
    write_private(p, b"abc")
    assert read_private(p) == b"abc" and stat.S_IMODE(os.stat(p).st_mode) == 0o600
    link = tmp_path / "l"
    link.symlink_to(p)
    with pytest.raises(OSError):
        read_private(link)
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises((UnsafePathError, OSError)):
        fd = os.open(tmp_path / "fifo", os.O_RDWR)  # Leser offenhalten, damit open nicht blockiert
        try:
            read_private(tmp_path / "fifo")
        finally:
            os.close(fd)


# ---------------------------------------------------------------- Recovery-Code


def test_recovery_code_format_and_typos():
    code = new_recovery_code()
    groups = code.split("-")
    assert len(groups) == 7 and all(len(g) == 4 for g in groups)
    norm = normalize_recovery_code(code.lower().replace("-", " "))
    assert format_recovery_code(norm) == code
    # 26 Zufallszeichen à 5 Bit = 130 Bit
    assert len(norm) == 28
    i = 3
    wrong = norm[:i] + ("0" if norm[i] != "0" else "1") + norm[i + 1:]
    t0 = time.monotonic()
    with pytest.raises(InvalidRecoveryCode):
        normalize_recovery_code(wrong)
    with pytest.raises(InvalidRecoveryCode):
        normalize_recovery_code("UUUU-" + code[5:])
    assert time.monotonic() - t0 < 0.1


# ----------------------------------------------------------------- Tresor


def test_vault_template_layout(operator_template):
    d = operator_template.directory
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(d / "slots").st_mode) == 0o700
    for f in ("vault.json", "payload.age", "slots/passphrase.age", "slots/recovery.age"):
        assert stat.S_IMODE(os.stat(d / f).st_mode) == 0o600, f
    meta = json.loads((d / "vault.json").read_text())
    assert meta["recipient"] == operator_template.op.recipient
    assert set(meta["slots"]) == {"passphrase", "recovery"}
    blob = b"".join((d / f).read_bytes() for f in ("vault.json", "payload.age", "slots/passphrase.age"))
    assert OWN_SECRET.encode() not in blob and b"AGE-SECRET-KEY" not in blob
    assert operator_template.op.identity.startswith("AGE-SECRET-KEY-")


def test_vault_unlock_wrong_recovery_and_change(tmp_path, operator_template):
    """Ein Ablauf, damit age-scrypt (langsam) möglichst selten läuft."""
    d = tmp_path / "operator"
    shutil.copytree(operator_template.directory, d)
    vault = OperatorVault(d)
    assert vault.exists
    with pytest.raises(VaultExists):
        vault.create(PASSPHRASE)
    op = vault.unlock(PASSPHRASE)
    assert op.operator_id == operator_template.op.operator_id and op.handle == "tester"
    assert op.own_secrets == [("sudo", OWN_SECRET)]
    with pytest.raises(WrongPassphrase):
        vault.unlock("falsche-passphrase")
    op.add_secret("api", "sk-ant-xyz-1234")
    op.set_api_key("anthropic", "sk-ant-api-0000")
    op.save()
    rec = vault.unlock(recovery_code=operator_template.recovery_code.lower())
    assert rec.secret_labels() == ["sudo", "api"]
    assert rec.get_api_key("anthropic") == "sk-ant-api-0000"
    with pytest.raises(VaultError):
        rec.change_passphrase("kurz")
    rec.change_passphrase("neue-passphrase-42")
    assert vault.unlock("neue-passphrase-42").operator_id == op.operator_id
    rec.wipe()
    with pytest.raises(VaultError):
        _ = rec.identity


def test_vault_create_checks_before_scrypt(tmp_path):
    v = OperatorVault(tmp_path / "op")
    with pytest.raises(VaultError):
        v.create("kurz")
    assert not v.exists
    with pytest.raises(VaultError):
        v.unlock("egal")


def test_secret_label_validation(operator):
    with pytest.raises(VaultError):
        operator.add_secret("bad label", "x" * 8)
    with pytest.raises(VaultError):
        operator.add_secret("ok", "")
    with pytest.raises(VaultError, match="zu kurz"):
        operator.add_secret("pin", "123")  # würde nie geschwärzt
    operator.add_secret("ok", "wert-1")
    operator.add_secret("ok", "wert-2")
    assert operator.own_secrets[-1] == ("ok", "wert-2") and operator.secret_labels().count("ok") == 1
    assert operator.remove_secret("ok") and not operator.remove_secret("ok")
