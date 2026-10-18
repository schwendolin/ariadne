"""Vertragstests für Journal und Blob-Store: gleiche Erwartungen an Memory- und SQLCipher-Variante."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from dataclasses import dataclass
from typing import Any

import pytest

from ariadne.crypto import age
from ariadne.crypto.db import new_key, open_db
from ariadne.store import chain
from ariadne.store.api import AppendItem, BlobStore, DuplicateStreamChunk, Journal, JournalError
from ariadne.store.blobs import AgeBlobStore
from ariadne.store.journal import SqlCipherJournal
from ariadne.store.memory import MemoryBlobStore, MemoryJournal

PID = "test-project"


@dataclass
class Store:
    kind: str
    journal: Any
    blobs: Any
    path: Any = None
    key: bytes | None = None


def _sql_store(tmp_path) -> Store:
    key = new_key()
    path = tmp_path / "journal.db"
    j = SqlCipherJournal.open(path, key, project_id=PID, operator_id="test-operator", boot_id="test-boot")
    ident, recip = age.generate_identity()
    b = AgeBlobStore(tmp_path / "blobs", j.conn, recipient=recip, identity=ident)
    return Store("sqlcipher", j, b, path, key)


@pytest.fixture(params=["memory", "sqlcipher"])
def store(request, tmp_path):
    if request.param == "memory":
        yield Store("memory", MemoryJournal(project_id=PID), MemoryBlobStore())
        return
    st = _sql_store(tmp_path)
    yield st
    st.journal.close()


@pytest.fixture
def sql_store(tmp_path):
    st = _sql_store(tmp_path)
    yield st
    st.journal.close()


def out_header(off: int, n: int, tid: str = "t1") -> dict[str, Any]:
    return {"terminal_id": tid, "stream_off": off, "length": n, "t_shim_ns": 1}


def out_item(off: int, data: bytes, tid: str = "t1") -> AppendItem:
    return AppendItem("term.out", out_header(off, len(data), tid), data, origin="shim", terminal_id=tid,
                      stream_off=off)


# ------------------------------------------------------------------- Journal


def test_protocols(store):
    assert isinstance(store.journal, Journal)
    assert isinstance(store.blobs, BlobStore)


def test_empty_head_is_genesis(store):
    assert store.journal.head() == (0, chain.genesis_hash(PID))
    rep = store.journal.verify()
    assert rep.ok and rep.events == 0 and rep.head_seq == 0


def test_append_validates_and_sets_fields(store):
    j = store.journal
    r = j.append("rec.set", {"on": True, "source": "cli"}, origin="cli", ts_utc_ns=123)
    assert (r.seq, r.layer, r.kind, r.origin, r.ts_utc_ns) == (1, "raw", "rec.set", "cli", 123)
    assert r.operator_id == j.operator_id and r.body is None
    d = j.append("d.note.set", {"subject": "ip:default/10.0.0.1", "text": "notiz"})
    assert d.layer == "decision" and d.seq == 2
    with pytest.raises(ValueError):
        j.append("unbekannt.art", {})
    with pytest.raises(ValueError):
        j.append("rec.set", {"on": True, "source": "cli", "extra": 1})
    with pytest.raises(JournalError):
        j.append("rec.set", {"on": True, "source": "cli"}, b"body verboten")
    with pytest.raises(JournalError):
        j.append("term.out", out_header(0, 1), b"x")  # ohne terminal_id/stream_off
    assert j.head()[0] == 2
    assert j.get(1) == r and j.get(99) is None


def test_chain_links_and_verify(store):
    j = store.journal
    recs = [j.append("rec.set", {"on": i % 2 == 0, "source": "cli"}) for i in range(5)]
    prev = chain.genesis_hash(PID)
    for r in recs:
        hdr = j.get(r.seq).header
        h = chain.event_hash(prev, seq=r.seq, event_id=r.id, layer=r.layer, kind=r.kind,
                             ts_utc_ns=r.ts_utc_ns, mono_ns=r.mono_ns, boot_id=r.boot_id,
                             operator_id=r.operator_id, origin=r.origin, terminal_id=r.terminal_id,
                             stream_off=r.stream_off,
                             header_json=chain_header(hdr), body_commit=None)
        assert h == r.hash
        prev = r.hash
    assert j.head() == (5, recs[-1].hash)
    rep = j.verify()
    assert rep.ok and rep.events == 5 and rep.head_hash == recs[-1].hash.hex()


def chain_header(header: dict[str, Any]) -> bytes:
    from ariadne.events import canonical_json

    return canonical_json(header)


def test_term_out_idempotence(store):
    j = store.journal
    j.append("term.out", out_header(0, 3), b"abc", origin="shim", terminal_id="t1", stream_off=0)
    with pytest.raises(DuplicateStreamChunk):
        j.append("term.out", out_header(0, 3), b"abc", origin="shim", terminal_id="t1", stream_off=0)
    # andere Terminals und andere Arten am gleichen Offset sind erlaubt
    j.append("term.out", out_header(0, 3, "t2"), b"xyz", origin="shim", terminal_id="t2", stream_off=0)
    j.append("term.mark", {"terminal_id": "t1", "stream_off": 0, "mark": "A", "counter": 1, "fg_shell": True},
             origin="shim", terminal_id="t1", stream_off=0)
    got = j.append_many([out_item(0, b"abc"), out_item(3, b"def"), out_item(3, b"def"), out_item(6, b"g")])
    assert [(r.stream_off, r.body) for r in got] == [(3, b"def"), (6, b"g")]
    assert j.verify().ok


def test_append_many_is_atomic(store):
    j = store.journal
    j.append("rec.set", {"on": True, "source": "cli"})
    head = j.head()
    bad = AppendItem("rec.set", {"on": "vielleicht", "source": "cli", "x": 1})
    with pytest.raises(ValueError):
        j.append_many([out_item(0, b"eins"), bad])
    assert j.head() == head
    assert list(j.iter_events(kinds=["term.out"])) == []
    # nach dem Fehlschlag geht es normal weiter
    got = j.append_many([out_item(0, b"eins")])
    assert got[0].seq == head[0] + 1 and j.verify().ok


def test_iter_events_filters(store):
    j = store.journal
    j.append("rec.set", {"on": True, "source": "cli"})
    j.append_many([out_item(0, b"a", "t1"), out_item(0, b"b", "t2"), out_item(1, b"c", "t1")])
    j.append("rec.set", {"on": False, "source": "cli"})
    assert [r.seq for r in j.iter_events()] == [1, 2, 3, 4, 5]
    assert [r.seq for r in j.iter_events(after_seq=3)] == [4, 5]
    assert [r.body for r in j.iter_events(kinds=["term.out"], terminal_id="t1")] == [b"a", b"c"]
    assert [r.seq for r in j.iter_events(kinds=["rec.set"])] == [1, 5]
    assert list(j.iter_events(kinds=[])) == []


def test_redaction(store):
    j = store.journal
    j.append("rec.set", {"on": True, "source": "cli"})
    o = j.append("term.out", out_header(0, 11), b"pw=hunter22", origin="shim", terminal_id="t1", stream_off=0)
    red = j.redact(o.seq, label="own:pw", replacement=b"pw=********", reason="eigenes Passwort")
    assert red.kind == "system.redaction" and red.layer == "system"
    assert red.header == {"ref_seq": o.seq, "label": "own:pw", "reason": "eigenes Passwort"}
    assert red.body == b"pw=********"
    assert j.get(o.seq).body is None
    assert j.get(o.seq).hash == o.hash
    assert j.verify().ok
    with pytest.raises(JournalError):
        j.redact(o.seq, label="x", replacement=None, reason="schon weg")
    with pytest.raises(JournalError):
        j.redact(1, label="x", replacement=None, reason="ohne Body")
    with pytest.raises(JournalError):
        j.redact(999, label="x", replacement=None, reason="gibt es nicht")


# --------------------------------------------------------------------- Blobs


def test_blob_roundtrip_dedupe_delete(store):
    b = store.blobs
    data = b"\x89PNG kanarienvogel-blob"
    r1 = b.put_bytes(data, kind="screenshot")
    r2 = b.put_bytes(data)
    assert r1 == r2 and r1.sha256 == hashlib.sha256(data).hexdigest() and r1.size == len(data)
    assert b.open_bytes(r1.blob_id) == data
    assert b.find_by_sha256(r1.sha256) == r1
    assert b.find_by_sha256("0" * 64) is None
    other = b.put_bytes(b"anders")
    assert other.blob_id != r1.blob_id
    b.delete(r1.blob_id)
    assert b.find_by_sha256(r1.sha256) is None
    with pytest.raises(KeyError):
        b.open_bytes(r1.blob_id)
    with pytest.raises(KeyError):
        b.delete(r1.blob_id)
    with pytest.raises(KeyError):
        b.open_bytes("../../etc/passwd")
    assert b.open_bytes(other.blob_id) == b"anders"


# ------------------------------------------------------- nur SQLCipher und age


def test_reopen_keeps_chain(sql_store):
    j = sql_store.journal
    j.append_many([out_item(0, b"eins"), out_item(4, b"zwei")])
    head = j.head()
    j.close()
    j2 = SqlCipherJournal.open(sql_store.path, sql_store.key, project_id=PID, operator_id="op2")
    assert j2.head() == head and j2.stream_end("t1") == 8
    j2.append("rec.set", {"on": False, "source": "cli"})
    assert j2.verify().ok and j2.head()[0] == 3
    j2.close()
    with pytest.raises(JournalError):
        SqlCipherJournal.open(sql_store.path, sql_store.key, project_id="anderes-projekt",
                              operator_id="x")
    sql_store.journal = SqlCipherJournal.open(sql_store.path, sql_store.key, project_id=PID,
                                              operator_id="x")


def test_triggers_forbid_update_and_delete(sql_store):
    j = sql_store.journal
    j.append("term.out", out_header(0, 3), b"abc", origin="shim", terminal_id="t1", stream_off=0)
    import sqlcipher3

    for sql in ("DELETE FROM event WHERE seq = 1",
                "UPDATE event SET header = '{}' WHERE seq = 1",
                "UPDATE event SET body = NULL WHERE seq = 1",  # Salt bleibt: keine gültige Redaktion
                "UPDATE event SET body = x'00', salt = NULL WHERE seq = 1"):
        with pytest.raises(sqlcipher3.IntegrityError):
            j.conn.execute(sql)
    assert j.verify().ok


@pytest.mark.parametrize("tamper", [
    "UPDATE event SET header = replace(header, '\"on\":true', '\"on\":false') WHERE seq = 1",
    "UPDATE event SET ts_utc_ns = ts_utc_ns + 1 WHERE seq = 1",
    "UPDATE event SET operator_id = 'mallory' WHERE seq = 2",
    "UPDATE event SET body = x'616263' WHERE seq = 2",
    "UPDATE event SET body = NULL, salt = NULL WHERE seq = 2",
    "DELETE FROM event WHERE seq = 2",
])
def test_tampering_is_detected(sql_store, tamper):
    """Wer den Schlüssel hat, kann Trigger löschen und Zeilen ändern. verify() merkt es."""
    j = sql_store.journal
    j.append("rec.set", {"on": True, "source": "cli"})
    j.append("term.out", out_header(0, 3), b"xyz", origin="shim", terminal_id="t1", stream_off=0)
    j.append("rec.set", {"on": False, "source": "cli"})
    assert j.verify().ok
    raw = open_db(sql_store.path, sql_store.key)
    raw.execute("DROP TRIGGER event_no_delete")
    raw.execute("DROP TRIGGER event_redact_only")
    raw.execute(tamper)
    raw.commit()
    raw.close()
    rep = j.verify()
    assert not rep.ok and rep.problems


def test_files_are_ciphertext(sql_store, tmp_path):
    j = sql_store.journal
    canary = b"KANARIENVOGEL-JOURNAL-7731"
    j.append("term.out", out_header(0, len(canary)), canary, origin="shim", terminal_id="t1", stream_off=0)
    ref = sql_store.blobs.put_bytes(canary + b"-blob")
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert canary not in f.read_bytes(), f
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(sql_store.path).execute("SELECT * FROM event").fetchall()
    blob_files = list((tmp_path / "blobs").rglob("*.age"))
    assert len(blob_files) == 1
    bf = blob_files[0]
    assert bf.name == f"{ref.blob_id}.age" and ref.sha256 not in str(bf)
    assert stat.S_IMODE(os.stat(bf).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(bf.parent).st_mode) == 0o700
    assert sql_store.blobs.verify() == []
    bf.write_bytes(b"kaputt")
    assert sql_store.blobs.verify()


def test_stream_end_and_verify_head(store):
    j = store.journal
    assert j.stream_end("t1") == 0 and j.verify_head()
    j.append_many([out_item(0, b"abc"), out_item(3, b"defg"), out_item(0, b"x", tid="t2")])
    assert j.stream_end("t1") == 7 and j.stream_end("t2") == 1 and j.stream_end("t3") == 0
    j.append("d.note.set", {"subject": "ip:default/10.0.0.1", "text": "n"})
    assert j.verify_head()


def test_journal_reader_sees_commits_readonly(sql_store):
    from ariadne.store.journal import JournalReader

    j = sql_store.journal
    j.append_many([out_item(0, b"abc")])
    reader = JournalReader(open_db(sql_store.path, sql_store.key, readonly=True))
    try:
        assert [r.kind for r in reader.iter_events()] == ["term.out"]
        j.append("d.note.set", {"subject": "ip:default/10.0.0.1", "text": "n"})
        assert [r.kind for r in reader.iter_events(1)] == ["d.note.set"]
        assert reader.get(1).body == b"abc" and reader.stream_end("t1") == 3
        # Kettenkopf und Event nach ID ohne SQL im Aufrufer (Bericht «api»)
        assert reader.read_head() == j.head() == j.read_head()
        note = reader.get(2)
        assert reader.get_by_id(note.id).kind == "d.note.set" and reader.get_by_id("nicht-da") is None
        with pytest.raises(Exception):  # nur lesend
            reader.conn.execute("DELETE FROM meta")
    finally:
        reader.close()
