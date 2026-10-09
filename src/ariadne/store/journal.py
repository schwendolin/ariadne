"""Journal auf SQLCipher (Architektur 5.2).

Gleiche Semantik wie :class:`ariadne.store.memory.MemoryJournal`, dazu
Persistenz und Schutz in der Datenbank:

* Tabelle ``event`` mit allen Spalten der Hash-Kette, Salt in eigener Spalte.
* Partieller UNIQUE-Index ``(terminal_id, stream_off)`` für ``term.out``.
* Trigger: ``DELETE`` verboten, ``UPDATE`` nur als Redaktion (``body`` und
  ``salt`` auf NULL, sonst nichts geändert).
* :meth:`SqlCipherJournal.verify` rechnet Kette und Commitments vollständig nach.

Die Tabelle ``blob`` (Index des Blob-Stores) liegt ebenfalls in ``journal.db``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import sqlcipher3

from ariadne import events
from ariadne.crypto.db import open_db
from ariadne.ids import new_id
from ariadne.store import chain
from ariadne.store.api import (
    AppendItem,
    DuplicateStreamChunk,
    EventRecord,
    JournalError,
    VerifyReport,
)

__all__ = ["SCHEMA_VERSION", "SqlCipherJournal", "init_schema", "read_boot_id"]

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS event (
  seq         INTEGER PRIMARY KEY,
  id          TEXT NOT NULL UNIQUE,
  layer       TEXT NOT NULL CHECK (layer IN ('raw','decision','system')),
  kind        TEXT NOT NULL,
  ts_utc_ns   INTEGER NOT NULL,
  mono_ns     INTEGER,
  boot_id     TEXT,
  operator_id TEXT NOT NULL,
  origin      TEXT NOT NULL,
  terminal_id TEXT,
  stream_off  INTEGER,
  header      TEXT NOT NULL,
  body        BLOB,
  salt        BLOB,
  body_commit BLOB,
  prev_hash   BLOB NOT NULL,
  hash        BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS event_stream_uq ON event(terminal_id, stream_off)
  WHERE kind = 'term.out';
CREATE INDEX IF NOT EXISTS event_kind_idx ON event(kind, seq);
CREATE INDEX IF NOT EXISTS event_terminal_idx ON event(terminal_id, seq) WHERE terminal_id IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS event_no_delete BEFORE DELETE ON event
BEGIN
  SELECT RAISE(ABORT, 'journal ist append-only');
END;
CREATE TRIGGER IF NOT EXISTS event_redact_only BEFORE UPDATE ON event
WHEN NOT (
  NEW.body IS NULL AND NEW.salt IS NULL AND OLD.body IS NOT NULL
  AND NEW.seq IS OLD.seq AND NEW.id IS OLD.id AND NEW.layer IS OLD.layer
  AND NEW.kind IS OLD.kind AND NEW.ts_utc_ns IS OLD.ts_utc_ns AND NEW.mono_ns IS OLD.mono_ns
  AND NEW.boot_id IS OLD.boot_id AND NEW.operator_id IS OLD.operator_id
  AND NEW.origin IS OLD.origin AND NEW.terminal_id IS OLD.terminal_id
  AND NEW.stream_off IS OLD.stream_off AND NEW.header IS OLD.header
  AND NEW.body_commit IS OLD.body_commit AND NEW.prev_hash IS OLD.prev_hash
  AND NEW.hash IS OLD.hash
)
BEGIN
  SELECT RAISE(ABORT, 'nur Redaktion erlaubt');
END;
CREATE TABLE IF NOT EXISTS blob (
  blob_id    TEXT PRIMARY KEY,
  sha256     TEXT NOT NULL UNIQUE,
  size       INTEGER NOT NULL,
  kind       TEXT NOT NULL,
  created_ns INTEGER NOT NULL
);
"""

_COLS = ("seq, id, layer, kind, ts_utc_ns, mono_ns, boot_id, operator_id, origin, terminal_id, "
         "stream_off, header, body, salt, body_commit, prev_hash, hash")
_PAGE = 512


def read_boot_id() -> str | None:
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def init_schema(conn: sqlcipher3.Connection, project_id: str) -> None:
    """Legt das Schema an (idempotent) und bindet die Datei an ``project_id``."""
    conn.executescript(_SCHEMA)
    row = conn.execute("SELECT value FROM meta WHERE key = 'project_id'").fetchone()
    if row is None:
        conn.execute("INSERT INTO meta(key, value) VALUES ('project_id', ?)", (project_id,))
        conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
    elif row[0] != project_id:
        raise JournalError("journal.db gehört zu einem anderen Projekt")
    conn.commit()


class _Built:
    __slots__ = ("rec", "salt", "commit", "header_json", "prev")

    def __init__(self, rec: EventRecord, salt: bytes | None, commit: bytes | None,
                 header_json: bytes, prev: bytes) -> None:
        self.rec = rec
        self.salt = salt
        self.commit = commit
        self.header_json = header_json
        self.prev = prev


class SqlCipherJournal:
    """Append-only Journal mit Hash-Kette in einer SQLCipher-Datenbank.

    Die Verbindung gehört dem Journal (``isolation_level=None``, Transaktionen
    explizit). Nicht threadsicher: nur aus einem Thread benutzen.
    """

    def __init__(self, conn: sqlcipher3.Connection, *, project_id: str, operator_id: str,
                 boot_id: str | None = None) -> None:
        self.conn = conn
        self.conn.isolation_level = None
        self.project_id = project_id
        self.operator_id = operator_id
        self.boot_id = boot_id
        init_schema(conn, project_id)
        row = conn.execute("SELECT seq, hash FROM event ORDER BY seq DESC LIMIT 1").fetchone()
        self._head: tuple[int, bytes] = (
            (int(row[0]), bytes(row[1])) if row else (0, chain.genesis_hash(project_id))
        )

    @classmethod
    def open(cls, path: Path, key: bytes, *, project_id: str, operator_id: str,
             boot_id: str | None = None) -> SqlCipherJournal:
        return cls(open_db(path, key), project_id=project_id, operator_id=operator_id,
                   boot_id=boot_id if boot_id is not None else read_boot_id())

    # ------------------------------------------------------------------ #
    def _build(self, item: AppendItem, seq: int, prev: bytes) -> _Built:
        header = events.validate_header(item.kind, item.header)
        spec = events.KINDS[item.kind]
        if item.body is not None and not spec.has_body:
            raise JournalError(f"{item.kind} hat keinen Body")
        if item.kind == "term.out" and (item.terminal_id is None or item.stream_off is None):
            raise JournalError("term.out braucht terminal_id und stream_off")
        ts = item.ts_utc_ns if item.ts_utc_ns is not None else time.time_ns()
        mono = time.monotonic_ns()
        eid = new_id()
        header_json = events.canonical_json(header)
        salt = commit = None
        body = bytes(item.body) if item.body is not None else None
        if body is not None:
            salt = chain.new_salt()
            commit = chain.body_commit(salt, body)
        h = chain.event_hash(
            prev, seq=seq, event_id=eid, layer=spec.layer, kind=item.kind, ts_utc_ns=ts,
            mono_ns=mono, boot_id=self.boot_id, operator_id=self.operator_id, origin=item.origin,
            terminal_id=item.terminal_id, stream_off=item.stream_off, header_json=header_json,
            body_commit=commit,
        )
        rec = EventRecord(
            seq=seq, id=eid, layer=spec.layer, kind=item.kind, ts_utc_ns=ts, mono_ns=mono,
            boot_id=self.boot_id, operator_id=self.operator_id, origin=item.origin,
            terminal_id=item.terminal_id, stream_off=item.stream_off, header=header, body=body,
            hash=h,
        )
        return _Built(rec, salt, commit, header_json, prev)

    def _insert(self, b: _Built) -> None:
        r = b.rec
        self.conn.execute(
            f"INSERT INTO event ({_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",  # noqa: S608 (feste Spalten)
            (r.seq, r.id, r.layer, r.kind, r.ts_utc_ns, r.mono_ns, r.boot_id, r.operator_id,
             r.origin, r.terminal_id, r.stream_off, b.header_json.decode(), r.body, b.salt,
             b.commit, b.prev, r.hash),
        )

    def _stream_exists(self, terminal_id: str | None, stream_off: int | None) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM event WHERE kind = 'term.out' AND terminal_id IS ? AND stream_off IS ?",
            (terminal_id, stream_off),
        ).fetchone()
        return row is not None

    def _begin(self) -> None:
        self.conn.execute("BEGIN IMMEDIATE")

    def _rollback(self) -> None:
        try:
            self.conn.execute("ROLLBACK")
        except sqlcipher3.Error:
            pass

    # ------------------------------------------------------------------ #
    def append(self, kind: str, header: dict[str, Any], body: bytes | None = None, *,
               origin: str = "daemon", terminal_id: str | None = None,
               stream_off: int | None = None, ts_utc_ns: int | None = None) -> EventRecord:
        item = AppendItem(kind, header, body, origin, terminal_id, stream_off, ts_utc_ns)
        if kind == "term.out" and self._stream_exists(terminal_id, stream_off):
            raise DuplicateStreamChunk(f"{terminal_id}@{stream_off}")
        seq, prev = self._head
        built = self._build(item, seq + 1, prev)
        self._begin()
        try:
            self._insert(built)
            self.conn.execute("COMMIT")
        except sqlcipher3.IntegrityError as exc:
            self._rollback()
            if kind == "term.out":
                raise DuplicateStreamChunk(f"{terminal_id}@{stream_off}") from exc
            raise JournalError("Schreiben abgelehnt") from exc
        except BaseException:
            self._rollback()
            raise
        self._head = (built.rec.seq, built.rec.hash)
        return built.rec

    def append_many(self, items: Iterable[AppendItem]) -> list[EventRecord]:
        seq, prev = self._head
        out: list[EventRecord] = []
        staged: set[tuple[str | None, int | None]] = set()
        self._begin()
        try:
            for it in items:
                if it.kind == "term.out":
                    key = (it.terminal_id, it.stream_off)
                    if key in staged or self._stream_exists(*key):
                        continue
                    staged.add(key)
                built = self._build(it, seq + 1, prev)
                self._insert(built)
                seq, prev = built.rec.seq, built.rec.hash
                out.append(built.rec)
            self.conn.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        self._head = (seq, prev)
        return out

    def _record(self, row: tuple[Any, ...]) -> EventRecord:
        return EventRecord(
            seq=int(row[0]), id=row[1], layer=row[2], kind=row[3], ts_utc_ns=int(row[4]),
            mono_ns=row[5], boot_id=row[6], operator_id=row[7], origin=row[8], terminal_id=row[9],
            stream_off=row[10], header=json.loads(row[11]),
            body=bytes(row[12]) if row[12] is not None else None, hash=bytes(row[16]),
        )

    def iter_events(self, after_seq: int = 0, *, kinds: Iterable[str] | None = None,
                    terminal_id: str | None = None) -> Iterator[EventRecord]:
        where = ["seq > ?"]
        params: list[Any] = []
        if kinds is not None:
            kind_list = list(kinds)
            if not kind_list:
                return
            where.append(f"kind IN ({','.join('?' * len(kind_list))})")
            params.extend(kind_list)
        if terminal_id is not None:
            where.append("terminal_id = ?")
            params.append(terminal_id)
        # Nur feste Spaltennamen und Platzhalter im SQL, Werte immer als Parameter.
        sql = f"SELECT {_COLS} FROM event WHERE {' AND '.join(where)} ORDER BY seq LIMIT {_PAGE}"  # noqa: S608
        last = after_seq
        while True:
            rows = self.conn.execute(sql, [last, *params]).fetchall()
            if not rows:
                return
            for row in rows:
                yield self._record(row)
            last = int(rows[-1][0])

    def get(self, seq: int) -> EventRecord | None:
        row = self.conn.execute(f"SELECT {_COLS} FROM event WHERE seq = ?", (seq,)).fetchone()  # noqa: S608
        return self._record(row) if row else None

    def head(self) -> tuple[int, bytes]:
        return self._head

    def verify_head(self) -> bool:
        """Schnelle Prüfung beim Öffnen: Hash des letzten Events nachrechnen."""
        row = self.conn.execute(f"SELECT {_COLS} FROM event ORDER BY seq DESC LIMIT 1").fetchone()  # noqa: S608
        if row is None:
            return True
        commit = bytes(row[14]) if row[14] is not None else None
        h = chain.event_hash(
            bytes(row[15]), seq=int(row[0]), event_id=row[1], layer=row[2], kind=row[3], ts_utc_ns=row[4],
            mono_ns=row[5], boot_id=row[6], operator_id=row[7], origin=row[8], terminal_id=row[9],
            stream_off=row[10], header_json=str(row[11]).encode(), body_commit=commit,
        )
        return h == bytes(row[16])

    def stream_end(self, terminal_id: str) -> int:
        """Ende des gespeicherten Stroms eines Terminals (0, wenn nichts gespeichert)."""
        row = self.conn.execute(
            "SELECT stream_off, header FROM event WHERE kind = 'term.out' AND terminal_id = ? "
            "ORDER BY stream_off DESC LIMIT 1",
            (terminal_id,),
        ).fetchone()
        if row is None:
            return 0
        return int(row[0]) + int(json.loads(row[1]).get("length", 0))

    def verify(self) -> VerifyReport:
        problems: list[str] = []
        prev = chain.genesis_hash(self.project_id)
        expected_seq = 1
        count = 0
        last_hash = prev
        redacted: set[int] = set()
        redaction_refs: set[int] = set()
        cur = self.conn.execute(f"SELECT {_COLS} FROM event ORDER BY seq")  # noqa: S608
        for row in cur:
            count += 1
            seq = int(row[0])
            header_text, body, salt, commit = row[11], row[12], row[13], row[14]
            row_prev, row_hash = bytes(row[15]), bytes(row[16])
            if seq != expected_seq:
                problems.append(f"seq {seq}: Lücke oder Sprung (erwartet {expected_seq})")
            expected_seq = seq + 1
            if row_prev != prev:
                problems.append(f"seq {seq}: prev_hash passt nicht zum Vorgänger")
            commit_b = bytes(commit) if commit is not None else None
            if body is not None:
                if salt is None or commit_b is None:
                    problems.append(f"seq {seq}: Body ohne Salt oder Commitment")
                elif chain.body_commit(bytes(salt), bytes(body)) != commit_b:
                    problems.append(f"seq {seq}: Body passt nicht zum Commitment")
            elif salt is not None:
                problems.append(f"seq {seq}: Salt ohne Body")
            elif commit_b is not None:
                redacted.add(seq)
            try:
                header = json.loads(header_text)
                if events.canonical_json(header).decode() != header_text:
                    problems.append(f"seq {seq}: Header nicht kanonisch")
                if row[3] == "system.redaction":
                    redaction_refs.add(int(header.get("ref_seq", -1)))
            except (ValueError, TypeError):
                problems.append(f"seq {seq}: Header unlesbar")
            h = chain.event_hash(
                row_prev, seq=seq, event_id=row[1], layer=row[2], kind=row[3], ts_utc_ns=row[4],
                mono_ns=row[5], boot_id=row[6], operator_id=row[7], origin=row[8],
                terminal_id=row[9], stream_off=row[10], header_json=header_text.encode(),
                body_commit=commit_b,
            )
            if h != row_hash:
                problems.append(f"seq {seq}: Hash stimmt nicht")
            prev = row_hash
            last_hash = row_hash
        for seq in sorted(redacted - redaction_refs):
            problems.append(f"seq {seq}: Body entfernt ohne Redaktionsvermerk")
        head_seq, head_hash = (expected_seq - 1, last_hash) if count else self._head
        if count and (head_seq, head_hash) != self._head:
            problems.append("Kettenkopf im Speicher weicht von der Datenbank ab")
        return VerifyReport(ok=not problems, events=count, head_seq=head_seq,
                            head_hash=head_hash.hex(), problems=problems)

    def redact(self, seq: int, *, label: str, replacement: bytes | None,
               reason: str) -> EventRecord:
        row = self.conn.execute("SELECT body IS NOT NULL FROM event WHERE seq = ?", (seq,)).fetchone()
        if row is None:
            raise JournalError(f"seq {seq} existiert nicht")
        if not row[0]:
            raise JournalError(f"seq {seq} hat keinen Body")
        head_seq, prev = self._head
        built = self._build(
            AppendItem("system.redaction", {"ref_seq": seq, "label": label, "reason": reason},
                       replacement),
            head_seq + 1, prev,
        )
        self._begin()
        try:
            self.conn.execute("UPDATE event SET body = NULL, salt = NULL WHERE seq = ?", (seq,))
            self._insert(built)
            self.conn.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        self._head = (built.rec.seq, built.rec.hash)
        return built.rec

    def checkpoint(self, vacuum: bool = False) -> None:
        """WAL in die Hauptdatei schreiben und kürzen, optional VACUUM."""
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        if vacuum:
            self.conn.execute("VACUUM")
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlcipher3.Error:
            pass
