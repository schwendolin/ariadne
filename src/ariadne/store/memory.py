"""In-Memory-Implementierungen von Journal und BlobStore für Tests.

Gleiche Semantik wie die SQLCipher-Variante: Validierung, Hash-Kette,
Idempotenz von ``term.out``, Redaktion. Keine Persistenz, keine Verschlüsselung.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable, Iterator
from dataclasses import replace
from typing import Any

from ariadne import events
from ariadne.ids import new_id
from ariadne.store import chain
from ariadne.store.api import (
    AppendItem,
    BlobRef,
    DuplicateStreamChunk,
    EventRecord,
    JournalError,
    VerifyReport,
)

__all__ = ["MemoryJournal", "MemoryBlobStore"]


class _Row:
    __slots__ = ("rec", "salt", "commit", "header_json")

    def __init__(self, rec: EventRecord, salt: bytes | None, commit: bytes | None,
                 header_json: bytes) -> None:
        self.rec = rec
        self.salt = salt
        self.commit = commit
        self.header_json = header_json


class MemoryJournal:
    def __init__(self, project_id: str = "test-project", operator_id: str = "test-operator",
                 boot_id: str | None = "test-boot") -> None:
        self.project_id = project_id
        self.operator_id = operator_id
        self.boot_id = boot_id
        self._rows: list[_Row] = []
        self._stream_keys: set[tuple[str, int]] = set()

    # ------------------------------------------------------------------ #
    def _prev_hash(self) -> bytes:
        return self._rows[-1].rec.hash if self._rows else chain.genesis_hash(self.project_id)

    def _build(self, item: AppendItem) -> _Row:
        header = events.validate_header(item.kind, item.header)
        spec = events.KINDS[item.kind]
        if item.body is not None and not spec.has_body:
            raise JournalError(f"{item.kind} hat keinen Body")
        if item.kind == "term.out" and (item.terminal_id is None or item.stream_off is None):
            raise JournalError("term.out braucht terminal_id und stream_off")
        seq = len(self._rows) + 1
        ts = item.ts_utc_ns if item.ts_utc_ns is not None else time.time_ns()
        mono = time.monotonic_ns()
        eid = new_id()
        header_json = events.canonical_json(header)
        salt = commit = None
        if item.body is not None:
            salt = chain.new_salt()
            commit = chain.body_commit(salt, item.body)
        h = chain.event_hash(
            self._prev_hash(), seq=seq, event_id=eid, layer=spec.layer, kind=item.kind,
            ts_utc_ns=ts, mono_ns=mono, boot_id=self.boot_id, operator_id=self.operator_id,
            origin=item.origin, terminal_id=item.terminal_id, stream_off=item.stream_off,
            header_json=header_json, body_commit=commit,
        )
        rec = EventRecord(
            seq=seq, id=eid, layer=spec.layer, kind=item.kind, ts_utc_ns=ts, mono_ns=mono,
            boot_id=self.boot_id, operator_id=self.operator_id, origin=item.origin,
            terminal_id=item.terminal_id, stream_off=item.stream_off, header=header,
            body=item.body, hash=h,
        )
        return _Row(rec, salt, commit, header_json)

    # ------------------------------------------------------------------ #
    def append(self, kind: str, header: dict[str, Any], body: bytes | None = None, *,
               origin: str = "daemon", terminal_id: str | None = None,
               stream_off: int | None = None, ts_utc_ns: int | None = None) -> EventRecord:
        item = AppendItem(kind, header, body, origin, terminal_id, stream_off, ts_utc_ns)
        if kind == "term.out" and (terminal_id, stream_off) in self._stream_keys:
            raise DuplicateStreamChunk(f"{terminal_id}@{stream_off}")
        row = self._build(item)
        self._rows.append(row)
        if kind == "term.out":
            self._stream_keys.add((terminal_id, stream_off))  # type: ignore[arg-type]
        return row.rec

    def append_many(self, items: Iterable[AppendItem]) -> list[EventRecord]:
        out: list[EventRecord] = []
        staged_keys: set[tuple[str, int]] = set()
        start = len(self._rows)
        try:
            for it in items:
                if it.kind == "term.out":
                    key = (it.terminal_id, it.stream_off)
                    if key in self._stream_keys or key in staged_keys:
                        continue
                    staged_keys.add(key)  # type: ignore[arg-type]
                row = self._build(it)
                self._rows.append(row)
                out.append(row.rec)
        except Exception:
            del self._rows[start:]
            raise
        self._stream_keys |= staged_keys
        return out

    def iter_events(self, after_seq: int = 0, *, kinds: Iterable[str] | None = None,
                    terminal_id: str | None = None) -> Iterator[EventRecord]:
        kind_set = set(kinds) if kinds is not None else None
        for row in self._rows[after_seq:]:
            r = row.rec
            if kind_set is not None and r.kind not in kind_set:
                continue
            if terminal_id is not None and r.terminal_id != terminal_id:
                continue
            yield r

    def get(self, seq: int) -> EventRecord | None:
        if 1 <= seq <= len(self._rows):
            return self._rows[seq - 1].rec
        return None

    def head(self) -> tuple[int, bytes]:
        if not self._rows:
            return 0, chain.genesis_hash(self.project_id)
        return len(self._rows), self._rows[-1].rec.hash

    def verify(self) -> VerifyReport:
        problems: list[str] = []
        prev = chain.genesis_hash(self.project_id)
        for row in self._rows:
            r = row.rec
            if r.body is not None and row.salt is not None:
                if chain.body_commit(row.salt, r.body) != row.commit:
                    problems.append(f"seq {r.seq}: Body passt nicht zum Commitment")
            h = chain.event_hash(
                prev, seq=r.seq, event_id=r.id, layer=r.layer, kind=r.kind,
                ts_utc_ns=r.ts_utc_ns, mono_ns=r.mono_ns, boot_id=r.boot_id,
                operator_id=r.operator_id, origin=r.origin, terminal_id=r.terminal_id,
                stream_off=r.stream_off, header_json=row.header_json, body_commit=row.commit,
            )
            if h != r.hash:
                problems.append(f"seq {r.seq}: Hash stimmt nicht")
            prev = r.hash
        seq, head = self.head()
        return VerifyReport(ok=not problems, events=len(self._rows), head_seq=seq,
                            head_hash=head.hex(), problems=problems)

    def redact(self, seq: int, *, label: str, replacement: bytes | None,
               reason: str) -> EventRecord:
        row = self._rows[seq - 1] if 1 <= seq <= len(self._rows) else None
        if row is None:
            raise JournalError(f"seq {seq} existiert nicht")
        if row.rec.body is None:
            raise JournalError(f"seq {seq} hat keinen Body")
        r = row.rec
        row.rec = replace(r, body=None)
        row.salt = None  # Commitment bleibt, Salt verschwindet
        return self.append("system.redaction", {"ref_seq": seq, "label": label, "reason": reason},
                           replacement)

    def close(self) -> None:
        pass


class MemoryBlobStore:
    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}
        self._by_sha: dict[str, str] = {}

    def put_bytes(self, data: bytes, *, kind: str = "file") -> BlobRef:
        sha = hashlib.sha256(data).hexdigest()
        if sha in self._by_sha:
            bid = self._by_sha[sha]
            return BlobRef(bid, sha, len(data))
        bid = new_id()
        self._data[bid] = bytes(data)
        self._by_sha[sha] = bid
        return BlobRef(bid, sha, len(data))

    def open_bytes(self, blob_id: str) -> bytes:
        return self._data[blob_id]

    def find_by_sha256(self, sha256: str) -> BlobRef | None:
        bid = self._by_sha.get(sha256)
        if bid is None:
            return None
        return BlobRef(bid, sha256, len(self._data[bid]))

    def delete(self, blob_id: str) -> None:
        data = self._data.pop(blob_id)
        self._by_sha.pop(hashlib.sha256(data).hexdigest(), None)
