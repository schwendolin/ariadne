"""Schnittstellen für Journal und Blob-Store (Architektur 5.1, 5.2).

Die echte Implementierung liegt in ``ariadne.store.journal`` (SQLCipher) und
``ariadne.store.blobs`` (age). ``ariadne.store.memory`` enthält Fakes mit
identischem Verhalten für Tests anderer Teilsysteme. Beide Implementierungen
müssen die Vertragstests in ``tests/unit/test_store_contract.py`` bestehen.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "EventRecord",
    "AppendItem",
    "VerifyReport",
    "BlobRef",
    "Journal",
    "BlobStore",
    "DuplicateStreamChunk",
    "JournalError",
]


class JournalError(RuntimeError):
    pass


class DuplicateStreamChunk(JournalError):
    """``(terminal_id, stream_off)`` existiert schon (idempotente Wiederholung)."""


@dataclass(frozen=True)
class EventRecord:
    seq: int
    id: str
    layer: str
    kind: str
    ts_utc_ns: int
    mono_ns: int | None
    boot_id: str | None
    operator_id: str
    origin: str
    terminal_id: str | None
    stream_off: int | None
    header: dict[str, Any]
    body: bytes | None  # ohne Salt; None nach Redaktion oder ohne Body
    hash: bytes = b""


@dataclass(frozen=True)
class AppendItem:
    kind: str
    header: dict[str, Any]
    body: bytes | None = None
    origin: str = "daemon"
    terminal_id: str | None = None
    stream_off: int | None = None
    ts_utc_ns: int | None = None  # None = jetzt (Empfangszeit im Daemon)


@dataclass
class VerifyReport:
    ok: bool
    events: int
    head_seq: int
    head_hash: str
    problems: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BlobRef:
    blob_id: str
    sha256: str
    size: int


@runtime_checkable
class Journal(Protocol):
    """Append-only Journal mit Hash-Kette (Schicht 1 und 3, System-Events).

    * ``append`` validiert den Header über ``ariadne.events.validate_header``,
      setzt ``layer`` aus dem Katalog, ``operator_id`` aus dem Journal-Kontext
      und die Empfangszeit.
    * ``term.out``-Events sind über ``(terminal_id, stream_off)`` eindeutig.
      Eine Wiederholung mit gleichem Schlüssel wirft :class:`DuplicateStreamChunk`.
    * ``append_many`` schreibt in einer Transaktion. Duplikate von ``term.out``
      werden dort still übersprungen und fehlen im Ergebnis.
    """

    operator_id: str

    def append(self, kind: str, header: dict[str, Any], body: bytes | None = None, *,
               origin: str = "daemon", terminal_id: str | None = None,
               stream_off: int | None = None, ts_utc_ns: int | None = None) -> EventRecord: ...

    def append_many(self, items: Iterable[AppendItem]) -> list[EventRecord]: ...

    def iter_events(self, after_seq: int = 0, *, kinds: Iterable[str] | None = None,
                    terminal_id: str | None = None) -> Iterator[EventRecord]: ...

    def get(self, seq: int) -> EventRecord | None: ...

    def head(self) -> tuple[int, bytes]: ...

    def verify(self) -> VerifyReport: ...

    def redact(self, seq: int, *, label: str, replacement: bytes | None,
               reason: str) -> EventRecord:
        """Einzige erlaubte Änderung: Body von ``seq`` entfernen und ein
        ``system.redaction``-Event mit der Ersatzfassung anhängen."""
        ...

    def close(self) -> None: ...


@runtime_checkable
class BlobStore(Protocol):
    """Verschlüsselte Ablage für Dateien, Bilder und KI-Payloads.

    Dateinamen sind zufällig. Der SHA-256 des Klartexts steht nur verschlüsselt
    in der Datenbank. Die API adressiert nur ``blob_id``.
    """

    def put_bytes(self, data: bytes, *, kind: str = "file") -> BlobRef: ...

    def open_bytes(self, blob_id: str) -> bytes: ...

    def find_by_sha256(self, sha256: str) -> BlobRef | None: ...

    def delete(self, blob_id: str) -> None: ...
