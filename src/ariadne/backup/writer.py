"""Schreiben der Sicherung: Tar-Strom (PAX) im Takt der Verschlüsselung, age über ``pyrage``.

Der innere Strom entsteht stückweise aus einem Generator (:func:`tar_chunks`); ``pyrage.encrypt_io``
zieht ihn über :class:`_PullReader` und schreibt das Chiffrat über :class:`_GuardedWriter`. So
liegt nie der ganze Klartext im Speicher und nie eine Klartextdatei auf der Platte.

Fehler mitten im Strom (Datei geändert, Ausgabe abgebrochen, Ctrl-C) brechen die Verschlüsselung
ab, **bevor** age den letzten Block schreibt: Ein abgebrochener Strom lässt sich darum nie
entschlüsseln und gilt nie als gültige, aber unvollständige Sicherung.
"""

from __future__ import annotations

import tarfile
from collections.abc import Iterator, Sequence
from typing import Any, BinaryIO

import pyrage
from pyrage import x25519

from ariadne.backup.collect import Entry, iter_file
from ariadne.backup.model import BackupError

__all__ = ["tar_chunks", "encrypt_stream"]

BLOCK = tarfile.BLOCKSIZE


def _header(name: str, *, size: int, mtime: int, is_dir: bool) -> bytes:
    ti = tarfile.TarInfo(name)
    ti.size = 0 if is_dir else size
    ti.mtime = max(0, int(mtime))
    ti.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    ti.mode = 0o700 if is_dir else 0o600
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti.tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape")


def _pad(n: int) -> bytes:
    rest = n % BLOCK
    return b"\0" * (BLOCK - rest) if rest else b""


def tar_chunks(manifest_name: str, manifest: bytes, entries: Sequence[Entry], mtime: int) -> Iterator[bytes]:
    """Manifest zuerst, dann Ordner und Dateien in der Reihenfolge der Auswahl, dann Tar-Ende."""
    yield _header(manifest_name, size=len(manifest), mtime=mtime, is_dir=False)
    yield manifest + _pad(len(manifest))
    for e in entries:
        yield _header(e.arc, size=e.size, mtime=e.mtime, is_dir=e.is_dir)
        if e.is_dir:
            continue
        yield from iter_file(e)
        yield _pad(e.size)
    yield b"\0" * (2 * BLOCK)


class _GuardedWriter:
    """Schreibt vollständig nach ``out``, zählt Bytes und merkt sich den ersten Fehler.

    ``pyrage`` meldet Schreibfehler nicht in jedem Fall (z. B. beim Kopf eines kleinen Stroms);
    darum prüft :func:`encrypt_stream` danach selbst, und der Leser bricht beim nächsten Block ab.
    """

    def __init__(self, out: BinaryIO) -> None:
        self._out = out
        self.count = 0
        self.error: BaseException | None = None

    def write(self, data: Any) -> int:
        if self.error is not None:
            raise OSError("Ausgabe abgebrochen")
        view = memoryview(data).cast("B")
        try:
            while view:
                n = self._out.write(view)
                if n is None:  # gepufferte Ströme schreiben alles oder werfen
                    n = len(view)
                if n <= 0:
                    raise OSError("Ausgabe nimmt nichts mehr an")
                view = view[n:]
        except BaseException as exc:
            self.error = exc
            raise
        self.count += len(data)
        return len(data)

    def flush(self) -> None:
        if self.error is not None:
            return
        try:
            self._out.flush()
        except BaseException as exc:
            self.error = exc
            raise


class _PullReader:
    """Datei-artiger Leser über einem Generator von Blöcken (für ``pyrage.encrypt_io``)."""

    def __init__(self, chunks: Iterator[bytes], writer: _GuardedWriter) -> None:
        self._chunks = chunks
        self._writer = writer
        self._cur = b""
        self._pos = 0
        self.error: BaseException | None = None
        self.plain = 0

    def read(self, n: int = -1) -> bytes:
        if self._writer.error is not None:
            raise OSError("Ausgabe abgebrochen")
        try:
            while self._pos >= len(self._cur):
                nxt = next(self._chunks, None)
                if nxt is None:
                    return b""
                self._cur, self._pos = nxt, 0
        except BaseException as exc:
            self.error = exc
            raise
        if n is None or n < 0:
            n = len(self._cur) - self._pos
        out = self._cur[self._pos:self._pos + n]
        self._pos += len(out)
        self.plain += len(out)
        return out


def encrypt_stream(chunks: Iterator[bytes], out: BinaryIO, recipients: Sequence[str]) -> int:
    """Verschlüsselt den Strom an alle Empfänger nach ``out``. Gibt die geschriebenen Bytes zurück."""
    try:
        recips = [x25519.Recipient.from_str(r) for r in recipients]
    except Exception as exc:  # noqa: BLE001 (pyrage.RecipientError)
        raise BackupError("bad_recipient", "Empfänger ungültig") from exc
    if not recips:
        raise BackupError("no_recipients", "Keine Empfänger für die Sicherung")
    writer = _GuardedWriter(out)
    reader = _PullReader(chunks, writer)
    try:
        pyrage.encrypt_io(reader, writer, recips)
        if writer.error is None:
            writer.flush()
    except BaseException as exc:
        if isinstance(reader.error, BaseException):
            if isinstance(reader.error, BackupError | KeyboardInterrupt):
                raise reader.error from None
            raise BackupError("io", "Lesen für die Sicherung fehlgeschlagen; nichts Gültiges "
                                    "geschrieben.") from exc
        if writer.error is not None:
            raise BackupError("io", "Die Ausgabe brach ab (Verbindung getrennt oder Platte voll); "
                                    "die Sicherung ist unvollständig und unbrauchbar.") from None
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise BackupError("io", "Verschlüsselung fehlgeschlagen; nichts Gültiges geschrieben.") from exc
    finally:
        close = getattr(chunks, "close", None)
        if close is not None:
            close()  # Generator beenden: schliesst eine offene Datei des zweiten Durchgangs
    if writer.error is not None:
        raise BackupError("io", "Die Ausgabe brach ab (Verbindung getrennt oder Platte voll); "
                                "die Sicherung ist unvollständig und unbrauchbar.")
    return writer.count
