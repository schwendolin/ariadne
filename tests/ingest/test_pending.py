"""Vorläufige Zeilen für Leser (``ariadne.ingest.pending``): zurückgehaltene Bytes des Stroms laufen
durch eine Kopie des Normalisierers, der echte bleibt unberührt."""

from __future__ import annotations

from types import SimpleNamespace

from ariadne.ingest import pending
from ariadne.ingest.normalizer import Normalizer
from ariadne.ingest.seg_stream import _Chunk


def _stream(norm: Normalizer, chunks: list[_Chunk]) -> SimpleNamespace:
    return SimpleNamespace(
        norm=norm,
        pending=chunks,
        finished=False,
        stream_end=chunks[-1].off + len(chunks[-1].data) if chunks else norm._off,
        pending_lines=norm.pending,
    )


def test_held_back_chunk_is_previewed_without_touching_the_normalizer():
    norm = Normalizer(0, cols=120)
    norm.feed(b"msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run\r\n", 0)
    off = norm._off
    held = b"[*] Command shell session 1 opened (192.168.56.102:4444 -> 192.168.56.101:6200)\r\n"
    ts = _stream(norm, [_Chunk(off, held)])
    before = [ln.text for ln in norm.pending()]
    with pending.bound(SimpleNamespace(terms={"t": ts})):
        texts = [ln.text for ln in pending._stream_lines("t", ts)]
        again = [ln.text for ln in pending._stream_lines("t", ts)]  # aus dem Zwischenspeicher
    assert any("session 1 opened" in x for x in texts), texts
    assert texts[0].startswith("msf6 exploit")
    assert again == texts
    # der echte Normalisierer hat nichts davon gesehen
    assert norm._off == off
    assert [ln.text for ln in norm.pending()] == before


def test_without_held_bytes_the_normalizer_pending_lines_count():
    norm = Normalizer(0, cols=80)
    norm.feed(b"listening on [any] 4445 ...\r\n", 0)
    ts = _stream(norm, [])
    assert [ln.text for ln in pending._stream_lines("t", ts)] == [ln.text for ln in norm.pending()]
    ts.finished = True
    assert pending._stream_lines("t", ts) == []
