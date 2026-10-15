"""Writer (Vertrag 4.6): Zusammenfassen von Ausgabe-Rahmen ohne Verlust an Zeitgenauigkeit."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ariadne import events
from ariadne.daemon.terminal import Terminal
from ariadne.daemon.writer import MERGE_MAX, OutChunk, Writer, merge_tix
from ariadne.store.api import AppendItem
from ariadne.store.memory import MemoryJournal

TID = "term-00000001"


class FakeDaemon:
    def __init__(self) -> None:
        self.project = SimpleNamespace(journal=MemoryJournal(project_id="p"))
        self.terminals: dict[str, Terminal] = {TID: Terminal(TID)}
        self.committed: list = []

    def advance_acks(self) -> None:
        pass

    def run_commit_hooks(self, records) -> None:
        self.committed.extend(records)

    def run_mark_hooks(self, rec, ctx) -> None:
        pass


def chunk(t: Terminal, off: int, data: bytes, dt_ns: int, tix=(), **kw) -> OutChunk:
    return OutChunk(t, off, data, 1_700_000_000_000_000_000 + dt_ns, 5_000_000_000 + dt_ns, tuple(tix),
                    recv=1_700_000_000_000_000_000 + dt_ns, **kw)


def outs(d: FakeDaemon) -> list:
    return [r for r in d.committed if r.kind == "term.out"]


def test_merge_tix_rules():
    assert merge_tix([], 5, 0, ((2, 7),)) == [(7, 7)]  # gleiche Zeit wie zuvor: kein Eintrag
    assert merge_tix([(3, 10)], 5, 20, ((1, 5),)) == [(3, 10), (5, 20), (6, 25)]


def test_merge_contiguous_frames_and_stop_at_own_events():
    d = FakeDaemon()
    w = Writer(d)
    t = d.terminals[TID]
    w.add_out(chunk(t, 0, b"abc", 0, ((1, 3),)))
    w.add_out(chunk(t, 3, b"def", 2_500_777))
    other = "anderes-00000001"
    w.add_event(AppendItem("term.gap", {"terminal_id": other, "stream_off": 0, "reason": "pause"},
                           terminal_id=other, stream_off=0))
    w.add_out(chunk(t, 6, b"ghi", 4_000_000))  # fremdes Event trennt nicht
    w.add_event(AppendItem("term.resize", {"terminal_id": TID, "stream_off": 9, "rows": 1, "cols": 1},
                           terminal_id=TID, stream_off=9), t)
    w.add_out(chunk(t, 9, b"jkl", 5_000_000))  # eigenes Event trennt
    w.add_out(chunk(t, 13, b"mno", 6_000_000))  # Lücke im Strom trennt
    w.flush_now()
    o = outs(d)
    assert [(r.stream_off, r.body) for r in o] == [(0, b"abcdefghi"), (9, b"jkl"), (13, b"mno")]
    assert o[0].header["tix"] == [[1, 3], [3, 2500], [6, 4000]]
    assert [r.kind for r in d.committed][:2] == ["term.out", "term.gap"]  # Position des ersten Bytes


@pytest.mark.parametrize("second", [
    dict(origin="preroll"),
    dict(suspect=True),
])
def test_no_merge_across_origin_or_suspect(second):
    d = FakeDaemon()
    w = Writer(d)
    t = d.terminals[TID]
    w.add_out(chunk(t, 0, b"a", 0))
    w.add_out(chunk(t, 1, b"b", 1_000_000, **second))
    w.flush_now()
    assert len(outs(d)) == 2


def test_merge_limits_bytes_and_index():
    d = FakeDaemon()
    w = Writer(d, max_bytes=1 << 30)
    t = d.terminals[TID]
    big = b"x" * (MERGE_MAX - 10)
    w.add_out(chunk(t, 0, big, 0))
    w.add_out(chunk(t, len(big), b"y" * 20, 1_000_000))
    off = len(big) + 20
    for i in range(events.MAX_TIX + 10):
        w.add_out(chunk(t, off + i, b"z", 2_000_000 + i * 1_000_000))
    w.flush_now()
    o = outs(d)
    assert len(o[0].body) == len(big) and all(len(r.header.get("tix") or ()) <= events.MAX_TIX for r in o)
    assert sum(len(r.body) for r in o) == len(big) + 20 + events.MAX_TIX + 10


@settings(max_examples=60, deadline=None)
@given(st.lists(st.tuples(st.integers(1, 40), st.integers(0, 3_000_000), st.integers(0, 3)),
                min_size=1, max_size=12))
def test_merge_keeps_byte_times(frames):
    """Jedes Byte hat nach dem Zusammenfassen dieselbe Shim-Zeit wie vorher (bis 1 µs)."""
    d = FakeDaemon()
    w = Writer(d)
    t = d.terminals[TID]
    off, dt, src = 0, 0, []
    for length, gap_ns, n_tix in frames:
        dt += gap_ns
        tix = tuple((r, 7 * r) for r in range(1, min(n_tix, length - 1) + 1))
        c = chunk(t, off, bytes(length), dt, tix)
        src.append(c)
        w.add_out(c)
        off += length
    w.flush_now()
    merged = outs(d)
    for c in src:
        h = {"t_shim_ns": c.wall, "mono_ns": c.mono, "tix": c.tix}
        rec = next(r for r in merged if r.stream_off <= c.off < r.stream_off + r.header["length"])
        for rel in range(len(c.data)):
            before = events.body_time(h, rel)
            after = events.body_time(rec.header, c.off + rel - rec.stream_off)
            assert abs(after[0] - before[0]) < 1000 and abs(after[1] - before[1]) < 1000
