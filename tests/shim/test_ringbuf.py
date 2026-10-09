"""RAM-Ringpuffer: Freigabe, Umbruch, Überlauf."""

from __future__ import annotations

import pytest

from ariadne._shim.ringbuf import MIN_CAPACITY, FrameRing, capacity_from_env


def test_append_get_release():
    r = FrameRing(MIN_CAPACITY)
    for s in range(1, 6):
        assert r.append(s, bytes([s]) * 10, data_len=10, stream_off=s * 10) == []
    assert (r.first_seq, r.last_seq, len(r), r.used) == (1, 5, 5, 50)
    assert r.get(3) == b"\x03" * 10 and r.get(9) is None
    assert r.release_upto(3) == 3
    assert r.first_seq == 4 and r.used == 20
    assert r.release_upto(100) == 2 and not r and r.first_seq is None


def test_seq_must_be_contiguous():
    r = FrameRing(MIN_CAPACITY)
    r.append(1, b"a")
    with pytest.raises(ValueError):
        r.append(3, b"b")


def test_wraparound_keeps_data_intact():
    cap = MIN_CAPACITY
    r = FrameRing(cap)
    size = cap // 4 - 1000
    frames = {s: bytes([s % 251]) * size for s in range(1, 30)}
    acked = 0
    for s, fr in frames.items():
        ev = r.append(s, fr)
        assert ev == []
        if len(r) > 3:
            acked = r.first_seq
            r.release_upto(acked)
        for k in range(r.first_seq, r.last_seq + 1):
            assert r.get(k) == frames[k]


def test_overflow_evicts_oldest():
    r = FrameRing(MIN_CAPACITY)
    big = b"x" * (MIN_CAPACITY // 3)
    for s in range(1, 4):
        assert r.append(s, big, data_len=len(big), stream_off=(s - 1) * len(big)) == []
    ev = r.append(4, big, data_len=len(big), stream_off=3 * len(big))
    assert [e.seq for e in ev] == [1]
    assert ev[0].stream_off == 0 and ev[0].data_len == len(big)
    assert r.first_seq == 2 and r.get(4) == big


def test_frame_larger_than_buffer_is_reported():
    r = FrameRing(MIN_CAPACITY)
    r.append(1, b"a")
    ev = r.append(2, b"x" * (MIN_CAPACITY + 1), data_len=5, stream_off=9)
    assert [e.seq for e in ev] == [1, 2] and not r


def test_capacity_from_env():
    assert capacity_from_env(None) == 32 << 20
    assert capacity_from_env("4") == 4 << 20
    assert capacity_from_env("0") == 2 << 20
    assert capacity_from_env("x") == 32 << 20
    assert capacity_from_env("99999") == 1024 << 20
