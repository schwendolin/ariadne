"""Bündelung der Eingaben (E26): Enter, Ctrl-C/D, Paste als ein Rahmen, 4 KiB, 1 s, Zeitindex."""

from __future__ import annotations

from ariadne._shim import protocol as P
from ariadne._shim.inputrec import INPUT_MAX, PASTE_MAX, InputRecorder

MS = 1_000_000


def make() -> tuple[InputRecorder, list[dict]]:
    out: list[dict] = []

    def emit(data, off, out_end, wall, mono, tix, paste):
        out.append({"data": data, "off": off, "out_end": out_end, "wall": wall, "mono": mono, "tix": tix,
                    "paste": paste})

    return InputRecorder(emit), out


def test_bundles_until_enter_with_time_index_and_offsets():
    r, out = make()
    r.feed(b"i", 10, 1000 * MS, 50 * MS, 0.0)
    r.feed(b"d", 11, 1000 * MS + 300_000, 50 * MS + 300_000, 0.0)  # < 1 ms: kein Eintrag
    r.feed(b"\r", 12, 1002 * MS, 52 * MS, 0.0)
    assert out == [{"data": b"id\r", "off": 10, "out_end": 12, "wall": 1000 * MS, "mono": 50 * MS,
                    "tix": ((2, 2000),), "paste": False}]
    assert not r and r.deadline() is None


def test_terminators_split_and_keep_rest():
    r, out = make()
    r.feed(b"ls\nwhoami\x03rest", 0, 1, 1, 0.0)
    assert [o["data"] for o in out] == [b"ls\n", b"whoami\x03"]
    assert bytes(r.buf) == b"rest"
    r.feed(b"\x04", 5, 2 * MS, 2 * MS, 0.1)
    assert out[-1]["data"] == b"rest\x04"


def test_bracketed_paste_is_one_frame_even_with_newlines():
    r, out = make()
    r.feed(b"echo ", 0, 1, 1, 0.0)
    r.feed(b"\x1b[200~a\nb\r", 0, 2 * MS, 2 * MS, 0.1)
    assert [o["data"] for o in out] == [b"echo "]
    r.feed(b"c\x1b[201~\r", 0, 4 * MS, 4 * MS, 0.2)
    assert out[1] == {"data": b"\x1b[200~a\nb\rc\x1b[201~", "off": 0, "out_end": 0, "wall": 2 * MS,
                      "mono": 2 * MS, "tix": ((10, 2000),), "paste": True}
    assert out[2]["data"] == b"\r" and out[2]["paste"] is False


def test_paste_marker_split_across_reads():
    r, out = make()
    r.feed(b"\x1b[20", 0, 1, 1, 0.0)
    r.feed(b"0~x\ny\x1b[2", 0, 1, 1, 0.0)
    r.feed(b"01~", 0, 1, 1, 0.0)
    assert [(o["data"], o["paste"]) for o in out] == [(b"\x1b[200~x\ny\x1b[201~", True)]


def test_size_and_time_limits():
    r, out = make()
    r.feed(b"a" * (INPUT_MAX + 10), 0, 1, 1, 0.0)
    assert len(out) == 1 and len(out[0]["data"]) == INPUT_MAX + 10
    r.feed(b"xy", 0, 1, 1, 5.0)
    assert r.deadline() == 6.0
    r.expire(5.9)
    assert len(out) == 1
    r.expire(6.0)
    assert out[-1]["data"] == b"xy"
    # Paste ohne Ende: Notbremse nach 2 s Ruhe, als Paste markiert
    r.feed(b"\x1b[200~" + b"z" * 100, 0, 1, 1, 10.0)
    assert r.deadline() == 12.0
    r.expire(12.0)
    assert out[-1]["paste"] and out[-1]["data"].endswith(b"z" * 100) and not r.paste
    r.feed(b"\x1b[200~" + b"q" * PASTE_MAX, 0, 1, 1, 20.0)
    assert out[-1]["paste"] and len(out[-1]["data"]) == PASTE_MAX + 6


def test_time_index_is_valid_protocol():
    r, out = make()
    for i in range(50):
        r.feed(b"k", i, i * 2 * MS, i * 2 * MS, 0.0)
    r.feed(b"\r", 50, 100 * MS, 100 * MS, 0.0)
    frame = P.encode_input(1, out[0]["off"], out[0]["out_end"], out[0]["wall"], out[0]["mono"],
                           out[0]["data"], out[0]["tix"])
    dec = P.decode_input(P.FrameDecoder().feed(frame)[0].payload)
    assert len(dec.tix) == 50 and dec.tix[-1] == (50, 100_000) and dec.out_end == 50


def test_flush_and_drop():
    r, out = make()
    r.feed(b"geheim", 0, 1, 1, 0.0)
    r.drop()
    assert not r and out == []
    r.feed(b"x", 0, 1, 1, 0.0)
    r.flush()
    assert out[-1]["data"] == b"x"
