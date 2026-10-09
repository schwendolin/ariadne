"""Hotkey-Filter: nur einzeln ankommende Tasten, Bursts und Antworten laufen durch."""

from __future__ import annotations

import pytest

from ariadne._shim.hotkey import (
    PASTE_LOCK_S,
    TIMEOUT_S,
    Armed,
    Cancelled,
    Forward,
    InputFilter,
    Key,
    parse_hotkey,
)

F12 = b"\x1b[24~"


def feed_all(f: InputFilter, chunks, t0=0.0, step=0.2):
    out = []
    t = t0
    for c in chunks:
        out += f.feed(c, t)
        t += step
    return out


@pytest.mark.parametrize(
    "name,expected",
    [(None, b"\x1b[24~"), ("F12", b"\x1b[24~"), ("ctrl-space", b"\x00"), ("ctrl+space", b"\x00"),
     ("ctrl-]", b"\x1d"), ("ctrl-_", b"\x1f"), ("unsinn", b"\x1b[24~")],
)
def test_parse_hotkey(name, expected):
    assert parse_hotkey(name)[1] == expected


def test_f12_alone_then_key():
    f = InputFilter(F12)
    assert feed_all(f, [F12, b"r"]) == [Armed(), Key("r")]


def test_plain_keys_forwarded():
    f = InputFilter(F12)
    assert feed_all(f, [b"l", b"s", b"\r"]) == [Forward(b"l"), Forward(b"s"), Forward(b"\r")]


def test_f12_inside_burst_is_forwarded():
    f = InputFilter(F12)
    burst = b"echo " + F12 + b"r"
    assert f.feed(burst, 0.0) == [Forward(burst)]
    assert f.feed(F12 + b"r", 1.0) == [Forward(F12 + b"r")]


def test_armed_then_burst_cancels_and_forwards():
    f = InputFilter(F12)
    acts = feed_all(f, [F12, b"rm -rf /tmp/x\r"])
    assert acts == [Armed(), Cancelled("burst"), Forward(b"rm -rf /tmp/x\r")]


def test_double_prefix_sends_prefix():
    f = InputFilter(F12)
    assert feed_all(f, [F12, F12]) == [Armed(), Forward(F12)]
    assert not f.armed


def test_timeout_and_escape():
    f = InputFilter(F12)
    assert f.feed(F12, 0.0) == [Armed()]
    assert f.deadline() == TIMEOUT_S
    assert f.expire(TIMEOUT_S - 0.01) == []
    assert f.expire(TIMEOUT_S) == [Cancelled("timeout")]
    assert f.feed(b"r", TIMEOUT_S + 0.1) == [Forward(b"r")]
    assert feed_all(f, [F12, b"\x1b"], t0=10) == [Armed(), Cancelled("esc")]
    assert feed_all(f, [F12, b"\x03"], t0=20) == [Armed(), Cancelled("abort")]


def test_bracketed_paste_blocks_hotkeys_and_locks_after_end():
    f = InputFilter(F12)
    assert f.feed(b"\x1b[200~some text", 0.0) == [Forward(b"\x1b[200~some text")]
    # Mitten im Paste ein einzelner F12-Chunk: kein Hotkey
    assert f.feed(F12, 0.01) == [Forward(F12)]
    assert f.feed(b"more\x1b[201~", 0.02) == [Forward(b"more\x1b[201~")]
    # direkt nach dem Ende gesperrt
    assert f.feed(F12, 0.02 + PASTE_LOCK_S / 2) == [Forward(F12)]
    assert f.feed(F12, 0.02 + PASTE_LOCK_S + 0.01) == [Armed()]


def test_paste_breakout_does_not_arm():
    f = InputFilter(F12)
    evil = b"\x1b[200~harmless\x1b[201~" + F12 + b"r"
    assert f.feed(evil, 0.0) == [Forward(evil)]
    assert f.feed(F12, 0.01) == [Forward(F12)]  # Sperre nach Paste-Ende
    assert f.feed(b"r", 0.02) == [Forward(b"r")]


def test_paste_end_split_across_reads():
    f = InputFilter(F12)
    for i, c in enumerate([b"\x1b[200~abc\x1b[2", b"01", b"~"]):
        f.feed(c, i * 0.001)
    assert not f.tracker.in_paste
    assert f.feed(F12, 1.0) == [Armed()]


@pytest.mark.parametrize(
    "first,second",
    [
        (b"\x1b]11;rgb:0000/0000/00", b"r"),  # OSC-Antwort ohne Ende
        (b"\x1bP1$r0;1m", b"r"),  # DCS-Antwort ohne ST
        (b"\x1b[12;", b"R"),  # CPR zerteilt
    ],
)
def test_split_response_never_triggers(first, second):
    f = InputFilter(F12)
    assert f.feed(F12, 0.0) == [Armed()]
    acts = f.feed(first, 0.01)
    assert acts == [Cancelled("burst"), Forward(first)]
    # Der Rest der Antwort kommt allein, darf aber keine Taste sein
    assert f.feed(second, 0.02) == [Forward(second)]
    # Auch ein Präfix, der mitten in einer offenen Antwort ankommt, zählt nicht
    f2 = InputFilter(F12)
    f2.feed(first, 0.0)
    assert f2.feed(F12, 0.01) == [Forward(F12)]


def test_complete_response_as_single_read_is_burst():
    f = InputFilter(F12)
    for resp in (b"\x1b[24;80R", b"\x1b[?1;2c", b"\x1b]11;rgb:0/0/0\x07", b"\x1bP1$r0m\x1b\\"):
        assert f.feed(resp, 0.0) == [Forward(resp)]
        assert not f.armed


def test_lone_escape_key_does_not_block_prefix():
    f = InputFilter(F12)
    f.feed(b"\x1b", 0.0)
    assert f.feed(F12, 0.01) == [Armed()]


@pytest.mark.parametrize("name", ["ctrl-space", "ctrl-]", "ctrl-_"])
def test_other_prefixes(name):
    _, prefix = parse_hotkey(name)
    f = InputFilter(prefix)
    assert feed_all(f, [prefix, b"k"]) == [Armed(), Key("k")]
    assert f.feed(b"a" + prefix, 5.0) == [Forward(b"a" + prefix)]
