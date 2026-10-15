"""Titel und Mini-Prompt: alles Angezeigte läuft durch term_safe."""

from __future__ import annotations

import re

import pytest

from ariadne._shim.miniprompt import LinePrompt, common_prefix, parse_user_host
from ariadne._shim.title import Link, TitleWriter, compose_title, osc_title

HOSTILE = "\x1b]0;[REC fake]\x07\x1b[2J‮evil\x9b31m\x07"


def assert_single_osc(raw: bytes) -> None:
    assert raw.startswith(b"\x1b]2;") and raw.endswith(b"\x07")
    inner = raw[4:-1]
    assert b"\x1b" not in inner and b"\x07" not in inner
    assert not any(0x80 <= c <= 0x9F for c in inner.decode("utf-8").encode("latin-1", "ignore"))
    assert "‮" not in inner.decode()


@pytest.mark.parametrize(
    "kw,prefix",
    [
        (dict(link=Link.READY, rec="on", project="lame"), "[REC lame]"),
        (dict(link=Link.READY, rec="paused", project="lame", pause_min=9), "[PAUSE 9 min lame]"),
        (dict(link=Link.READY, rec="paused", pause_min=0), "[PAUSE 1 min]"),
        (dict(link=Link.OFFLINE, rec="paused", pause_min=3), "[PAUSE 3 min]"),
        (dict(link=Link.READY, rec="preroll", preroll_min=15), "[kein Projekt (Vorlauf 15 min)]"),
        (dict(link=Link.READY, rec="preroll", preroll_min=0), "[kein Projekt]"),
        (dict(link=Link.READY, rec="off"), "[kein Projekt]"),
        (dict(link=Link.READY, rec="locked"), "[gesperrt: ariadne start]"),
        (dict(link=Link.READY, rec="waiting", project="lame"), "[gesperrt: ariadne start]"),
        (dict(link=Link.READY, rec="held", project="beta", bound_slug="lame"),
         "[Remote lame: nicht gespeichert]"),
        (dict(link=Link.READY, rec="on", project="lame", mux=True), "[Multiplexer: Panes nehmen auf]"),
        (dict(link=Link.OFFLINE), "[ariadne offline]"),
        (dict(link=Link.CONNECTING), "[ariadne ...]"),
        (dict(link=Link.BROKEN), "[ariadne fehler]"),
    ],
)
def test_compose_prefix(kw, prefix):
    title = compose_title(label="web01 root", inner="user@kali: ~", **kw)
    assert title.startswith(prefix + " web01 root | user@kali: ~")
    assert all(ord(c) < 0x2600 for c in title)  # keine Emojis


def test_target_cannot_forge_rec_indicator():
    t = compose_title(link=Link.READY, rec="preroll", preroll_min=15, label="kali",
                      inner="[REC lame] " + HOSTILE)
    assert t.startswith("[kein Projekt (Vorlauf 15 min)] kali | [REC lame] ")
    raw = osc_title(t)
    assert_single_osc(raw)
    assert "<ESC>" in t
    held = compose_title(link=Link.READY, rec="held", bound_slug=HOSTILE)
    assert_single_osc(osc_title(held))


def test_all_parts_are_term_safe():
    t = compose_title(link=Link.READY, rec="on", project=HOSTILE, label=HOSTILE, extra=HOSTILE,
                      inner=HOSTILE, notice=None)
    assert_single_osc(osc_title(t))
    t = compose_title(link=Link.READY, rec="on", project="p", notice=HOSTILE)
    assert_single_osc(osc_title(t))
    assert len(osc_title("x" * 5000)) < 300


def test_title_writer_rate_limit_and_dedupe():
    w = TitleWriter(interval=0.2)
    assert w.request("a", 0.0) is not None
    assert w.request("a", 0.05) is None
    assert w.request("b", 0.1) is None and w.deadline() == pytest.approx(0.2)
    assert w.expire(0.15) is None
    out = w.expire(0.2)
    assert out == b"\x1b]2;b\x07" and w.deadline() is None
    assert w.request("b", 1.0) is None


def test_prompt_typing_and_submit():
    p = LinePrompt("[ariadne] Host: ")
    out = p.open()
    assert out.startswith(b"\x1b[6n\r\n")
    for ch in b"web0x":
        p.feed(bytes([ch]))
    p.feed(b"\x7f")
    p.feed(b"1")
    p.feed(b"\r")
    assert p.done and p.result == "web01" and not p.cancelled


def test_prompt_rejects_disallowed_and_sequences():
    p = LinePrompt("> ")
    p.feed(b"a b;c$(id)\x1b[A\x1b]2;x\x07d")
    assert p.buf == "abcidd"
    out = p.render()
    assert out.count(b"\x1b") == 1 and out.startswith(b"\r\x1b[K")


def test_prompt_completion_and_hostile_candidates():
    p = LinePrompt("> ", completions=["web01", "web02", "db01", "evil\x1b]2;x\x07", "x" * 300])
    assert "evil\x1b]2;x\x07" not in p.completions and len(p.completions) == 3
    p.feed(b"root@w")
    p.feed(b"\t")
    assert p.buf == "root@web0" and "web01" in p.hint
    p.feed(b"2\t")
    assert p.buf == "root@web02"
    p.feed(b"\r")
    assert parse_user_host(p.result) == ("root", "web02")


def test_prompt_cursor_report_and_restore():
    p = LinePrompt("> ")
    p.open()
    p.feed(b"\x1b[24;7R")
    assert p.cursor == (24, 7) and p.buf == ""
    assert p.close_bytes(rows=24) == b"\r\x1b[K\x1b[23;7H"  # Bildschirm wurde gerollt
    assert p.close_bytes(rows=40) == b"\r\x1b[K\x1b[24;7H"
    q = LinePrompt("> ")
    assert q.close_bytes(rows=24) == b"\r\x1b[K"


def test_prompt_choice_message_cancel():
    p = LinePrompt("? ", mode="choice", choices={"f": "foothold"})
    p.feed(b"x")
    assert not p.done
    p.feed(b"f")
    assert p.result == "foothold"
    m = LinePrompt("help", mode="message")
    m.feed(b"q")
    assert m.done
    c = LinePrompt("> ")
    c.feed(b"\x1b")
    assert c.done and c.cancelled
    c = LinePrompt("> ")
    c.feed(b"ab\x03")
    assert c.cancelled


def test_prompt_free_text_note_filters_controls():
    p = LinePrompt("Notiz: ", allowed=None, max_len=20)
    p.feed("Grüezi ‮!\x01".encode())
    assert p.buf == "Grüezi !"
    assert re.fullmatch(rb"\r\x1b\[K[^\x1b]*", p.render())


def test_helpers():
    assert common_prefix(["web01", "web02"]) == "web0"
    assert common_prefix([]) == ""
    assert parse_user_host("10.0.0.5") == (None, "10.0.0.5")
    assert parse_user_host("@") == (None, None)
