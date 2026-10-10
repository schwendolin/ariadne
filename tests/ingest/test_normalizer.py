"""Normalizer: Goldens mit echten Bytes, Einzelfälle und metamorphe Tests (Architektur 5.5)."""

from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ariadne.ingest.normalizer import (
    FLAG_ALTSCREEN,
    FLAG_CONCEALED,
    FLAG_OVERWRITTEN,
    FLAG_PROMPT,
    MAX_STRING,
    MAX_UP,
    Normalizer,
    NormLine,
    colmap_from_json,
    colmap_lookup,
    colmap_to_json,
    normalize,
    sgr_from_json,
    sgr_to_json,
)

GOLDEN = Path(__file__).parent / "golden_normalizer"
CASES = sorted(p.name for p in GOLDEN.iterdir() if (p / "input.bin").exists())
UPDATE = os.environ.get("ARIADNE_UPDATE_GOLDEN") == "1"
_OSC133 = re.compile(rb"\x1b\]133;([ACD])[^\x07]*\x07")


def _marks(data: bytes, mode: str) -> list[tuple[int, str]]:
    if mode != "osc133":
        return []
    return [(m.end(), m.group(1).decode()) for m in _OSC133.finditer(data)]


def run_golden(data: bytes, meta: dict, cuts: list[int] | None = None) -> list[NormLine]:
    """Wie der Segmenter: Grenzen an den Markern (A = D + A wie in init.zsh), Bytes in Stücken."""
    n = Normalizer(0, cols=meta.get("cols", 80), rows=meta.get("rows", 24))
    marks = dict(_marks(data, meta.get("marks", "none")))
    points = sorted(set(marks) | set(cuts or []) | {len(data)})
    pos = 0
    for p in points:
        if p > pos:
            n.feed(data[pos:p])
            pos = p
        k = marks.get(p)
        if k == "A":
            n.boundary(p, prompt=True, eol_mark=True)
        elif k == "C":
            n.boundary(p, prompt=False)
        elif k == "D":
            n.boundary(p, prompt=False, eol_mark=True)
    return n.finish()


def _dump(lines: list[NormLine]) -> list[dict]:
    return [
        {"text": ln.text, "raw": [ln.raw_start, ln.raw_end], "flags": ln.flags,
         "sgr": json.loads(sgr_to_json(ln.sgr) or "[]"), "colmap": list(ln.colmap)}
        for ln in lines
    ]


def _load(case: str) -> tuple[bytes, dict]:
    d = GOLDEN / case
    return (d / "input.bin").read_bytes(), tomllib.loads((d / "meta.toml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES)
def test_golden(case):
    data, meta = _load(case)
    got = _dump(run_golden(data, meta))
    exp_path = GOLDEN / case / "expected.json"
    if UPDATE or not exp_path.exists():
        exp_path.write_text(json.dumps(got, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        if not UPDATE:
            pytest.fail(f"expected.json für {case} fehlte und wurde geschrieben; bitte prüfen")
    assert got == json.loads(exp_path.read_text(encoding="utf-8"))


def test_golden_expectations_make_sense():
    """Stichproben in den Goldens, damit ein falsches expected.json auffällt."""
    zsh = _dump(run_golden(*_load("zsh_highlight")))
    texts = [(d["text"], d["flags"]) for d in zsh]
    assert ("kali@kali:~$ nmap -sV 10.10.10.3", FLAG_PROMPT | FLAG_OVERWRITTEN) in texts
    assert ("no newline at end", 0) in texts  # PROMPT_SP-Markierung entfernt
    assert ("Nmap scan report for 10.10.10.3", 0) in texts
    assert not any("mmap" in t or "scans/lame" in t for t, _ in texts)  # Vorschlag nicht im Text
    gob = [d["text"] for d in _dump(run_golden(*_load("gobuster_progress")))]
    assert "/admin                (Status: 301) [Size: 312] [--> http://10.10.10.3/admin/]" in gob
    assert sum(t.startswith("Progress:") for t in gob) == 1
    win = [d["text"] for d in _dump(run_golden(*_load("winpeas_crlf")))]
    assert "    DefaultPassword               :  P@ssw0rd2024!" in win
    assert all("\r" not in t for t in win)
    lp = _dump(run_golden(*_load("linpeas_colors")))
    pk = next(d for d in lp if "/usr/bin/pkexec" in d["text"])
    assert any(s.get("fg") == "red" and s.get("bg") == "bright_yellow" for s in pk["sgr"])
    alt = _dump(run_golden(*_load("less_alt")))
    assert alt and all(d["flags"] & FLAG_ALTSCREEN for d in alt)
    conc = _dump(run_golden(*_load("concealed_text")))
    assert [bool(d["flags"] & FLAG_CONCEALED) for d in conc] == [True] * 5 + [False]


# --------------------------------------------------------------------------- metamorph

_INTERESTING = st.sampled_from([
    b"a", b"xyz ", b"\r\n", b"\n", b"\r", b"\x08", b"\t", b"\x1b[31m", b"\x1b[0m", b"\x1b[K", b"\x1b[2K",
    b"\x1b[1K", b"\x1b[3D", b"\x1b[5C", b"\x1b[10G", b"\x1b[A", b"\x1b[2A", b"\x1b]0;title\x07",
    b"\x1b]8;;http://x\x1b\\", b"\x1bP1$r\x1b\\", b"\x1b_apc\x1b\\", b"\xc3\xa4", b"\xe2\x82\xac",
    b"\xf0\x9f\x94\x91",
    b"\xff", b"\xc3", b"\x1b[38;5;196m", b"\x1b[38;2;1;2;3m", b"\x1b[8m", b"\x1b[28m", b"\x1b[30;40m",
    b"\x1b[?1049h", b"\x1b[?1049l", b"\x1b7", b"\x1b8", b"\x1b[s", b"\x1b[u", b"\x1b[P", b"\x1b[@", b"\x1b[X",
    b"\x1b[J", b"\x1b[H", b"\x1b(B", b"\x18", b"\x1b", b"\x1b[", b"0123456789" * 3,
])


def _feed_chunks(data: bytes, cuts: list[int], cols: int, start: int = 0) -> list[NormLine]:
    n = Normalizer(start, cols=cols)
    pos = 0
    for c in sorted(set(cuts)):
        if 0 < c < len(data):
            n.feed(data[pos:c])
            pos = c
    n.feed(data[pos:])
    return n.finish()


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_INTERESTING, max_size=60), st.lists(st.integers(0, 2000), max_size=12),
       st.sampled_from([0, 7, 80]))
def test_metamorphic_chunk_boundaries(parts, cuts, cols):
    data = b"".join(parts)
    whole = _dump(normalize(data, cols=cols))
    assert _dump(_feed_chunks(data, cuts, cols)) == whole
    assert _dump(_feed_chunks(data, list(range(len(data))), cols)) == whole  # Byte für Byte


@settings(max_examples=40, deadline=None)
@given(st.sampled_from(CASES), st.lists(st.integers(0, 4000), max_size=20))
def test_metamorphic_goldens(case, cuts):
    data, meta = _load(case)
    assert _dump(run_golden(data, meta, cuts)) == _dump(run_golden(data, meta))


@settings(max_examples=60, deadline=None)
@given(st.lists(_INTERESTING, max_size=40))
def test_offsets_stay_in_range(parts):
    data = b"".join(parts)
    for ln in normalize(data, 1000, cols=80):
        assert 1000 <= ln.raw_start <= ln.raw_end <= 1000 + len(data)
        for col in range(len(ln.text)):
            raw = ln.col_to_raw(col) if ln.colmap else None
            if raw is not None:
                assert 1000 <= raw < 1000 + len(data)


# --------------------------------------------------------------------------- Einzelfälle


def texts(data: bytes, **kw) -> list[str]:
    return [ln.text for ln in normalize(data, **kw)]


def test_crlf_and_offsets_absolute():
    lines = normalize(b"one\r\ntwo\r\n", 500)
    assert [(ln.text, ln.raw_start, ln.raw_end) for ln in lines] == [("one", 500, 505), ("two", 505, 510)]
    assert lines[1].col_to_raw(0) == 505 and lines[1].col_to_raw(2) == 507


def test_cr_overwrites_from_column_zero():
    lines = normalize(b"10%\r50%\rdone\r\n")
    assert lines[0].text == "done" and lines[0].overwritten


def test_cr_same_text_is_not_overwritten():
    assert not normalize(b"abc\rabc\r\n")[0].overwritten


def test_backspace_and_erase():
    assert texts(b"abc\x08\x08X\r\n") == ["aXc"]
    assert texts(b"abcdef\x1b[3D\x1b[K\r\n") == ["abc"]
    assert texts(b"abcdef\x1b[3D\x1b[1K\r\n") == ["    ef"]
    assert texts(b"abcdef\x1b[2K\rxy\r\n") == ["xy"]


def test_horizontal_moves():
    assert texts(b"abc\x1b[5GX\r\n") == ["abc X"]
    assert texts(b"abcdef\x1b[10D\x1b[2CZ\r\n") == ["abZdef"]
    assert texts(b"a\tb\r\n") == ["a       b"]


def test_cursor_up_rewrites_previous_lines_up_to_limit():
    data = b"".join(b"line%d\r\n" % i for i in range(10)) + b"\x1b[3AX\r\n"
    lines = normalize(data)
    assert lines[7].text == "Xine7" and lines[7].overwritten
    many = b"".join(b"l%d\r\n" % i for i in range(MAX_UP + 20)) + b"\x1b[200AY"
    out = normalize(many)
    assert out[19].text == f"l{19}"  # ausserhalb des Fensters unverändert
    assert out[20].text.startswith("Y")


def test_wrap_emulation_with_known_width():
    # 100 Zeichen bei 40 Spalten: \r springt an den Anfang der physischen Zeile (Index 80)
    assert texts(b"x" * 100 + b"\rAB\r\n", cols=40) == ["x" * 80 + "AB" + "x" * 18]
    # genau volle Zeile: Umbruch steht aus, \r bleibt in derselben physischen Zeile
    assert texts(b"y" * 40 + b"\rZ\r\n", cols=40) == ["Z" + "y" * 39]
    # ohne bekannte Breite: \r an den Anfang der logischen Zeile
    assert texts(b"x" * 100 + b"\rAB\r\n") == ["AB" + "x" * 98]


def test_eol_mark_of_zsh_prompt_sp():
    mark = b"\x1b[1m\x1b[7m%\x1b[27m\x1b[1m\x1b[0m" + b" " * 79 + b"\r \r"
    n = Normalizer(0, cols=80)
    n.feed(b"flag{abc}" + mark)
    n.boundary(prompt=True, eol_mark=True)
    n.feed(b"$ ")
    lines = n.finish()
    assert [(ln.text, ln.prompt_echo) for ln in lines] == [("flag{abc}", False), ("$", True)]
    # ohne Markierung bleibt ein echtes Prozentzeichen
    n = Normalizer(0, cols=80)
    n.feed(b"100%")
    n.boundary(eol_mark=True)
    assert n.finish()[0].text == "100%"


def test_sgr_spans():
    line = normalize(b"\x1b[1;31mA\x1b[0mB\x1b[38;5;208mC\x1b[38;2;10;20;30mD"
                     b"\x1b[38:2::1:2:3mE\x1b[92;44mF\r\n")[0]
    assert line.text == "ABCDEF"
    spans = {(s.col_start, s.fg, s.bg, s.bold) for s in line.sgr}
    assert (0, "red", None, True) in spans
    assert (2, "#ff8700", None, False) in spans
    assert (3, "#0a141e", None, False) in spans
    assert (4, "#010203", None, False) in spans
    assert (5, "bright_green", "blue", False) in spans
    assert sgr_from_json(sgr_to_json(line.sgr)) == line.sgr


def test_concealed_variants():
    assert normalize(b"\x1b[8mx\x1b[0m\r\n")[0].concealed
    assert normalize(b"\x1b[34;44mx\x1b[0m\r\n")[0].concealed
    assert not normalize(b"\x1b[34;104mx\x1b[0m\r\n")[0].concealed
    assert not normalize(b"\x1b[8m   \x1b[0mx\r\n")[0].concealed  # nur Leerzeichen verdeckt


def test_strings_are_removed():
    data = b"a\x1b]0;evil title\x07b\x1b]8;;http://x\x1b\\c\x1bPq#0;2;0;0;0\x1b\\d\x1b_x\x1b\\e\x1b^pm\x1b\\f\x1bXsos\x1b\\g"
    assert texts(data) == ["abcdefg"]


def test_overlong_osc_becomes_text():
    data = b"\x1b]0;" + b"A" * (MAX_STRING + 10) + b"\x07tail"
    line = normalize(data)[0]
    rest = line.text[:-4]  # nach 8 KiB ist der Rest Text, BEL wird ignoriert
    assert line.text.endswith("tail") and set(rest) == {"A"} and 10 <= len(rest) <= 16


def test_can_aborts_sequence():
    assert texts(b"\x1b[31\x18x\r\n") == ["x"]


def test_alt_screen_final_picture_only():
    data = b"before\r\n\x1b[?1049h\x1b[H\x1b[2Jsecret first\x1b[H\x1b[2Jfinal view\x1b[?1049lafter\r\n"
    lines = normalize(data, cols=80)
    assert [(ln.text, bool(ln.flags & FLAG_ALTSCREEN)) for ln in lines] == [
        ("before", False), ("final view", True), ("after", False)]


def test_alt_screen_closed_by_boundary():
    n = Normalizer(0, cols=40, rows=5)
    n.feed(b"\x1b[?1049hhello")
    n.boundary()
    n.feed(b"next\r\n")
    lines = n.finish()
    assert [(ln.text, ln.flags & FLAG_ALTSCREEN) for ln in lines] == [("hello", FLAG_ALTSCREEN), ("next", 0)]


def test_hostile_pyte_input_does_not_crash():
    junk = b"\x1b[?1049h" + b"\x1b[99999999999;99999999999H" + b"\x1b[9999999L\x1b[<1;2;3M\x1b[99999@x" \
        + bytes(range(256)) * 4 + b"\x1b[?1049l"
    normalize(junk, cols=80, rows=24)


def test_prompt_flag_via_boundaries():
    n = Normalizer(0)
    n.feed(b"out\r\n")
    n.boundary(prompt=True)
    n.feed(b"$ ls\r\n")
    n.boundary(prompt=False)
    n.feed(b"file\r\n")
    got = [(ln.text, ln.prompt_echo) for ln in n.finish()]
    assert got == [("out", False), ("$ ls", True), ("file", False)]


def test_gap_via_offset_jump():
    n = Normalizer(0)
    n.feed(b"abc")
    n.feed(b"def\r\n", 100)
    lines = n.finish()
    assert [(ln.text, ln.raw_start) for ln in lines] == [("abc", 0), ("def", 100)]
    with pytest.raises(ValueError):
        n2 = Normalizer(10)
        n2.feed(b"x", 5)


def test_pending_and_final_offset():
    n = Normalizer(0)
    n.feed(b"done\r\nopen line")
    assert [ln.text for ln in n.take_final()] == []
    assert [ln.text for ln in n.pending()] == ["done", "open line"]
    assert n.final_off == 0
    n.feed(b"".join(b"x\r\n" for _ in range(MAX_UP + 5)))
    final = n.take_final()
    assert final[0].text == "done" and n.final_off > 0


def test_utf8_split_across_chunks():
    n = Normalizer(0)
    for b in b"\xe2\x82\xac\xf0\x9f\x94\x91\r\n":
        n.feed(bytes([b]))
    line = n.finish()[0]
    assert line.text == "€🔑" and line.col_to_raw(1) == 3


def test_colmap_roundtrip_and_lookup():
    line = normalize(b"\x1b[31mab\x1b[0mcd\r\n", 10)[0]
    assert [line.col_to_raw(i) for i in range(4)] == [15, 16, 21, 22]
    cm = colmap_from_json(colmap_to_json(line.colmap))
    assert colmap_lookup(cm, 3) == 12 and colmap_lookup(cm, 9) is None


def test_overwritten_by_erase_flag():
    assert normalize(b"secret\r\x1b[2K\r\n") == [] or not normalize(b"secret\r\x1b[2K\r\n")[0].text
    assert normalize(b"secret\r\x1b[2Kshown\r\n")[0].overwritten
    assert not normalize(b"\x1b[2Kshown\r\n")[0].overwritten


@pytest.mark.parametrize("flag", [FLAG_PROMPT, FLAG_CONCEALED, FLAG_OVERWRITTEN])
def test_line_conversion_keeps_flags(flag):
    nl = NormLine("x", 0, 1, (), flag, ())
    ln = nl.to_line()
    assert (ln.prompt_echo, ln.concealed, ln.overwritten) == (
        bool(flag & FLAG_PROMPT), bool(flag & FLAG_CONCEALED), bool(flag & FLAG_OVERWRITTEN))


@pytest.mark.parametrize("cols", [0, 80])
@pytest.mark.parametrize("data", [
    b"x" + b"\x1b[65535b" * 2000,
    b"\x1b[16000Cx\r\n" * 2000,
    b"x\x1b[60000@\r\n" * 2000,
    b"\x1b[9999;9999Hx" * 2000,
    b"\t" * 20000 + b"x",
])
def test_hostile_amplification_is_bounded(data, cols):
    total = sum(len(ln.text) for ln in normalize(data, cols=cols))
    assert total <= 40 * len(data)
