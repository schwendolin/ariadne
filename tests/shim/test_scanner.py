"""Ausgabe-Scanner: Marker, Titel, OSC 52, reflektierende Anfragen, Grenzen."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ariadne._shim.scanner import (
    MAX_HOLD_S,
    MAX_STRING,
    AltScreen,
    Dropped,
    Forged,
    Marker,
    Osc52,
    OutputScanner,
    Title,
)

NONCE = "0123456789abcdef0123456789abcdef"


def scan(data: bytes, now: float = 0.0):
    sc = OutputScanner()
    return sc, sc.feed(data, now)


def scan_split(parts: list[bytes]):
    sc = OutputScanner()
    disp, rec, items = [], [], []
    for p in parts:
        r = sc.feed(p, 0.0)
        disp.append(r.display)
        rec.append(r.record)
        items += r.items
    return b"".join(disp), b"".join(rec), items, sc


def marker(mark: str = "C", fields: str = "cmd=ls", nonce: str = NONCE, ctr: int = 1) -> bytes:
    return f"\x1b]7701;ariadne;v1;{nonce};42:{ctr};{mark};{fields}\x07".encode()


def test_plain_passthrough():
    sc, r = scan(b"hello \xc3\xa4 world\r\n")
    assert r.display == r.record == b"hello \xc3\xa4 world\r\n"
    assert r.items == [] and sc.offset == len(r.record)


def test_sgr_and_common_sequences_pass():
    data = b"\x1b[31mred\x1b[0m\x1b[2J\x1b[H\x1b(B\x1b7\x1b8\x1b[?25l"
    _, r = scan(data)
    assert r.display == r.record == data


def test_marker_removed_from_display_and_record():
    sc, r = scan(b"ab" + marker() + b"cd")
    assert r.display == r.record == b"abcd"
    assert r.items == [Marker(f"7701;ariadne;v1;{NONCE};42:1;C;cmd=ls".encode(), 2)]
    assert sc.offset == 4


def test_marker_with_st_terminator_and_forged_nonce_also_removed():
    data = b"x\x1b]7701;ariadne;v1;ffffffffffffffffffffffffffffffff;1:1;D;exit=0\x1b\\y"
    _, r = scan(data)
    assert r.display == b"xy"
    assert isinstance(r.items[0], Marker)  # Prüfung der Nonce macht der Validator


def test_foreign_osc133_passes_unchanged():
    data = b"\x1b]133;A\x07$ \x1b]133;D;0\x1b\\"
    _, r = scan(data)
    assert r.display == r.record == data and r.items == []


def test_title_intercepted_but_recorded():
    data = b"a\x1b]0;user@kali: ~\x07b\x1b]2;vim\x1b\\c"
    _, r = scan(data)
    assert r.display == b"abc"
    assert r.record == data
    assert [i.text for i in r.items if isinstance(i, Title)] == [b"user@kali: ~", b"vim"]


def test_icon_title_osc1_passes():
    _, r = scan(b"\x1b]1;icon\x07")
    assert r.display == b"\x1b]1;icon\x07"


def test_osc52_set_and_query_removed():
    _, r = scan(b"a\x1b]52;c;Y3VybCBldmlsIHwgc2g=\x07b\x1b]52;c;?\x07c")
    assert r.display == r.record == b"abc"
    o = [i for i in r.items if isinstance(i, Osc52)]
    assert [x.query for x in o] == [False, True]
    assert o[0].length == len(b"\x1b]52;c;Y3VybCBldmlsIHwgc2g=\x07")


def test_reflective_queries_removed():
    for q in (b"\x1b[20t", b"\x1b[21t", b"\x1b[8;100;200t", b"\x1b[021t", b"\x1b[21;0t",
              b"\x1bP$qm\x1b\\", b"\x1bP$q\"p\x07", b"\x1bP1$qm\x1b\\"):
        _, r = scan(b"a" + q + b"b")
        assert r.display == r.record == b"ab", q
        assert any(isinstance(i, Dropped) for i in r.items), q


def test_reflective_query_with_embedded_c0_removed():
    # VT500-Parser führen C0 mitten in CSI aus und setzen die Sequenz fort.
    for q in (b"\x1b[2\n1t", b"\x1b\r[21t", b"\x1b\n]52;c;?\x07"):
        _, r = scan(b"a" + q + b"b")
        assert r.display == b"ab", q


def test_title_stack_only_hidden_from_display():
    _, r = scan(b"\x1b[22;0t\x1b[23;0t")
    assert r.display == b""
    assert r.record == b"\x1b[22;0t\x1b[23;0t"


def test_harmless_queries_kept():
    data = b"\x1b[c\x1b[>c\x1b[6n\x1b[5n\x1b]10;?\x07\x1b]11;?\x1b\\\x1b]4;1;?\x07\x1b[18t\x1bP+q544e\x1b\\"
    _, r = scan(data)
    assert r.display == r.record == data


def test_alt_screen_tracking():
    sc, r = scan(b"\x1b[?1049h")
    assert sc.alt_screen and r.items == [AltScreen(True, 0)]
    r = sc.feed(b"vim\x1b[?1049l", 0)
    assert not sc.alt_screen and r.items == [AltScreen(False, 8 + 3)]
    r = sc.feed(b"\x1b[?47h\x1b[?1047l\x1b[?2004;1049h", 0)
    assert sc.alt_screen and [i.on for i in r.items] == [True, False, True]


def test_offsets_count_recorded_bytes_only():
    sc, r = scan(b"12" + marker() + b"34\x1b]52;c;x\x0756" + marker(ctr=2) + b"7")
    assert r.record == b"1234567"
    offs = [i.stream_off for i in r.items]
    assert offs == [2, 4, 6] and sc.offset == 7


def test_split_marker_across_chunks():
    data = b"ab" + marker() + b"cd"
    for cut in range(1, len(data)):
        disp, rec, items, _ = scan_split([data[:cut], data[cut:]])
        assert disp == rec == b"abcd", cut
        assert len(items) == 1 and isinstance(items[0], Marker)


def test_lone_esc_held_until_next_chunk():
    sc = OutputScanner()
    r1 = sc.feed(b"abc\x1b", 0.0)
    assert r1.display == b"abc" and sc.pending() == 1
    r2 = sc.feed(b"[31mx", 0.01)
    assert r2.display == b"\x1b[31mx"


def test_oversize_marker_is_forged_and_passed_as_plain():
    body = b"\x1b]7701;ariadne;v1;" + b"a" * (MAX_STRING + 100)
    sc, r = scan(body)
    assert any(isinstance(i, Forged) and i.reason == "oversize" for i in r.items)
    assert r.display == body  # als normale Bytes weiter
    assert sc.pending() == 0


def test_oversize_generic_osc_passed_through():
    body = b"\x1b]8;;" + b"u" * (MAX_STRING + 10) + b"\x07tail"
    _, r = scan(body)
    assert r.display == body


def test_timeout_releases_partial_sequence():
    sc = OutputScanner()
    r = sc.feed(b"x\x1b]2;never ending", 1.0)
    assert r.display == b"x" and sc.deadline() == 1.0 + MAX_HOLD_S
    assert sc.expire(1.05).display == b""
    r = sc.expire(1.0 + MAX_HOLD_S)
    assert r.display == b"\x1b]2;never ending" and sc.pending() == 0


def test_timeout_on_partial_marker_reports_forged():
    sc = OutputScanner()
    sc.feed(b"\x1b]7701;ariadne;v1;", 0.0)
    r = sc.expire(1.0)
    assert [i.reason for i in r.items if isinstance(i, Forged)] == ["malformed"]


def test_aborted_strings():
    _, r = scan(b"a\x1b]8;;x\x1b[31mb")  # ESC bricht ab, CSI danach gilt
    assert r.display == b"a\x1b]8;;x\x1b[31mb"
    _, r = scan(b"a\x1b]7701;ariadne\x1b[31mb")
    assert r.display == b"a\x1b[31mb"
    assert [i.reason for i in r.items if isinstance(i, Forged)] == ["malformed"]
    _, r = scan(b"a\x1b]2;t\x18b")  # CAN
    assert r.display == b"a\x1b]2;t\x18b" and not any(isinstance(i, Title) for i in r.items)


CORPUS = (
    b"pre\x1b[1;32mgreen\x1b[0m"
    + marker("A", "cwd=/root")
    + b"\x1b]0;root@kali: ~\x07$ ls\r\n"
    + marker("C", "cmd=ls%20-la&cwd=/root", ctr=2)
    + b"\x1b]133;C\x07file\r\n\x1b]52;c;ZXZpbA==\x07\x1b[21t\x1b[?1049hvim\x1b[?1049l"
    + b"\x1bP$qm\x1b\\\x1b]7701;broken\x1b[0m"
    + marker("D", "exit=0&pipestatus=0", ctr=3)
    + b"\xe2\x82\xac end\x1b"
)


@settings(max_examples=150, deadline=None)
@given(st.lists(st.integers(min_value=0, max_value=len(CORPUS)), max_size=12))
def test_chunk_boundaries_do_not_matter(cuts):
    _, ref = scan(CORPUS)
    ref_sc = OutputScanner()
    ref = ref_sc.feed(CORPUS, 0.0)
    pts = sorted(set(cuts))
    parts, prev = [], 0
    for c in pts:
        parts.append(CORPUS[prev:c])
        prev = c
    parts.append(CORPUS[prev:])
    disp, rec, items, sc = scan_split(parts)
    assert (disp, rec, items) == (ref.display, ref.record, ref.items)
    assert sc.offset == ref_sc.offset and sc.pending() == ref_sc.pending()
