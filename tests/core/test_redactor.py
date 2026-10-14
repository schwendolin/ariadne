"""Redaktor: längenerhaltend, über Chunk-Grenzen, auf der Sicht ohne ANSI-Sequenzen."""

from __future__ import annotations

import json
from urllib.parse import quote

from hypothesis import given, settings
from hypothesis import strategies as st

from ariadne.secrets.redactor import Redactor, scan_outgoing

SECRET = "Sudo-Geheim-4711"


def feed_all(r: Redactor, chunks: list[bytes], tid: str = "t", start: int = 0) -> list:
    out = []
    off = start
    for c in chunks:
        out += r.feed(tid, off, c)
        off += len(c)
    out += r.flush(tid)
    return out


def joined(out: list[tuple[int, bytes, list]], start: int = 0) -> bytes:
    data = b""
    for off, chunk, _ in out:
        assert off == start + len(data), "Offsets müssen lückenlos sein"
        data += chunk
    return data


def stars(n: int) -> bytes:
    return b"*" * n


def test_literal_single_chunk():
    r = Redactor([("sudo", SECRET)])
    out = feed_all(r, [f"pw: {SECRET}\r\n".encode()], start=100)
    assert joined(out, 100) == b"pw: " + stars(len(SECRET)) + b"\r\n"
    reds = [x for _, _, rs in out for x in rs]
    assert [(x.label, x.start, x.end) for x in reds] == [("sudo", 104, 104 + len(SECRET))]


def test_url_and_json_variants():
    secret = 'p@ss "wort"/1'
    r = Redactor([("web", secret)])
    url = quote(secret, safe="").encode()
    js = json.dumps(secret)[1:-1].encode()
    data = b"GET /login?pw=" + url + b" body={\"pw\":\"" + js + b"\"}"
    out = joined(feed_all(r, [data]))
    assert url not in out and js not in out
    assert len(out) == len(data)
    assert out.count(b"*") == len(url) + len(js)


def test_split_across_chunks_every_position():
    data = f"echo {SECRET} fertig".encode()
    expected = b"echo " + stars(len(SECRET)) + b" fertig"
    for cut in range(1, len(data)):
        r = Redactor([("sudo", SECRET)])
        assert joined(feed_all(r, [data[:cut], data[cut:]])) == expected, cut


def test_ansi_interleaved_echo_from_syntax_highlighting():
    # zsh-syntax-highlighting färbt jedes Zeichen einzeln und setzt den Cursor zurück
    parts = [f"\x1b[32m{c}\x1b[39m".encode() for c in SECRET]
    data = b"$ mysql -p" + b"".join(parts) + b"\x1b]0;titel\x07\r\n"
    r = Redactor([("db", SECRET)])
    out = feed_all(r, [data[:17], data[17:40], data[40:]])
    result = joined(out)
    assert len(result) == len(data)
    start = data.index(parts[0]) + len(b"\x1b[32m")  # ab dem ersten Zeichen des Secrets
    end = len(b"$ mysql -p") + len(b"".join(parts)) - len(b"\x1b[39m")
    assert result[start:end] == stars(end - start)
    assert result[:start] == data[:start] and result[end:] == data[end:]
    reds = [x for _, _, rs in out for x in rs]
    assert [(x.start, x.end) for x in reds] == [(start, end)]


def test_incomplete_escape_at_chunk_end_is_held():
    r = Redactor([("sudo", SECRET)])
    a = b"vorher \x1b[3"  # CSI noch offen
    b_ = b"1m" + SECRET.encode() + b"\x1b[0m nachher"
    out = joined(feed_all(r, [a, b_]))
    assert SECRET.encode() not in out and out.startswith(b"vorher \x1b[31m")


def test_short_secrets_ignored_and_no_hold_without_secrets():
    r = Redactor([("kurz", "abc"), ("leer", "")])
    assert not r.active
    assert r.feed("t", 0, b"abc abc") == [(0, b"abc abc", [])]
    assert r.pending("t") is None


def test_hold_back_only_possible_secret_start_and_flush():
    r = Redactor([("sudo", SECRET)])
    out = r.feed("t", 0, b"0123456789" * 3)
    assert sum(len(c) for _, c, _ in out) == 30 and r.pending("t") is None  # nichts kann ein Secret sein
    out = r.feed("t", 30, b"pw: " + SECRET[:7].encode())
    emitted = 30 + sum(len(c) for _, c, _ in out)
    assert emitted == 34 and r.pending("t") == (34, 7)  # nur "Sudo-Ge" wartet
    rest = r.flush("t")
    assert rest[0][0] == emitted and r.pending("t") is None


def test_idle_flush_keeps_secret_prefix():
    """Pause beim Tippen (über 10 s): der Anfang des Secrets darf nicht frei werden."""
    r = Redactor([("sudo", SECRET)])
    out = r.feed("t", 0, b"$ mysql -u root -p" + SECRET[:7].encode())
    out += r.flush("t", keep_prefix=True)
    assert r.pending("t") == (18, 7)
    out += r.feed("t", 25, SECRET[7:].encode() + b"\r\n")
    out += r.flush("t")
    assert joined(out) == b"$ mysql -u root -p" + stars(len(SECRET)) + b"\r\n"
    r2 = Redactor([("sudo", SECRET)])
    out = r2.feed("t", 0, b"abc\x1b[3")  # unvollständige Sequenz: im Leerlauf frei
    out += r2.flush("t", keep_prefix=True)
    assert joined(out) == b"abc\x1b[3" and r2.pending("t") is None


def test_secret_inside_osc_title_and_hyperlink():
    r = Redactor([("own", "hunter2-Secret")])
    data = b"\x1b]2;curl -u admin:hunter2-Secret http://x\x07ok \x1b]8;;http://h/?t=hunter2-Secret\x1b\\x"
    res = joined(feed_all(r, [data[:20], data[20:]]))
    assert b"hunter2-Secret" not in res and len(res) == len(data)
    assert res.startswith(b"\x1b]2;curl -u admin:**************") and res.endswith(b"\x1b\\x")


def test_discontinuity_flushes_old_state():
    r = Redactor([("sudo", SECRET)])
    out = r.feed("t", 0, b"abc" + SECRET[:5].encode())
    out += r.feed("t", 1000, SECRET[5:].encode() + b"xyz")  # Lücke: kein Treffer über die Lücke
    out += r.flush("t")
    assert sum(len(c) for _, c, _ in out) == 3 + len(SECRET) + 3
    assert [o for o, _, _ in out][-1] >= 1000


def test_overlapping_and_repeated_hits():
    r = Redactor([("a", "geheim-geheim"), ("b", "heim-gehe")])
    data = b"x geheim-geheim y geheim-geheim z"
    out = feed_all(r, [data])
    res = joined(out)
    assert res == b"x " + stars(13) + b" y " + stars(13) + b" z"
    assert len([x for _, _, rs in out for x in rs]) == 2


def test_terminals_are_independent():
    r = Redactor([("sudo", SECRET)])
    s = SECRET.encode()
    out1 = r.feed("t1", 0, s[:6])
    out2 = r.feed("t2", 0, s[6:])
    out1 += r.feed("t1", 6, s[6:])
    out1 += r.flush("t1")
    out2 += r.flush("t2")
    assert joined(out1) == stars(len(s))
    assert joined(out2) == s[6:]


def test_max_hold_raw_forces_output():
    r = Redactor([("sudo", SECRET)], max_hold_raw=64)
    junk = b"\x1b[1m" * 100  # nur Sequenzen, keine Sicht
    out = r.feed("t", 0, b"a" + junk)
    pend = r.pending("t")
    assert pend is None or pend[1] <= 64
    assert sum(len(c) for _, c, _ in out) + (pend[1] if pend else 0) == 1 + len(junk)


def test_redact_text_and_update():
    r = Redactor()
    assert r.redact_text(f"mysql -p{SECRET}") == (f"mysql -p{SECRET}", [])
    r.update_secrets([("db", SECRET)])
    text, labels = r.redact_text(f"mysql -p{SECRET} -h ä")
    assert text == "mysql -p" + "*" * len(SECRET) + " -h ä" and labels == ["db"]


def test_scan_outgoing():
    r = Redactor([("api", "mein-eigener-key")])
    text = ("key=mein-eigener-key\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"
            "sk-ant-api03-abcdefghijkl AKIAABCDEFGHIJKLMNOP")
    own, warn = scan_outgoing(text, r)
    assert [h.label for h in own] == ["api"]
    assert [w.kind for w in warn] == ["private_key", "anthropic_key", "aws_access_key"]
    assert scan_outgoing("nichts hier")[1] == []
    assert r.scan_outgoing(text) == (own, warn)


@settings(max_examples=150, deadline=None)
@given(
    prefix=st.binary(max_size=40),
    middle=st.binary(max_size=40),
    cuts=st.lists(st.integers(min_value=0, max_value=200), max_size=8),
    color=st.booleans(),
)
def test_property_random_chunking(prefix, middle, cuts, color):
    """Beliebige Chunk-Grenzen ergeben dasselbe Ergebnis wie ein einziger Chunk."""
    s = SECRET.encode()
    if color:
        s = b"".join(b"\x1b[3%dm%c" % (i % 8, c) for i, c in enumerate(s))
    data = prefix.replace(b"\x1b", b"") + s + middle.replace(b"\x1b", b"") + s
    ref = joined(feed_all(Redactor([("sudo", SECRET)]), [data]))
    bounds = sorted({c for c in cuts if 0 < c < len(data)})
    chunks = [data[a:b] for a, b in zip([0, *bounds], [*bounds, len(data)], strict=True)]
    got = joined(feed_all(Redactor([("sudo", SECRET)]), chunks))
    assert got == ref
    assert len(got) == len(data)
    assert SECRET.encode() not in got
