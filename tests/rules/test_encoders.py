"""Kontext-Encoder (E68, web-api.md 18.6): jeder Typ, jeder Sperrgrund, Reihenfolge der Gründe und
Eigenschaften über einen feindlichen Korpus (Hypothesis)."""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ariadne.rules.encoders import PLACEHOLDER_TYPES, SHELL_META, Scope, encode

SCOPE = Scope(
    ip=lambda a: "in" if a.startswith("192.168.56.") or a.startswith("fd00:56:") else "out",
    name=lambda n: "in" if n.endswith(".htb") else "out",
    net=lambda net: str(net).startswith("192.168.56."),
)

# Feindlicher Korpus: Shell, Steuerzeichen, Bidi, Zero-Width, Homoglyphen, Zeilenumbrüche
CORPUS = [
    "vsftpd'; !sh -c 'id",
    "$(id)",
    "`id`",
    "a;b",
    "a|b",
    "a&b",
    "a>b",
    "a<b",
    "(a)",
    "{a,b}",
    "a*",
    "a?",
    "[ab]",
    "a\\b",
    "#a",
    "~root",
    "^a",
    "a b",
    " a",
    "a\nb",
    "a\rb",
    "a\u2028b",
    "a\x85b",
    "a\x1b[2Jb",
    "a\x07",
    "a\x00b",
    "a\tb",
    "a\x7fb",
    "a\x9bb",
    "a\u202eb",
    "a\u200bb",
    "a\ufeffb",
    "a\U000e0041b",
    "vsftрd",  # kyrillisches «р»
    "ｖｓｆｔｐｄ",
    "-oProxyCommand=id",
    "--help",
    "a=b",
    "",
]


@pytest.mark.parametrize(
    ("ptype", "raw", "text"),
    [
        ("ip", "192.168.56.101", "192.168.56.101"),
        ("ip", "fd00:56:0::0101", "fd00:56::101"),  # kanonische Form
        ("port", 21, "21"),
        ("port", "8180", "8180"),
        ("port", 65535, "65535"),
        ("hostname", "lame.htb", "lame.htb"),
        ("hostname", "a-b.c.htb", "a-b.c.htb"),
        ("cidr", "192.168.56.0/24", "192.168.56.0/24"),
        ("url", "http://192.168.56.101:8180/", "http://192.168.56.101:8180/"),
        ("url", "https://lame.htb/a/b%20c", "https://lame.htb/a/b%20c"),
        ("word", "vsftpd", "vsftpd"),
        ("word", "2.3.4", "2.3.4"),
        ("word", "4.7p1", "4.7p1"),
        ("words", "Apache Tomcat Coyote", "Apache Tomcat Coyote"),
        ("path", "/usr/share/wordlists/dirb/common.txt", "/usr/share/wordlists/dirb/common.txt"),
        ("user", "msfadmin", "msfadmin"),
        ("share", "tmp", "tmp"),
        ("share", "IPC$", "IPC$"),
        ("share", "C$", "C$"),
    ],
)
def test_valid_values_pass(ptype, raw, text):
    e = encode(ptype, raw, SCOPE)
    assert e.safe and e.reason is None and e.text == text


@pytest.mark.parametrize(
    ("ptype", "raw", "reason"),
    [
        ("ip", "10.0.0.1", "out_of_scope"),
        ("ip", "192.168.056.1", "invalid"),  # führende Null
        ("ip", "fe80::1%eth0", "invalid"),  # Zonen-ID
        ("ip", "fe80::1%$(id)", "shell_meta"),
        ("ip", "192.168.56.101 ", "shell_meta"),
        ("ip", "1.2.3.4/32", "invalid"),
        ("port", 0, "invalid"),
        ("port", 65536, "invalid"),
        ("port", True, "invalid"),
        ("port", "021", "invalid"),
        ("port", "21;id", "shell_meta"),
        ("hostname", "lame.htb.", "invalid"),
        ("hostname", "-x.htb", "invalid"),
        ("hostname", "lame.example", "out_of_scope"),
        ("hostname", "lаme.htb", "non_ascii"),  # kyrillisches «а»
        ("hostname", "a_b.htb", "invalid"),
        ("cidr", "10.0.0.0/8", "out_of_scope"),
        ("cidr", "192.168.56.1/24", "invalid"),  # nicht kanonisch (Host-Bits)
        ("url", "ftp://192.168.56.101/", "invalid"),
        ("url", "http://user:pw@192.168.56.101/", "invalid"),
        ("url", "http://192.168.56.101/?a=b", "shell_meta"),
        ("url", "http://192.168.56.101/#x", "shell_meta"),
        ("url", "http://192.168.56.101/~user", "shell_meta"),
        ("url", "http://10.0.0.1/", "out_of_scope"),
        ("url", "http://[fd00:56::1]:80/", "shell_meta"),
        ("url", "http://192.168.56.101:99999/", "invalid"),
        ("word", "a b", "shell_meta"),
        ("word", "-x", "invalid"),
        ("word", "a,b", "invalid"),
        ("word", "x" * 65, "invalid"),
        ("words", "a  b", "shell_meta"),
        ("words", " a", "shell_meta"),
        ("words", "a b c d e f g", "invalid"),
        ("words", "a -o", "invalid"),
        ("path", "relative/path", "invalid"),
        ("path", "/a/../etc/passwd", "invalid"),
        ("path", "/a b", "shell_meta"),
        ("user", "root$", "shell_meta"),
        ("user", "-root", "invalid"),
        ("share", "AD$MIN", "shell_meta"),  # Dollar nur am Ende
        ("share", "C$$", "shell_meta"),
        ("share", "-x", "invalid"),
        ("word", "", "invalid"),
        ("word", None, "invalid"),
    ],
)
def test_blocked_values_name_the_first_reason(ptype, raw, reason):
    e = encode(ptype, raw, SCOPE)
    assert not e.safe and e.text is None and e.reason == reason


@pytest.mark.parametrize("ptype", sorted(PLACEHOLDER_TYPES - {"port"}))
@pytest.mark.parametrize("raw", CORPUS)
def test_hostile_corpus_never_passes(ptype, raw):
    """Kein Wert des feindlichen Korpus besteht einen Encoder, der ihn in einen Befehl liesse
    (Ausnahmen: harmlose Werte, die zum Typ passen)."""
    e = encode(ptype, raw, SCOPE)
    harmless = {("words", "a b")}  # zwei Wörter sind für ``words`` erlaubt
    assert e.safe is ((ptype, raw) in harmless), (ptype, raw, e)


def test_reason_order_newline_before_control_before_non_ascii_before_meta():
    assert encode("word", "a\x1b\n;", SCOPE).reason == "newline"
    assert encode("word", "a\x1b;ü", SCOPE).reason == "control"
    assert encode("word", "aü;", SCOPE).reason == "non_ascii"
    assert encode("word", "a;-", SCOPE).reason == "shell_meta"
    assert encode("ip", "10.0.0.1", Scope()).reason == "out_of_scope"  # ohne Scope: fail-closed


def test_scope_missing_is_fail_closed():
    assert encode("ip", "192.168.56.101", Scope()).reason == "out_of_scope"
    assert encode("hostname", "lame.htb", Scope()).reason == "out_of_scope"
    assert encode("cidr", "192.168.56.0/24", Scope()).reason == "out_of_scope"


def test_unknown_type_is_programming_error():
    with pytest.raises(ValueError):
        encode("shell", "x", SCOPE)


_SAFE_CHARS = {
    "ip": re.compile(r"[0-9a-f.:]+"),
    "port": re.compile(r"[0-9]+"),
    "hostname": re.compile(r"[A-Za-z0-9.-]+"),
    "cidr": re.compile(r"[0-9a-f.:/]+"),
    "url": re.compile(r"[A-Za-z0-9._:/@=%+-]+"),
    "word": re.compile(r"[A-Za-z0-9._+-]+"),
    "words": re.compile(r"[A-Za-z0-9._+ -]+"),
    "path": re.compile(r"[A-Za-z0-9._/+-]+"),
    "user": re.compile(r"[A-Za-z0-9._-]+"),
    "share": re.compile(r"[A-Za-z0-9._-]+\$?"),
}
_HOSTILE_ALPHABET = st.sampled_from(
    list("aZ09.-_+/:@=%~^ ")
    + sorted(SHELL_META)
    + ["\n", "\r", "\x1b", "\x00", "\t", "\u202e", "\u200b", "\u2028", "р", "ü", "•", "$", "'", '"']
)


@settings(max_examples=400, deadline=None, derandomize=True, database=None)
@given(ptype=st.sampled_from(sorted(PLACEHOLDER_TYPES)), raw=st.text(_HOSTILE_ALPHABET, max_size=24))
def test_property_encoded_text_is_shell_inert(ptype, raw):
    """Was ein Encoder durchlässt, besteht nur aus Zeichen ohne Bedeutung für die Shell, beginnt nie mit
    einem Bindestrich (ausser Port-freien Typen ohne Option) und ist für alle Typen ausser ip/cidr/port
    unverändert."""
    e = encode(ptype, raw, SCOPE)
    if not e.safe:
        assert e.text is None and e.reason in (
            "shell_meta",
            "control",
            "newline",
            "non_ascii",
            "invalid",
            "out_of_scope",
        )
        return
    assert e.text and _SAFE_CHARS[ptype].fullmatch(e.text), (ptype, raw)
    assert not any(ch in SHELL_META for ch in e.text.rstrip("$")), (ptype, raw)
    assert not e.text.startswith("-")
    if ptype not in ("ip", "cidr", "port"):
        assert e.text == raw  # prüft, formt nie um
