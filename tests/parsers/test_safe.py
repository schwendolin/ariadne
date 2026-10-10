from __future__ import annotations

import pytest

from ariadne.parsers.safe import (
    MAX_LINE,
    ParseError,
    UnsafeXmlError,
    clip,
    neutralize_doctype,
    rx,
    safe_xml_iterparse,
    safe_xml_parse,
)

NMAP_PROLOG = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
    b'<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>\n'
    b"<!-- Nmap 7.94SVN scan -->\n"
)


def test_bare_doctype_is_blanked_with_same_length():
    data = NMAP_PROLOG + b'<nmaprun scanner="nmap"/>\n'
    out = neutralize_doctype(data)
    assert len(out) == len(data) and out.count(b"\n") == data.count(b"\n")
    assert b"DOCTYPE" not in out
    assert safe_xml_parse(data).tag == "nmaprun"


@pytest.mark.parametrize(
    "doctype",
    [
        b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">',
        b'<!DOCTYPE nmaprun PUBLIC "-//x//EN" "http://evil/x.dtd">',
        b'<!DOCTYPE nmaprun [<!ENTITY x "y">]>',
        b"<!DOCTYPE nmaprun[]>",
    ],
)
def test_other_doctypes_stay_and_are_refused(doctype):
    data = b'<?xml version="1.0"?>\n' + doctype + b"\n<nmaprun/>"
    assert neutralize_doctype(data) == data
    with pytest.raises(UnsafeXmlError):
        safe_xml_parse(data)


def test_doctype_after_root_is_not_touched():
    data = b"<nmaprun/>\n<!DOCTYPE nmaprun>"
    assert neutralize_doctype(data) == data


def test_billion_laughs_fails_fast():
    lol = (
        b'<!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
        + b"".join(
            b'<!ENTITY a%d "%s">' % (i, (b"&a;" if i == 1 else b"&a%d;" % (i - 1)) * 10) for i in range(1, 10)
        )
        + b"]><r>&a9;</r>"
    )
    with pytest.raises(UnsafeXmlError):
        safe_xml_parse(lol)
    with pytest.raises(UnsafeXmlError):
        list(safe_xml_iterparse(lol))


def test_undeclared_entity_is_parse_error_not_expansion():
    with pytest.raises(ParseError):
        safe_xml_parse(b"<r>&xxe;</r>")


def test_iterparse_yields_until_truncation():
    data = NMAP_PROLOG + b"<nmaprun>\n<host><a/></host>\n<host><a/></host>\n<host><a"
    seen = []
    with pytest.raises(ParseError):
        for ev, el in safe_xml_iterparse(data):
            if el.tag == "host":
                seen.append(ev)
    assert seen == ["end", "end"]


def test_size_limit(monkeypatch):
    import ariadne.parsers.safe as safe

    monkeypatch.setattr(safe, "MAX_XML_BYTES", 10)
    with pytest.raises(UnsafeXmlError):
        safe.safe_xml_parse(b"<nmaprun></nmaprun>")


def test_rx_is_re2_and_cached():
    p = rx(r"(?i)cve-[0-9]{4}")
    assert p is rx(r"(?i)cve-[0-9]{4}")
    assert p.search("see CVE-2011-x").group(0) == "CVE-2011"
    with pytest.raises(Exception):
        rx(r"(?<=a)b")  # Lookbehind gibt es in re2 nicht


def test_clip_limits_long_lines():
    assert clip("x" * 10) == "x" * 10
    assert len(clip("x" * (MAX_LINE + 5))) == MAX_LINE
