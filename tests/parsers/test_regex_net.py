from __future__ import annotations

import pytest

from ariadne.parsers.api import Mention
from ariadne.parsers.regex_net import SECRET_TYPES, RegexNetParser
from ariadne.parsers.safe import MAX_LINE
from tests.parsers.helpers import make_unit

P = RegexNetParser()


def mentions(text: str, **kw) -> list[Mention]:
    return list(P.parse(make_unit(text, cmd="cat x", **kw)))


def values(text: str, vtype: str) -> list[str]:
    return [m.value for m in mentions(text) if m.value_type == vtype]


def test_contract_and_match():
    assert (P.trust, P.auto_eligible) == ("heuristic", False)
    assert P.match(make_unit("x", cmd="ls")) == 1
    assert P.match(make_unit("", cmd="ls")) == 0
    assert P.match(make_unit("x", kind="image")) == 0
    assert P.companions(["nmap", "-oX", "a.xml"], "/w") == []
    assert all(isinstance(m, Mention) for m in mentions("10.0.0.1 CVE-2011-2523 http://x.lab/"))


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Host 10.10.10.3 up", ["10.10.10.3"]),
        ("ends 10.10.10.4.", ["10.10.10.4"]),
        ("Apache/2.4.41 and 2.4.41", []),
        ("Apache/2.4.41.1", []),
        ("version 1.8.0.181", []),
        ("Version: 4.1.2.3", []),
        ("1.2.3.4.5", []),
        ("10.0.0.256", []),
        ("010.1.1.1", []),
        ("0.9.8.1", []),
        ("v1.2.3.4", []),
        ("4.3.2.1.in-addr.arpa", []),
        ("date 08.10.2026 14:02:33.123", []),
        ("2026.10.08", []),
        ("range 10.0.0.1-10.0.0.9", ["10.0.0.1", "10.0.0.9"]),
        ("http://10.0.0.7:8080/x", ["10.0.0.7"]),
        ("[10.0.0.8]:22", ["10.0.0.8"]),
    ],
)
def test_ipv4_traps(text, expected):
    assert values(text, "ip") == expected


def test_ip_in_url_is_marked():
    ms = mentions("see http://10.0.0.7/admin and 10.0.0.8")
    ips = {m.value: m for m in ms if m.value_type == "ip"}
    assert ips["10.0.0.7"].attrs.get("in_url") == "1"
    assert "in_url" not in ips["10.0.0.8"].attrs
    assert values("see http://10.0.0.7/admin", "url") == ["http://10.0.0.7/admin"]


def test_cidr_and_interface_address():
    ms = mentions("inet 10.10.14.2/23 brd x; net 10.10.10.0/24; bad 10.0.0.1/33")
    assert sorted(m.value for m in ms if m.value_type == "cidr") == ["10.10.10.0/24", "10.10.14.0/23"]
    assert sorted(m.value for m in ms if m.value_type == "ip") == ["10.0.0.1", "10.10.14.2"]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("addr fe80::a00:27ff:fe63:7ee7%eth0", ["fe80::a00:27ff:fe63:7ee7"]),
        ("[::1]:8080", ["::1"]),
        ("2001:db8:0:0:0:0:0:1 x", ["2001:db8::1"]),
        ("::ffff:10.0.0.1", ["10.0.0.1"]),
        ("mac 08:00:27:63:7e:e7 at 14:02:33", []),
        ("std::string Foo::Bar::baz", []),
        ("netstat :::22 and ::", []),
    ],
)
def test_ipv6(text, expected):
    assert values(text, "ip") == expected


def test_url_password_is_masked():
    ms = mentions("(https://admin:tomcat@10.0.0.5:8443/manager).")
    url = [m for m in ms if m.value_type == "url"][0]
    assert url.value == "https://admin:***@10.0.0.5:8443/manager"
    assert "tomcat" not in url.value and url.attrs["userinfo"] == "masked"
    assert values("ftp://x.lab/ http//broken http://", "url") == []


def test_email_cve():
    assert values("mail root@metasploitable.localdomain, ssh user@10.0.0.5", "email") == [
        "root@metasploitable.localdomain"
    ]
    assert values("CVE-2011-2523, cve-2007-2447, XCVE-2000-0001, CVE-2000-00011x", "cve") == [
        "CVE-2011-2523",
        "CVE-2007-2447",
    ]


def test_secret_formats():
    text = (
        "root:$6$salt$" + "a" * 86 + ":19000:0:99999:7:::\n"
        "u:$1$abc$" + "b" * 22 + ":1\n"
        "k:$y$j9T$" + "c" * 22 + "$" + "d" * 43 + ":1\n"
        "admin::CORP:" + "1" * 16 + ":" + "2" * 32 + ":" + "3" * 40 + "\n"
        "$krb5asrep$23$u@CORP.LOCAL:" + "e" * 32 + "$" + "f" * 64 + "\n"
        "$krb5tgs$23$*svc$CORP$spn*$" + "e" * 32 + "$" + "f" * 64 + "\n"
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln\n"
        "AKIAABCDEFGHIJKLMNOP and aws_secret_access_key=" + "A" * 40 + "\n"
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "sha256 " + "ab" * 32 + "\n"
    )
    ms = mentions(text)
    kinds = sorted(m.value_type for m in ms)
    assert kinds.count("crypt") == 3
    assert kinds.count("hash32") == 2  # LM und NT, nicht der SHA-256 und nicht der NTLMv2-Teil
    for k in ("netntlmv2", "krb5asrep", "krb5tgs", "jwt"):
        assert kinds.count(k) == 1, k
    assert kinds.count("awskey") == 2
    assert not [m for m in ms if m.value_type == "email"]  # u@CORP.LOCAL steckt im Hash
    assert {m.value_type for m in ms} - {
        "crypt",
        "hash32",
        "netntlmv2",
        "krb5asrep",
        "krb5tgs",
        "jwt",
        "awskey",
    } == set()


def test_private_key_block():
    text = "x\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\ny\n"
    ms = mentions(text)
    keys = [m for m in ms if m.value_type == "privkey"]
    assert len(keys) == 1 and keys[0].span.line_start == 1 and keys[0].span.line_end == 3
    assert keys[0].attrs == {"kind": "OPENSSH", "complete": "1"}
    assert "privkey" in SECRET_TYPES
    trunc = mentions("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n")
    assert [m.attrs["complete"] for m in trunc if m.value_type == "privkey"] == ["0"]


def test_long_lines_are_clipped():
    head = "x " * 100 + "10.0.0.1 "
    tail = "y" * (MAX_LINE + 10) + " 10.0.0.2"
    assert values(head + tail, "ip") == ["10.0.0.1"]


def test_prompt_echo_skipped_and_concealed_marked():
    unit = make_unit(
        "ping 10.0.0.1\n10.0.0.2 hidden\n10.0.0.3\n",
        cmd="ping 10.0.0.1",
        flags={0: "prompt_echo", 1: "concealed"},
    )
    ms = list(P.parse(unit))
    assert [m.value for m in ms] == ["10.0.0.2", "10.0.0.3"]
    assert ms[0].attrs["suspect"] == "concealed" and "suspect" not in ms[1].attrs


def test_spans_have_columns():
    m = mentions("abc 10.0.0.1 def")[0]
    assert (m.span.line_start, m.span.col_start, m.span.col_end) == (0, 4, 12)
