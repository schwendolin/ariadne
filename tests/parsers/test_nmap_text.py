from __future__ import annotations

from pathlib import Path

import pytest

from ariadne.ctxrules import split_command
from ariadne.parsers.api import Mention, Obs, Ref
from ariadne.parsers.nmap_text import NmapTextParser, split_version
from ariadne.parsers.nmap_xml import NmapXmlParser
from tests.parsers.helpers import make_unit

GOLDEN = Path(__file__).parents[1] / "golden"
MS2_TXT = (GOLDEN / "nmap.text" / "ms2_sv_sc" / "input.txt").read_text()
MS2_XML = (GOLDEN / "nmap.xml" / "ms2_sv_sc" / "input.xml").read_bytes()
P = NmapTextParser()


def _key(o: Obs) -> tuple:
    v = o.value.key if isinstance(o.value, Ref) else o.value
    return (o.subject.key, o.predicate, v)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("vsftpd 2.3.4", ("vsftpd", "2.3.4", None)),
        (
            "OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)",
            ("OpenSSH", "4.7p1 Debian 8ubuntu1", "protocol 2.0"),
        ),
        ("Apache httpd 2.2.8 ((Ubuntu) DAV/2)", ("Apache httpd", "2.2.8", "(Ubuntu) DAV/2")),
        ("2-4 (RPC #100000)", (None, "2-4", "RPC #100000")),
        ("Samba smbd 3.X - 4.X (workgroup: WORKGROUP)", ("Samba smbd", "3.X - 4.X", "workgroup: WORKGROUP")),
        ("Linux telnetd", ("Linux telnetd", None, None)),
        ("(access denied)", (None, None, "access denied")),
        ("PostgreSQL DB 8.3.0 - 8.3.7", ("PostgreSQL DB", "8.3.0 - 8.3.7", None)),
        ("Apache Tomcat/Coyote JSP engine 1.1", ("Apache Tomcat/Coyote JSP engine", "1.1", None)),
        ("broken (paren", ("broken (paren", None, None)),
    ],
)
def test_split_version(text, expected):
    assert split_version(text) == expected


def test_match():
    assert P.match(make_unit("x", cmd="sudo nmap -sV 10.0.0.1")) == 60
    assert P.match(make_unit("x", cmd="nmapx 10.0.0.1")) == 0
    assert P.match(make_unit("x", kind="file", path="scans/a.nmap", data=b"x")) == 60
    assert (
        P.match(
            make_unit(
                "Nmap scan report for 10.0.0.1\n", kind="segment", context={"kind": "ssh", "opened_at": 1}
            )
        )
        == 40
    )
    assert P.match(make_unit("hello\n", kind="segment", context={"kind": "ssh", "opened_at": 1})) == 0


def test_companions():
    argv = split_command("sudo nmap -sV -oA scans/lame 10.0.0.1")
    assert P.companions(argv, "/w") == ["/w/scans/lame.nmap", "/w/scans/lame.gnmap"]
    assert P.companions(split_command("nmap -oN - 10.0.0.1"), "/w") == []


def test_text_and_xml_agree_on_main_facts():
    """Normalausgabe und XML desselben Laufs ergeben dieselben Claims (Zusammenführung)."""
    text = {
        _key(o) for o in P.parse(make_unit(MS2_TXT, cmd="nmap -sV -sC 192.168.56.101")) if isinstance(o, Obs)
    }
    xml = {
        _key(o)
        for o in NmapXmlParser().parse(make_unit(kind="file", data=MS2_XML, path="a.xml"))
        if isinstance(o, Obs)
    }
    for pred in (
        "host.state",
        "host.address",
        "host.mac",
        "service.state",
        "service.name",
        "service.product",
        "service.version",
        "service.extrainfo",
        "host.netbios",
        "host.smb_os",
        "host.domain",
        "service.tls_cn",
        "service.script",
        "host.script",
    ):
        t = {k for k in text if k[1] == pred}
        x = {k for k in xml if k[1] == pred}
        assert t == x, pred
    # MD5-Kennungen der SSH-Hostkeys gibt es in beiden Formaten
    assert {k for k in text if k[1] == "host.sshkey"} <= {k for k in xml if k[1] == "host.sshkey"}
    assert {k for k in text if k[1] == "host.name"} == {k for k in xml if k[1] == "host.name"}


def test_hostile_lines_in_scripts_are_not_hosts():
    data = (GOLDEN / "nmap.text" / "hostile_banner" / "input.txt").read_text()
    items = list(P.parse(make_unit(data, cmd="nmap -sV -sC 192.168.56.110")))
    subjects = {o.subject.key for o in items if isinstance(o, Obs)}
    assert all("6.6.6.6" not in s and "7.7.7.7" not in s for s in subjects)
    assert not any(
        o.predicate == "host.mac" and o.value == "66:66:66:66:66:66" for o in items if isinstance(o, Obs)
    )
    assert not [o for o in items if isinstance(o, Obs) and o.subject.key.endswith("tcp/21")]


def test_uncertain_and_ssl_service_names():
    text = (
        "Nmap scan report for 10.0.0.5\nHost is up.\nPORT    STATE SERVICE  VERSION\n"
        "443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)\n8080/tcp open http-proxy?\n"
    )
    items = [o for o in P.parse(make_unit(text, cmd="nmap -sV 10.0.0.5")) if isinstance(o, Obs)]
    by = {(o.subject.key.rsplit("|", 1)[1], o.predicate): o for o in items if "|" in o.subject.key}
    assert by[("tcp/443", "service.name")].value == "http"
    assert by[("tcp/443", "service.tunnel")].value == "ssl"
    assert by[("tcp/443", "service.product")].value == "nginx"
    assert by[("tcp/8080", "service.name")].confidence == 0.3
    assert ("tcp/8080", "service.product") not in by  # verschobene Spalte: kein Müll als Produkt


def test_without_version_column_names_are_table_guesses():
    data = (GOLDEN / "nmap.text" / "multi_hosts" / "input.txt").read_text()
    items = list(P.parse(make_unit(data, cmd="nmap -O -v 192.168.56.100-104")))
    names = [o for o in items if isinstance(o, Obs) and o.predicate == "service.name"]
    assert names and all(o.confidence == 0.3 for o in names)
    down = {m.value for m in items if isinstance(m, Mention)}
    assert down == {"192.168.56.100", "192.168.56.103"}
    os_ = [o for o in items if isinstance(o, Obs) and o.predicate == "host.os"]
    assert [(o.subject.key, o.value) for o in os_] == [("ip:default/192.168.56.101", "Linux 2.6.9 - 2.6.33")]


def test_prompt_echo_and_concealed_lines():
    text = "nmap 10.0.0.9\nNmap scan report for 10.0.0.9\nHost is up.\nMAC Address: 00:11:22:33:44:55 (X)\n"
    unit = make_unit(text, cmd="nmap 10.0.0.9", flags={0: "prompt_echo", 3: "concealed"})
    items = [o for o in P.parse(unit) if isinstance(o, Obs)]
    mac = [o for o in items if o.predicate == "host.mac"][0]
    assert mac.attrs["suspect"] == "concealed"
    assert all(o.span.line_start >= 1 for o in items)


def test_nothing_before_report_line():
    text = "PORT STATE SERVICE\n22/tcp open ssh\nMAC Address: 00:11:22:33:44:55 (X)\n"
    assert list(P.parse(make_unit(text, cmd="nmap 10.0.0.9"))) == []
