from __future__ import annotations

from pathlib import Path

import pytest

from ariadne.parsers.api import Mention, Obs, Ref
from ariadne.parsers.nmap_xml import NmapXmlParser, ssh_fingerprint, ssh_key_type
from ariadne.parsers.safe import UnsafeXmlError
from tests.parsers.helpers import make_unit

GOLDEN = Path(__file__).parents[1] / "golden" / "nmap.xml"
MS2 = (GOLDEN / "ms2_sv_sc" / "input.xml").read_bytes()
P = NmapXmlParser()


def _xml_unit(data: bytes, **kw):
    kw.setdefault("path", "scans/x.xml")
    return make_unit(kind="file", data=data, **kw)


def _obs(items, pred, subject=None):
    return [
        o
        for o in items
        if isinstance(o, Obs) and o.predicate == pred and (subject is None or o.subject.key == subject)
    ]


def test_contract():
    assert (P.id, P.trust, P.auto_eligible) == ("nmap.xml", "structured", True)


def test_match_sniff_path_and_content():
    assert P.match(_xml_unit(MS2, sniff="xml:nmaprun")) == 100
    assert P.match(_xml_unit(MS2, sniff=None)) == 90
    assert P.match(_xml_unit(b"<?xml version='1.0'?><burpItems/>", sniff=None)) == 0
    assert P.match(_xml_unit(MS2, path="scans/x.txt", mime="text/plain")) == 0
    assert P.match(make_unit("x", cmd="nmap -sV 10.0.0.1")) == 0
    assert P.match(make_unit("x", cmd="nmap -sV -oX - 10.0.0.1")) == 90


@pytest.mark.parametrize(
    "cmd,cwd,expected",
    [
        ("nmap -sV -oX scan.xml 10.0.0.1", "/home/kali/lab", ["/home/kali/lab/scan.xml"]),
        ("nmap -oA scans/lame 10.0.0.1", "/home/kali/lab", ["/home/kali/lab/scans/lame.xml"]),
        ("sudo nmap -sS -oA /tmp/x 10.0.0.1", "/w", ["/tmp/x.xml"]),
        ("proxychains4 -q nmap -sT -oX=out.xml 10.0.0.1", "/w", ["/w/out.xml"]),
        ("nmap --oX ../up.xml 10.0.0.1", "/w/sub", ["/w/up.xml"]),
        ("nmap -oX - 10.0.0.1", "/w", []),
        ("nmap -oN scan.nmap 10.0.0.1", "/w", []),
        ("nc -lvnp 4444", "/w", []),
    ],
)
def test_companions(cmd, cwd, expected):
    from ariadne.ctxrules import split_command

    assert P.companions(split_command(cmd), cwd) == expected


def test_ms2_core_facts():
    items = list(P.parse(_xml_unit(MS2)))
    host = "ip:default/192.168.56.101"
    assert [o.value for o in _obs(items, "host.state", host)] == ["up"]
    assert [o.value for o in _obs(items, "host.mac")] == ["08:00:27:63:7e:e7"]
    assert _obs(items, "host.mac")[0].attrs["vendor"] == "Oracle VirtualBox virtual NIC"
    ports = sorted(int(o.subject.key.rsplit("/", 1)[1]) for o in _obs(items, "service.state"))
    assert ports == [
        21,
        22,
        23,
        25,
        53,
        80,
        111,
        139,
        445,
        512,
        513,
        514,
        1099,
        1524,
        2049,
        2121,
        3306,
        5432,
        5900,
        6000,
        6667,
        8009,
        8180,
    ]
    svc = Ref.service(Ref.ip("192.168.56.101"), "tcp", 21).key
    assert [o.value for o in _obs(items, "service.product", svc)] == ["vsftpd"]
    assert [o.value for o in _obs(items, "service.version", svc)] == ["2.3.4"]
    netbios = {o.value for o in _obs(items, "host.netbios")}
    assert netbios == {"METASPLOITABLE"}
    assert {o.value for o in _obs(items, "host.smb_os")} == {"Unix (Samba 3.0.20-Debian)"}
    assert {o.value for o in _obs(items, "service.tls_cn")} == {"ubuntu804-base.localdomain"}
    keys = {o.value.key for o in _obs(items, "host.sshkey")}
    assert any(k.startswith("sshkey:rsa:SHA256:") for k in keys)
    assert any(k.startswith("sshkey:dsa:MD5:") for k in keys)


def test_spans_point_at_port_lines():
    items = list(P.parse(_xml_unit(MS2)))
    lines = MS2.decode().split("\n")
    for o in _obs(items, "service.state"):
        port = o.subject.key.rsplit("/", 1)[1]
        assert f'portid="{port}"' in lines[o.span.line_start]
        assert o.span.path.startswith("/nmaprun/host[1]/ports/port[")


def test_method_table_lowers_confidence():
    data = (GOLDEN / "multi_hosts" / "input.xml").read_bytes()
    items = list(P.parse(_xml_unit(data)))
    names = _obs(items, "service.name")
    assert names and all(o.confidence == 0.3 for o in names)
    os_ = {o.subject.key: o for o in _obs(items, "host.os")}
    assert os_["ip:default/192.168.56.101"].value == "Linux 2.6.9 - 2.6.33"
    assert os_["ip:default/192.168.56.104"].confidence == pytest.approx(0.95 * 0.91)


def test_down_hosts_only_mentions():
    data = (GOLDEN / "multi_hosts" / "input.xml").read_bytes()
    items = list(P.parse(_xml_unit(data)))
    down = [m for m in items if isinstance(m, Mention)]
    assert {m.value for m in down} == {"192.168.56.100", "192.168.56.103"}
    assert all(m.attrs["state"] == "down" for m in down)
    subjects = {o.subject.key for o in items if isinstance(o, Obs)}
    assert "ip:default/192.168.56.100" not in subjects


def test_incomplete_xml_keeps_only_complete_hosts():
    full = (GOLDEN / "multi_hosts" / "input.xml").read_bytes()
    for cut in range(200, len(full), 397):  # viele Abbruchstellen, nie ein Absturz
        items = list(P.parse(_xml_unit(full[:cut])))
        complete = full[:cut].count(b"</host>")
        hosts = {o.subject.key for o in items if isinstance(o, Obs) and o.predicate == "host.state"}
        downs = {m.value for m in items if isinstance(m, Mention)}
        assert len(hosts) + len(downs) <= complete


def test_garbage_and_other_roots_yield_nothing():
    assert list(P.parse(_xml_unit(b"\x00\xff\xfenot xml at all"))) == []
    assert list(P.parse(_xml_unit(b"<?xml version='1.0'?><other><host/></other>"))) == []
    assert list(P.parse(_xml_unit(b""))) == []


def test_dtd_attacks_refused():
    for case in ("xxe", "billion_laughs"):
        data = (GOLDEN / case / "input.xml").read_bytes()
        with pytest.raises(UnsafeXmlError):
            list(P.parse(_xml_unit(data)))


def test_hostile_values_are_validated():
    data = b"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/><address addr="zz:zz" addrtype="mac"/>
<hostnames><hostname name="&lt;script&gt;alert(1)&lt;/script&gt;" type="PTR"/>
<hostname name="ok.lab." type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="99999"><state state="open"/></port>
<port protocol="icmp" portid="1"><state state="open"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="x' ; rm -rf ~"/></port>
</ports></host></nmaprun>"""
    items = list(P.parse(_xml_unit(data)))
    assert [o.value for o in _obs(items, "host.name")] == ["ok.lab"]
    assert _obs(items, "host.mac") == []
    assert {o.subject.key for o in _obs(items, "service.state")} == {"svc:ip:default/10.0.0.5|tcp/80"}
    # Produkttext bleibt Zieldaten (Kodierung macht die Senke), wird aber nicht verworfen
    assert [o.value for o in _obs(items, "service.product")] == ["x' ; rm -rf ~"]


def test_command_unit_with_xml_on_stdout():
    text = "Warning: something\n" + MS2.decode()
    unit = make_unit(text, cmd="nmap -sV -sC -oX - 192.168.56.101")
    items = list(P.parse(unit))
    assert _obs(items, "host.state")
    st = _obs(items, "service.state")[0]
    assert 'portid="21"' in unit.lines[st.span.line_start].text


def test_ssh_helpers():
    assert ssh_key_type("ssh-dss") == "dsa"
    assert ssh_key_type("ecdsa-sha2-nistp256") == "ecdsa"
    assert ssh_key_type("weird") is None
    import base64
    import hashlib

    raw = b"\x00\x00\x00\x07ssh-rsa\x01\x02"
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    assert ssh_fingerprint(base64.b64encode(raw).decode()) == expected
    assert ssh_fingerprint("not base64!") is None
