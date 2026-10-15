"""Durchstich mit den Golden-Eingaben: nmap-Text und -XML, Regex-Netz, Listener, Entscheide."""

from __future__ import annotations

import json
from pathlib import Path

from tests.parsers.helpers import make_unit
from tests.projection.helpers import claims, dec, entity, feed, inbox, new_projector, rows

GOLDEN = Path(__file__).parents[1] / "golden"
HOST = "ip:default/192.168.56.101"


def _ms2(p):
    txt = (GOLDEN / "nmap.text" / "ms2_sv_sc" / "input.txt").read_text()
    xml = (GOLDEN / "nmap.xml" / "ms2_sv_sc" / "input.xml").read_bytes()
    cmd = make_unit(txt, cmd="nmap -sV -sC -oA scans/ms2 192.168.56.101", unit_id="cmd1", ts=1_000)
    f = make_unit(kind="file", data=xml, path="scans/ms2.xml", sniff="xml:nmaprun", unit_id="file1", ts=2_000)
    feed(p, cmd, journal_seq=10)
    feed(p, f, journal_seq=20)


def test_text_and_xml_merge_without_conflicts():
    conn, p = new_projector(profile="customer")
    _ms2(p)
    p.rebuild()
    assert rows(conn, "SELECT COUNT(*) FROM conflict") == [(0,)]
    hosts = rows(conn, "SELECT host_id, knowledge, progress, scope FROM v_host ORDER BY host_id")
    assert (HOST, "versions", 3, "in") in hosts
    services = rows(
        conn, "SELECT port, name, product, version FROM v_service WHERE host_id = ? ORDER BY port", HOST
    )
    assert len(services) == 23
    assert (21, "ftp", "vsftpd", "2.3.4") in services
    assert (139, "netbios-ssn", "Samba smbd", "3.X - 4.X") in services
    c = claims(conn)
    ver = c[(f"svc:{HOST}|tcp/21", "service.version", "2.3.4")]
    assert ver["sources"] >= 2 and ver["confidence"] == 0.99 and ver["trust"] == "structured"
    ids = dict(rows(conn, "SELECT key, entity_id FROM identifier"))
    assert ids["mac:08:00:27:63:7e:e7"] == HOST
    assert all(v == HOST for k, v in ids.items() if k.startswith("sshkey:"))
    attrs = json.loads(entity(conn, HOST)["attrs_json"])
    assert attrs["names"] == ["irc.metasploitable.lan", "metasploitable.localdomain"]
    groups = {i["group"] for i in inbox(conn, "candidate_group")}
    assert "unit:cmd1" in groups  # der Befehl kam zuerst, die Datei ergänzt nur


def test_automode_adopts_nmap_xml_only():
    conn, p = new_projector(profile="customer")
    p.apply_decision(dec(5, "d.automode.set", enabled=True, parsers=["nmap.xml"]))
    _ms2(p)
    p.rebuild()
    states = {k: v["state"] for k, v in claims(conn).items()}
    # zuerst vom Text gesehen (nmap.text nicht freigegeben) bleibt Kandidat, auch wenn das XML es bestätigt
    assert states[(HOST, "host.state", "up")] == "candidate"
    assert states[(HOST, "host.smb_domain", "WORKGROUP")] == "auto"  # nur im XML


def test_listener_to_foothold_flow():
    conn, p = new_projector(profile="customer")  # lab setzt den Kontext selbst (test_ausw_*)
    _ms2(p)
    seg = make_unit(
        "listening on [any] 4444 ...\n"
        "connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 49152\nid\n"
        "uid=33(www-data) gid=33(www-data)\n",
        kind="segment",
        unit_id="seg1",
        terminal_id="t1",
        context={"kind": "revshell", "opened_at": 4000},
        start=4000,
        ts=3_000,
    )
    feed(p, seg, journal_seq=30)
    p.rebuild()
    (sug,) = inbox(conn, "ctx_suggestion")
    assert sug["payload"]["suggested_host"] == HOST
    p.apply_decision(dec(40, "d.ctx.set", terminal_id="t1", from_off=4100, host=HOST))
    p.apply_decision(dec(41, "d.keystep.mark", step="foothold", terminal_id="t1", stream_off=4100))
    p.rebuild()
    assert not inbox(conn, "ctx_suggestion") and not inbox(conn, "ctx_unknown")
    h = entity(conn, HOST)
    assert (h["access"], h["progress"]) == ("user", 4)
    assert rows(conn, "SELECT step, entity_id FROM v_keystep") == [("foothold", HOST)]
