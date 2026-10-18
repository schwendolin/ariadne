"""Erledigt-Erkennung und Ausschlüsse je Regel (docs/denkanstoesse.md): Ein Denkanstoss verschwindet,
sobald ein aufgenommener Befehl die Prüfung gemacht hat (Skript-Ausgabe, nmap-Optionen eines
beobachtenden Laufs, Werkzeug gegen Host und Port). Befehle gegen andere Hosts, misstraute Befehle,
Sackgassen, Nebel und Dienste ausserhalb zählen nicht bzw. lösen nichts aus."""

from __future__ import annotations

import pytest

from ariadne.parsers.api import Obs, Ref, Span
from tests.rules import helpers as H

U = H.MS2
HOST = Ref.ip(U)
SP = Span(0, 0)


def _svc(port: int, proto: str = "tcp") -> list[Obs]:
    return [Obs(Ref.service(HOST, proto, port), "service.state", "open", SP)]


def _keys(items: list[dict]) -> set[tuple[str, str | None]]:
    """(Regel, Port) je Denkanstoss; bei einer Liste (E119, «Versionen recherchieren») je Eintrag."""
    out: set[tuple[str, str | None]] = set()
    for s in items:
        if s["items"]:
            out |= {(s["rule_id"], i["service_id"].rsplit("/", 1)[1]) for i in s["items"]}
        else:
            out.add((s["rule_id"], s["service_id"].rsplit("/", 1)[1] if s["service_id"] else None))
    return out


@pytest.fixture(scope="module")
def baseline() -> set[tuple[str, str | None]]:
    conn, _p = H.ms2(scripts=False)
    return _keys(H.suggestions(conn))


CASES = [
    # (Befehl, Beobachtungen, verschwindet, bleibt)
    (f"nmap -p 21 --script ftp-anon {U}", _svc(21), {("R-ANON-ZUGRIFF", "21")}, {("R-ANON-ZUGRIFF", "2121")}),
    (
        f"sudo nmap -sC -p 21,2121 {U}",
        _svc(21) + _svc(2121),
        {("R-ANON-ZUGRIFF", "21"), ("R-ANON-ZUGRIFF", "2121")},
        {("R-SMB-SHARES", "445")},
    ),
    (f"ftp {U} 2121", [], {("R-ANON-ZUGRIFF", "2121")}, {("R-ANON-ZUGRIFF", "21")}),
    (f"ftp {U}", [], {("R-ANON-ZUGRIFF", "21")}, {("R-ANON-ZUGRIFF", "2121")}),
    (f"curl ftp://{U}/", [], {("R-ANON-ZUGRIFF", "21")}, {("R-ANON-ZUGRIFF", "2121")}),
    (f"rpcclient -U '' -N {U}", [], {("R-ANON-ZUGRIFF", "445")}, {("R-SMB-SHARES", "445")}),
    (f"smbclient -N -L //{U}", [], {("R-ANON-ZUGRIFF", "445"), ("R-SMB-SHARES", "445")}, set()),
    (f"nxc smb {U} -u '' -p '' --shares", [], {("R-ANON-ZUGRIFF", "445"), ("R-SMB-SHARES", "445")}, set()),
    (f"enum4linux -a {U}", [], {("R-SMB-SHARES", "445")}, {("R-NFS-EXPORTS", "2049")}),
    (f"nmap -p 445 --script smb-enum-shares {U}", _svc(445), {("R-SMB-SHARES", "445")}, set()),
    (f"showmount -e {U}", [], {("R-NFS-EXPORTS", "2049")}, set()),
    (f"sudo mount -t nfs {U}:/ /mnt/x", [], {("R-NFS-EXPORTS", "2049")}, set()),
    (f"gobuster dir -u http://{U}/ -w common.txt", [], {("R-WEB-INHALT", "80")}, {("R-WEB-INHALT", "8180")}),
    (f"curl -s http://{U}:8180/ | head", [], {("R-WEB-INHALT", "8180")}, {("R-WEB-INHALT", "80")}),
    (f"nmap -p 80 --script http-enum {U}", _svc(80), {("R-WEB-INHALT", "80")}, {("R-WEB-INHALT", "8180")}),
    ("searchsploit vsftpd", [], {("R-VERSION-RECHERCHE", "21")}, {("R-VERSION-RECHERCHE", "2121")}),
    (
        f"nmap -sV --script vulners -p 2121 {U}",
        _svc(2121),
        {("R-VERSION-RECHERCHE", "2121")},
        {("R-VERSION-RECHERCHE", "21")},
    ),
    (
        f"nmap -p- {U}",
        [Obs(HOST, "host.state", "up", SP)],
        {("R-FULL-PORTSCAN", None)},
        {("R-UDP-SCAN", None)},
    ),
    ("nmap -p 1-65535 -T4 192.168.56.0/24", [], {("R-FULL-PORTSCAN", None)}, {("R-UDP-SCAN", None)}),
    ("rustscan -a 192.168.56.100-110", [], {("R-FULL-PORTSCAN", None)}, set()),
    ("masscan -p0-65535 192.168.56.101 --rate 1000", [], {("R-FULL-PORTSCAN", None)}, set()),
    (f"sudo nmap -sU --top-ports 20 {U}", [], {("R-UDP-SCAN", None)}, {("R-FULL-PORTSCAN", None)}),
    (f"nmap -sV {U}", _svc(161, "udp"), {("R-UDP-SCAN", None)}, set()),  # UDP-Dienst schon bekannt
    (f"mysql -h {U} -u root", [], {("R-DB-ZUGRIFF", "3306")}, {("R-DB-ZUGRIFF", "5432")}),
    (f"psql -h {U} -U postgres", [], {("R-DB-ZUGRIFF", "5432")}, {("R-DB-ZUGRIFF", "3306")}),
    (
        f"hydra -l tomcat -P pw.txt {U} -s 8180 http-get /manager/html",
        [],
        {("R-STANDARD-CREDS", "8180")},
        {("R-STANDARD-CREDS", "5900")},
    ),
    (f"vncviewer {U}::5900", [], {("R-STANDARD-CREDS", "5900")}, {("R-STANDARD-CREDS", "23")}),
    (f"telnet {U}", [], {("R-STANDARD-CREDS", "23")}, {("R-STANDARD-CREDS", "5900")}),
    (f"smtp-user-enum -M VRFY -U users.txt -t {U}", [], {("R-SMTP-USER", "25")}, set()),
    # gegen einen anderen Host: nichts erledigt
    ("smbclient -N -L //192.168.56.150", [], set(), {("R-SMB-SHARES", "445"), ("R-ANON-ZUGRIFF", "445")}),
    ("showmount -e 192.168.56.10", [], set(), {("R-NFS-EXPORTS", "2049")}),
    ("nmap -p- 192.168.56.150", [], set(), {("R-FULL-PORTSCAN", None)}),
    # Port passt nicht: telnet auf 2323 erledigt Port 23 nicht
    (f"telnet {U} 2323", [], set(), {("R-STANDARD-CREDS", "23")}),
]


@pytest.mark.parametrize(("cmd", "obs", "gone", "stays"), CASES, ids=[c[0][:40] for c in CASES])
def test_command_covers_check(cmd, obs, gone, stays, baseline):
    assert gone <= baseline and stays <= baseline
    conn, _p = H.ms2(scripts=False, extra=[(cmd, "x1", obs)])
    now = _keys(H.suggestions(conn))
    assert not (gone & now), cmd
    assert stays <= now, cmd


def test_xml_import_counts_options_of_the_producing_command():
    """Der XML-Import hat die Optionen seines Befehls (``-sC``): ftp-anon lief auch ohne Ausgabe auf 2121."""
    conn, _p = H.ms2()
    keys = _keys(H.suggestions(conn))
    assert ("R-ANON-ZUGRIFF", "2121") not in keys and ("R-ANON-ZUGRIFF", "21") not in keys


def test_distrusted_command_does_not_count():
    conn, p = H.ms2(scripts=False, extra=[(f"showmount -e {U}", "x1", [])])
    assert ("R-NFS-EXPORTS", "2049") not in _keys(H.suggestions(conn))
    # Rückgängig pro Befehl auf den nmap-Lauf und den showmount-Befehl
    H.decide(p, 100, "d.unit.distrust", cmd_id="t@30")
    assert ("R-NFS-EXPORTS", "2049") in _keys(H.suggestions(conn))


def test_dead_end_done_and_out_of_scope_suppress():
    conn, p = H.ms2(scripts=False)
    H.decide(p, 100, "d.status.work", subject=f"svc:ip:default/{U}|tcp/80", value="done")
    keys = _keys(H.suggestions(conn))
    assert ("R-WEB-INHALT", "80") not in keys and ("R-WEB-INHALT", "8180") in keys
    H.decide(p, 101, "d.status.work", subject=f"ip:default/{U}", value="dead_end", reason="nur RDP")
    assert H.suggestions(conn) == []
    H.decide(p, 102, "d.revoke", decision_id="dec-101")
    # 16 ohne Web auf Port 80 (erledigt); die Versionen bilden einen Denkanstoss ohne Port 80 (E119)
    sugg = H.suggestions(conn)
    assert len(sugg) == 15
    (ver,) = H.by_rule(sugg, "R-VERSION-RECHERCHE")
    assert "80" not in {i["service_id"].rsplit("/", 1)[1] for i in ver["items"]}


def test_fog_and_out_of_scope_hosts_trigger_nothing():
    from tests.parsers.helpers import make_unit
    from tests.projection.helpers import FakeScope, apply_items, new_projector

    conn, p = new_projector(FakeScope(nets=["192.168.56.0/24"]), own=[H.KALI])
    out = Ref.ip("10.66.66.66")
    s = Ref.service(out, "tcp", 21)
    items = [
        Obs(out, "host.state", "up", SP),
        Obs(s, "service.state", "open", SP),
        Obs(s, "service.name", "ftp", SP),
    ]
    apply_items(p, make_unit("x", cmd="nmap 10.66.66.66", unit_id="u1", ts=H.T0), items)
    # Nebel: nur heuristisch erwähnt (Vorschlag, nicht übernommen)
    fog = Ref.ip("192.168.56.103")
    fs = Ref.service(fog, "tcp", 21)
    apply_items(
        p,
        make_unit("x", unit_id="u2", ts=H.T0),
        [
            Obs(fog, "host.state", "up", SP),
            Obs(fs, "service.state", "open", SP),
            Obs(fs, "service.name", "ftp", SP),
        ],
        parser_id="regex.guess",
        trust="heuristic",
        auto_eligible=False,
    )
    p.rebuild()
    assert H.suggestions(conn) == []


def test_customer_profile_has_no_login_templates():
    conn, _p = H.ms2(scripts=False, profile="customer")
    items = H.suggestions(conn, profile="customer")
    for s in items:
        if s["rule_id"] in ("R-STANDARD-CREDS", "R-DB-ZUGRIFF"):
            assert s["templates"] == [] and s["stages"]["question"]
        else:
            assert s["templates"]


def test_rejected_claims_trigger_nothing():
    conn, p = H.ms2(scripts=False)
    sg = next(s for s in H.suggestions(conn) if s["rule_id"] == "R-SMTP-USER")
    H.decide(p, 100, "d.claim.reject", claim_key=sg["evidence"][0]["claim_key"])  # Name smtp verworfen
    assert not H.by_rule(H.suggestions(conn), "R-SMTP-USER")


def test_known_secret_values_are_masked_and_block_templates():
    """Ein bekannter Secret-Wert in einem Banner erscheint nie im Klartext und nie in einem Befehl."""
    secret = "Sup3rGeheim!"
    svc = Ref.service(HOST, "tcp", 9999)
    banner = [
        Obs(svc, "service.state", "open", SP),
        Obs(svc, "service.name", "ftp", SP),
        Obs(svc, "service.product", f"vsftpd {secret}", SP),
        Obs(svc, "service.version", "2.3.4", SP),
    ]
    conn, p = H.ms2(scripts=False, extra=[(f"nmap -sV -p 9999 {U}", "x1", banner)])
    conn.execute("INSERT INTO secret_value VALUES ('secret:x', 'password', ?)", (secret,))
    items = H.suggestions(conn, state="all")
    assert secret not in repr(items)
    (ver,) = H.by_rule(items, "R-VERSION-RECHERCHE")
    item = next(i for i in ver["items"] if i["service_id"].endswith("/9999"))
    assert item["label"] == "vsftpd •••••••• 2.3.4 · 9999/tcp"
    assert item["label_parts"][0] == {"text": "vsftpd •••••••• 2.3.4", "target": True}
    tpl = item["template"]
    assert not tpl["rendered"] and tpl["blocked_reason"] == "non_ascii" and tpl["command"] is None
    assert tpl["values"][1]["value"] == "vsftpd ••••••••"
    anon = next(s for s in items if s["rule_id"] == "R-ANON-ZUGRIFF" and s["service_id"].endswith("/9999"))
    assert anon["stages"]["direction"].startswith("Viele vsftpd-Installationen")


def test_observer_in_the_middle_of_three_scans_counts():
    """Mit mehr als zwei Quellen liest die Engine die Beobachter aus ``claim_source`` (nicht nur den ersten
    und letzten Lauf): ``nmap -p-`` zwischen zwei anderen Läufen erledigt den Full-Port-Scan."""
    up = [Obs(HOST, "host.state", "up", SP)]
    conn, _p = H.ms2(scripts=False, extra=[(f"nmap -p- {U}", "x1", up), (f"nmap -sV {U}", "x2", up)])
    hid = f"ip:default/{U}"
    (row,) = conn.execute(
        "SELECT first_unit, last_unit, sources FROM claim WHERE subject_identifier = ? AND predicate = "
        "'host.state'",
        (hid,),
    ).fetchall()
    assert row == ("cmd1", "x2", 3)
    assert ("R-FULL-PORTSCAN", None) not in _keys(H.suggestions(conn))
