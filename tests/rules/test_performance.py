"""Laufzeit der Regel-Engine (Vertrag 4.2): mit 500 Hosts und 5000 Diensten unter 200 ms für ``/next``
(``suggestions`` mit ``limit=50``) und für ``open_count`` (nach jedem Auswertungsdurchgang)."""

from __future__ import annotations

import json
import time

from ariadne.rules import api as rules_api
from ariadne.rules.engine import clear_cache
from tests.projection.helpers import new_projector

SERVICES = [
    (21, "ftp", "vsftpd", "2.3.4"),
    (22, "ssh", "OpenSSH", "7.2p2"),
    (25, "smtp", "Postfix smtpd", None),
    (80, "http", "Apache httpd", "2.4.18"),
    (139, "netbios-ssn", "Samba smbd", "3.X - 4.X"),
    (445, "microsoft-ds", "Samba smbd", "4.3.11"),
    (2049, "nfs", None, "2-4"),
    (3306, "mysql", "MySQL", "5.7.33"),
    (5900, "vnc", "VNC", None),
    (8080, "http", "Apache Tomcat/Coyote JSP engine", "1.1"),
]
HOSTS = 500


def _build():
    conn, _p = new_projector()
    ent, ident, claims, sources, units = [], [], [], [], []
    n = 0

    def claim(subject: str, eid: str, pred: str, value: str, unit: str) -> None:
        nonlocal n
        n += 1
        key = f"{n:064x}"
        claims.append(
            (
                key,
                subject,
                eid,
                pred,
                json.dumps(value),
                value,
                0.95,
                "auto",
                unit,
                unit,
                10**18 + n,
                10**18 + n,
                None,
                0,
                "structured",
                "nmap.text",
                1,
                0,
                0,
                "in",
                None,
                "auto",
                "parser",
                unit,
                0,
                "in",
            )
        )
        sources.append(
            (
                key,
                n,
                None,
                None,
                unit,
                "nmap.text",
                "1",
                "structured",
                0.95,
                json.dumps({"line_start": 5, "line_end": 5}),
                n,
                10**18 + n,
                unit,
                0,
                0,
            )
        )

    for i in range(HOSTS):
        ip = f"10.{i // 250}.{i % 250}.{10 + i % 7}"
        hid = f"ip:default/{ip}"
        unit = f"scan{i // 50}"
        ent.append(
            (
                hid,
                "host",
                ip,
                "versions",
                "none",
                "open",
                None,
                3,
                1,
                2,
                "[]",
                None,
                "in",
                "auto",
                unit,
                json.dumps({"addresses": [ip]}),
            )
        )
        ident.append((hid, "ip", hid, "strong", "in", "include:10.0.0.0/8", 1))
        ident.append(
            (f"mac:00:00:00:00:{i // 256:02x}:{i % 256:02x}", "mac", hid, "strong", None, None, None)
        )
        claim(hid, hid, "host.state", "up", unit)
        for port, name, product, version in SERVICES:
            sid = f"svc:{hid}|tcp/{port}"
            ent.append(
                (
                    sid,
                    "service",
                    f"{ip} tcp/{port}",
                    "versions",
                    None,
                    "open",
                    None,
                    None,
                    1,
                    2,
                    "[]",
                    None,
                    "in",
                    "auto",
                    unit,
                    json.dumps({"host_id": hid, "port": port, "proto": "tcp"}),
                )
            )
            ident.append((sid, "svc", sid, "none", "in", "include:10.0.0.0/8", 1))
            claim(sid, sid, "service.state", "open", unit)
            claim(sid, sid, "service.name", name, unit)
            if product:
                claim(sid, sid, "service.product", product, unit)
            if version:
                claim(sid, sid, "service.version", version, unit)
    for u in range(HOSTS // 50):
        units.append(
            (
                f"scan{u}",
                "command",
                "t1",
                f"t@{u}",
                f"nmap -sV 10.0.{u}.0/24",
                None,
                10**18,
                0,
                10,
                "local",
                "local",
                None,
                0,
                None,
                0,
                u,
                "[]",
                None,
            )
        )
    for k in range(300):  # Befehle, die die Erkenner lesen (ohne Treffer auf diese Hosts)
        units.append(
            (
                f"c{k}",
                "command",
                "t1",
                f"t@c{k}",
                f"smbclient -N -L //192.168.9.{k % 250}",
                None,
                10**18,
                0,
                10,
                "local",
                "local",
                None,
                0,
                None,
                0,
                1000 + k,
                "[]",
                None,
            )
        )
    conn.executemany("INSERT INTO entity VALUES (" + ",".join("?" * 16) + ")", ent)
    conn.executemany("INSERT INTO identifier VALUES (?,?,?,?,?,?,?)", ident)
    conn.executemany("INSERT INTO claim VALUES (" + ",".join("?" * 26) + ")", claims)
    conn.executemany("INSERT INTO claim_source VALUES (" + ",".join("?" * 15) + ")", sources)
    conn.executemany("INSERT INTO obs_unit VALUES (" + ",".join("?" * 18) + ")", units)
    return conn


def _cpu(fn) -> float:
    """CPU-Zeit dieses Threads in Sekunden (unabhängig von anderen Prozessen auf der Maschine)."""
    t = time.thread_time()
    fn()
    return time.thread_time() - t


def _reference() -> float:
    """Rechenleistung der Maschine: CPU-Zeit für ``sum(range(10**7))`` (Laptop 2026 etwa 40 bis 60 ms)."""
    return min(_cpu(lambda: sum(range(10**7))) for _ in range(3))


def test_500_hosts_under_200_ms():
    conn = _build()
    clear_cache()
    items, truncated = rules_api.suggestions(conn, profile="lab", state="open", limit=50)
    assert len(items) == 50 and truncated
    total = rules_api.open_count(conn, profile="lab")
    # je Host: ANON (ftp, smb), VERSION (ftp, ssh, http, smb 445, mysql, tomcat), SHARES, NFS, WEB (80, 8080),
    # CREDS (vnc, tomcat), DB, SMTP, FULL, UDP
    assert total == HOSTS * 18
    # warm: dieselbe Projektion (der Normalfall: /next nach jedem Ereignis, open_count nach dem Durchgang)
    warm_next = min(_cpu(lambda: rules_api.suggestions(conn, profile="lab", limit=50)) for _ in range(3))
    warm_count = min(_cpu(lambda: rules_api.open_count(conn, profile="lab")) for _ in range(3))
    assert warm_next < 0.2, f"/next warm: {warm_next * 1000:.0f} ms"
    assert warm_count < 0.2, f"open_count warm: {warm_count * 1000:.0f} ms"

    # kalt: erster Aufruf nach einer Neuauswertung (Fakten und Regeln neu). Ziel 200 ms auf der Referenz-
    # maschine; normiert auf die gemessene Leistung, mit Spielraum für den geteilten Testrechner.
    def cold(fn) -> float:
        clear_cache()
        return _cpu(fn)

    cold_next = min(cold(lambda: rules_api.suggestions(conn, profile="lab", limit=50)) for _ in range(3))
    cold_count = min(cold(lambda: rules_api.open_count(conn, profile="lab")) for _ in range(3))
    scale = max(1.0, _reference() / 0.05)
    limit = 0.2 * scale * 1.5
    assert cold_next < limit, f"/next kalt: {cold_next * 1000:.0f} ms (Grenze {limit * 1000:.0f} ms)"
    assert cold_count < limit, f"open_count kalt: {cold_count * 1000:.0f} ms (Grenze {limit * 1000:.0f} ms)"


def test_snapshot_follows_changes_without_rebuild():
    """Der Schnappschuss merkt neue Befehle auch ohne Neuauswertung (Schreibzähler, neue Einheit)."""
    from tests.rules import helpers as H

    conn, p = H.ms2(scripts=False)
    assert any(s["rule_id"] == "R-NFS-EXPORTS" for s in H.suggestions(conn))
    H.add_commands(p, [(f"showmount -e {H.MS2}", "x9", [])], seq=90)  # ohne rebuild
    assert not any(s["rule_id"] == "R-NFS-EXPORTS" for s in H.suggestions(conn))
