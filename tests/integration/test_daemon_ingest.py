"""Daemon mit eingebauter Auswertung: Fake-Shim über echte Sockets, echte Pipeline,
echte Parser in Worker-Prozessen, echte SQLCipher-Datenbanken.

Geprüft wird die Verdrahtung: Commit-Hook -> Pipeline, Mark-Hook -> Begleitdateien
und ``net.route``, die Ansichten der CLI-Operationen, Entscheide, Import und Reparse.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import pytest

from ariadne.daemon.core import Daemon
from ariadne.daemon.ingest import IngestService
from tests.core.fakeshim import FakeShim, ctl, ctl_ok
from tests.integration.helpers import LHOST, TARGET, Term, ms2

FAKE_IP = f"""#!/bin/sh
echo "$3 via 10.0.2.2 dev tun0 src {LHOST} uid 1000"
echo "    cache"
"""


async def _fake_clock() -> dict[str, Any]:
    return {"detail": "test"}


def run(paths, operator, scenario, **kw: Any) -> None:
    async def main() -> None:
        d = Daemon(paths, check_peer_comm=False, operator=operator, batch_interval=0.02,
                   clock_check=_fake_clock, ingest=IngestService(debounce=0.05, periodic=0), **kw)
        await d.start()
        try:
            await scenario(d)
        finally:
            await d.stop()

    asyncio.run(main())


@pytest.fixture
def fake_ip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    ip = bindir / "ip"
    ip.write_text(FAKE_IP)
    ip.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    return ip


async def _start(paths) -> tuple[FakeShim, Term, Path]:
    res = await ctl_ok(paths.ctl_sock, "project.new", slug="lame", targets=[TARGET])
    ws = Path(res["workspace"])
    shim = await FakeShim(paths.term_sock).connect()
    await shim.wait_state(rec="off")
    await ctl_ok(paths.ctl_sock, "rec.on")
    await shim.wait_state(rec="on")
    return shim, Term(shim), ws


def test_nmap_flow_companions_routes_views_and_decisions(paths, operator, fake_ip, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()

    async def scenario(d: Daemon) -> None:
        shim, term, ws = await _start(paths)
        cwd = str(ws)
        # nmap -oA schreibt drei Dateien; der Befehl gibt die Normalausgabe aus
        (ws / "scans" / "lame.xml").write_bytes(ms2("xml"))
        (ws / "scans" / "lame.nmap").write_bytes(ms2("text"))
        (ws / "scans" / "lame.gnmap").write_bytes(b"# Nmap done\n")
        await term.command(f"nmap -sV -oA scans/lame {TARGET}", ms2("text").replace(b"\n", b"\r\n"), cwd=cwd)
        # Datei ausserhalb des Arbeitsbereichs: nur Warteliste
        (outside / "o.xml").write_bytes(ms2("xml"))
        await term.command(f"nmap -oX {outside}/o.xml {TARGET}", b"done\r\n", cwd=cwd)
        # Symlink im Arbeitsbereich: wird nie gelesen
        os.symlink("/etc/hostname", ws / "scans" / "link.xml")
        await term.command(f"nmap -oX scans/link.xml {TARGET}", b"done\r\n", cwd=cwd)
        await term.mark("A", cwd=cwd)
        await term.acked()

        res = await ctl_ok(paths.ctl_sock, "show", what="hosts")
        hosts = {h["label"]: h for h in res["items"]}
        assert TARGET in hosts, hosts.keys()
        svcs = {(s["port"], s["proto"]): s for s in hosts[TARGET]["services"]}
        assert svcs[(21, "tcp")]["product"] == "vsftpd" and svcs[(21, "tcp")]["version"] == "2.3.4"
        assert len(svcs) >= 20
        assert hosts[TARGET]["scope"] == "in" and hosts[TARGET]["claim_state"] == "candidate"

        j = d.project.journal
        files = [r for r in j.iter_events(kinds=["file.observed"])]
        by_path = {r.header["path"]: r.header for r in files}
        assert set(by_path) == {"scans/lame.xml", "scans/lame.nmap", "scans/lame.gnmap"}
        assert all(h["origin"] == "companion" and h["produced_by_cmd"].startswith(shim.terminal_id + "@")
                   for h in by_path.values())
        assert by_path["scans/lame.xml"]["sniff"] == "nmaprun" and by_path["scans/lame.xml"]["blob_id"]
        routes = [r.header for r in j.iter_events(kinds=["net.route"])]
        assert routes and routes[0]["target"] == TARGET and routes[0]["src_ip"] == LHOST
        assert routes[0]["dev"] == "tun0" and routes[0]["via"] == "10.0.2.2"

        pend = (await ctl_ok(paths.ctl_sock, "show", what="pending"))["items"]
        reasons = {Path(p["path"]).name: p["reason"] for p in pend}
        assert reasons == {"o.xml": "outside_workspace", "link.xml": "symlink"}

        tl = (await ctl_ok(paths.ctl_sock, "show", what="timeline"))["items"]
        nmap_rows = [e for e in tl if e["type"] == "command" and (e["title"] or "").startswith("nmap -sV")]
        assert nmap_rows and nmap_rows[0]["src_ip"] == LHOST and nmap_rows[0]["context"] == "Kali"
        assert any(e["type"] == "file" and e["title"] == "scans/lame.xml" for e in tl)

        inbox = (await ctl_ok(paths.ctl_sock, "show", what="inbox"))["items"]
        groups = [g for g in inbox if g["kind"] == "candidate_group"]
        nmap_group = next(g for g in groups if g["title"].startswith(f"nmap -sV -oA scans/lame {TARGET}"))
        assert nmap_group["summary"]["services"] >= 20

        # Sammelbestätigung über den kurzen Gruppenverweis
        res = await ctl_ok(paths.ctl_sock, "claim.confirm", ref=nmap_group["ref"])
        assert res["confirmed"] == len(nmap_group["items"])
        assert all(c["state"] == "confirmed" for c in res["claims"])
        hosts = {h["label"]: h for h in (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"]}
        assert hosts[TARGET]["claim_state"] == "confirmed"

        assert not [g for g in (await ctl_ok(paths.ctl_sock, "show", what="inbox"))["items"]
                    if g["kind"] == "candidate_group"]

        # Einzelnen Claim über ein Präfix verwerfen
        some = next(c for c in res["claims"] if c["predicate"] == "service.product")
        res = await ctl_ok(paths.ctl_sock, "claim.reject", ref=some["claim_key"][:10])
        assert res["claims"][0]["state"] == "rejected"
        bad = await ctl(paths.ctl_sock, "claim.confirm", ref="g00000000")
        assert not bad["ok"] and bad["error"]["code"] == "not_found"

        # Schlüsselschritt über die CLI-Operation, mit Terminal
        res = await ctl_ok(paths.ctl_sock, "keystep.mark", step="foothold", host=TARGET,
                           terminal_id=shim.terminal_id, note="ftp")
        assert res["host"] == f"ip:default/{TARGET}" and res["terminal"]
        ks = (await ctl_ok(paths.ctl_sock, "show", what="keysteps"))["items"]
        assert [(k["step"], k["host"]) for k in ks] == [("foothold", TARGET)]
        hosts = {h["label"]: h for h in (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"]}
        assert hosts[TARGET]["access"] == "user"

        # Volltextsuche über die Ausgabe
        hits = (await ctl_ok(paths.ctl_sock, "search", text="vsftpd 2.3.4"))["items"]
        assert hits and all("vsftpd" in h["text"].lower() for h in hits)

        # Reparse: gleiche Claims, Entscheide bleiben, nichts verwaist
        diff = await ctl_ok(paths.ctl_sock, "reparse")
        assert diff["added"] == 0 and diff["removed"] == 0 and diff["changed"] == 0, diff
        assert diff["orphans"] == [] and diff["claims_after"] == diff["claims_before"] > 0
        hosts = {h["label"]: h for h in (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"]}
        assert hosts[TARGET]["claim_state"] == "confirmed"
        vault = d.project.info.vault
        assert not (vault / "derived.reparse.db").exists()
        await shim.close()

    run(paths, operator, scenario)


def test_import_and_redaction_rebuilds_index(paths, operator, tmp_path):
    loot = tmp_path / "loot"
    loot.mkdir()
    (loot / "passwd").write_bytes(b"root:x:0:0:root:/root:/bin/bash\n"
                                  b"msfadmin:x:1000:1000::/home/msfadmin:/bin/sh\n")
    os.symlink(loot / "passwd", loot / "link")

    async def scenario(d: Daemon) -> None:
        shim, term, ws = await _start(paths)
        res = await ctl_ok(paths.ctl_sock, "import", path=str(loot / "passwd"), host=TARGET)
        assert res["stored"] and res["path"] == str(loot / "passwd")
        rec = next(d.project.journal.iter_events(kinds=["file.observed"]))
        assert rec.header["origin"] == "import" and rec.header["host_hint"] == f"ip:default/{TARGET}"
        assert rec.header["rec"] is True and rec.origin == "cli"
        for bad, code in ((loot / "link", "unsafe_file"), (paths.home / ".ssh" / "id_rsa", "unsafe_file"),
                          (tmp_path / "missing", "unsafe_file")):
            r = await ctl(paths.ctl_sock, "import", path=str(bad))
            assert not r["ok"] and r["error"]["code"] == code, (bad, r)
        hits = (await ctl_ok(paths.ctl_sock, "search", text="msfadmin"))["items"]
        assert hits and hits[0]["context"].startswith(TARGET)

        # Ausgabe mit einem Fremdwert aufnehmen, dann schwärzen: der Index wird neu gebaut
        await term.command("cat notes.txt", b"geheimnis-vom-ziel-42\r\n", cwd=str(ws))
        await term.mark("A", cwd=str(ws))
        await term.acked()
        assert (await ctl_ok(paths.ctl_sock, "search", text="geheimnis-vom-ziel-42"))["items"]
        outs = sorted(d.project.journal.iter_events(kinds=["term.out"]), key=lambda r: r.stream_off)
        stream = b"".join(r.body or b"" for r in outs)
        start = stream.index(b"geheimnis-vom-ziel-42")
        end = start + len(b"geheimnis-vom-ziel-42")
        hit = [r for r in outs if r.stream_off < end and r.stream_off + len(r.body or b"") > start]
        for r in hit:  # der Redaktor-Rückhalt kann den Wert auf zwei Chunks verteilen
            await ctl_ok(paths.ctl_sock, "redact", seq=r.seq, label="fremd", reason="Test")
        assert not (await ctl_ok(paths.ctl_sock, "search", text="geheimnis-vom-ziel-42"))["items"]
        assert (await ctl_ok(paths.ctl_sock, "search", text="msfadmin"))["items"]
        assert (await ctl_ok(paths.ctl_sock, "verify"))["ok"]
        await shim.close()

    run(paths, operator, scenario)


def test_show_without_project_and_bad_view(paths, operator):
    async def scenario(d: Daemon) -> None:
        r = await ctl(paths.ctl_sock, "show", what="hosts")
        assert not r["ok"] and r["error"]["code"] == "no_project"
        await ctl_ok(paths.ctl_sock, "project.new", slug="leer", targets=[TARGET])
        r = await ctl(paths.ctl_sock, "show", what="secrets")
        assert not r["ok"] and r["error"]["code"] == "invalid"
        assert (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"] == []
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["ingest"]["active"] and st["ingest"]["last_error"] is None

    run(paths, operator, scenario)
