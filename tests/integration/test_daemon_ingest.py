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
from ariadne.ingest.schema_claims import CLAIMS_VERSION
from tests.core.fakeshim import FakeShim, close_all, ctl, ctl_ok
from tests.integration.helpers import LHOST, TARGET, Term, ms2

FAKE_IP = f"""#!/bin/sh
echo "$3 via 10.0.2.2 dev tun0 src {LHOST} uid 1000"
echo "    cache"
"""


async def _fake_clock() -> dict[str, Any]:
    return {"detail": "test"}


def run(paths, operator, scenario, **kw: Any) -> None:
    kw.setdefault("local_addrs", lambda: None)  # hermetisch: nie die Adressen des Testrechners

    async def main() -> None:
        d = Daemon(paths, check_peer_comm=False, operator=operator, batch_interval=0.02,
                   clock_check=_fake_clock, ingest=IngestService(debounce=0.05, periodic=0), **kw)
        await d.start()
        try:
            await scenario(d)
        finally:
            await d.stop()
            await close_all()

    asyncio.run(main())


def test_run_never_reads_local_addresses_of_the_test_machine(paths, operator):
    """Befund F8: Integrationstests lesen nie /proc des Testrechners (wie tests/core)."""

    async def scenario(d: Daemon) -> None:
        assert d._read_addrs is not None and d._read_addrs() is None

    run(paths, operator, scenario)


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
    """Projekt anlegen; läuft mit altem (REC-Schalter) und neuem Daemon (Daueraufnahme)."""
    res = await ctl_ok(paths.ctl_sock, "project.new", slug="lame", targets=[TARGET])
    ws = Path(res["workspace"])
    shim = await FakeShim(paths.term_sock).connect()
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
        # «~/…» hat die Shell ersetzt, argv aus dem Marker zeigt es noch: Pfad im eigenen Home
        (paths.home / "privat").mkdir(exist_ok=True)
        (paths.home / "privat" / "t.xml").write_bytes(ms2("xml"))
        await term.command(f"nmap -oX ~/privat/t.xml {TARGET}", b"done\r\n", cwd=cwd)
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
        # Drei-Spuren-Regel (Profil lab): nmap im Scope geht direkt auf die Karte
        assert hosts[TARGET]["scope"] == "in" and hosts[TARGET]["claim_state"] == "auto"
        assert svcs[(21, "tcp")]["claim_state"] == "auto"
        assert LHOST not in hosts  # eigene Adresse (net.route) wird nie Host

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
        assert reasons == {"o.xml": "outside_workspace", "t.xml": "outside_workspace", "link.xml": "symlink"}
        assert str(paths.home / "privat" / "t.xml") in {p["path"] for p in pend}

        tl = (await ctl_ok(paths.ctl_sock, "show", what="timeline"))["items"]
        nmap_rows = [e for e in tl if e["type"] == "command" and (e["title"] or "").startswith("nmap -sV")]
        assert nmap_rows and nmap_rows[0]["src_ip"] == LHOST and nmap_rows[0]["context"] == "Kali"
        nmap_row = nmap_rows[0]
        assert nmap_row["adopted"] >= 50 and not nmap_row["distrusted"]
        assert nmap_row["cmd_ref"] == f"{shim.terminal_id[-8:]}@{nmap_row['cmd_id'].rpartition('@')[2]}"
        assert any(e["type"] == "file" and e["title"] == "scans/lame.xml" for e in tl)

        # Nichts zu entscheiden: kein Eintrag für den nmap-Lauf (vorher eine Gruppe pro Lauf)
        res = await ctl_ok(paths.ctl_sock, "show", what="inbox")
        assert [g for g in res["items"] if g["kind"] in ("candidate_group", "decide_value")] == []
        assert set(res["quiet"]) >= {"heuristic", "out_of_scope", "mentions", "system_accounts"}

        # Einzelnen Claim bestätigen und verwerfen (Präfix)
        cid = (await ctl_ok(paths.ctl_sock, "search", text="vsftpd 2.3.4"))["items"]
        assert cid
        claims_ = await d.ingest.query(lambda c: c.execute(
            "SELECT claim_key, predicate FROM claim WHERE predicate = 'service.product' "
            "AND state = 'auto' ORDER BY claim_key").fetchall())
        res = await ctl_ok(paths.ctl_sock, "claim.confirm", ref=claims_[0][0][:12])
        assert res["confirmed"] == 1 and res["claims"][0]["state"] == "confirmed" and not res["group"]
        res = await ctl_ok(paths.ctl_sock, "claim.reject", ref=claims_[1][0][:10])
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

        # Reparse: gleiche Claims, auto und Entscheide bleiben, nichts verwaist
        diff = await ctl_ok(paths.ctl_sock, "reparse")
        assert diff["added"] == 0 and diff["removed"] == 0 and diff["changed"] == 0, diff
        assert diff["orphans"] == [] and diff["claims_after"] == diff["claims_before"] > 0
        assert diff["auto"] > 50
        hosts = {h["label"]: h for h in (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"]}
        svcs = {(sv["port"], sv["proto"]): sv for sv in hosts[TARGET]["services"]}
        assert hosts[TARGET]["claim_state"] == "auto"
        assert "confirmed" in {sv["claim_state"] for sv in svcs.values()}
        vault = d.project.info.vault
        assert not (vault / "derived.reparse.db").exists()

        # Rückgängig pro Befehl (A2): Werte nur aus diesem nmap-Lauf (Text und Begleitdateien) fallen weg
        res = await ctl_ok(paths.ctl_sock, "unit.distrust", ref=nmap_row["cmd_ref"], reason="falsches Ziel")
        assert res["cmd_id"] == nmap_row["cmd_id"] and res["rejected"] >= 50 and res["weakened"] == 0
        state = await d.ingest.query(lambda c: c.execute(
            "SELECT state, lane FROM claim WHERE claim_key = ?", (claims_[0][0],)).fetchone())
        assert tuple(state) == ("rejected", "user")  # der spätere Entscheid gilt (auch gegen confirm)
        tl = (await ctl_ok(paths.ctl_sock, "show", what="timeline"))["items"]
        row = next(e for e in tl if e.get("cmd_id") == nmap_row["cmd_id"])
        assert row["distrusted"] and row["adopted"] == 0
        svcs = {h["label"]: h for h in (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"]}
        assert all(sv["claim_state"] != "auto" for sv in svcs.get(TARGET, {}).get("services", []))
        diff = await ctl_ok(paths.ctl_sock, "reparse")  # übersteht Reparse
        assert diff["added"] == 0 and diff["removed"] == 0 and diff["changed"] == 0, diff
        dis = next(d.project.journal.iter_events(kinds=["d.unit.distrust"]))
        assert dis.header == {"cmd_id": nmap_row["cmd_id"], "reason": "falsches Ziel"}
        assert res["decision_id"] == dis.id  # zum Aufheben mit d.revoke (Web-API)
        bad = await ctl(paths.ctl_sock, "unit.distrust", ref="ffffffff@1")
        assert not bad["ok"] and bad["error"]["code"] == "not_found"
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


def test_companion_file_with_own_secret_is_redacted(paths, operator, tmp_path):
    """E72: Begleitdateien werden vollständig (verschlüsselt) gespeichert; eigene Secrets
    ersetzt erst der Ausgang (``show``, ``search``) über ``redact_json``."""
    from tests.core.conftest import OWN_SECRET

    async def scenario(d: Daemon) -> None:
        shim, term, ws = await _start(paths)
        args = b"-sV --script-args creds.global=admin:" + OWN_SECRET.encode() + b" -oA scans/lame"
        xml = ms2("xml").replace(b"-sV -oA scans/lame", args)
        assert OWN_SECRET.encode() in xml
        (ws / "scans" / "lame.xml").write_bytes(xml)
        await term.command(f"nmap -sV -oA scans/lame {TARGET}", b"Nmap done\r\n", cwd=str(ws))
        await term.mark("A", cwd=str(ws))
        await term.acked()
        await ctl_ok(paths.ctl_sock, "show", what="hosts")
        rec = next(r for r in d.project.journal.iter_events(kinds=["file.observed"])
                   if r.header["path"] == "scans/lame.xml")
        assert not rec.header.get("redactions")  # nicht mehr vor dem Speichern geschwärzt
        blob = d.project.blobs.open_bytes(rec.header["blob_id"])
        assert blob == xml
        hits = (await ctl_ok(paths.ctl_sock, "search", text="creds.global"))["items"]
        assert hits and all(OWN_SECRET not in h["text"] for h in hits)
        assert any("*" * len(OWN_SECRET) in h["text"] for h in hits)
        for what in ("hosts", "services", "timeline", "inbox"):
            res = await ctl_ok(paths.ctl_sock, "show", what=what)
            assert OWN_SECRET not in repr(res), what
        await shim.close()

    run(paths, operator, scenario)


def test_shred_overwrites_before_unlink(tmp_path):
    from ariadne.daemon.ingest import _shred

    f = tmp_path / "old.db"
    f.write_bytes(b"klartext" * 1000)
    keep = os.open(f, os.O_RDONLY)  # zweiter Verweis: Inhalt nach dem Löschen noch lesbar
    try:
        _shred(f)
        assert not f.exists()
        assert os.pread(keep, 8000, 0) == b"\0" * 8000
    finally:
        os.close(keep)


def test_projection_failure_keeps_recording_and_recovers(paths, operator, monkeypatch):
    """Fehler der Auswertung im Daemon-Pfad: Aufnahme und ACKs laufen weiter, ``show`` meldet
    den Fehler, nach Wegfall holt die Auswertung auf."""
    from ariadne.ingest import projection

    orig = projection.Projector.rebuild
    state = {"fail": True}

    def rebuild(self: Any) -> int:
        if state["fail"]:
            raise RuntimeError("kaputt")
        return orig(self)

    monkeypatch.setattr(projection.Projector, "rebuild", rebuild)

    async def scenario(d: Daemon) -> None:
        shim, term, ws = await _start(paths)
        await term.command(f"nmap -sV {TARGET}", ms2("text").replace(b"\n", b"\r\n"), cwd=str(ws))
        await term.mark("A", cwd=str(ws))
        await term.acked()
        res = await ctl_ok(paths.ctl_sock, "show", what="hosts")
        assert res["items"] == [] and res["ingest"]["last_error"] == "RuntimeError"
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["ingest"]["last_error"] == "RuntimeError"
        await term.command("id", b"uid=1000(kali)\r\n", cwd=str(ws))  # Aufnahme läuft weiter
        await term.mark("A", cwd=str(ws))
        await term.acked()
        state["fail"] = False
        res = await ctl_ok(paths.ctl_sock, "show", what="hosts")
        assert TARGET in {h["label"] for h in res["items"]} and res["ingest"]["last_error"] is None
        assert (await ctl_ok(paths.ctl_sock, "search", text="uid=1000"))["items"]
        await shim.close()

    run(paths, operator, scenario)


def test_two_terminals_interleaved_keep_their_context(paths, operator):
    """Mehrere Terminals gleichzeitig (Normalfall): Ströme, Kontexte und Redaktor getrennt."""
    from tests.core.conftest import OWN_SECRET

    async def scenario(d: Daemon) -> None:
        shim_a, a, ws = await _start(paths)
        shim_b = await FakeShim(paths.term_sock).connect()
        await shim_b.wait_state(rec="on")
        b = Term(shim_b)
        cwd = str(ws)
        await b.command("ssh root@10.10.10.5", b"Welcome\r\n", cwd=cwd, end=False)
        await b.request("req.ctx.set", host="10.10.10.5", user="root")
        await a.command("echo LOCAL-A-1", b"LOCAL-A-1\r\n", cwd=cwd)
        await a.out(b"pw: " + OWN_SECRET[:6].encode())  # Secret in A geteilt ...
        await b.out(b"REMOTE-B-1\r\nroot@target:~# ")  # ... während B Ausgabe und Events schickt
        await b.request("req.keystep", step="foothold")
        await a.out(OWN_SECRET[6:].encode() + b"\r\n")
        await a.command("echo LOCAL-A-2", b"LOCAL-A-2\r\n", cwd=cwd)
        await b.out(b"REMOTE-B-2\r\n")
        await b.mark("D", exit=0, cwd=cwd)  # ssh beendet: Segment fertig
        await b.mark("A", cwd=cwd)
        await a.mark("A", cwd=cwd)
        await a.acked()
        await b.acked()
        hits = {h["text"]: h for h in (await ctl_ok(paths.ctl_sock, "search", text="LOCAL"))["items"]}
        assert hits and all(h["context"] == "Kali" for h in hits.values())
        remote = (await ctl_ok(paths.ctl_sock, "search", text="REMOTE"))["items"]
        assert remote and all(h["context"].startswith("10.10.10.5") for h in remote)
        hits = (await ctl_ok(paths.ctl_sock, "search", text=OWN_SECRET[:6]))["items"]
        assert all(OWN_SECRET not in h["text"] for h in hits)  # Ausgang ersetzt eigene Secrets (E72)
        await shim_a.close()
        await shim_b.close()

    run(paths, operator, scenario)


class _FlakyReparse(IngestService):
    """Der erste Neuaufbau scheitert (Platte voll); der Bedarf darf nicht verloren gehen."""

    fails = 1

    def _reparse_job(self, snap: Any) -> dict[str, Any]:
        if self.fails:
            self.fails -= 1
            raise OSError("No space left on device")
        return super()._reparse_job(snap)


def test_redaction_reparse_retried_after_failure(paths, operator):
    async def scenario(d: Daemon) -> None:
        shim, term, ws = await _start(paths)
        await term.command("cat notes.txt", b"geheimnis-vom-ziel-42\r\n", cwd=str(ws))
        await term.mark("A", cwd=str(ws))
        await term.acked()
        assert (await ctl_ok(paths.ctl_sock, "search", text="geheimnis-vom-ziel-42"))["items"]
        outs = sorted(d.project.journal.iter_events(kinds=["term.out"]), key=lambda r: r.stream_off)
        stream = b"".join(r.body or b"" for r in outs)
        start = stream.index(b"geheimnis-vom-ziel-42")
        end = start + len(b"geheimnis-vom-ziel-42")
        for r in outs:
            if r.stream_off < end and r.stream_off + len(r.body or b"") > start:
                await ctl_ok(paths.ctl_sock, "redact", seq=r.seq, label="fremd", reason="Test")
        assert d.ingest is not None
        for _ in range(3):
            await d.ingest.sync()
        assert isinstance(d.ingest, _FlakyReparse) and d.ingest.fails == 0
        assert not (await ctl_ok(paths.ctl_sock, "search", text="geheimnis-vom-ziel-42"))["items"]
        await shim.close()

    async def main() -> None:
        d = Daemon(paths, check_peer_comm=False, operator=operator, batch_interval=0.02,
                   clock_check=_fake_clock, ingest=_FlakyReparse(debounce=0.05, periodic=0),
                   local_addrs=lambda: None)
        await d.start()
        try:
            await scenario(d)
        finally:
            await d.stop()
            await close_all()

    asyncio.run(main())


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


def test_scope_update_reaches_projection(paths, operator):
    from ariadne.project.settings import default_settings
    from ariadne.store.api import AppendItem

    async def scenario(d: Daemon) -> None:
        shim, term, ws = await _start(paths)
        await term.command(f"nmap -sV {TARGET}", ms2("text").replace(b"\n", b"\r\n"), cwd=str(ws))
        await term.mark("A", cwd=str(ws))
        await term.acked()
        hosts = {h["label"]: h for h in (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"]}
        assert hosts[TARGET]["scope"] == "in"
        toml = default_settings(name="lame", profile="lab", include=["10.10.10.0/24"])
        toml = toml.replace("exclude = []", f'exclude = ["{TARGET}"]')
        d.submit(AppendItem("d.scope.update", {"version": 2, "toml": toml}, origin="cli"))
        hosts = {h["label"]: h for h in (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"]}
        assert d.project.settings_version == 2
        assert hosts[TARGET]["scope"] == "excluded"
        await shim.close()

    run(paths, operator, scenario)


def test_callback_sets_auto_context_and_hotkey_overrides(paths, operator):
    """A7/E23: Der erste Callback auf eine Listener-Stufe setzt den Host im Live-Stapel
    (Titel ``(auto)``), ins Journal kommt nichts; ``ctx.set`` (wie F12 h) geht vor."""

    async def scenario(d: Daemon) -> None:
        shim, term, ws = await _start(paths)
        cwd = str(ws)
        await term.command("nc -lvnp 4444", b"listening on [any] 4444 ...\r\n"
                           + f"connect to [{LHOST}] from (UNKNOWN) [{TARGET}] 4711\r\n".encode()
                           + b"uid=33(www-data) gid=33(www-data)\r\n", cwd=cwd, end=False)
        await term.acked()
        tl = (await ctl_ok(paths.ctl_sock, "show", what="timeline"))["items"]
        label = ""
        for _ in range(50):
            label = (await ctl_ok(paths.ctl_sock, "ctx.show", terminal_id=shim.terminal_id))["label"]
            if "(auto)" in label:
                break
            await asyncio.sleep(0.05)
        assert label == f"{TARGET} revshell (auto)", label
        assert tl
        auto = await d.ingest.query(lambda c: c.execute("SELECT host FROM ctx_auto").fetchall())
        assert [tuple(r) for r in auto] == [(f"ip:default/{TARGET}",)]
        assert not [r for r in d.project.journal.iter_events(kinds=["d.ctx.set"])]
        inbox = (await ctl_ok(paths.ctl_sock, "show", what="inbox"))["items"]
        assert not [g for g in inbox if g["kind"] in ("ctx_unknown", "ctx_suggestion")]
        # F12 h: Entscheid des Nutzers überschreibt, rückwirkend für die Stufe
        await ctl_ok(paths.ctl_sock, "ctx.set", terminal_id=shim.terminal_id, host="10.10.10.9")
        await ctl_ok(paths.ctl_sock, "show", what="hosts")
        label = (await ctl_ok(paths.ctl_sock, "ctx.show", terminal_id=shim.terminal_id))["label"]
        assert "(auto)" not in label and "10.10.10.9" in label
        auto = await d.ingest.query(lambda c: c.execute("SELECT COUNT(*) FROM ctx_auto").fetchone()[0])
        assert auto == 0
        # zweites Terminal: Sitzung beendet, die Zeitachse zeigt den Kontext mit (auto)
        shim2 = await FakeShim(paths.term_sock).connect()
        await shim2.wait_state(rec="on")
        t2 = Term(shim2)
        await t2.command("nc -lvnp 5555", b"listening on [any] 5555 ...\r\n"
                         + f"connect to [{LHOST}] from (UNKNOWN) [{TARGET}] 4712\r\n".encode()
                         + b"whoami\r\nwww-data\r\n", cwd=cwd)
        await t2.mark("A", cwd=cwd)
        await t2.acked()
        tl = (await ctl_ok(paths.ctl_sock, "show", what="timeline"))["items"]
        seg = [e for e in tl if e["type"] == "segment" and e["terminal_id"] == shim2.terminal_id]
        assert seg and seg[0]["context"] == f"{TARGET} [revshell] (auto)", seg
        hits = (await ctl_ok(paths.ctl_sock, "search", text="www-data"))["items"]
        assert any(h["context"] == f"{TARGET} [revshell] (auto)" for h in hits), hits
        await shim2.close()
        await shim.close()

    run(paths, operator, scenario)


def test_stale_derived_db_is_rebuilt_before_queries(paths, operator):
    """Schema von derived.db älter als der Code: beim Anhängen neu bauen (wie Reparse)."""

    async def scenario(d: Daemon) -> None:
        shim, term, ws = await _start(paths)
        await term.command(f"nmap -sV {TARGET}", ms2("text").replace(b"\n", b"\r\n"), cwd=str(ws))
        await term.mark("A", cwd=str(ws))
        await term.acked()
        before = (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"]
        assert before
        ing = d.ingest
        assert ing is not None and d.project is not None
        ing.detach()
        conn = d.project.connect_derived()
        try:  # alte Datei nachstellen: Version 1, ohne neue Spalten
            conn.execute("UPDATE meta SET value = '1' WHERE key = 'schema_claims_version'")
            conn.execute("DROP VIEW v_claim")
            conn.execute("ALTER TABLE claim DROP COLUMN group_key")
            conn.commit()
        finally:
            conn.close()
        ing.attach(d.project)
        after = (await ctl_ok(paths.ctl_sock, "show", what="hosts"))["items"]
        assert after == before
        conn = d.project.connect_derived(readonly=True)
        try:
            row = conn.execute("SELECT value FROM meta WHERE key = 'schema_claims_version'").fetchone()
            assert tuple(row) == (str(CLAIMS_VERSION),)
        finally:
            conn.close()
        await shim.close()

    run(paths, operator, scenario)
