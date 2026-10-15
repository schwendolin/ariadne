"""End-to-End: der neue Alltag mit Daueraufnahme und Drei-Spuren-Regel (E22, E42, E95, E96).

Echte zsh mit Shim, echter Daemon-Prozess mit Auswertung, CLI per Subprozess.
Fixture-Netz ist Metasploitable2 (``tests/golden``): Ziel 192.168.56.101, Kali
192.168.56.102 im selben Netz. Ein Fake-``nmap`` gibt die Golden-Ausgabe aus und
schreibt bei ``-oA`` die Golden-XML; ``ip route get`` nennt Kali als Quelle.

* :func:`test_two_terminals_auto_map_pause_undo_stop`: ``ariadne start lab1 --target
  192.168.56.0/24 --passphrase-fd``, zwei parallele Terminals, nmap, Callback mit
  Kontext ``(auto)``, Karte ``auto``, Inbox leer, keine Kali-Adresse als Host,
  verschränkte Zeitstempel, ``F12 r`` nur in einem Terminal, ``ariadne undo``,
  ``ariadne stop`` sperrt.
* :func:`test_preroll_question_in_terminal_adopts_both_terminals`: ohne Projekt
  arbeiten, dann ``ariadne start`` im Terminal selbst (Passphrase per ``getpass``,
  Frage «Die letzten N Minuten aus K Terminals übernehmen? [j/N]»), Vorlauf beider
  Terminals mit Original-Zeiten im Projekt, Passphrase nirgends gespeichert.
"""

from __future__ import annotations

import re
import shutil
import sys
import time

import pytest

from ariadne.crypto.vault import OperatorVault
from ariadne.project.service import ProjectService
from tests.e2e.helpers import PASSPHRASE, PROMPT, Lab, expect_title, hotkey, run_cmd, scan
from tests.integration.helpers import GOLDEN

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.pty,
    pytest.mark.skipif(shutil.which("zsh") is None, reason="zsh fehlt"),
]

NET = "192.168.56.0/24"
TARGET = "192.168.56.101"
KALI = "192.168.56.102"
CLI = f"{sys.executable} -m ariadne.cli.main"


@pytest.fixture
def lab(lab: Lab) -> Lab:
    lab.tools((GOLDEN / "nmap.xml" / "ms2_sv_sc" / "input.xml").read_bytes(),
              (GOLDEN / "nmap.text" / "ms2_sv_sc" / "input.txt").read_bytes(), target=TARGET, lhost=KALI)
    lab.setup()
    return lab


def _host_lines(hosts: str) -> list[str]:
    return [ln for ln in hosts.splitlines() if ln and not ln.startswith(" ")]


def _journal(lab: Lab, slug: str):  # type: ignore[no-untyped-def]
    """Eigene Entsperrung bei gestopptem Daemon; gibt (Operator, Projekt) zurück."""
    op = OperatorVault(lab.paths.operator_dir).unlock(PASSPHRASE)
    return op, ProjectService(lab.paths, op).open(slug)


def test_two_terminals_auto_map_pause_undo_stop(lab: Lab) -> None:
    # Nach einem Neustart der VM: gesperrt, kein Projekt. Einmal start mit Passphrase.
    assert "Gesperrt." in lab.cli("lock")
    out = lab.cli("start", "lab1", "--target", NET, "--preroll", "no", secret=PASSPHRASE)
    assert "Entsperrt." in out and "Projekt lab1 angelegt" in out and "Aufnahme läuft" in out, out
    t1, t2 = lab.terminal(), lab.terminal()
    for c in (t1, t2):
        expect_title(c, rb"\[REC lab1\]")
    lab.wait_status("2 verbunden, 2 nehmen auf")
    for c in (t1, t2):
        run_cmd(c, "cd ~/ariadne/lab1")

    # ---- Arbeit in zwei Terminals, abwechselnd --------------------------------------
    out = run_cmd(t1, f"nmap -sV -sC -oA scans/ms2 {TARGET}")
    assert "vsftpd 2.3.4" in out
    run_cmd(t2, "echo zwei-$((1+1))")
    run_cmd(t1, "echo drei-$((1+2))")
    run_cmd(t2, "echo vier-$((2+2))")

    # ---- F12 r pausiert nur dieses Terminal -----------------------------------------
    hotkey(t1, b"r")
    expect_title(t1, rb"\[PAUSE 10 min lab1\]")
    st = lab.wait_status("Pause bis")
    assert len(re.findall(r"nimmt auf", st)) == 1 and "1 nehmen auf" in st, st
    run_cmd(t1, "echo heimlich-$((3+3))")
    run_cmd(t2, "echo offen-$((3+4))")
    hotkey(t1, b"r")
    expect_title(t1, rb"\[REC lab1\]")
    lab.wait_status("2 nehmen auf")
    run_cmd(t1, "echo fuenf-$((2+3))")

    # ---- Reverse Shell in T2: Kontext aus dem ersten Callback (E23) -----------------
    t2.sendline("nc -lvnp 4444")
    t2.expect_exact(f"from (UNKNOWN) [{TARGET}] 49152")
    t2.expect_exact("$ ")
    expect_title(t2, rb"\[REC lab1\] " + re.escape(TARGET.encode()) + rb" revshell \(auto\)")
    t2.sendline("id")
    t2.expect_exact("uid=33(www-data)")
    t2.expect_exact("$ ")
    t2.sendline("exit")
    t2.expect_exact(PROMPT)

    # ---- Karte: Hosts und Services auto, keine Kali-Adresse als Host ----------------
    hosts = lab.cli("show", "hosts")
    heads = _host_lines(hosts)
    assert any(ln.startswith(f"{TARGET}  [auto, in Scope]") for ln in heads), hosts
    assert not any(KALI in ln for ln in heads), hosts
    for svc in (r"21/tcp\s+open\s+ftp\s+vsftpd 2\.3\.4\s+\(auto\)",
                r"22/tcp\s+open\s+ssh\s+OpenSSH 4\.7p1.*\(auto\)"):
        assert re.search(r"^  " + svc, hosts, re.M), (svc, hosts)
    services = lab.cli("show", "services")
    assert KALI not in services and services.count("(auto)") >= 20, services
    inbox = lab.cli("show", "inbox")
    assert "Inbox leer." in inbox, inbox
    assert "Kontext klären" not in inbox and "Konflikt" not in inbox, inbox

    # Ausgaben der Reverse Shell gehören zum Host aus dem Callback
    hits = lab.cli("search", "uid=33")
    assert re.search(rf"{re.escape(TARGET)} \[revshell\] \(auto\)\s+uid=33\(www-data\)", hits), hits
    assert "Keine Treffer." in lab.cli("search", "heimlich-6")
    assert "offen-7" in lab.cli("search", "offen-7")

    # ---- Zeitachse: beide Terminals nach Shim-Zeit verschränkt ----------------------
    timeline = lab.cli("show", "timeline")
    order = [f"nmap -sV -sC -oA scans/ms2 {TARGET}", "echo zwei-", "echo drei-", "echo vier-",
             "echo offen-", "echo fuenf-", "nc -lvnp 4444"]
    pos = [timeline.find(x) for x in order]
    assert all(p >= 0 for p in pos) and pos == sorted(pos), (pos, timeline)
    m = re.search(r"^    nmap \d\d:\d\d: (\d+) Werte übernommen \(ariadne undo ([0-9a-f]{8}@\d+)\)$",
                  timeline, re.M)
    assert m and int(m.group(1)) >= 50, timeline
    ref = m.group(2)
    terms = [ln.split()[0] for ln in lab.cli("status").splitlines() if "nimmt auf" in ln]
    assert ref.split("@")[0] in terms, (ref, terms)  # dieselbe Kurz-ID wie in ariadne status

    # ---- ariadne undo verwirft die Werte dieses Befehls -----------------------------
    out = lab.cli("undo", ref, "--reason", "falsches Ziel")
    n = int(re.search(r"rückgängig gemacht: (\d+) Werte verworfen", out).group(1))  # type: ignore[union-attr]
    assert n >= 50, out
    hosts = lab.cli("show", "hosts")
    assert not re.search(r"vsftpd 2\.3\.4\s+\(auto\)", hosts), hosts
    assert f"nmap {m.group(0).split()[1]} rückgängig gemacht (Befehl {ref})" in lab.cli("show", "timeline")
    assert "Inbox leer." in lab.cli("show", "inbox")

    # ---- ariadne stop sperrt; die Terminals laufen ohne Projekt weiter --------------
    out = lab.cli("stop")
    assert "Projekt lab1 beendet und gesperrt" in out, out
    st = lab.cli("status")
    assert "Tresor:   gesperrt" in st and "Projekt:  -" in st, st
    for c in (t1, t2):
        expect_title(c, rb"\[kein Projekt \(Vorlauf 15 min\)\]")
    assert "Kein Projekt offen" in lab.cli("show", "hosts", check=False)
    for c in (t1, t2):
        c.sendline("exit")
    lab.close_terminals()
    assert lab.stop_daemon() == 0

    # ---- Journal direkt prüfen ------------------------------------------------------
    op, project = _journal(lab, "lab1")
    try:
        j = project.journal
        assert j.verify().ok
        tids = {r.header["terminal_id"] for r in j.iter_events(kinds=["term.open"])}
        assert len(tids) == 2
        marks = [r.header for r in j.iter_events(kinds=["term.mark"]) if r.header["mark"] == "C"]
        assert all(h.get("t_shim_ns") and h.get("mono_ns") for h in marks)
        by_mono = [h.get("cmd_typed") or "" for h in sorted(marks, key=lambda h: h["mono_ns"])]
        by_wall = [h.get("cmd_typed") or "" for h in sorted(marks, key=lambda h: h["t_shim_ns"])]
        assert by_mono == by_wall
        seen = [next(i for i, c in enumerate(by_mono) if c.startswith(x)) for x in order]
        assert seen == sorted(seen), by_mono
        assert len({h["terminal_id"] for h in marks}) == 2
        pauses = [r.header for r in j.iter_events(kinds=["term.pause"])]
        assert len(pauses) == 1 and pauses[0]["source"] == "hotkey"
        t1_id = pauses[0]["terminal_id"]
        streams: dict[str, bytes] = {}
        for r in sorted(j.iter_events(kinds=["term.out"]), key=lambda r: r.stream_off):
            streams[r.terminal_id] = streams.get(r.terminal_id, b"") + (r.body or b"")
        assert b"heimlich-6" not in streams[t1_id] and b"drei-3" in streams[t1_id]
        t2_id = next(t for t in tids if t != t1_id)
        assert b"offen-7" in streams[t2_id] and b"uid=33" in streams[t2_id]
        inputs = b"".join(r.body or b"" for r in j.iter_events(kinds=["term.input"]))
        assert b"heimlich" not in inputs and b"echo offen" in inputs and b"\x1b[24~" not in inputs
        distrust = [r.header for r in j.iter_events(kinds=["d.unit.distrust"])]
        assert len(distrust) == 1 and distrust[0]["cmd_id"].endswith("@" + ref.split("@")[1])
        assert distrust[0]["reason"] == "falsches Ziel"
        routes = [r.header for r in j.iter_events(kinds=["net.route"])]
        assert routes and {r["src_ip"] for r in routes} == {KALI}
        assert [r.header["reason"] for r in j.iter_events(kinds=["system.project_end"])] == ["stop"]
        assert "d.ctx.set" not in {r.kind for r in j.iter_events()}  # Auto-Kontext nie im Journal
    finally:
        project.close()
        op.wipe()
    assert scan(lab.home, [PASSPHRASE.encode()]) == []


def test_preroll_question_in_terminal_adopts_both_terminals(lab: Lab) -> None:
    lab.cli("lock")
    before_ns = time.time_ns()
    t1, t2 = lab.terminal(), lab.terminal()
    for c in (t1, t2):
        expect_title(c, rb"\[kein Projekt \(Vorlauf 15 min\)\]")
    lab.wait_status("2 verbunden, 0 nehmen auf")
    out = run_cmd(t1, f"nmap -sV -sC {TARGET}")  # vergessen zu starten: nur im RAM
    assert "vsftpd 2.3.4" in out
    run_cmd(t2, "echo vorlauf-$((5*5))")
    st = lab.wait_status("Vorlauf:  1 min aus 2 Terminals")
    assert "gesperrt" in st
    assert not (lab.home / "ariadne").exists()  # nichts auf der Platte, kein Projektordner

    # ariadne start im Terminal selbst: Passphrase per getpass, Frage nach dem Vorlauf
    start_ns = time.time_ns()
    t2.sendline(f"{CLI} start lab1 --target {NET}")
    t2.expect_exact("Passphrase: ")
    t2.sendline(PASSPHRASE)
    t2.expect_exact("Die letzten 1 Minuten aus 2 Terminals übernehmen? [j/N] ".encode())
    t2.sendline("j")
    t2.expect_exact("Vorlauf übernommen: 1 min aus 2 Terminals.".encode())
    t2.expect_exact(PROMPT)
    done_ns = time.time_ns()
    for c in (t1, t2):
        expect_title(c, rb"\[REC lab1\]")
    run_cmd(t1, "echo danach-$((6*7))")

    hosts = lab.cli("show", "hosts")
    assert any(ln.startswith(f"{TARGET}  [auto, in Scope]") for ln in _host_lines(hosts)), hosts
    assert re.search(r"^  21/tcp\s+open\s+ftp\s+vsftpd 2\.3\.4\s+\(auto\)", hosts, re.M), hosts
    assert not any(KALI in ln for ln in _host_lines(hosts)), hosts
    assert "vorlauf-25" in lab.cli("search", "vorlauf-25")
    assert "Inbox leer." in lab.cli("show", "inbox")
    timeline = lab.cli("show", "timeline")
    assert timeline.find(f"nmap -sV -sC {TARGET}") < timeline.find("echo vorlauf-") \
        < timeline.find("echo danach-"), timeline

    assert "beendet und gesperrt" in lab.cli("stop")
    for c in (t1, t2):
        c.sendline("exit")
    lab.close_terminals()
    assert lab.stop_daemon() == 0

    op, project = _journal(lab, "lab1")
    try:
        j = project.journal
        assert j.verify().ok
        pre = [r.header for r in j.iter_events(kinds=["term.preroll"])]
        assert len(pre) == 2 and all(before_ns <= h["t_first_ns"] < start_ns for h in pre), pre
        outs = list(j.iter_events(kinds=["term.out"]))
        adopted = [r for r in outs if r.origin == "preroll"]
        # Original-Zeiten: Shim-Zeit und Empfangszeit aus dem Vorlauf, nicht die Zeit der Übernahme
        assert adopted and all(before_ns <= r.header["t_shim_ns"] < done_ns for r in adopted)
        assert all(before_ns <= r.ts_utc_ns < done_ns for r in adopted)
        scan_out = [r for r in adopted if b"vsftpd 2.3.4" in (r.body or b"")]
        assert scan_out and all(r.header["t_shim_ns"] < start_ns and r.ts_utc_ns < start_ns
                                for r in scan_out)
        stream = b"".join(r.body or b"" for r in sorted(outs, key=lambda r: (r.terminal_id, r.stream_off)))
        assert b"vsftpd 2.3.4" in stream and b"vorlauf-25" in stream and b"danach-42" in stream
        marks = [r for r in j.iter_events(kinds=["term.mark"])
                 if (r.header.get("cmd_typed") or "").startswith("nmap ")]
        assert marks and marks[0].origin == "preroll"
        inputs = b"".join(r.body or b"" for r in j.iter_events(kinds=["term.input"]))
        assert f"nmap -sV -sC {TARGET}".encode() in inputs
        assert PASSPHRASE.encode() not in inputs + stream
    finally:
        project.close()
        op.wipe()
    assert scan(lab.home, [PASSPHRASE.encode()]) == []
    assert scan(lab.run, [PASSPHRASE.encode()]) == []
