"""Lokale Quellen im Daemon: ``ip route get`` auswerten, Ziele ohne DNS, Mark-Hook-Regeln."""

from __future__ import annotations

from types import SimpleNamespace

from ariadne.daemon.sources import LocalSources, _ip_targets, parse_route
from ariadne.daemon.terminal import MarkContext
from ariadne.store.api import EventRecord


def test_parse_route():
    out = "10.10.10.3 via 10.0.2.2 dev tun0 src 10.10.14.5 uid 1000 \n    cache \n"
    assert parse_route(out) == {"src_ip": "10.10.14.5", "dev": "tun0", "via": "10.0.2.2"}
    assert parse_route("192.168.56.101 dev vboxnet0 src 192.168.56.1 uid 1000") == {
        "src_ip": "192.168.56.1", "dev": "vboxnet0"}
    assert parse_route("local 127.0.0.1 dev lo src 127.0.0.1") == {"src_ip": "127.0.0.1", "dev": "lo"}
    # feindliche oder kaputte Werte fallen weg
    assert parse_route("x src not-an-ip dev $(reboot) via ;") is None
    assert parse_route("") is None


def test_ip_targets_never_names():
    assert _ip_targets(["nmap", "-sV", "10.10.10.3", "lame.htb", "10.10.10.0/24"]) == ["10.10.10.3"]
    assert _ip_targets(["ssh", "root@10.10.10.5"]) == ["10.10.10.5"]
    assert _ip_targets(["curl", "http://web.lab/"]) == []
    assert _ip_targets(["echo", "10.0.0.1"]) == []


def _rec(mark: str, **h) -> EventRecord:
    header = {"terminal_id": "t1", "stream_off": 10, "mark": mark, "counter": 1, "fg_shell": True, **h}
    return EventRecord(1, "id", "raw", "term.mark", 0, None, None, "op", "shim", "t1", 10, header, None)


def test_mark_hook_rules():
    d = SimpleNamespace(project=None, paths=None)
    src = LocalSources(d, routes=False)  # type: ignore[arg-type]
    local = MarkContext("t1", "p1", (), True, True)
    remote = MarkContext("t1", "p1", (), False, False)
    # ohne Kontext (kein Projekt) passiert nichts
    assert src.on_mark(_rec("C", cmd_typed="nmap -oA x 10.0.0.1", cwd="/w"), None) is None
    # C auf Kali merkt sich den Befehl, D startet das Einlesen (Coroutine)
    assert src.on_mark(_rec("C", cmd_typed="nmap -oA x 10.0.0.1", cwd="/w"), local) is None
    co = src.on_mark(_rec("D", exit=0), local)
    assert co is not None
    co.close()
    # D ohne C: nichts; D ohne Vordergrund (gefälscht) zählt nicht, der Befehl bleibt offen
    assert src.on_mark(_rec("D", exit=0), local) is None
    src.on_mark(_rec("C", cmd_typed="nmap -oA x 10.0.0.1", cwd="/w"), local)
    assert src.on_mark(_rec("D", exit=0, fg_shell=False), local) is None
    co = src.on_mark(_rec("D", exit=0), local)
    assert co is not None
    co.close()
    # Befehl ohne Begleitdateien-Kandidaten (kein argv): nichts
    src.on_mark(_rec("C", cwd="/w"), local)
    assert src.on_mark(_rec("D", exit=0), local) is None
    # Befehl in einer Remote-Stufe getippt (lokaler Stapel oben remote): nie Begleitdateien
    src.on_mark(_rec("C", cmd_typed="nmap -oA x 10.0.0.1", cwd="/w"), remote)
    assert src.on_mark(_rec("D", exit=0), local) is None


def test_d_after_rec_gap_does_not_read_companions_of_old_c():
    """Befund: REC aus während A, an während B; der D von B las die Begleitdateien von A."""
    d = SimpleNamespace(project=None, paths=None)
    src = LocalSources(d, routes=False)  # type: ignore[arg-type]
    local = MarkContext("t1", "p1", (), True, True)
    src.on_mark(_rec("C", cmd_typed="nc -lvnp 4444 -oA x", cwd="/w"), local)
    gap = EventRecord(2, "g", "raw", "term.gap", 0, None, None, "op", "shim", "t1", 500,
                      {"terminal_id": "t1", "stream_off": 500, "reason": "rec_off", "bytes_lost": 900}, None)
    src.on_commit([gap])
    assert src.on_mark(_rec("D", exit=0), local) is None
    # Pause für Schlüsselmaterial verliert keine Marker: dort gilt der Befehl weiter
    src2 = LocalSources(d, routes=False)  # type: ignore[arg-type]
    src2.on_mark(_rec("C", cmd_typed="nmap -oA x 10.0.0.1", cwd="/w"), local)
    pause = EventRecord(3, "p", "raw", "term.gap", 0, None, None, "op", "daemon", "t1", 20,
                        {"terminal_id": "t1", "stream_off": 20, "reason": "sensitive_output",
                         "bytes_lost": 9}, None)
    src2.on_commit([pause])
    co = src2.on_mark(_rec("D", exit=0), local)
    assert co is not None
    co.close()
