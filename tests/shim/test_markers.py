"""Marker-Parser und -Validator: Nonce, Wiederholung, Vordergrund, Event-Felder."""

from __future__ import annotations

import pytest

from ariadne import events
from ariadne._shim.markers import MarkerValidator, mark_event, parse_marker, percent_decode

NONCE = "0123456789abcdef0123456789abcdef"


def payload(mark="C", fields="cmd=ls", nonce=NONCE, pid=100, ctr=5) -> bytes:
    return f"7701;ariadne;v1;{nonce};{pid}:{ctr};{mark};{fields}".encode()


def validator(**kw) -> MarkerValidator:
    deps = dict(tcgetpgrp=lambda fd: 100, getpgid=lambda pid: 100, comm=lambda pid: "zsh",
                descends=lambda pid, anc: True)
    deps.update(kw)
    return MarkerValidator(NONCE, child_pid=100, master_fd=-1, **deps)


def test_percent_decode():
    assert percent_decode(b"ls%20-la%20%C3%A4%3B%26%3D%25") == "ls -la ä;&=%".encode()
    assert percent_decode(b"100%") == b"100%"
    assert percent_decode(b"%zz%4") == b"%zz%4"


def test_parse_valid_fields():
    m = parse_marker(payload("C", "cmd=ssh%20root%40web01&cwd=/tmp&var.IP=10.0.0.1&shlvl=2"))
    assert not isinstance(m, str)
    assert (m.mark, m.shell_pid, m.counter) == ("C", 100, 5)
    assert m.fields == {"cmd": "ssh root@web01", "cwd": "/tmp", "var.IP": "10.0.0.1", "shlvl": "2"}


@pytest.mark.parametrize(
    "raw,reason",
    [
        (b"7701;ariadne;v1", "malformed"),
        (b"7701;other;v1;" + NONCE.encode() + b";1:1;C;", "malformed"),
        (b"7701;ariadne;v1;nothex;1:1;C;", "bad_nonce"),
        (b"7701;ariadne;v1;" + NONCE.encode() + b";1:x;C;", "malformed"),
        (b"7701;ariadne;v1;" + NONCE.encode() + b";1:1;Z;", "malformed"),
        (b"7701;ariadne;v1;" + NONCE.encode() + b";0:1;C;", "malformed"),
        (b"7701;ariadne;v1;" + NONCE.encode() + b";1:1;C;bad field=1", "malformed"),
        (b"7701;ariadne;v1;" + NONCE.encode() + b";1:1;C", "malformed"),
    ],
)
def test_parse_malformed(raw, reason):
    assert parse_marker(raw) == reason


def test_validator_nonce_and_replay():
    v = validator()
    assert v.check(payload(nonce="f" * 32)).reason == "bad_nonce"
    ok = v.check(payload(ctr=5))
    assert ok.ok and ok.fg_shell
    assert v.check(payload(ctr=5)).reason == "replay"
    assert v.check(payload(ctr=4)).reason == "replay"
    assert v.check(payload(ctr=6)).ok
    # andere Shell-PID hat eigene Zähler
    assert v.check(payload(pid=200, ctr=1)).ok


@pytest.mark.parametrize(
    "deps",
    [
        dict(tcgetpgrp=lambda fd: 999),  # ssh oder nc im Vordergrund
        dict(comm=lambda pid: "python3"),
        dict(descends=lambda pid, anc: False),
        dict(tcgetpgrp=lambda fd: (_ for _ in ()).throw(OSError("weg"))),
    ],
)
def test_validator_foreground_checks(deps):
    v = validator(**deps)
    verdict = v.check(payload())
    assert verdict.ok and verdict.fg_shell is False


def test_mark_event_matches_event_model():
    m = parse_marker(payload("D", "exit=148&pipestatus=0,148&cwd=/root&cmd=sleep%2030&user=kali"))
    ev = mark_event(m, terminal_id="t1", stream_off=77, fg_shell=True)
    assert ev["exit"] == 148 and ev["pipestatus"] == [0, 148] and ev["cmd_typed"] == "sleep 30"
    events.validate_header("term.mark", ev)
    m = parse_marker(payload("C", "cmd=ssh%20%24IP&cmdx=ssh%20%24IP&var.IP=10.10.10.5&shlvl=1"))
    ev = mark_event(m, terminal_id="t1", stream_off=0, fg_shell=False)
    assert ev["cmd_vars"] == {"IP": "10.10.10.5"} and ev["shlvl"] == 1
    events.validate_header("term.mark", ev)


def test_mark_event_ignores_garbage_numbers():
    m = parse_marker(payload("D", "exit=abc&pipestatus=1,x&cwd="))
    ev = mark_event(m, terminal_id="t", stream_off=0, fg_shell=True)
    assert "exit" not in ev and "pipestatus" not in ev and "cwd" not in ev


def test_non_foreground_d_cannot_burn_the_counter():
    """Befund: Ein D mit geleakter Nonce und riesigem Zähler aus einem Hintergrundprozess
    machte alle echten Marker der Shell zu Wiederholungen."""
    fg = {"pgrp": 999}
    v = validator(tcgetpgrp=lambda fd: fg["pgrp"])
    forged = v.check(payload("D", "exit=0", ctr=999_999_999_999))
    assert forged.ok and not forged.fg_shell
    fg["pgrp"] = 100
    real = v.check(payload("D", "exit=0", ctr=7))
    assert real.ok and real.fg_shell
