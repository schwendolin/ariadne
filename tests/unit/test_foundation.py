"""Tests für die gemeinsamen Verträge (Fundament)."""

from __future__ import annotations

import pytest

from ariadne import ctxrules, events
from ariadne._shim import protocol as P
from ariadne.ids import cmd_id, uuid7
from ariadne.store.api import DuplicateStreamChunk, Journal
from ariadne.store.memory import MemoryBlobStore, MemoryJournal
from ariadne.termsafe import term_safe

# --------------------------------------------------------------------------- ids


def test_uuid7_version_and_order():
    a, b = uuid7(), uuid7()
    assert a.version == 7 and b.version == 7
    assert str(a)[:8] <= str(b)[:8]
    assert cmd_id("t1", 42) == "t1@42"


# --------------------------------------------------------------------- termsafe


@pytest.mark.parametrize(
    "raw",
    [
        "\x1b]0;evil\x07",
        "a\x1b[2Jb",
        "\x9b31m",
        "x‮exe.txt",
        "zero​width",
        "tag\U000E0041",
        "del\x7f",
    ],
)
def test_term_safe_removes_control(raw):
    out = term_safe(raw)
    assert "\x1b" not in out and "\x07" not in out and "\x7f" not in out
    assert not any(0x80 <= ord(c) <= 0x9F for c in out)
    assert "‮" not in out and "​" not in out
    assert "<" in out


def test_term_safe_truncates():
    assert len(term_safe("x" * 500, max_len=20)) == 20


# ---------------------------------------------------------------------- events


def test_validate_header_rejects_unknown_and_extra():
    with pytest.raises(ValueError):
        events.validate_header("nope", {})
    with pytest.raises(Exception):
        events.validate_header("rec.set", {"on": True, "source": "cli", "x": 1})


def test_canonical_json_rejects_floats():
    with pytest.raises(ValueError):
        events.canonical_json({"a": 1.5})
    assert events.canonical_json({"b": 1, "a": "ä"}) == '{"a":"ä","b":1}'.encode()


def test_every_kind_has_layer():
    for k, spec in events.KINDS.items():
        assert spec.layer in ("raw", "decision", "system")
        assert (spec.layer == "decision") == k.startswith("d.")


# -------------------------------------------------------------------- protocol


def test_frame_roundtrip_and_chunked_decode():
    frames = (
        P.encode_json(P.HELLO, {"proto": 1, "terminal_id": "t"})
        + P.encode_out(1, 0, 10, 20, b"hello\x1b[31m")
        + P.encode_json(P.EVENT, {"seq": 2, "kind": "term.mark"})
    )
    dec = P.FrameDecoder()
    got = []
    for i in range(0, len(frames), 3):
        got += dec.feed(frames[i : i + 3])
    assert [f.type for f in got] == [P.HELLO, P.OUT, P.EVENT]
    assert P.decode_out(got[1].payload) == (1, 0, 10, 20, b"hello\x1b[31m")
    assert P.decode_json(got[2].payload)["kind"] == "term.mark"


def test_frame_rejects_oversize():
    import struct

    dec = P.FrameDecoder()
    with pytest.raises(P.ProtocolError):
        dec.feed(struct.pack(">IB", P.MAX_PAYLOAD + 1, P.OUT))


# -------------------------------------------------------------------- ctxrules


@pytest.mark.parametrize(
    "cmd,expected",
    [
        ("ssh user@10.10.10.5", ("ssh", "10.10.10.5", "user")),
        ("ssh -i id_rsa -p 2222 root@web01", ("ssh", "web01", "root")),
        ("proxychains4 -q ssh -l bob 172.16.1.2", ("ssh", "172.16.1.2", "bob")),
        ("evil-winrm -i 10.10.10.161 -u administrator -H aad3b", ("winrm", "10.10.10.161", "administrator")),
        ("rlwrap nc -lvnp 4444", ("revshell", None, None)),
        ("nc 10.10.10.5 4444", ("revshell", "10.10.10.5", None)),
        ("impacket-psexec corp/admin:pw@10.0.0.5", ("remote", "10.0.0.5", "admin")),
        ("python3 wmiexec.py corp/admin@dc01", ("remote", "dc01", "admin")),
        ("mysql -h 10.10.10.3 -u root", ("db", "10.10.10.3", "root")),
        ("smbclient //10.10.10.3/tmp -U guest%", ("remote", "10.10.10.3", "guest")),
        ("msfconsole -q", ("msf", None, None)),
    ],
)
def test_classify_session_starts(cmd, expected):
    c = ctxrules.classify(ctxrules.split_command(cmd))
    assert isinstance(c, ctxrules.SessionStart), cmd
    assert (c.kind, c.candidate, c.user) == expected


@pytest.mark.parametrize(
    "cmd",
    [
        "ssh -N -L 8080:127.0.0.1:80 user@10.10.10.5",
        "ssh user@10.10.10.5 id",
        "nc -zv 10.10.10.5 1-1000",
        "impacket-secretsdump corp/admin:pw@10.0.0.5",
        "impacket-psexec corp/admin:pw@10.0.0.5 whoami",
        "mysql -h 10.10.10.3 -u root -e 'show databases'",
        "smbclient -L //10.10.10.3 -N",
        "msfconsole -q -x 'use x; run; exit'",
        "nmap -sV 10.10.10.3",
        "ls -la",
    ],
)
def test_classify_non_interactive(cmd):
    assert not isinstance(ctxrules.classify(ctxrules.split_command(cmd)), ctxrules.SessionStart)


def test_classify_priv_and_resume():
    assert isinstance(ctxrules.classify(["sudo", "-i"]), ctxrules.PrivChange)
    assert isinstance(ctxrules.classify(["sudo", "su"]), ctxrules.PrivChange)
    assert isinstance(ctxrules.classify(["su", "-", "bob"]), ctxrules.PrivChange)
    assert isinstance(ctxrules.classify(["fg"]), ctxrules.Resume)
    assert ctxrules.classify(["sudo", "nmap", "-sS", "10.0.0.1"]) is None


def test_stack_upgrade_flow():
    """nc -lvnp, Shell-Upgrade mit Ctrl-Z, stty raw -echo; fg, dann Ende."""
    st = ctxrules.ContextStack()
    st.on_command_start(ctxrules.split_command("nc -lvnp 4444"), 100)
    assert st.top().kind == "revshell" and st.top().host is None
    st.set_top(host="ip:default/10.10.10.5", user="www-data")
    assert st.label() == "10.10.10.5 www-data"
    st.on_command_end(148, 500)  # Ctrl-Z
    assert st.top().kind == "local"
    st.on_command_start(ctxrules.split_command("stty raw -echo; fg"), 600)
    # "stty raw -echo; fg" ist zwar eine Liste, aber Resume über die fg-Zeile
    st.on_command_start(["fg"], 610)
    assert st.top().host == "ip:default/10.10.10.5"
    st.on_command_end(0, 900)
    assert st.top().kind == "local" and len(st.stages) == 1


def test_stack_snapshot_roundtrip_matches_event_model():
    st = ctxrules.ContextStack()
    st.on_command_start(["ssh", "root@10.0.0.1"], 5)
    snap = st.snapshot()
    events.validate_header(
        "term.ctx_snapshot", {"terminal_id": "t", "stream_off": 5, "stack": snap}
    )
    assert ctxrules.ContextStack.from_snapshot(snap).snapshot() == snap


# ------------------------------------------------------------- memory journal


def test_memory_journal_chain_and_idempotence():
    j = MemoryJournal()
    assert isinstance(j, Journal)
    j.append("rec.set", {"on": True, "source": "cli"}, origin="cli")
    h = {"terminal_id": "t", "stream_off": 0, "length": 3, "t_shim_ns": 1}
    j.append("term.out", h, b"abc", origin="shim", terminal_id="t", stream_off=0)
    with pytest.raises(DuplicateStreamChunk):
        j.append("term.out", h, b"abc", origin="shim", terminal_id="t", stream_off=0)
    assert j.verify().ok
    red = j.redact(2, label="own:sudo", replacement=b"***", reason="test")
    assert red.kind == "system.redaction"
    assert j.get(2).body is None
    assert j.verify().ok


def test_memory_blobs_dedupe():
    b = MemoryBlobStore()
    r1, r2 = b.put_bytes(b"x"), b.put_bytes(b"x")
    assert r1 == r2 and b.open_bytes(r1.blob_id) == b"x"
