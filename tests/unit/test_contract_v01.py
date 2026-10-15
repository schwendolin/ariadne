"""Vertragstests für den Bau v0.1-Bedienung (Phase 1): neue Events, Protokoll v2,
Auto-Kontext im Stapel, Ontologie v2, Ausgangs-API des Redaktors, Aufteilung der
ctl-Operationen. Diese Datei gehört keinem Bau-Agenten; Änderungen nur additiv."""

from __future__ import annotations

import asyncio
import struct

import pytest

from ariadne import ctxrules, events, ontology
from ariadne._shim import protocol as P
from ariadne.daemon import core, ops_eval
from ariadne.daemon.ingest import AutoContext, IngestService, IngestUpdate
from ariadne.daemon.terminal import parse_hello
from ariadne.paths import default_paths
from ariadne.secrets.redactor import Redactor

TID = "0199a2b3-0000-7000-8000-000000000001"

# ---------------------------------------------------------------------- events


def test_new_kinds_and_layers():
    expected = {
        "term.input": "raw", "term.pause": "raw", "term.preroll": "raw", "net.local_addrs": "raw",
        "system.project_end": "system", "d.unit.distrust": "decision",
    }
    for kind, layer in expected.items():
        assert events.layer_of(kind) == layer
    assert events.KINDS["term.input"].has_body and events.KINDS["term.out"].has_body


def test_shim_time_fields_are_optional_and_kept():
    old = {"terminal_id": TID, "stream_off": 5, "mark": "C", "counter": 1, "fg_shell": True}
    assert events.validate_header("term.mark", old) == old  # alte Header unverändert
    new = dict(old, t_shim_ns=1_700_000_000_000_000_000, mono_ns=42)
    assert events.validate_header("term.mark", new)["mono_ns"] == 42
    for kind, h in [
        ("term.gap", {"terminal_id": TID, "stream_off": 1, "reason": "pause", "bytes_lost": 0,
                      "t_shim_ns": 9}),
        ("term.gap", {"terminal_id": TID, "stream_off": 1, "reason": "no_project"}),
        ("term.resize", {"terminal_id": TID, "stream_off": 1, "rows": 2, "cols": 3, "mono_ns": 1}),
        ("term.close", {"terminal_id": TID, "stream_off": 1, "t_shim_ns": 1}),
    ]:
        assert events.validate_header(kind, h)


def test_term_out_tix_validation_and_body_time():
    base = {"terminal_id": TID, "stream_off": 100, "length": 10, "t_shim_ns": 1_000, "mono_ns": 50}
    h = events.validate_header("term.out", dict(base, tix=[[4, 2], [8, 7]]))
    assert "tix" in h and "tix" not in events.validate_header("term.out", base)
    assert events.body_time(h, 0) == (1_000, 50)
    assert events.body_time(h, 5) == (3_000, 2_050)
    assert events.body_time(h, 9) == (8_000, 7_050)
    assert events.body_time({"stream_off": 0}, 3) == (None, None)
    assert events.shim_time({"t_shim_ns": 7}, 99) == 7 and events.shim_time({}, 99) == 99
    for bad in ([[0, 1]], [[4, 2], [4, 3]], [[4, 5], [6, 2]], [[10, 1]], [[3]]):
        with pytest.raises(ValueError):
            events.validate_header("term.out", dict(base, tix=bad))


def test_term_input_pause_preroll_localaddrs_distrust():
    h = events.validate_header("term.input", {"terminal_id": TID, "stream_off": 10, "out_end": 12,
                                              "length": 4, "t_shim_ns": 5, "paste": True})
    assert h["paste"] is True and "time_suspect" not in h
    with pytest.raises(ValueError):
        events.validate_header("term.input", {"terminal_id": TID, "stream_off": 10, "out_end": 9, "length": 1,
                                              "t_shim_ns": 5})
    assert events.validate_header("term.pause", {"terminal_id": TID, "stream_off": 3, "until_ns": 10,
                                                 "source": "hotkey"})
    assert events.validate_header("term.preroll", {"terminal_id": TID, "from_off": 0, "to_off": 9,
                                                   "frames": 2})
    la = events.validate_header("net.local_addrs", {"addrs": ["10.10.14.5", "fe80::1"]})
    assert la["source"] == "proc"
    with pytest.raises(ValueError):
        many = [f"10.0.{i // 256}.{i % 256}" for i in range(300)]
        events.validate_header("net.local_addrs", {"addrs": many})
    assert events.validate_header("system.project_end", {"reason": "idle", "idle_s": 43200})
    with pytest.raises(ValueError):
        events.validate_header("system.project_end", {"reason": "nope"})
    d = events.validate_header("d.unit.distrust", {"cmd_id": f"{TID}@120", "reason": "falsches Ziel"})
    assert d["cmd_id"].endswith("@120")


def test_stage_accepts_host_source():
    snap = [{"kind": "local", "host": "local", "opened_at": 0},
            {"kind": "revshell", "host": "ip:default/10.10.10.3", "opened_at": 5, "host_source": "auto"}]
    assert events.validate_header("term.ctx_snapshot", {"terminal_id": TID, "stream_off": 9, "stack": snap})


# -------------------------------------------------------------------- protocol


def test_protocol_v2_frames_roundtrip():
    assert P.PROTO_VERSION == 2 and P.ACCEPTED_PROTOS == (1, 2)
    stream = (P.encode_outx(1, 0, 10, 20, b"hello world", [(5, 3)])
              + P.encode_input(2, 11, 11, 30, 40, b"pw\r", paste=False)
              + P.encode_out(3, 11, 50, 60, b"x"))
    frames = []
    dec = P.FrameDecoder()
    for i in range(0, len(stream), 4):
        frames += dec.feed(stream[i:i + 4])
    assert [f.type for f in frames] == [P.OUTX, P.INPUT, P.OUT]
    ox = P.decode_outx(frames[0].payload)
    assert (ox.seq, ox.stream_off, ox.t_wall_ns, ox.t_mono_ns, ox.tix, ox.data) == (
        1, 0, 10, 20, ((5, 3),), b"hello world")
    ip = P.decode_input(frames[1].payload)
    assert (ip.seq, ip.stream_off, ip.out_end, ip.paste, ip.data) == (2, 11, 11, False, b"pw\r")
    assert [P.frame_seq(f.type, f.payload) for f in frames] == [1, 2, 3]
    pasted = P.FrameDecoder().feed(P.encode_input(4, 1, 2, 0, 0, b"a", paste=True))[0]
    assert P.decode_input(pasted.payload).paste


def test_protocol_v2_rejects_bad_index():
    with pytest.raises(P.ProtocolError):
        P.encode_outx(1, 0, 0, 0, b"abc", [(3, 0)])  # rel_off am Ende
    with pytest.raises(P.ProtocolError):
        P.encode_outx(1, 0, 0, 0, b"abcd", [(2, 5), (3, 4)])  # dt fällt
    with pytest.raises(P.ProtocolError):
        P.encode_input(1, 5, 4, 0, 0, b"a")
    bad = struct.pack(">QQqqH", 1, 0, 0, 0, 2) + struct.pack(">II", 1, 0)  # Index abgeschnitten
    with pytest.raises(P.ProtocolError):
        P.decode_outx(bad)
    forged = struct.pack(">QQqqH", 1, 0, 0, 0, 1) + struct.pack(">II", 9, 0) + b"ab"
    with pytest.raises(P.ProtocolError):
        P.decode_outx(forged)


def test_rec_states_and_capture_states():
    assert set(P.CAPTURE_STATES) <= set(P.REC_STATES)
    assert {"on", "paused", "preroll", "locked", "held", "off"} <= set(P.REC_STATES)
    assert "paused" not in P.CAPTURE_STATES and "held" not in P.CAPTURE_STATES


def test_daemon_accepts_proto_1_and_2():
    for proto in (1, 2):
        assert parse_hello({"proto": proto, "terminal_id": TID})["proto"] == proto
    for proto in (3, True, None, "2", 1.0):
        with pytest.raises(P.ProtocolError):
            parse_hello({"proto": proto, "terminal_id": TID})


# -------------------------------------------------------------------- ctxrules


def test_auto_host_never_in_journal_and_user_wins():
    st = ctxrules.ContextStack()
    st.on_command_start(["nc", "-lvnp", "4444"], 100)
    assert st.set_auto_host(100, "ip:default/10.10.10.3")
    assert not st.set_auto_host(100, "ip:default/10.10.10.3")  # unverändert
    assert st.label() == "10.10.10.3 revshell (auto)"
    top = st.journal_snapshot()[-1]
    assert "host" not in top and "host_source" not in top
    assert st.snapshot()[-1]["host_source"] == "auto"
    st.set_top(host="ip:default/10.10.10.4", source="hotkey", offset=200)
    assert st.label() == "10.10.10.4 revshell"
    assert not st.set_auto_host(100, "ip:default/10.10.10.3")  # Nutzer geht vor
    assert st.journal_snapshot()[-1]["host"] == "ip:default/10.10.10.4"
    assert not ctxrules.ContextStack().set_auto_host(0, "ip:default/10.10.10.3")  # nie auf Kali


def test_stage_roundtrip_with_host_source():
    st = ctxrules.Stage.from_dict({"kind": "ssh", "host": "name:web", "opened_at": 3, "host_source": "auto"})
    assert st.to_dict()["host_source"] == "auto"


# -------------------------------------------------------------------- ontology


def test_ontology_v2_natures():
    assert ontology.VERSION == 2
    p = ontology.PREDICATES
    assert p["service.version"].nature == "version" and p["service.product"].nature == "version"
    assert p["service.state"].nature == "state" and p["host.state"].nature == "state"
    assert p["host.address"].nature == "set" and p["service.name"].nature == "fact"
    assert all((x.nature == "set") == (x.cardinality == "many") for x in p.values())
    assert {n for n, x in p.items() if x.important} == {"identity.secret", "secret.kind", "access.shell"}
    with pytest.raises(ValueError):
        ontology.Predicate("x.y", "host", "str", "one", "none", nature="set")


# ----------------------------------------------------------------------- paths


def test_active_file_in_state_dir(tmp_path):
    pa = default_paths({"HOME": str(tmp_path)})
    assert pa.active_file.parent == pa.state_dir and pa.active_file.name == "active.json"


# -------------------------------------------------------------------- redactor


def test_redact_for_exit_and_json():
    r = Redactor([("kali", "Sommer2026!")])
    out, labels = r.redact_for_exit("pw=Sommer2026! url=Sommer2026%21")
    assert "Sommer2026" not in out and labels == ["kali"]
    assert len(out) == len("pw=Sommer2026! url=Sommer2026%21")
    raw = b"x\x1b[31mSommer\x1b[0m2026!y"
    red, _ = r.redact_for_exit(raw)
    assert isinstance(red, bytes) and len(red) == len(raw) and b"Sommer" not in red
    obj, labels = r.redact_json({"a": ["Sommer2026!", 3, ("x Sommer2026!",)], "b": None, "Sommer2026!": 1})
    assert obj["a"][0] == "*" * 11 and obj["a"][1] == 3 and obj["a"][2] == ("x " + "*" * 11,)
    assert "Sommer2026!" in obj and labels == ["kali"]  # Schlüssel bleiben
    assert Redactor().redact_for_exit("Sommer2026!") == ("Sommer2026!", [])


# ------------------------------------------------------------- Aufteilung, Listener


def test_eval_ops_registered_in_core():
    for op in ("show", "search", "claim.confirm", "claim.reject", "reparse"):
        assert core._OPS[op] is ops_eval.OPS[op]
    assert core.OpError is __import__("ariadne.daemon.ops_util", fromlist=["OpError"]).OpError


def test_ingest_listener_runs_in_loop():
    got: list[IngestUpdate] = []

    async def main() -> None:
        svc = IngestService(periodic=0)
        svc._loop = asyncio.get_running_loop()
        svc.add_listener(got.append)
        svc.add_listener(lambda u: 1 / 0)  # Fehler eines Listeners stoppt nichts
        upd = IngestUpdate(3, (AutoContext(TID, 100, "ip:default/10.10.10.3"),))
        await asyncio.to_thread(svc._publish, upd)
        await asyncio.sleep(0.05)

    asyncio.run(main())
    assert got and got[0].auto_contexts[0].opened_at == 100
