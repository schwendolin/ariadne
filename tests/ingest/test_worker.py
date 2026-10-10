"""Worker-Subprozess: Roundtrip, Grenzen, Absturz ohne Pipeline-Absturz (Architektur 9.3)."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from ariadne.ingest import worker
from ariadne.ingest.runner import InProcessRunner, SubprocessRunner, item_from_dict, validate_item
from ariadne.ingest.units import Unit
from ariadne.parsers.api import Line, Mention, Obs, Ref
from tests.ingest import worker_parsers as wp

ROOT = str(Path(__file__).resolve().parents[2])


def runner(**kw) -> SubprocessRunner:
    kw.setdefault("timeout", 20)
    return SubprocessRunner(extra_paths=[ROOT], allowed_prefixes=("ariadne.parsers.", "tests.ingest."), **kw)


def unit(n: int = 3) -> Unit:
    lines = [Line("$ id", 0, 5, prompt_echo=True)] + [Line(f"line {i} 10.10.10.{i}", 5 + i * 20, 25 + i * 20)
                                                      for i in range(n)]
    return Unit("u:t@0", "command", 123, argv=("id",), cmd_text="id", exit_code=0, cwd="/tmp",
                context={"kind": "local", "host": "local"}, all_lines=tuple(lines), terminal_id="t",
                cmd_id="t@5", start_off=0, end_off=100)


def test_unit_roundtrip_and_hidden_lines():
    u = unit()
    assert [ln.text for ln in u.lines] == ["line 0 10.10.10.0", "line 1 10.10.10.1", "line 2 10.10.10.2"]
    full = Unit.from_dict(json.loads(json.dumps(u.to_dict(include_hidden=True))))
    assert full == u
    slim = u.to_dict()
    assert all("$ id" != ln["t"] for ln in slim["lines"])  # Prompt-Echo verlässt den Daemon nie
    f = Unit("f:1", "file", 1, path="scans/x.xml", data=b"\x00\x01<nmaprun>")
    assert Unit.from_dict(f.to_dict()).open_bytes() == b"\x00\x01<nmaprun>"


def test_subprocess_roundtrip():
    res = runner().run(unit(), [wp.NeverParser(), wp.EchoParser()])
    assert [r.parser_id for r in res] == ["w.echo"]
    r = res[0]
    assert r.error is None and r.priority == 20
    mentions = [i for i in r.items if isinstance(i, Mention)]
    obs = [i for i in r.items if isinstance(i, Obs)]
    assert [m.value for m in mentions] == ["line 0 10.10.10.0", "line 1 10.10.10.1", "line 2 10.10.10.2"]
    assert mentions[0].attrs == {"kind": "command"}
    assert obs[0].subject == Ref("ip:default/10.10.10.3") and obs[0].confidence == 0.9
    assert obs[1].value == Ref("x:y")
    # gleiches Ergebnis wie im Prozess
    inproc = InProcessRunner().run(unit(), [wp.NeverParser(), wp.EchoParser()])
    assert [(x.parser_id, x.items) for x in inproc] == [(r.parser_id, r.items)]


def test_worker_is_isolated():
    res = runner().run(unit(), [wp.EnvParser()])[0]
    assert res.error is None
    vals = {}
    for m in res.items:
        vals.setdefault(m.value_type, []).append(m.value)
    env_keys = set(vals["env"][0].split(",")) - {""}
    assert env_keys <= {"PATH", "LC_CTYPE"}  # LC_CTYPE setzt Python selbst (PEP 538)
    assert len(vals["fds"][0].split(",")) <= 4  # 0, 1, 2 und das fd von listdir
    assert vals["cwd"] == ["/"]
    limits = dict(v.split("=") for v in vals["rlimit"])
    assert limits == {"RLIMIT_AS": str(1 << 30), "RLIMIT_CPU": "30", "RLIMIT_FSIZE": "0", "RLIMIT_CORE": "0",
                      "RLIMIT_NOFILE": "64"}
    assert vals["nnp"] == ["1"]
    assert vals["write"] != ["ok"]


def test_memory_bomb_is_contained():
    res = runner(mem_limit=256 << 20).run(unit(), [wp.BombParser(), wp.EchoParser()])
    by = {r.parser_id: r for r in res}
    assert by["w.bomb"].error is not None and not by["w.bomb"].items
    assert by["w.echo"].error is None and by["w.echo"].items  # der nächste Parser läuft trotzdem


def test_exit_timeout_flood_and_invalid_output():
    res = {r.parser_id: r for r in runner().run(unit(), [wp.ExitParser(), wp.EchoParser()])}
    assert res["w.echo"].error is None and res["w.echo"].items  # lief vorher (höhere Priorität)
    assert res["w.exit"].error == "exit:7"
    assert not res["w.exit"].items  # angefangene Ergebnisse werden verworfen
    slow = runner(timeout=1.5).run(unit(), [wp.SleepParser()])
    assert [r.error for r in slow] == ["timeout"]
    flood = runner(max_output=200_000).run(unit(), [wp.FloodParser()])
    assert [r.error for r in flood] == ["output_too_large"]
    bad = runner().run(unit(), [wp.BadSpanParser()])[0]
    assert bad.error.startswith("invalid:") and not bad.items
    crash = runner().run(unit(), [wp.MatchCrashParser(), wp.EchoParser()])
    assert {r.parser_id: r.error for r in crash} == {"w.matchcrash": "match:ValueError", "w.echo": None}


def test_disallowed_factory_is_not_imported():
    r = SubprocessRunner(extra_paths=[ROOT], timeout=20).run(unit(), [wp.EchoParser()])
    assert r[0].error.startswith("load:ImportError:not_allowed")


def test_worker_main_rejects_garbage():
    out = io.BytesIO()
    assert worker.main([], io.BytesIO(b"not json"), out) == 3
    assert worker.main([], io.BytesIO(b"[1, 2]"), out) == 3
    assert out.getvalue() == b""


@pytest.mark.parametrize("item", [
    {"subject": "ip:default/1.2.3.4", "predicate": "host.state", "value": "up", "span": {"line_start": 0,
                                                                                        "line_end": 0}},
    {"value_type": "ip", "value": "1.2.3.4", "span": {"line_start": 1, "line_end": 2, "col_start": 0}},
])
def test_validate_item_accepts(item):
    validate_item(item, 3)
    assert item_from_dict(item, 3) is not None


@pytest.mark.parametrize("item", [
    {},
    {"subject": "", "predicate": "host.state", "value": "x", "span": {"line_start": 0, "line_end": 0}},
    {"subject": "s", "predicate": "Host State", "value": "x", "span": {"line_start": 0, "line_end": 0}},
    {"subject": "s", "predicate": "host.state", "value": [1], "span": {"line_start": 0, "line_end": 0}},
    {"subject": "s", "predicate": "host.state", "value": "x", "span": {"line_start": 2, "line_end": 1}},
    {"subject": "s", "predicate": "host.state", "value": "x", "span": {"line_start": 0, "line_end": 3}},
    {"subject": "s", "predicate": "host.state", "value": "x", "span": {"line_start": -1, "line_end": 0}},
    {"subject": "s", "predicate": "host.state", "value": "x", "span": {"line_start": 0, "line_end": 0},
     "confidence": float("nan")},
    {"subject": "s", "predicate": "host.state", "value": "x", "span": {"line_start": 0, "line_end": 0},
     "confidence": 1.5},
    {"subject": "s", "predicate": "host.state", "value": "x", "span": {"line_start": 0, "line_end": 0},
     "evil": 1},
    {"value_type": "ip", "value": "x" * 70_000, "span": {"line_start": 0, "line_end": 0}},
    {"value_type": "ip", "value": "1", "span": {"line_start": 0, "line_end": 0}, "attrs": {"k": 1}},
])
def test_validate_item_rejects(item):
    with pytest.raises(ValueError):
        validate_item(item, 3)


def test_pipeline_survives_worker_bomb(env):
    t = env.term
    t.open()
    t.command("id", b"uid=0 10.10.10.5\r\n")
    p = env.pipeline(runner=runner(mem_limit=256 << 20), registry=[wp.BombParser(), wp.EchoParser()])
    st = p.process_new()
    assert st.failures == 1
    assert env.rows("SELECT parser_id FROM parse_failure") == [("w.bomb",)]
    assert any(k[1] == "w.echo" for k in env.projector.applied)
    assert p.watermark > 0
