"""Zufällige Sitzungen: Segmenter und Pipeline bleiben konsistent (Architektur 5.4, 9.3 Fuzzing)."""

from __future__ import annotations

import sqlite3

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ariadne.ingest.pipeline import Pipeline
from ariadne.ingest.runner import InProcessRunner
from ariadne.ingest.segmenter import SegEvent, compute_layout
from ariadne.store.memory import MemoryJournal
from tests.ingest.helpers import TID, StubParser, StubProjector, TermSim
from tests.ingest.test_pipeline import dump

_OUT = st.sampled_from([b"line\r\n", b"10.10.10.3 open\r\n", b"\x1b[31mred\x1b[0m", b"\rprog 50%", b"x" * 90,
                        b"\x1b[?1049hvim\x1b[?1049l", b"\xc3", b"\xa4\r\n", b"\x1b[2A", b"$ "])
_CMDS = st.sampled_from(["ls", "ssh root@10.10.10.3", "nc -lvnp 4444", "fg", "stty raw -echo; fg", "sudo -i",
                         "nmap 10.10.10.3", "evil-winrm -i 10.10.10.5 -u a"])
_STEP = st.one_of(
    st.tuples(st.just("out"), _OUT),
    st.tuples(st.just("cmd"), _CMDS),
    st.tuples(st.just("D"), st.sampled_from([0, 1, 148])),
    st.tuples(st.just("Dforged"), st.just(0)),
    st.tuples(st.just("A"), st.just(0)),
    st.tuples(st.just("set"), st.integers(0, 400)),
    st.tuples(st.just("push"), st.just(0)),
    st.tuples(st.just("pop"), st.just(0)),
    st.tuples(st.just("gap"), st.integers(1, 50)),
    st.tuples(st.just("snap"), st.just(0)),
    st.tuples(st.just("resize"), st.sampled_from([40, 80, 0])),
)


def _play(t: TermSim, steps) -> None:
    t.open()
    for kind, arg in steps:
        if kind == "out":
            t.out(arg, chunk=7)
        elif kind == "cmd":
            t.prompt(arg)
            t.mark("C", cmd_typed=arg, cwd="/home/kali")
        elif kind == "D":
            t.end(arg)
        elif kind == "Dforged":
            t.end(0, fg=False)
        elif kind == "A":
            t.mark("A")
        elif kind == "set":
            t.decision("d.ctx.set", from_off=max(0, t.off - arg), host="ip:default/10.10.10.7")
        elif kind == "push":
            t.decision("d.ctx.push", kind="unknown", host="name:web01")
        elif kind == "pop":
            t.decision("d.ctx.pop")
        elif kind == "gap":
            t.snapshot()
            t.gap(arg)
        elif kind == "snap":
            t.snapshot()
        elif kind == "resize":
            t._append("term.resize", {"stream_off": t.off, "rows": 24, "cols": arg}, stream_off=t.off)


def _pipe(j, conn):
    return Pipeline(j, None, conn, project_key=b"k" * 32, scope=None, runner=InProcessRunner(),
                    projector=StubProjector(conn), registry=[StubParser()], clock=lambda: 0)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_STEP, max_size=25))
def test_layout_partitions_stream(steps):
    j = MemoryJournal()
    t = TermSim(j)
    _play(t, steps)
    evs = [SegEvent(r.seq, r.kind, r.header.get("from_off", r.header.get("stream_off")), r.ts_utc_ns,
                    r.header) for r in j.iter_events() if r.kind != "term.out"]
    lay = compute_layout(TID, evs, t.off)
    pos = lay.rec_start or 0
    if t.off == pos:
        assert lay.units == []
        return
    for u in lay.units:
        assert u.start == pos
        assert u.end is None or u.end > u.start
        assert u.kind in ("command", "segment")
        pos = u.end if u.end is not None else pos
    assert lay.units[-1].end is None or lay.units[-1].end == max(t.off, lay.units[-1].end)
    starts = [s.start for s in lay.spans]
    assert starts == sorted(starts) and len(set(starts)) == len(starts)


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_STEP, max_size=20), st.integers(1, 6))
def test_incremental_equals_single_pass(steps, every):
    j_all = MemoryJournal()
    _play(TermSim(j_all), steps)
    one = sqlite3.connect(":memory:")
    _pipe(j_all, one).process_new()

    j = MemoryJournal()
    t = TermSim(j)
    inc = sqlite3.connect(":memory:")
    pipe = [_pipe(j, inc)]
    orig_append = j.append
    count = [0]

    def append(*a, **kw):
        rec = orig_append(*a, **kw)
        count[0] += 1
        if count[0] % every == 0:
            pipe[0].process_new()
        if count[0] % (every * 3) == 0:
            pipe[0] = _pipe(j, inc)  # Neustart: Zustand nur aus der Datenbank
        return rec

    j.append = append  # type: ignore[method-assign]
    _play(t, steps)
    pipe[0].process_new()
    restarted = _pipe(j, inc)
    restarted.process_new()
    a, b = dump(one), dump(inc)
    assert a["unit_line"] == b["unit_line"]
    assert a["unit"] == b["unit"]
    assert a["cmd_block"] == b["cmd_block"] and a["ctx_span"] == b["ctx_span"]
    lines = inc.execute("SELECT unit_id, pos, idx FROM unit_line ORDER BY unit_id, pos").fetchall()
    by_unit: dict[str, list] = {}
    for uid, p, i in lines:
        by_unit.setdefault(uid, []).append((p, i))
    for rows in by_unit.values():
        assert [p for p, _ in rows] == list(range(len(rows)))
        vis = [i for _, i in rows if i is not None]
        assert vis == list(range(len(vis)))
