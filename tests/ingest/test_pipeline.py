"""Pipeline mit Stub-Parser und Stub-Projector (Architektur 5.4, 5.10).

Inkrement, Neustart, Reparse, Stille, Dateien.
"""

from __future__ import annotations

import sqlite3

import pytest

from ariadne.ingest.db import apply_schema, versions
from ariadne.ingest.normalizer import NORMALIZER_VERSION
from ariadne.store.memory import MemoryJournal
from tests.ingest.helpers import SEC, TID, StubParser, StubProjector, TermSim

TABLES = {
    "unit": "SELECT unit_id, kind, terminal_id, cmd_id, span_id, start_off, end_off, argv, cmd_text, "
            "exit_code, cwd, context, ts_utc_ns, ts_end_ns, state, flags, sig, line_count, vis_count "
            "FROM unit ORDER BY unit_id",
    "unit_line": "SELECT unit_id, pos, idx, terminal_id, n, text, raw_start, raw_end, flags, sgr, colmap "
                 "FROM unit_line ORDER BY terminal_id, n, unit_id, pos",
    "cmd_block": "SELECT * FROM cmd_block ORDER BY cmd_id",
    "ctx_span": "SELECT * FROM ctx_span ORDER BY span_id",
    "activity": "SELECT * FROM activity ORDER BY cmd_id",
}


def dump(conn):
    return {name: conn.execute(sql).fetchall() for name, sql in TABLES.items()}


def scenario(t: TermSim):
    """Schritte einer Sitzung; jeder Schritt hängt Events an."""
    yield lambda: t.open()
    yield lambda: t.command("nmap -sV 10.10.10.3", b"".join(b"%d/tcp open svc%d\r\n" % (p, p)
                                                           for p in range(20, 100)), )
    yield lambda: t.prompt("gobuster dir -u http://10.10.10.3")
    c = {}

    def start_gob():
        c["g"] = t.off
        t.mark("C", cmd_typed="gobuster dir -u http://10.10.10.3 -w w.txt", cwd="/home/kali")
        t.out(b"\rProgress: 1 / 10 (10.00%)\r\x1b[2K/admin (Status: 301)\r\n\rProgress: 10 / 10", chunk=7)

    yield start_gob
    yield lambda: (t.out(b"\r\x1b[2KProgress: 10 / 10 (100.00%)\r\n"), t.end(0))
    yield lambda: t.start("ssh root@10.10.10.3", b"Welcome\r\n10.10.10.3 says hi\r\n")
    yield lambda: t.out(b"\x1b[?1049h\x1b[H\x1b[2Jvim on target\x1b[?1049lroot@lame:~# exit\r\n", chunk=5)
    yield lambda: (t.end(0), t.prompt())
    yield lambda: t.decision("d.ctx.set", from_off=c["g"] + 3, to_off=c["g"] + 40, host="ip:default/1.2.3.4")
    yield lambda: t.command("cat notes", "Größe: 10.10.10.9 ✓\r\n".encode() * 3, exit=1)
    yield lambda: t.prompt()


def _journal_with(steps_until: int | None = None):
    j = MemoryJournal()
    t = TermSim(j)
    for i, step in enumerate(scenario(t)):
        if steps_until is not None and i >= steps_until:
            break
        step()
    return j


def _pipe(journal, conn, projector=None, **kw):
    from ariadne.ingest.pipeline import Pipeline

    return Pipeline(journal, None, conn, project_key=b"k" * 32, scope=None,
                    projector=projector if projector is not None else StubProjector(conn),
                    registry=[StubParser()], clock=lambda: 0, **kw)


def test_incremental_with_restarts_equals_single_pass(tmp_path):
    j_all = _journal_with()
    one = sqlite3.connect(tmp_path / "one.db")
    _pipe(j_all, one).process_new()

    j = MemoryJournal()
    t = TermSim(j)
    inc = sqlite3.connect(tmp_path / "inc.db")
    pipe = _pipe(j, inc)
    for i, step in enumerate(scenario(t)):
        step()
        pipe.process_new()
        if i % 2:
            pipe = _pipe(j, inc)  # Daemon-Neustart: Zustand nur aus der Datenbank
    pipe.process_new()
    assert dump(inc) == dump(one)


def test_byte_by_byte_journal_equals_single_pass(tmp_path):
    j_all = _journal_with()
    one = sqlite3.connect(tmp_path / "one.db")
    _pipe(j_all, one).process_new()
    # gleiche Sitzung, aber jeder Chunk nur 3 Bytes gross
    j = MemoryJournal()
    t = TermSim(j)
    orig = t.out
    t.out = lambda data, chunk=None: orig(data, chunk=3)  # type: ignore[method-assign]
    for step in scenario(t):
        step()
    small = sqlite3.connect(tmp_path / "small.db")
    _pipe(j, small).process_new()
    a, b = dump(one), dump(small)
    assert a["unit_line"] == b["unit_line"]
    no_ts = [(r[:12] + r[14:]) for r in a["cmd_block"]]  # Zeitstempel hängen an der Zahl der Events
    assert no_ts == [(r[:12] + r[14:]) for r in b["cmd_block"]]
    assert [r[:12] for r in a["unit"]] == [r[:12] for r in b["unit"]]


def test_reparse_into_new_connection(tmp_path):
    j = _journal_with()
    conn = sqlite3.connect(tmp_path / "a.db")
    p = _pipe(j, conn)
    p.process_new()
    new = sqlite3.connect(tmp_path / "b.db")
    p2 = p.reparse(new)
    assert dump(new) == dump(conn)
    assert p2.conn is new and isinstance(p2.projector, StubProjector) and p2.projector.conn is new
    assert versions(new)["normalizer_version"] == NORMALIZER_VERSION


def test_idempotent_second_run(env):
    for step in scenario(env.term):
        step()
    p = env.pipeline()
    p.process_new()
    before = dump(env.conn)
    calls = len(env.projector.calls)
    st = p.process_new()
    assert st.events == 0 and dump(env.conn) == before and len(env.projector.calls) == calls


def test_silence_parses_open_unit_provisionally(env):
    t = env.term
    t.open()
    t.start("curl -v ftp://10.10.10.3/", b"220 (vsFTPd 2.3.4)\r\n21/tcp open ftp\r\nwaiting")
    p = env.pipeline()
    p.process_new()
    seg = [u for u in env.rows("SELECT unit_id, state FROM unit") if u[1] != "final"]
    assert not any((u[0], "stub.ip") in env.projector.applied for u in seg)
    env.now = t.ts + 11 * 60 * SEC
    st = p.process_new()
    assert st.units_provisional >= 1
    prov = env.rows("SELECT unit_id FROM unit WHERE state = 'provisional'")
    assert prov
    unit, items, *_ = env.projector.applied[(prov[0][0], "stub.ip")]
    assert unit.lines[-1].text == "waiting" and items
    # Befehl endet: endgültig parsen, vorläufige Ergebnisse werden ersetzt
    t.out(b" done\r\n")
    t.end(0)
    p.process_new()
    assert env.rows("SELECT state FROM unit WHERE unit_id = ?", prov[0][0])[0][0] == "final"
    assert ("clear_unit", prov[0][0]) in env.projector.calls
    unit, *_ = env.projector.applied[(prov[0][0], "stub.ip")]
    assert unit.lines[-1].text == "waiting done"


def test_file_units(env):
    data = b"Nmap scan report for 10.10.10.3\n22/tcp open ssh\r\n"
    ref = env.blobs.put_bytes(data)
    env.journal.append("file.observed", {"path": "scans/lame.nmap", "sha256": ref.sha256, "size": ref.size,
                                         "blob_id": ref.blob_id, "origin": "watcher"}, origin="watcher")
    bin_ref = env.blobs.put_bytes(b"\x00\x01\x02binary\xff")
    env.journal.append("file.observed", {"path": "loot/SAM", "sha256": bin_ref.sha256, "size": bin_ref.size,
                                         "blob_id": bin_ref.blob_id, "origin": "watcher"}, origin="watcher")
    env.journal.append("file.observed", {"path": "imports/huge.pcap", "sha256": "00" * 32, "size": 1 << 30,
                                         "origin": "import"}, origin="cli")
    env.pipeline().process_new()
    rows = env.rows("SELECT path, kind, line_count, flags, context FROM unit WHERE kind = 'file' "
                    "ORDER BY path")
    assert [(r[0], r[2], r[3]) for r in rows] == [
        ("imports/huge.pcap", 0, '["not_stored"]'), ("loot/SAM", 0, '["binary"]'),
        ("scans/lame.nmap", 2, "[]")]
    assert '"unknown"' in rows[1][4] and '"local"' in rows[2][4]
    uid = env.rows("SELECT unit_id FROM unit WHERE path = 'scans/lame.nmap'")[0][0]
    unit, items, *_ = env.projector.applied[(uid, "stub.ip")]
    assert unit.open_bytes() == data and [ln.text for ln in unit.lines] == [
        "Nmap scan report for 10.10.10.3", "22/tcp open ssh"]
    assert unit.lines[1].raw_start == 32 and items
    assert env.rows("SELECT text FROM unit_fts WHERE unit_fts MATCH 'ssh'") == [("22/tcp open ssh",)]


def test_decisions_reach_projector_in_order(env):
    t = env.term
    t.open()
    env.journal.append("d.claim.confirm", {"claim_key": "abc"}, origin="webui")
    env.journal.append("d.note.set", {"subject": "ip:default/10.10.10.3", "text": "hi"}, origin="webui")
    st = env.pipeline().process_new()
    assert st.decisions == 2
    kinds = [c[1] for c in env.projector.calls if c[0] == "apply_decision"]
    assert kinds == ["d.claim.confirm", "d.note.set"]
    assert env.projector.calls[-1][0] == "rebuild"


def test_runs_without_projector_and_registry(env):
    t = env.term
    t.open()
    t.command("id", b"uid=1000(kali)\r\n")
    p = env.pipeline(projector=False, registry=[])
    assert not p.can_parse
    p.process_new()
    assert env.rows("SELECT COUNT(*) FROM unit WHERE state = 'final'")[0][0] == 1
    assert env.rows("SELECT parsed_sig FROM unit WHERE state = 'final'")[0][0] is None
    assert env.projector.calls == []


def test_parser_crash_becomes_parse_failure(env):
    class Broken(StubParser):
        id = "stub.broken"

        def parse(self, unit):
            yield from ()
            raise RuntimeError("kaputt")

    t = env.term
    t.open()
    t.command("id", b"uid=1000(kali) 10.10.10.4\r\n")
    st = env.pipeline(registry=[Broken(), StubParser()]).process_new()
    assert st.failures == 1
    fail = env.rows("SELECT parser_id, reason FROM parse_failure")
    assert fail == [("stub.broken", "crash:RuntimeError")]
    assert any(k[1] == "stub.ip" for k in env.projector.applied)


def test_rollback_on_error_keeps_watermark(env):
    class Exploding(StubProjector):
        def rebuild(self):
            raise RuntimeError("boom")

    t = env.term
    t.open()
    t.command("id", b"uid=0\r\n")
    p = env.pipeline(projector=Exploding(env.conn))
    with pytest.raises(RuntimeError):
        p.process_new()
    assert p.watermark == 0
    assert env.rows("SELECT COUNT(*) FROM unit")[0][0] == 0
    p.projector = StubProjector(env.conn)
    p.process_new()
    assert env.rows("SELECT COUNT(*) FROM unit WHERE state = 'final'")[0][0] == 1


def test_apply_schema_is_idempotent_and_claims_optional(tmp_path):
    conn = sqlite3.connect(tmp_path / "x.db")
    apply_schema(conn)
    apply_schema(conn)
    v = versions(conn)
    assert v["normalizer_version"] == NORMALIZER_VERSION and v["generation"] == 0
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    need = {"unit", "unit_line", "unit_fts", "cmd_block", "ctx_span", "activity", "watermark", "meta"}
    assert need <= names


def test_sqlcipher_connection(tmp_path):
    sqlcipher3 = pytest.importorskip("sqlcipher3")
    conn = sqlcipher3.connect(str(tmp_path / "enc.db"))
    conn.execute("PRAGMA key = \"x'" + "11" * 32 + "'\"")
    j = _journal_with()
    _pipe(j, conn).process_new()
    ref = sqlite3.connect(tmp_path / "ref.db")
    _pipe(j, ref).process_new()
    assert dump(conn) == dump(ref)
    assert TID in {r[3] for r in dump(conn)["unit_line"]}


def test_with_real_projection_and_parsers(tmp_path):
    """Zusammenspiel mit Registry und Projektion des Parser-Agents, falls vorhanden."""
    pytest.importorskip("ariadne.ingest.projection")
    registry = pytest.importorskip("ariadne.parsers.registry")
    from ariadne.ingest.pipeline import Pipeline
    from ariadne.ingest.runner import SubprocessRunner
    from ariadne.scope.matcher import ScopeMatcher

    j = MemoryJournal()
    t = TermSim(j)
    t.open()
    t.command("nmap -sV 10.10.10.3", b"Nmap scan report for 10.10.10.3\r\nHost is up (0.05s latency).\r\n"
                                     b"PORT   STATE SERVICE VERSION\r\n21/tcp open  ftp     vsftpd 2.3.4\r\n"
                                     b"22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)\r\n")
    conn = sqlite3.connect(tmp_path / "d.db")
    scope = ScopeMatcher.from_settings({"scope": {"include": ["10.10.10.0/24"]}}, 1)
    p = Pipeline(j, None, conn, project_key=b"k" * 32, scope=scope, runner=SubprocessRunner(),
                 registry=registry.default_registry(), clock=lambda: 0)
    st = p.process_new()
    assert st.failures == 0 and st.units_parsed >= 1 and st.generation is not None
    assert conn.execute("SELECT COUNT(*) FROM parse_failure").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM observation").fetchone()[0] > 0
