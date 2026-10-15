"""Zeit in der Auswertung (E96, Vertrag 6.9) und neue Event-Arten in der Pipeline.

Shim-Zeit statt Empfangszeit, Sortierung über die monotone Uhr (auch wenn die Wanduhr
springt), Zeitindex ``tix``, alte Journale ohne Zeitfelder, Pausen, eigene Adressen,
Schema-Version von ``derived.db``.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from ariadne.ingest import queries
from ariadne.ingest.db import apply_schema, get_meta, schema_stale, set_meta
from ariadne.ingest.runner import InProcessRunner
from ariadne.store.memory import MemoryJournal
from tests.ingest.helpers import BASE_TS, SEC, StubParser, StubProjector

MS = 1_000_000


class ShimSim:
    """Events wie ein Shim mit Protokoll v2: Shim-Zeit (Wanduhr, monotone Uhr) im Header,
    Empfangszeit im Daemon ``lag`` später."""

    def __init__(self, journal: Any, tid: str, *, wall: int, mono: int, lag: int = 250 * MS) -> None:
        self.j, self.tid, self.wall, self.mono, self.lag = journal, tid, wall, mono, lag
        self.off = 0
        self.counter = 0

    def step(self, ns: int) -> None:
        self.wall += ns
        self.mono += ns

    def _ev(self, kind: str, header: dict[str, Any], body: bytes | None = None, origin: str = "shim",
            stream_off: int | None = None) -> Any:
        h = {"terminal_id": self.tid, "t_shim_ns": self.wall, "mono_ns": self.mono, **header}
        so = h.get("stream_off", stream_off)
        return self.j.append(kind, h, body, origin=origin, terminal_id=self.tid, stream_off=so,
                             ts_utc_ns=self.wall + self.lag)

    def open(self) -> None:
        self._ev("term.open", {"shell": "zsh", "rows": 24, "cols": 80, "shim_version": "2"}, origin="daemon",
                 stream_off=0)
        self._ev("term.ctx_snapshot", {"stream_off": 0, "stack": [{"kind": "local", "host": "local",
                                                                   "opened_at": 0}]}, origin="daemon")

    def out(self, data: bytes, tix: list[list[int]] | None = None) -> None:
        h: dict[str, Any] = {"stream_off": self.off, "length": len(data)}
        if tix:
            h["tix"] = tix
        self._ev("term.out", h, data)
        self.off += len(data)

    def mark(self, mark: str, **fields: Any) -> None:
        self.counter += 1
        self._ev("term.mark", {"stream_off": self.off, "mark": mark, "counter": self.counter,
                               "fg_shell": True, "shell_pid": 7, **fields})

    def command(self, cmd: str, output: bytes) -> int:
        self.mark("A", cwd="/home/kali")
        self.out(b"$ " + cmd.encode() + b"\r\n")
        c = self.off
        self.mark("C", cmd_typed=cmd, cwd="/home/kali", user="kali")
        self.step(10 * MS)
        self.out(output)
        self.step(10 * MS)
        self.mark("D", exit=0, cwd="/home/kali")
        return c


def _pipe(journal: Any, conn: Any, **kw: Any) -> Any:
    from ariadne.ingest.pipeline import Pipeline

    kw.setdefault("projector", StubProjector(conn))
    return Pipeline(journal, None, conn, project_key=b"k" * 32, scope=None, runner=InProcessRunner(),
                    registry=[StubParser()], clock=lambda: 0, **kw)


def _db(tmp_path, name: str = "d.db") -> sqlite3.Connection:
    return sqlite3.connect(tmp_path / name)


def test_units_and_blocks_use_shim_time(tmp_path):
    j = MemoryJournal()
    t = ShimSim(j, "t-a", wall=BASE_TS, mono=5 * SEC)
    t.open()
    c = t.command("id", b"uid=1000(kali)\r\n")
    conn = _db(tmp_path)
    try:
        _pipe(j, conn).process_new()
        (start, end, mono, boot), = conn.execute(
            "SELECT ts_start_ns, ts_end_ns, mono_ns, boot_id FROM cmd_block").fetchall()
        assert (start, end - start, mono, boot) == (BASE_TS, 20 * MS, 5 * SEC, "test-boot")
        (ts, umono), = conn.execute("SELECT ts_utc_ns, mono_ns FROM unit WHERE kind = 'command'").fetchall()
        assert (ts, umono) == (BASE_TS, 5 * SEC)  # nicht die Empfangszeit (250 ms später)
        assert conn.execute("SELECT mono_ns, boot_id FROM activity").fetchall() == [(5 * SEC, "test-boot")]
        assert c > 0
    finally:
        conn.close()


def test_tix_gives_byte_precise_times(tmp_path):
    from ariadne.ingest.seg_stream import TermStream

    j = MemoryJournal()
    t = ShimSim(j, "t-a", wall=BASE_TS, mono=7 * SEC)
    t.open()
    t.out(b"0123456789", tix=[[4, 1500], [8, 9000]])
    conn = _db(tmp_path)
    try:
        _pipe(j, conn).process_new()
        ts = TermStream.load(conn, "t-a", j, 10**9)
        assert ts.time_at(0) == BASE_TS and ts.time_at(5) == BASE_TS + 1_500_000
        assert ts.mono_at(9) == (7 * SEC + 9_000_000, "test-boot")
        # ungültiger Zeitindex wird verworfen statt geraten
        from ariadne.ingest.seg_stream import _tix

        assert _tix([[4, 5], [3, 6]]) == [] and _tix([[0, 1]]) == [] and _tix(None) == []
    finally:
        conn.close()


def test_timeline_sorts_by_monotonic_clock_across_terminals(tmp_path):
    """Die Wanduhr springt eine Stunde zurück: die monotone Uhr entscheidet."""
    from ariadne.ingest.projection import Projector

    j = MemoryJournal()
    a = ShimSim(j, "t-aaaaaaaa", wall=BASE_TS, mono=100 * SEC)
    b = ShimSim(j, "t-bbbbbbbb", wall=BASE_TS - 3600 * SEC, mono=110 * SEC)  # 10 s später, Uhr zurück
    a.open()
    b.open()
    b.command("echo zweiter", b"zweiter\r\n")  # zuerst gespeichert, aber später passiert
    a.command("echo erster", b"erster\r\n")
    conn = _db(tmp_path)
    try:
        _pipe(j, conn, projector=Projector(conn, project_key=b"k" * 32, scope=None)).process_new()
        tl = [e["title"] for e in queries.timeline(conn) if e["type"] == "command"]
        assert tl == ["echo erster", "echo zweiter"]
        # Neustart: der zweite Systemstart sortiert nach dem ersten, egal was die Uhren sagen
        j.boot_id = "boot-2"
        c = ShimSim(j, "t-cccccccc", wall=BASE_TS - 7200 * SEC, mono=1 * SEC)
        c.open()
        c.command("echo nach neustart", b"x\r\n")
        _pipe(j, conn, projector=Projector(conn, project_key=b"k" * 32, scope=None)).process_new()
        tl = [e["title"] for e in queries.timeline(conn) if e["type"] == "command"]
        assert tl == ["echo erster", "echo zweiter", "echo nach neustart"]
        assert conn.execute("SELECT boot_id FROM boot ORDER BY first_seq").fetchall() == [
            ("test-boot",), ("boot-2",)]
    finally:
        conn.close()


def test_sort_without_monotonic_clock_falls_back_to_wall():
    entries = [{"type": "command", "ts": 30, "boot_id": None}, {"type": "command", "ts": 10, "boot_id": None},
               {"type": "keystep", "ts": 20, "boot_id": "b", "mono_ns": None},
               {"type": "command", "ts": 25, "boot_id": "b", "mono_ns": 5}]
    queries._sort_time(entries, {"b": 0})
    assert [e["ts"] for e in entries] == [10, 30, 20, 25]  # ohne Systemstart zuerst; b: 20-20=0 < 5


def test_new_event_kinds_do_not_disturb_and_fill_own_addresses(tmp_path):
    def journal(extra: bool) -> MemoryJournal:
        j = MemoryJournal()
        t = ShimSim(j, "t-a", wall=BASE_TS, mono=SEC)
        t.open()
        if extra:
            j.append("net.local_addrs", {"addrs": ["10.10.14.5", "127.0.0.1"]})
            j.append("term.pause", {"terminal_id": "t-a", "stream_off": 0, "until_ns": BASE_TS + 600 * SEC,
                                    "source": "hotkey"}, terminal_id="t-a", stream_off=0)
            j.append("term.preroll", {"terminal_id": "t-a", "from_off": 0, "to_off": 0, "frames": 0},
                     terminal_id="t-a")
        t.command("nmap 10.10.10.3", b"22/tcp open ssh\r\n")
        if extra:
            t._ev("term.input", {"stream_off": t.off, "out_end": t.off, "length": 5, "paste": True},
                  b"pw\r\n")
            j.append("net.route", {"cmd_id": "t-a@1", "target": "10.10.10.3", "src_ip": "10.10.14.6"})
            j.append("system.project_end", {"reason": "stop"})
        return j

    plain, full = _db(tmp_path, "a.db"), _db(tmp_path, "b.db")
    try:
        _pipe(journal(False), plain).process_new()
        stats = _pipe(journal(True), full).process_new()
        assert stats.failures == 0
        q = "SELECT unit_id, kind, cmd_text, line_count FROM unit ORDER BY unit_id"
        assert plain.execute(q).fetchall() == full.execute(q).fetchall()
        assert full.execute("SELECT addr, source FROM own_addr ORDER BY addr").fetchall() == [
            ("10.10.14.5", "proc"), ("10.10.14.6", "route"), ("127.0.0.1", "proc")]
        assert get_meta(full, "rebuild_pending") == "0"  # Neuberechnung ist gelaufen
        hits = full.execute("SELECT COUNT(*) FROM unit_fts WHERE unit_fts MATCH 'pw'").fetchone()[0]
        assert hits == 0  # Eingaben stehen nie in der Suche (nicht Teil der Ausgabe)
    finally:
        plain.close()
        full.close()


def test_pause_gap_ends_running_command_even_without_lost_bytes(tmp_path):
    from ariadne.ingest.segmenter import SegEvent, compute_layout

    def layout(reason: str):
        evs = [SegEvent(1, "term.open", 0, 1, {"stream_off": 0}),
               SegEvent(2, "term.mark", 10, 2, {"mark": "C", "cmd_typed": "sleep 100", "fg_shell": True}),
               SegEvent(3, "term.gap", 20, 3, {"stream_off": 20, "reason": reason, "bytes_lost": 0}),
               SegEvent(4, "term.mark", 30, 4, {"mark": "D", "exit": 0, "fg_shell": True})]
        return compute_layout("t", evs, 40)

    paused = layout("pause").blocks
    assert [sorted(b.flags) for b in paused] == [["gap", "truncated"], ["partial"]]
    assert layout("no_project").blocks[0].end_off == 20
    kept = layout("sensitive_output").blocks
    assert len(kept) == 1 and kept[0].d_off == 30


def test_schema_stale_detection(tmp_path):
    fresh = _db(tmp_path, "fresh.db")
    old = _db(tmp_path, "old.db")
    try:
        assert not schema_stale(fresh)
        apply_schema(fresh)
        assert not schema_stale(fresh)
        assert get_meta(fresh, "schema_claims_version") == "2"
        old.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        old.execute("CREATE TABLE claim (claim_key TEXT PRIMARY KEY)")
        set_meta(old, "schema_units_version", "1")
        assert schema_stale(old)
        bare = _db(tmp_path, "bare.db")
        bare.execute("CREATE TABLE unit (unit_id TEXT)")
        assert schema_stale(bare)
        bare.close()
    finally:
        fresh.close()
        old.close()
