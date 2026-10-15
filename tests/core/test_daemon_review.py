"""Korrekturen aus den Reviews im Daemon: Strom-Ausrichtung beim Wiederaufnehmen, Pause für
Schlüsselmaterial, Ausfallpuffer nach einem Neustart, letzter Stapel beim Daemon-Ende.

Fake-Shims über echte Unix-Sockets, wie ``test_daemon_capture.py``.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from ariadne.ingest.seg_stream import seg_event_from_record
from ariadne.ingest.segmenter import SEG_KINDS, _blocks
from tests.core.conftest import OWN_SECRET, PASSPHRASE
from tests.core.fakeshim import FakeShim, ctl_ok
from tests.core.test_daemon import run
from tests.core.test_daemon_capture import backup_of, mark

MIN = 60_000_000_000
SEC = 1_000_000_000


def covered(journal, tid: str) -> list[tuple[int, int, str]]:
    """Prüft, dass jedes Byte des Stroms genau einmal term.out oder term.gap ist."""
    parts = [(r.stream_off, int(r.header["length"]), "out")
             for r in journal.iter_events(kinds=["term.out"], terminal_id=tid)]
    parts += [(int(r.header["stream_off"]), int(r.header["bytes_lost"]), str(r.header["reason"]))
              for r in journal.iter_events(kinds=["term.gap"], terminal_id=tid)
              if int(r.header["bytes_lost"]) > 0]
    parts.sort()
    pos = 0
    for off, n, what in parts:
        assert off == pos, f"Loch oder Überlappung bei {pos}..{off}: {parts}"
        pos = off + n
    return parts


def blocks_of(journal, tid: str) -> list[Any]:
    recs = [r for r in journal.iter_events(terminal_id=tid) if r.kind in SEG_KINDS]
    blocks, _ = _blocks(tid, [seg_event_from_record(r) for r in recs])
    return blocks


def test_switch_back_aligns_stream_with_gap(paths, operator):
    """Befund R2: A -> B -> A; der Strom von A hat zwischen 100 und 500 eine Lücke mit Grund."""

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="alpha", targets=["10.10.10.0/24"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"a" * 100)
        await s.wait_ack(1)
        await ctl_ok(paths.ctl_sock, "start", slug="beta", targets=["10.10.20.0/24"])
        await s.wait_state(rec="held")
        await s.event(2, "req.rebind", stream_off=100)
        await s.wait_state(rec="on", bound_slug="beta")
        await s.outx(3, 100, b"b" * 400)
        await s.wait_ack(3)
        await ctl_ok(paths.ctl_sock, "start", slug="alpha")
        await s.wait_state(rec="held", bound_slug="beta")
        await s.event(4, "req.rebind", stream_off=500)
        await s.wait_state(rec="on", bound_slug="alpha")
        await s.outx(5, 520, b"c" * 10)
        await s.wait_ack(5)
        d.flush()
        j = d.project.journal
        parts = covered(j, s.terminal_id)
        assert (100, 420, "project_switch") in parts
        snaps = [r.stream_off for r in j.iter_events(kinds=["term.ctx_snapshot"], terminal_id=s.terminal_id)]
        assert 500 not in snaps and snaps[-1] == 520  # kein Schnappschuss am Offset aus beta
        await s.close()

    run(paths, operator, scenario)


def test_lock_then_start_without_preroll_ends_running_command(paths, operator):
    """Befund R3: Die gesperrte Zeit ist no_project (beendet den Befehl), nicht sensitive_output."""

    async def scenario(d) -> None:
        backup = backup_of(operator)
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"$ ")
        await s.event(2, "term.mark", **mark(2, "C", 1, cmd_typed="sleep 1000"))
        await s.outx(3, 2, b"x" * 98)
        await s.wait_ack(3)
        await ctl_ok(paths.ctl_sock, "lock")
        await s.wait_state(rec="locked")
        await s.outx(4, 100, b"y" * 400)  # gesperrt: nur im Vorlauf
        await s.wait_ack(4)
        await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id=s.terminal_id)  # wie ariadne start
        d.operator = backup
        await ctl_ok(paths.ctl_sock, "start", adopt_preroll=False)
        await s.wait_state(rec="on")
        await s.outx(5, 500, b"z" * 10)  # Passphrase-Abfrage: verworfen
        await s.event(6, "term.mark", **mark(510, "D", 2, exit=0))
        await s.event(7, "term.mark", **mark(510, "A", 3))
        await s.wait_ack(7)
        d.flush()
        j = d.project.journal
        parts = covered(j, s.terminal_id)
        assert (100, 400, "no_project") in parts and (500, 10, "sensitive_output") in parts
        sleep = next(b for b in blocks_of(j, s.terminal_id) if b.text == "sleep 1000")
        assert sleep.exit is None and "truncated" in sleep.flags
        await s.close()

    run(paths, operator, scenario)


def test_stop_then_start_in_same_terminal(paths, operator):
    """Befund R3 im Alltag: ``ariadne stop``, dann ``ariadne start`` im selben Terminal."""

    async def scenario(d) -> None:
        backup = backup_of(operator)
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await s.event(1, "term.mark", **mark(0, "A", 1))
        await s.outx(2, 0, b"$ ariadne stop\r\n")
        await s.event(3, "term.mark", **mark(16, "C", 2, cmd_typed="ariadne stop"))
        await s.wait_ack(3)
        await ctl_ok(paths.ctl_sock, "stop")
        await s.wait_state(rec="held")
        await s.event(4, "req.rebind", stream_off=33)
        await s.wait_state(rec="preroll")
        await s.outx(5, 33, b"$ ariadne start\r\n")
        await s.event(6, "term.mark", **mark(50, "C", 5, cmd_typed="ariadne start"))
        await s.wait_ack(6)
        await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id=s.terminal_id)
        d.operator = backup
        await ctl_ok(paths.ctl_sock, "start", slug="lame", adopt_preroll=False)
        await s.wait_state(rec="on")
        await s.outx(7, 50, b"Passphrase: \r\nAufnahme laeuft\r\n")
        await s.event(8, "term.mark", **mark(83, "D", 6, exit=0))
        await s.event(9, "term.mark", **mark(83, "A", 7))
        await s.wait_ack(9)
        d.flush()
        j = d.project.journal
        covered(j, s.terminal_id)
        stop = next(b for b in blocks_of(j, s.terminal_id) if b.text == "ariadne stop")
        assert stop.exit is None and "truncated" in stop.flags  # D und Exit gehören nicht ihm
        await s.close()

    run(paths, operator, scenario)


def test_sensitive_pause_survives_user_pause_resume_and_lock(paths, operator):
    """Befund SEC-3: Die Anmeldung vor getpass gilt bis zum Prompt, auch wenn dazwischen
    pausiert, fortgesetzt oder aus einem anderen Terminal gesperrt wird."""

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        a = await FakeShim(paths.term_sock).connect(proto=2)
        b = await FakeShim(paths.term_sock).connect(proto=2)
        await a.wait_state(rec="on")
        await b.wait_state(rec="on")
        await a.outx(1, 0, b"$ ariadne unlock\r\n")
        await a.wait_ack(1)
        await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id=a.terminal_id, seconds=600)
        await ctl_ok(paths.ctl_sock, "term.pause", all=True)
        await ctl_ok(paths.ctl_sock, "term.resume", all=True)
        await a.wait_state(rec="on")
        await a.input(2, 18, PASSPHRASE.encode() + b"\r")
        await a.wait_ack(2)
        d.flush()
        bodies = b"".join(r.body or b"" for r in d.project.journal.iter_events(kinds=["term.input"]))
        assert PASSPHRASE.encode() not in bodies
        # zweite Abfrage (secrets add), derweil sperrt Terminal b
        await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id=b.terminal_id, seconds=600)
        await ctl_ok(paths.ctl_sock, "lock")
        await b.wait_state(rec="locked")
        await b.input(1, 0, OWN_SECRET.encode() + b"\r")
        await b.outx(2, 0, b"gespeichert\r\n")
        await b.wait_ack(2)
        held = d.preroll.bufs.get(b.terminal_id)
        data = b"".join(bytes(e.data or b"") for e in (held.entries if held else []))
        assert OWN_SECRET.encode() not in data and b"gespeichert" not in data
        await b.event(3, "term.mark", **mark(13, "D", 2, exit=0))  # Prompt: Pause endet
        await b.outx(4, 13, b"$ ")
        await b.wait_ack(4)
        held = d.preroll.bufs.get(b.terminal_id)
        assert held is not None and b"$ " in b"".join(bytes(e.data or b"") for e in held.entries)
        for s in (a, b):
            await s.close()

    run(paths, operator, scenario)


def test_sensitive_pause_not_ended_by_replayed_markers(paths, operator):
    """Befund F1 (Entscheidtreue): ``ariadne start`` startet den Daemon, die CLI meldet ihr
    Terminal vor dem HELLO an; der Shim sendet danach alte Marker aus seinem Ring. Die beenden
    die Pause nicht, alte Ausgabe bleibt, die Passphrase landet weder im Vorlauf noch im Journal."""

    async def scenario(d) -> None:
        tid = "term-replay-0001"
        await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id=tid, seconds=600)  # vor dem HELLO
        s = await FakeShim(paths.term_sock, tid).connect(proto=2, resume_from_seq=1)
        await s.wait_state(rec="preroll")
        old_m, old_w = time.monotonic_ns() - 30 * SEC, time.time_ns() - 30 * SEC
        await s.outx(1, 0, b"$ echo offline-4\r\noffline-4\r\n", wall=old_w, mono=old_m)
        await s.event(2, "term.mark", **mark(28, "D", 4, exit=0, mono_ns=old_m, t_shim_ns=old_w))
        await s.event(3, "term.mark", **mark(28, "A", 5, mono_ns=old_m, t_shim_ns=old_w))
        await s.wait_ack(3)
        assert d.terminals[tid].pause is not None  # Wiederholung beendet die Pause nicht
        await s.outx(4, 28, b"Passphrase: ")
        await s.input(5, 40, PASSPHRASE.encode() + b"\n")
        await s.wait_ack(5)
        now_m, now_w = time.monotonic_ns(), time.time_ns()
        await s.event(6, "term.mark", **mark(42, "D", 6, exit=0, mono_ns=now_m, t_shim_ns=now_w))
        await s.wait_ack(6)
        assert d.terminals[tid].pause is None
        await ctl_ok(paths.ctl_sock, "start", slug="lab1", targets=["10.10.10.0/24"], adopt_preroll=True)
        d.flush()
        j = d.project.journal
        raw = b"".join(r.body or b"" for r in j.iter_events(kinds=["term.out", "term.input"]))
        assert b"offline-4" in raw and PASSPHRASE.encode() not in raw and b"Passphrase: " not in raw
        gaps = [r.header for r in j.iter_events(kinds=["term.gap"])]
        assert any(g["reason"] == "sensitive_output" and g["stream_off"] == 28 for g in gaps)
        await s.close()

    run(paths, operator, scenario)


def test_outage_ring_kept_without_window_and_gap_reason(paths, operator):
    """Befund F1 (Tests): Nach einem Absturz bei aktivem Projekt sendet der Shim seinen Ring.
    Der gesperrte Daemon hält ihn ohne Vorlauf-Fenster; bei Nein heisst die Lücke daemon_down."""
    state: dict[str, Any] = {}
    tid = "term-crash-00001"

    async def first(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        state["pid"] = d.project.info.id
        s = await FakeShim(paths.term_sock, tid).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"vorher\r\n")
        await s.wait_ack(1)
        await s.close()

    async def second(d, adopt: bool) -> None:
        d.operator = backup_of(state["backup"])
        s = await FakeShim(paths.term_sock, tid).connect(proto=2, resume_from_seq=2,
                                                        bound_project_id=state["pid"], bound_slug="lame")
        await s.wait_state(rec="locked")
        old = 20 * MIN
        await s.outx(2, 8, b"nmap 445/tcp open\r\n", wall=time.time_ns() - old,
                     mono=time.monotonic_ns() - old)
        await s.outx(3, 27, b"jetzt\r\n")
        await s.wait_ack(3)
        info = await ctl_ok(paths.ctl_sock, "preroll.info")
        assert info["terminals"] == 1 and info["seconds"] >= 20 * 60
        await ctl_ok(paths.ctl_sock, "start", adopt_preroll=adopt)
        await s.outx(4, 34, b"danach\r\n")
        await s.wait_ack(4)
        d.flush()
        j = d.project.journal
        state["stream"] = b"".join(r.body for r in j.iter_events(kinds=["term.out"], terminal_id=tid))
        state["parts"] = covered(j, tid)
        await s.close()

    state["backup"] = backup_of(operator)
    run(paths, operator, first)
    run(paths, None, lambda d: second(d, True))
    assert b"445/tcp open" in state["stream"] and b"danach" in state["stream"]


def test_outage_discarded_on_no_names_daemon_down(paths, operator):
    state: dict[str, Any] = {}
    tid = "term-crash-00002"

    async def first(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        state["pid"] = d.project.info.id
        s = await FakeShim(paths.term_sock, tid).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"vorher\r\n")
        await s.wait_ack(1)
        await s.close()

    async def second(d) -> None:
        d.operator = backup_of(state["backup"])
        s = await FakeShim(paths.term_sock, tid).connect(proto=2, resume_from_seq=2,
                                                        bound_project_id=state["pid"], bound_slug="lame")
        await s.wait_state(rec="locked")
        await s.outx(2, 8, b"im Ring\r\n")
        await s.wait_ack(2)
        res = await ctl_ok(paths.ctl_sock, "start", adopt_preroll=False)
        assert res["preroll"]["discarded_terminals"] == 1
        await s.outx(3, 17, b"danach\r\n")
        await s.wait_ack(3)
        d.flush()
        parts = covered(d.project.journal, tid)
        assert (8, 9, "daemon_down") in parts
        await s.close()

    state["backup"] = backup_of(operator)
    run(paths, operator, first)
    run(paths, None, second)


def test_user_lock_keeps_preroll_window(paths, operator):
    """Nach ``ariadne lock`` gilt das Vorlauf-Fenster (kein Ausfallpuffer)."""

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await ctl_ok(paths.ctl_sock, "lock")
        await s.wait_state(rec="locked")
        old = 20 * MIN
        await s.outx(1, 0, b"alt\r\n", wall=time.time_ns() - old, mono=time.monotonic_ns() - old)
        await s.wait_ack(1)
        assert s.terminal_id not in d.preroll.bufs
        await s.close()

    run(paths, operator, scenario)


def test_shutdown_acks_last_batch_and_resend_is_not_duplicated(paths, operator):
    """Befund F4: Beim Daemon-Ende geht das ACK für den letzten Stapel noch hinaus; kommt er
    trotzdem erneut (Absturz), stehen Marker und Eingaben nicht doppelt im Journal."""
    state: dict[str, Any] = {}
    tid = "term-restart-0001"
    m = {"stream_off": 0, "mark": "C", "counter": 7, "fg_shell": True, "cmd_typed": "ariadne daemon restart"}

    async def first(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        state["pid"] = d.project.info.id
        s = await FakeShim(paths.term_sock, tid).connect(proto=2)
        await s.wait_state(rec="on")
        await asyncio.sleep(0.1)
        d.writer.interval = 3600  # der Takt schreibt nicht mehr dazwischen
        await asyncio.sleep(0.05)
        await s.event(1, "term.mark", **m)
        await s.input(2, 0, b"ariadne daemon restart\r")
        await s.outx(3, 0, b"\r\n")
        await asyncio.sleep(0.1)
        state["before"] = s.acked
        await d.stop()  # Daemon-Ende: erst bestätigen, dann Verbindungen schliessen
        await asyncio.sleep(0.1)
        state["after"] = s.acked
        await s.close()

    async def second(d) -> None:
        d.operator = backup_of(state["backup"])
        s = await FakeShim(paths.term_sock, tid).connect(proto=2, resume_from_seq=1,
                                                        bound_project_id=state["pid"], bound_slug="lame")
        await s.wait_state(rec="locked")
        await s.event(1, "term.mark", **m)  # wie nach einem Absturz: erneut gesendet
        await s.input(2, 0, b"ariadne daemon restart\r")
        await s.outx(3, 0, b"\r\n")
        await s.wait_ack(3)
        await ctl_ok(paths.ctl_sock, "start", adopt_preroll=True)
        d.flush()
        j = d.project.journal
        state["marks"] = [r.header["counter"] for r in j.iter_events(kinds=["term.mark"])]
        state["inputs"] = [r.body for r in j.iter_events(kinds=["term.input"])]
        state["opens"] = len(list(j.iter_events(kinds=["term.open"])))
        await s.close()

    state["backup"] = backup_of(operator)
    run(paths, operator, first)
    assert state["before"] < 3 and state["after"] == 3  # ACK beim Ende noch gesendet
    run(paths, None, second)
    assert state["marks"] == [7] and len(state["inputs"]) == 1 and state["opens"] == 1


# --------------------------------------------------------------------------- Uhren und Leerlauf


class Clocks:
    """Wanduhr, monotone Uhr und Bootzeit unabhängig verstellbar."""

    def __init__(self) -> None:
        self.wall_shift = self.mono_shift = self.boot_shift = 0

    def wall(self) -> int:
        return time.time_ns() + self.wall_shift

    def mono(self) -> int:
        return time.monotonic_ns() + self.mono_shift

    def boot(self) -> int:
        return time.monotonic_ns() + self.boot_shift


def _clock_daemon(paths, c: Clocks, **kw: Any):
    from ariadne.daemon.config import RecordingConfig
    from ariadne.daemon.core import Daemon

    return Daemon(paths, check_peer_comm=False, ingest=False, sources=False, local_addrs=None,
                  config=kw.pop("config", RecordingConfig()), wall_clock=c.wall, mono_clock=c.mono,
                  boot_clock=c.boot, **kw)


def test_open_after_long_idle_resets_idle_clock(paths, operator):
    """Befunde R4 und F4 (Entscheidtreue): ``project new``/``open`` und ``unlock`` zählen als
    Aktivität; ein gerade geöffnetes Projekt endet nicht im nächsten Takt."""
    from ariadne.daemon.config import RecordingConfig
    from tests.core.test_daemon_capture import Clock

    clock = Clock()

    async def scenario(d) -> None:
        clock.shift = 13 * 3600 * SEC  # Daemon lief 13 h ohne Rahmen (Vorlauf aus)
        await ctl_ok(paths.ctl_sock, "project.new", slug="lame", targets=["10.10.10.3"])
        assert not d._check_idle() and d.project is not None
        await ctl_ok(paths.ctl_sock, "lock")
        clock.shift = 26 * 3600 * SEC
        await ctl_ok(paths.ctl_sock, "unlock", passphrase=PASSPHRASE)
        assert d._idle_ns() < 60 * SEC

    run(paths, operator, scenario, wall_clock=clock.wall, mono_clock=clock.mono,
        config=RecordingConfig(preroll_minutes=0))


def test_idle_counts_suspend_and_wall_jump(paths, operator):
    """Befunde SEC-5 und F6: CLOCK_MONOTONIC steht bei Suspend still; Bootzeit bzw. Wanduhr nicht."""
    for which in ("boot", "wall"):
        c = Clocks()
        d = _clock_daemon(paths, c, operator=backup_of(operator))
        d.project = object()  # type: ignore[assignment]  # nur für die Prüfung «Projekt offen»
        ended: list[str] = []
        d._end_project = lambda reason, idle_s=None: ended.append(reason)  # type: ignore[method-assign]
        d._activity()
        setattr(c, f"{which}_shift", 13 * 3600 * SEC)  # 13 h Suspend bzw. angehaltene VM
        assert d._check_idle() and ended == ["idle"], which
        d.project = None
        d._lock_operator()


def test_preroll_window_uses_wall_clock_of_receipt(paths):
    """Befund SEC-5: Der Vorlauf hält nach einem Suspend nichts, was nach Wanduhr zu alt ist."""
    from ariadne.ctxrules import ContextStack
    from ariadne.daemon.preroll import Held, PrerollStore

    c = Clocks()
    store = PrerollStore(window_s=900, terminal_bytes=1 << 20, total_bytes=1 << 22, clock=c.mono,
                         wall_clock=c.wall)
    store.add("t1", Held("out", 0, c.wall(), c.mono(), None, bytearray(b"vor dem Suspend")), ContextStack())
    assert store.info()["terminals"] == 1
    c.wall_shift = 16 * MIN  # monotone Uhr steht, die Wanduhr ist 16 min weiter
    assert store.info()["terminals"] == 0


def test_user_pause_not_extended_by_wall_clock_jump_back(paths):
    """Befund F9: Ein Rücksprung der Wanduhr verlängert die Pause nicht."""
    from ariadne.daemon.terminal import Terminal

    c = Clocks()
    d = _clock_daemon(paths, c)
    t = Terminal("term-0001")
    t.proto = 2
    d.terminals[t.terminal_id] = t
    d._set_pause(t, 10, "cli")
    assert d.state_of(t) == "paused"
    c.wall_shift = -2 * 3600 * SEC + 11 * MIN  # NTP: 2 h zurück, dann vergehen 11 min
    c.mono_shift = 11 * MIN
    assert d.state_of(t) != "paused"
    d._check_user_pause(t)
    assert t.pause_until_ns is None and t.pause_mono_until is None


def test_late_but_consistent_frame_is_not_time_suspect(paths, operator):
    """Befund F3: Ein Rahmen, der spät ankommt (Ring nach Ausfall), behält seine Shim-Zeit."""
    from ariadne.ingest.seg_stream import record_time

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        w, m = time.time_ns() - 30 * SEC, time.monotonic_ns() - 30 * SEC  # vor 30 s gelesen
        await s.outx(1, 0, b"nmap -sV 10.10.10.3\r\n", wall=w, mono=m)
        await s.input(2, 21, b"id\r", wall=w, mono=m)
        await s.outx(3, 21, b"x\r\n", wall=time.time_ns() + 60 * SEC, mono=time.monotonic_ns())  # Uhr springt
        await s.wait_ack(3)
        d.flush()
        outs = list(d.project.journal.iter_events(kinds=["term.out"]))
        inp = next(d.project.journal.iter_events(kinds=["term.input"]))
        assert "time_suspect" not in outs[0].header and "time_suspect" not in inp.header
        assert abs(record_time(outs[0])[0] - w) < SEC
        assert outs[-1].header.get("time_suspect") is True
        await s.close()

    run(paths, operator, scenario)


# --------------------------------------------------------------------------- Kontext


def test_keystep_never_stores_auto_host(paths, operator):
    """Befund SEC-1: Ein Auto-Host (E23) kommt nicht als ``host`` in ``d.keystep.mark``; die
    Auswertung leitet ihn über terminal_id/stream_off ab (und F12 h korrigiert rückwirkend)."""
    from ariadne.daemon.ingest import AutoContext, IngestUpdate

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.0/24"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await s.event(1, "term.mark", **mark(10, "C", 1, cmd_typed="nc -lvnp 4444"))
        await s.wait_ack(1)
        d._on_ingest_update(IngestUpdate(3, (AutoContext(s.terminal_id, 10, "ip:default/10.10.10.5"),)))
        await s._wait(lambda: s.state.get("ctx_version") == 1, 3)
        await s.event(2, "req.keystep", step="foothold")
        await s.wait_ack(2)
        res = await ctl_ok(paths.ctl_sock, "keystep.mark", step="loot", terminal_id=s.terminal_id)
        assert res["host"] == "ip:default/10.10.10.5" and res["host_auto"] is True  # nur Anzeige
        await ctl_ok(paths.ctl_sock, "ctx.set", terminal_id=s.terminal_id, host="10.10.10.3")
        await ctl_ok(paths.ctl_sock, "keystep.mark", step="privesc", terminal_id=s.terminal_id)
        d.flush()
        ks = [r.header for r in d.project.journal.iter_events(kinds=["d.keystep.mark"])]
        assert [h.get("host") for h in ks] == [None, None, "ip:default/10.10.10.3"]
        assert all(h.get("terminal_id") == s.terminal_id and "stream_off" in h for h in ks)
        await s.close()

    run(paths, operator, scenario)


def test_decisions_refused_after_concurrent_project_switch(paths, operator, monkeypatch):
    """Befund F10: Wechselt ein anderes ``ariadne start`` das Projekt, während ``confirm``,
    ``reject`` oder ``undo`` die Referenz auflöst, landet nichts im neuen Projekt (E70)."""
    from ariadne.daemon import ops_eval

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="alpha", targets=["10.10.10.0/24"])
        slugs = iter(["beta", "alpha", "beta"])
        answers = {"claim.confirm": {"keys": ["k-aus-alpha"], "excluded": {}, "excluded_sample": [],
                                     "group": None},
                   "claim.reject": "k-aus-alpha", "unit.distrust": "0199a2b3-cmd"}

        for op in ("claim.confirm", "claim.reject", "unit.distrust"):
            async def slow_resolve(dd, fn, op=op):
                slug = next(slugs)
                await dd.call("start", {"slug": slug, "targets": ["10.10.20.0/24"]})
                return answers[op]

            monkeypatch.setattr(ops_eval, "_resolve", slow_resolve)
            before = d.project
            res = await d.call(op, {"ref": "egal"})
            assert res["error"]["code"] == "project_changed", res
            assert d.project is not before
            d.flush()
            kinds = {r.kind for r in d.project.journal.iter_events()}
            assert not kinds & {"d.claim.confirm", "d.claim.reject", "d.unit.distrust"}

    run(paths, operator, scenario)



def test_auto_context_test_survives_slow_ctl(paths, operator, monkeypatch):
    """Befund F7: Der Auto-Kontext-Test darf nicht gegen die echte Auswertung kämpfen; unter
    Last (jede ctl-Operation 0.6 s langsamer) blieb er sonst rot."""
    from tests.core import test_daemon_capture as tdc

    orig = tdc.ctl_ok

    async def slow(*a: Any, **kw: Any) -> Any:
        await asyncio.sleep(0.6)
        return await orig(*a, **kw)

    monkeypatch.setattr(tdc, "ctl_ok", slow)
    tdc.test_auto_context_from_ingest_sets_live_stack_not_journal(paths, operator)
