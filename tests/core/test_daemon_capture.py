"""Daueraufnahme (E22), Pause, Projektwechsel (E28), Vorlauf (E95), Zeit (E96), Eingaben (E26),
Schwärzen an den Ausgängen (E72), eigene Adressen und Auto-Kontext im Daemon.

Fake-Shims über echte Unix-Sockets; Wanduhr und monotone Uhr des Daemons sind wo nötig
künstlich (``Clock``).
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ariadne import events
from ariadne.daemon.config import RecordingConfig
from ariadne.daemon.core import Daemon
from ariadne.daemon.ingest import AutoContext, IngestUpdate
from ariadne.daemon.terminal import Terminal
from tests.core.conftest import OWN_SECRET, PASSPHRASE
from tests.core.fakeshim import FakeShim, ctl, ctl_ok
from tests.core.test_daemon import run, stream_of

MIN = 60_000_000_000
SEC = 1_000_000_000


class Clock:
    """Künstliche Uhren: Wanduhr und monotone Uhr laufen mit der echten Zeit plus Versatz."""

    def __init__(self) -> None:
        self.shift = 0

    def wall(self) -> int:
        return time.time_ns() + self.shift

    def mono(self) -> int:
        return time.monotonic_ns() + self.shift


def backup_of(operator):
    return dataclasses.replace(operator, _secrets=list(operator.own_secrets))


def mark(seq_off: int, m: str, ctr: int, **kw: Any) -> dict[str, Any]:
    return {"stream_off": seq_off, "mark": m, "counter": ctr, "fg_shell": True, **kw}


def headers(journal, kind: str) -> list[dict[str, Any]]:
    return [r.header for r in journal.iter_events(kinds=[kind])]


def collect(d: Daemon) -> list:
    """Alle geschriebenen Records (auch aus Projekten, die inzwischen geschlossen sind)."""
    seen: list = []
    d.add_commit_hook(seen.extend)
    return seen


# --------------------------------------------------------------------------- Zustände (3.4)


@pytest.mark.parametrize("case,expected,v1", [
    ("paused", "paused", "off"),
    ("held_other", "held", "off"),
    ("held_stopped", "held", "off"),
    ("on", "on", "on"),
    ("on_bound_same", "on", "on"),
    ("locked", "locked", "waiting"),
    ("locked_bound_active", "locked", "waiting"),
    ("preroll", "preroll", "waiting"),
    ("off", "off", "off"),
])
def test_state_table(paths, case, expected, v1):
    preroll = 0 if case == "off" else 15
    d = Daemon(paths, check_peer_comm=False, ingest=False, sources=False, local_addrs=None,
               config=RecordingConfig(preroll_minutes=preroll))
    t = Terminal("term-0001")
    if case == "paused":
        t.pause_until_ns = d._wall() + MIN
        d.project = SimpleNamespace(info=SimpleNamespace(id="P-AAAAAAAA", slug="a"))
    elif case == "held_other":
        t.bound_project_id = "P-AAAAAAAA"
        d.project = SimpleNamespace(info=SimpleNamespace(id="P-BBBBBBBB", slug="b"))
    elif case == "held_stopped":
        t.bound_project_id = "P-AAAAAAAA"
        d.active = {"slug": "a", "project_id": "P-AAAAAAAA", "stopped": True}
    elif case in ("on", "on_bound_same"):
        d.project = SimpleNamespace(info=SimpleNamespace(id="P-AAAAAAAA", slug="a"))
        if case == "on_bound_same":
            t.bound_project_id = "P-AAAAAAAA"
    elif case.startswith("locked"):
        d.active = {"slug": "a", "project_id": "P-AAAAAAAA", "stopped": False}
        if case == "locked_bound_active":
            t.bound_project_id = "P-AAAAAAAA"
    elif case == "preroll":
        d.active = {"slug": "a", "project_id": "P-AAAAAAAA", "stopped": True}
    assert d.state_of(t) == expected
    t.proto = 2
    assert d.status_of(t) == expected
    t.proto = 1
    assert d.status_of(t) == v1
    expired = Terminal("term-0002", pause_until_ns=d._wall() - 1)
    assert d.state_of(expired) != "paused"


def test_config_and_active_file(paths, tmp_path):
    from ariadne.daemon.active import read_active, write_active
    from ariadne.daemon.config import load_recording

    cfg = paths.config_file
    cfg.parent.mkdir(parents=True)
    cfg.write_text('[recording]\nidle_end_hours = 0\npause_minutes = 999\npreroll_minutes = 5\n'
                   'preroll_total_mib = "viel"\n')
    rc = load_recording(cfg)
    assert (rc.idle_end_hours, rc.pause_minutes, rc.preroll_minutes, rc.preroll_total_mib) == (0, 10, 5, 64)
    assert rc.idle_end_s is None
    cfg.write_text("kaputt = [")
    assert load_recording(cfg) == RecordingConfig()
    data = write_active(paths.active_file, "lame", "01a1b2c3-0000", stopped=False)
    assert read_active(paths.active_file) == data
    assert stat.S_IMODE(os.stat(paths.active_file).st_mode) == 0o600
    paths.active_file.write_text('{"slug": "../x", "project_id": "p", "stopped": false}')
    assert read_active(paths.active_file) is None


# --------------------------------------------------------------------------- start / stop / lock


def test_start_open_create_switch_stop_and_errors(paths, operator):
    async def scenario(d: Daemon) -> None:
        seen = collect(d)
        backup = backup_of(operator)
        resp = await ctl(paths.ctl_sock, "start", slug="nix")
        assert resp["error"]["code"] == "project_not_found"
        resp = await ctl(paths.ctl_sock, "start")
        assert resp["error"]["code"] == "no_active_project"
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        assert res["created"] and res["switched_from"] is None and not res["unlocked"]
        assert res["preroll"]["adopted"] is False
        active = json.loads(paths.active_file.read_text())
        assert active["slug"] == "lame" and active["stopped"] is False and set(active) == {
            "slug", "project_id", "stopped", "since_utc"}
        assert stat.S_IMODE(os.stat(paths.active_file).st_mode) == 0o600
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="on", project="lame")
        res = await ctl_ok(paths.ctl_sock, "start", targets=["10.10.10.9"])  # ohne Slug: aktives Projekt
        assert res["slug"] == "lame" and not res["created"]
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.9"])
        assert res.get("targets_ignored") is True
        lame_id = d.project.info.id
        res = await ctl_ok(paths.ctl_sock, "start", slug="beta", targets=["10.10.20.0/24"])
        assert res["created"] and res["switched_from"] == "lame"
        ends = [r for r in seen if r.kind == "system.project_end"]
        assert [r.header for r in ends] == [{"reason": "switch"}]
        lame_tail = [r.kind for r in seen if r.seq >= ends[0].seq and r.ts_utc_ns >= ends[0].ts_utc_ns]
        assert lame_tail[0] == "system.project_end" and d.project.info.id != lame_id
        res = await ctl_ok(paths.ctl_sock, "stop")
        assert res["stopped"] and res["slug"] == "beta" and res["head_seq"] > 0
        assert json.loads(paths.active_file.read_text())["stopped"] is True
        assert d.operator is None and d.project is None
        resp = await ctl(paths.ctl_sock, "start")
        assert resp["error"]["code"] == "no_active_project"  # vor der Passphrase geprüft
        resp = await ctl(paths.ctl_sock, "start", slug="beta")
        assert resp["error"]["code"] == "locked"
        d.operator = backup
        res = await ctl_ok(paths.ctl_sock, "stop")
        assert res["stopped"] is False
        await shim.close()

    run(paths, operator, scenario)


def test_start_unlocks_with_passphrase(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="lame", targets=["10.10.10.3"])
        await ctl_ok(paths.ctl_sock, "lock")
        assert json.loads(paths.active_file.read_text())["stopped"] is False  # lock lässt es aktiv
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="locked")
        resp = await ctl(paths.ctl_sock, "start", passphrase="falsch-falsch-falsch")
        assert resp["error"]["code"] == "wrong_passphrase"
        res = await ctl_ok(paths.ctl_sock, "start", passphrase=PASSPHRASE)
        assert res["unlocked"] and res["slug"] == "lame" and res["recording"] == 1
        await shim.wait_state(rec="on")
        await shim.close()

    run(paths, operator, scenario)


def test_idle_end_closes_and_locks_with_fake_clock(paths, operator):
    clock = Clock()

    async def scenario(d: Daemon) -> None:
        seen = collect(d)
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="on")
        d._idle_checked = clock.mono() + (1 << 62)  # der Takt prüft nicht dazwischen
        clock.shift = 11 * 3600 * SEC
        await shim.outx(1, 0, b"noch da\r\n")  # Aktivität setzt die Uhr zurück
        await shim.wait_ack(1)
        clock.shift = 22 * 3600 * SEC
        assert not d._check_idle()
        clock.shift = 23 * 3600 * SEC + 1
        assert d._check_idle()
        assert d.project is None and d.operator is None
        end = [r.header for r in seen if r.kind == "system.project_end"]
        assert end[0]["reason"] == "idle" and end[0]["idle_s"] >= 12 * 3600
        assert json.loads(paths.active_file.read_text())["stopped"] is True
        await shim.wait_state(rec="held")  # gebunden an das beendete Projekt
        await shim.close()

    run(paths, operator, scenario, wall_clock=clock.wall, mono_clock=clock.mono)


# --------------------------------------------------------------------------- Pause


def test_pause_toggle_event_drop_and_resume_gap(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="on")
        await shim.outx(1, 0, b"vorher\r\n")
        await shim.event(2, "req.pause", minutes=None, stream_off=8)  # F12 r
        st = await shim.wait_state(rec="paused", title_extra="Pause 10 min")
        assert st["pause_until_ns"] > time.time_ns() + 9 * MIN
        await shim.outx(3, 8, b"unterwegs\r\n")  # schon gesendet, als die Pause begann
        await shim.event(4, "req.pause", minutes=None, stream_off=19)  # zweites F12 r
        await shim.wait_state(rec="on", pause_until_ns=None)
        await shim.event(5, "term.gap", stream_off=19, reason="pause", bytes_lost=10)
        await shim.outx(6, 29, b"nachher\r\n")
        await shim.wait_ack(6)
        d.flush()
        j = d.project.journal
        outs = b"".join(r.body for r in j.iter_events(kinds=["term.out"]))
        assert outs == b"vorher\r\nnachher\r\n"
        pause = headers(j, "term.pause")
        assert len(pause) == 1 and pause[0]["stream_off"] == 8 and pause[0]["source"] == "hotkey"
        gap = headers(j, "term.gap")
        assert gap == [{"terminal_id": shim.terminal_id, "stream_off": 8, "reason": "pause",
                        "bytes_lost": 21}]
        await shim.close()

    run(paths, operator, scenario)


def test_pause_expires_and_ctl_pause_resume_all(paths, operator):
    clock = Clock()

    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        a = await FakeShim(paths.term_sock).connect(proto=2)
        b = await FakeShim(paths.term_sock).connect(proto=2)
        await a.wait_state(rec="on")
        await b.wait_state(rec="on")
        res = await ctl_ok(paths.ctl_sock, "term.pause", all=True, minutes=3)
        assert {x["terminal_id"] for x in res["paused"]} == {a.terminal_id, b.terminal_id}
        await a.wait_state(rec="paused")
        st = await ctl_ok(paths.ctl_sock, "status")
        assert {x["state"] for x in st["terminal_states"]} == {"paused"}
        res = await ctl_ok(paths.ctl_sock, "term.resume", terminal_id=b.terminal_id)
        assert res["resumed"] == [b.terminal_id]
        await b.wait_state(rec="on")
        clock.shift = 3 * MIN + SEC  # Pause läuft von selbst ab (Takt des Daemons)
        await a.wait_state(rec="on")
        resp = await ctl(paths.ctl_sock, "term.pause", terminal_id=a.terminal_id, minutes=999)
        assert resp["error"]["code"] == "invalid"
        resp = await ctl(paths.ctl_sock, "term.pause", terminal_id="gibt-es-nicht")
        assert resp["error"]["code"] == "unknown_terminal"
        sources = [h["source"] for h in headers(d.project.journal, "term.pause")]
        assert sources == ["cli", "cli"]
        await a.close()
        await b.close()

    run(paths, operator, scenario, wall_clock=clock.wall)


def test_pause_survives_daemon_restart_via_hello(paths, operator):
    until = time.time_ns() + 5 * MIN

    async def first(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])

    async def second(d: Daemon) -> None:
        d.operator = backup
        await ctl_ok(paths.ctl_sock, "start")
        shim = await FakeShim(paths.term_sock).connect(proto=2, pause_until_ns=until)
        st = await shim.wait_state(rec="paused")
        assert st["pause_until_ns"] == until
        old = await FakeShim(paths.term_sock).connect(proto=2, pause_until_ns=time.time_ns() - 1)
        await old.wait_state(rec="on")  # abgelaufene Pause zählt nicht
        await shim.close()
        await old.close()

    backup = backup_of(operator)
    run(paths, operator, first)
    run(paths, None, second)


# --------------------------------------------------------------------------- Projektwechsel (E28)


def test_switch_holds_remote_session_and_rebinds_at_prompt(paths, operator):
    async def scenario(d: Daemon) -> None:
        seen = collect(d)
        await ctl_ok(paths.ctl_sock, "start", slug="alpha", targets=["10.10.10.0/24"])
        alpha_id = d.project.info.id
        remote = await FakeShim(paths.term_sock).connect(proto=2)
        local = await FakeShim(paths.term_sock).connect(proto=2)
        await remote.wait_state(rec="on")
        await local.wait_state(rec="on")
        await remote.event(1, "term.mark", **mark(0, "C", 1, cmd_typed="ssh root@10.10.10.5"))
        await remote.outx(2, 0, b"root@target:~# ")
        await local.outx(1, 0, b"$ ")
        await remote.wait_ack(2)
        n_alpha = len(seen)
        await ctl_ok(paths.ctl_sock, "start", slug="beta", targets=["10.10.20.0/24"])
        alpha_tail = seen[n_alpha:]
        st = await remote.wait_state(rec="held")
        assert st["bound_slug"] == "alpha"
        await local.wait_state(rec="held")
        # Remote-Ausgabe nach dem Wechsel: nirgends gespeichert
        await remote.outx(3, 15, b"id\r\nuid=0(root)\r\n")
        await remote.wait_ack(3)
        # lokale Shell am Prompt: der Shim löst die Bindung, Aufnahme in beta
        await local.event(2, "req.rebind", stream_off=2)
        await local.wait_state(rec="on", bound_slug="beta")
        await local.outx(3, 2, b"in beta\r\n")
        await local.wait_ack(3)
        # Ende der Remote-Sitzung, A-Marker mit lokalem Stapel: auch dieses Terminal wechselt
        await remote.event(4, "req.rebind", stream_off=32)
        await remote.wait_state(rec="on", bound_slug="beta")
        await remote.event(5, "term.gap", stream_off=15, reason="project_switch", bytes_lost=17)
        await remote.outx(6, 32, b"$ ")
        await remote.wait_ack(6)
        d.flush()
        beta = d.project.journal
        assert b"uid=0" not in b"".join(r.body for r in beta.iter_events(kinds=["term.out"]))
        assert b"".join(r.body for r in beta.iter_events(kinds=["term.out"], terminal_id=local.terminal_id)) \
            == b"in beta\r\n"
        opens = {r.terminal_id: r.stream_off for r in beta.iter_events(kinds=["term.open"])}
        assert opens == {local.terminal_id: 2, remote.terminal_id: 32}
        assert [r.header["reason"] for r in alpha_tail[:3] if r.kind == "term.gap"] == [
            "project_switch", "project_switch"]
        assert alpha_tail[2].kind == "system.project_end" and alpha_id != d.project.info.id
        # req.rebind ausserhalb von held: wirkungslos
        await local.event(4, "req.rebind", stream_off=11)
        await local.wait_ack(4)
        assert d.terminals[local.terminal_id].bound_slug == "beta"
        # A wieder starten: ein noch gebundenes Terminal nimmt sofort wieder in A auf
        third = await FakeShim(paths.term_sock).connect(proto=2, bound_project_id=d.project.info.id,
                                                        bound_slug="beta")
        await third.wait_state(rec="on")
        await ctl_ok(paths.ctl_sock, "start", slug="alpha")
        await third.wait_state(rec="held", bound_slug="beta")
        await ctl_ok(paths.ctl_sock, "start", slug="beta")
        await third.wait_state(rec="on", project="beta")
        for s in (remote, local, third):
            await s.close()

    run(paths, operator, scenario)


# --------------------------------------------------------------------------- Vorlauf (E95)


def test_preroll_window_and_limits_with_fake_clock(paths, operator):
    clock = Clock()
    cfg = RecordingConfig(preroll_minutes=1, preroll_terminal_mib=1, preroll_total_mib=8)

    async def scenario(d: Daemon) -> None:
        a = await FakeShim(paths.term_sock).connect(proto=2)
        st = await a.wait_state(rec="preroll")
        assert st["preroll_minutes"] == 1 and st["project"] is None
        await a.outx(1, 0, b"alt\r\n", mono=clock.mono())
        await a.wait_ack(1)  # sofort bestätigt
        clock.shift = 2 * MIN  # älter als das Fenster
        await a.outx(2, 5, b"neu\r\n", mono=clock.mono())
        await a.wait_ack(2)
        info = await ctl_ok(paths.ctl_sock, "preroll.info")
        assert info == {"terminals": 1, "seconds": info["seconds"], "bytes": 5, "window_s": 60}
        assert info["seconds"] <= 2
        # Grenze pro Terminal: das Älteste wird verdrängt, der Puffer bleibt zusammenhängend
        big = b"x" * (600 << 10)
        await a.outx(3, 10, big, mono=clock.mono())
        await a.outx(4, 10 + len(big), big, mono=clock.mono())
        await a.wait_ack(4)
        buf = d.preroll.bufs[a.terminal_id]
        assert [e.stream_off for e in buf.entries] == [10 + len(big)]
        assert buf.dropped_bytes == 5 + 5 + len(big)
        # Grenze gesamt (8 MiB): ein zweites Terminal verdrängt das älteste Terminal
        d.preroll.total_bytes = (600 << 10) + 1000
        b = await FakeShim(paths.term_sock).connect(proto=2)
        await b.wait_state(rec="preroll")
        await b.outx(1, 0, b"y" * 1000, mono=clock.mono())
        await b.wait_ack(1)
        assert a.terminal_id not in d.preroll.bufs and d.preroll.bytes <= d.preroll.total_bytes
        await a.close()
        await b.close()

    run(paths, operator, scenario, config=cfg, mono_clock=clock.mono)


def test_preroll_adoption_original_times_stack_and_origin(paths, operator):
    async def scenario(d: Daemon) -> None:
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="preroll")
        t0 = time.time_ns()
        await shim.event(1, "term.mark", **mark(0, "C", 1, cmd_typed="ssh root@10.10.10.5"),
                         t_shim_ns=t0, mono_ns=time.monotonic_ns())
        await shim.outx(2, 0, b"root@lame:~# id\r\n", ((5, 1500),))
        await shim.input(3, 17, b"whoami\r", out_end=17)
        await shim.outx(4, 17, b"root\r\n")
        await shim.wait_ack(4)
        await asyncio.sleep(0.05)
        recv_before = time.time_ns()
        # Fenster beginnt nach dem C-Marker: Schnappschuss am Fensteranfang zeigt die ssh-Stufe
        d.preroll.bytes -= d.preroll.bufs[shim.terminal_id].pop_oldest().size
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"], adopt_preroll=True)
        pre = res["preroll"]
        assert pre["adopted"] and pre["terminals"] == 1 and pre["bytes"] == 23 + 7
        await shim.wait_state(rec="on")
        await shim.outx(5, 23, b"weiter\r\n")
        await shim.wait_ack(5)
        d.flush()
        j = d.project.journal
        recs = [r for r in j.iter_events() if r.terminal_id == shim.terminal_id]
        assert [r.kind for r in recs][:4] == ["term.open", "term.bind", "term.ctx_snapshot", "term.preroll"]
        snap = recs[2].header["stack"]
        assert [s["kind"] for s in snap] == ["local", "ssh"]
        held = [r for r in recs if r.origin == "preroll"]
        assert [r.kind for r in held] == ["term.out", "term.input", "term.out"]
        assert all(r.ts_utc_ns < recv_before for r in held)  # originale Empfangszeit
        assert held[0].header["tix"] == [[5, 1500]] and held[1].body == b"whoami\r"
        pr = recs[3].header
        assert (pr["from_off"], pr["to_off"], pr["frames"]) == (0, 23, 3)
        assert stream_of(j, shim.terminal_id) == b"root@lame:~# id\r\nroot\r\nweiter\r\n"
        assert [r.origin for r in j.iter_events(kinds=["term.out"])][-1] == "shim"
        assert d.preroll.bufs == {}
        await shim.close()

    run(paths, operator, scenario)


def test_preroll_discarded_on_no_and_foreign_binding(paths, operator):
    async def scenario(d: Daemon) -> None:
        spare = backup_of(operator)
        await ctl_ok(paths.ctl_sock, "start", slug="alpha", targets=["10.10.10.0/24"])
        bound = await FakeShim(paths.term_sock).connect(proto=2)
        await bound.wait_state(rec="on")
        await ctl_ok(paths.ctl_sock, "lock")
        await bound.wait_state(rec="locked")
        await bound.outx(1, 0, b"gehoert zu alpha\r\n")
        free = await FakeShim(paths.term_sock).connect(proto=2)
        await free.wait_state(rec="locked")
        await free.outx(1, 0, b"ohne Bindung\r\n")
        await bound.wait_ack(1)
        await free.wait_ack(1)
        assert (await ctl_ok(paths.ctl_sock, "preroll.info"))["terminals"] == 2
        d.operator = backup_of(spare)
        res = await ctl_ok(paths.ctl_sock, "start", slug="beta", targets=["10.10.20.0/24"],
                           adopt_preroll=True)
        assert res["preroll"]["terminals"] == 1
        d.flush()
        outs = b"".join(r.body for r in d.project.journal.iter_events(kinds=["term.out"]))
        assert outs == b"ohne Bindung\r\n"
        await bound.wait_state(rec="held")
        # Nein: verworfen
        await ctl_ok(paths.ctl_sock, "stop")
        await free.wait_state(rec="held")
        await free.event(2, "req.rebind", stream_off=14)
        await free.wait_state(rec="preroll")
        await free.outx(3, 14, b"vergessen\r\n")
        await free.wait_ack(3)
        d.operator = backup_of(spare)
        res = await ctl_ok(paths.ctl_sock, "start", slug="beta")
        assert res["preroll"]["adopted"] is False and res["preroll"]["discarded_terminals"] == 1
        await free.wait_state(rec="on", project="beta")
        await free.outx(4, 25, b"wieder\r\n")
        await free.wait_ack(4)
        d.flush()
        assert b"vergessen" not in b"".join(r.body for r in d.project.journal.iter_events(kinds=["term.out"]))
        gaps = headers(d.project.journal, "term.gap")
        assert gaps[-1]["reason"] == "no_project" and gaps[-1]["bytes_lost"] == 11
        await bound.close()
        await free.close()

    run(paths, operator, scenario)


def test_preroll_never_on_disk_and_passphrase_not_held(paths, operator):
    canary = b"VORLAUF-KANARIE-7781"

    async def scenario(d: Daemon) -> None:
        # Die CLI meldet ihr Terminal vor getpass an, auch bevor der Shim verbunden ist
        res = await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id="term-cli-000001")
        assert res == {"paused": True, "pending": True}
        cli = FakeShim(paths.term_sock, "term-cli-000001")
        await cli.connect(proto=2)
        await cli.wait_state(rec="preroll")
        await cli.input(1, 0, PASSPHRASE.encode() + b"\r")
        await cli.outx(2, 0, b"Passphrase: \r\n")
        await cli.event(3, "term.mark", **mark(14, "D", 1, exit=0))
        await cli.outx(4, 14, b"$ ")
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="preroll")
        await shim.outx(1, 0, canary + b"\r\n")
        await shim.wait_ack(1)
        await cli.wait_ack(4)
        held = d.preroll.bufs[cli.terminal_id]
        assert [e.kind for e in held.entries] == ["event", "event", "out"]  # Lücke, D, Prompt
        assert held.entries[0].fields["reason"] == "sensitive_output"
        assert held.entries[0].fields["bytes_lost"] == 14
        assert all(PASSPHRASE.encode() not in bytes(e.data or b"") for e in held.entries)
        roots = [Path(os.environ["HOME"]), paths.runtime_dir]
        for root in roots:
            for f in root.rglob("*"):
                if f.is_file() and not f.is_socket():
                    assert canary not in f.read_bytes(), f
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"], adopt_preroll=True)
        d.flush()
        j = d.project.journal
        assert PASSPHRASE.encode() not in b"".join(r.body or b"" for r in j.iter_events())
        assert b"".join(r.body for r in j.iter_events(kinds=["term.out"], terminal_id=shim.terminal_id)) \
            == canary + b"\r\n"
        await cli.close()
        await shim.close()

    run(paths, operator, scenario)


def test_closed_terminal_preroll_is_adopted(paths, operator):
    async def scenario(d: Daemon) -> None:
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="preroll")
        await shim.outx(1, 0, b"nmap fertig\r\n")
        await shim.event(2, "term.close", stream_off=13, exit_code=0)
        await shim.wait_ack(2)
        await shim.bye(0)
        await shim._wait(lambda: shim.closed, 3)
        assert shim.terminal_id in d._departed
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"], adopt_preroll=True)
        assert res["preroll"]["terminals"] == 1
        d.flush()
        j = d.project.journal
        assert [r.kind for r in j.iter_events() if r.terminal_id == shim.terminal_id][-2:] == [
            "term.out", "term.close"]
        assert shim.terminal_id not in d._departed
        await shim.close()

    run(paths, operator, scenario)


# --------------------------------------------------------------------------- Zeit (E96), Eingaben (E26)


def test_merge_keeps_time_index_and_time_suspect(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="on")
        w0, m0 = time.time_ns(), time.monotonic_ns()
        frames = [(0, b"eins\r\n", ((3, 250),), 0), (6, b"zwei\r\n", (), 7_000_123),
                  (12, b"drei\r\n", ((2, 40),), 9_500_000)]
        d.writer.interval = 3600  # alle drei Rahmen in einem Commit
        for i, (off, data, tix, dt) in enumerate(frames, 1):
            await shim.outx(i, off, data, tix, wall=w0 + dt, mono=m0 + dt)
        await shim.input(4, 18, b"\x1b[200~ls\nid\x1b[201~", out_end=18, paste=True, wall=w0, mono=m0)
        await shim.outx(5, 18, b"spaet\r\n", wall=w0 - 60 * SEC, mono=m0 + 10_000_000)  # Wanduhr springt
        await shim.outx(6, 25, b"zurueck\r\n", wall=w0, mono=m0)  # monotone Uhr rückwärts
        await asyncio.sleep(0.1)
        d.flush()
        await shim.wait_ack(6)
        j = d.project.journal
        outs = list(j.iter_events(kinds=["term.out"]))
        assert outs[0].header["length"] == 18 and outs[0].body == b"eins\r\nzwei\r\ndrei\r\n"
        h = outs[0].header
        for off, data, tix, dt in frames:  # Zeit jedes Bytes wie vor dem Zusammenfassen (1 µs)
            src = {"t_shim_ns": w0 + dt, "mono_ns": m0 + dt, "tix": tix}
            for rel in range(len(data)):
                before = events.body_time(src, rel)
                after = events.body_time(h, off + rel)
                assert abs(after[1] - before[1]) < 1000 and abs(after[0] - before[0]) < 1000
        assert "time_suspect" not in h
        assert outs[1].header["time_suspect"] is True and outs[2].header["time_suspect"] is True
        inp = next(j.iter_events(kinds=["term.input"]))
        assert inp.header["paste"] is True and inp.body.startswith(b"\x1b[200~") and inp.origin == "shim"
        assert inp.stream_off == 18 and inp.header["out_end"] == 18
        await shim.close()

    run(paths, operator, scenario)


def test_v1_shim_still_records(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        shim = await FakeShim(paths.term_sock).connect()  # proto 1
        await shim.wait_state(rec="on")
        await shim.out(1, 0, b"alt\r\n")
        await shim.event(2, "req.rec", on=None)  # v1-Hotkey: wie req.pause ohne Minuten
        st = await shim.wait_state(rec="off", title_extra="Pause 10 min")  # v1 kennt "paused" nicht
        assert st["pause_until_ns"] > time.time_ns()
        await shim.out(3, 5, b"in der Pause\r\n")
        await shim.wait_ack(3)
        d.flush()
        assert b"".join(r.body for r in d.project.journal.iter_events(kinds=["term.out"])) == b"alt\r\n"
        await shim.close()

    run(paths, operator, scenario)


# --------------------------------------------------------------------------- E72, A5, E23


def test_canary_secret_only_encrypted_and_redacted_at_exit(paths, operator, tmp_path):
    async def scenario(d: Daemon) -> None:
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        ws = Path(res["workspace"])
        loot = ws / "loot.txt"
        loot.write_text(f"db_pass={OWN_SECRET}\n")
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="on")
        await shim.outx(1, 0, f"$ echo {OWN_SECRET}\r\n{OWN_SECRET}\r\n".encode())
        await shim.input(2, 0, f"echo {OWN_SECRET}\r".encode())
        await shim.wait_ack(2)
        imp = await ctl_ok(paths.ctl_sock, "import", path=str(loot))
        assert imp["stored"]
        d.flush()
        j = d.project.journal
        body = b"".join(r.body or b"" for r in j.iter_events())
        assert body.count(OWN_SECRET.encode()) == 3  # Ausgabe zweimal, Eingabe einmal
        fo = next(j.iter_events(kinds=["file.observed"])).header
        assert not fo.get("redactions")
        assert OWN_SECRET.encode() in d.project.blobs.open_bytes(fo["blob_id"])
        red, labels = d.redactor.redact_for_exit(body)
        assert OWN_SECRET.encode() not in red and labels == ["sudo"]
        obj, _ = d.redactor.redact_json({"x": [OWN_SECRET]})
        assert obj == {"x": ["*" * len(OWN_SECRET)]}
        await ctl_ok(paths.ctl_sock, "stop")
        loot.unlink()
        for root in (Path(os.environ["HOME"]), paths.runtime_dir):
            for f in root.rglob("*"):
                if f.is_file() and not f.is_socket():
                    assert OWN_SECRET.encode() not in f.read_bytes(), f
        await shim.close()

    run(paths, operator, scenario)


def test_local_addrs_on_open_and_change(paths, operator):
    addrs = [("10.10.14.5", "127.0.0.1")]

    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="on")
        await shim.event(1, "term.mark", **mark(0, "C", 1, cmd_typed="ls"))
        await shim.wait_ack(1)
        d._addrs_checked = 0
        addrs[0] = ("10.10.14.5", "10.10.14.9", "127.0.0.1")
        await shim.event(2, "term.mark", **mark(0, "C", 2, cmd_typed="ip a"))
        await shim.wait_ack(2)
        d._addrs_checked = 0
        await shim.event(3, "term.mark", **mark(0, "C", 3, cmd_typed="id"))
        await shim.wait_ack(3)
        d.flush()
        got = headers(d.project.journal, "net.local_addrs")
        assert got == [{"addrs": ["10.10.14.5", "127.0.0.1"], "source": "proc"},
                       {"addrs": ["10.10.14.5", "10.10.14.9", "127.0.0.1"], "source": "proc"}]
        await shim.close()

    run(paths, operator, scenario, local_addrs=lambda: addrs[0])


def test_localaddr_parsers():
    from ariadne.sources.localaddr import parse_fib_trie, parse_if_inet6, read_local_addrs

    fib = ("Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 10.10.14.5\n        /32 host LOCAL\n"
           "     |-- 10.10.14.255\n        /32 link BROADCAST\n     |-- 127.0.0.1\n        /32 host LOCAL\n"
           "Local:\n     |-- 10.10.14.5\n        /32 host LOCAL\n"
           "     |-- 300.1.1.1\n        /32 host LOCAL\n")
    assert parse_fib_trie(fib) == {"10.10.14.5", "127.0.0.1"}
    v6 = ("fe800000000000000a0027fffe4e9e2a 02 40 20 80     eth0\n"
          "00000000000000000000000000000001 01 80 10 80       lo\nkaputt\n")
    assert parse_if_inet6(v6) == {"fe80::a00:27ff:fe4e:9e2a", "::1"}
    assert read_local_addrs(Path("/nicht/da"), Path("/auch/nicht")) is None


def test_auto_context_from_ingest_sets_live_stack_not_journal(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="on")
        await shim.event(1, "term.mark", **mark(10, "C", 1, cmd_typed="nc -lvnp 4444"))
        await shim.wait_ack(1)
        d._on_ingest_update(IngestUpdate(3, (AutoContext(shim.terminal_id, 10, "ip:default/10.10.10.3"),
                                             AutoContext("unbekannt-0001", 1, "ip:default/10.10.10.4"))))
        st = await shim._wait(lambda: shim.state if shim.state.get("ctx_version") == 1 else None, 3)
        assert st["stack"][-1]["host"] == "ip:default/10.10.10.3" and st["stack"][-1]["host_source"] == "auto"
        shown = await ctl_ok(paths.ctl_sock, "ctx.show", terminal_id=shim.terminal_id)
        assert shown["label"] == "10.10.10.3 revshell (auto)"
        # Pause und Fortsetzen schreiben einen Schnappschuss: ohne Auto-Host
        await ctl_ok(paths.ctl_sock, "term.pause", terminal_id=shim.terminal_id)
        await ctl_ok(paths.ctl_sock, "term.resume", terminal_id=shim.terminal_id)
        # ein Schnappschuss vom Shim ohne Host lässt den Auto-Host im Live-Stapel stehen
        snap = [{"kind": "local", "host": "local", "opened_at": 0},
                {"kind": "revshell", "opened_at": 10, "host": "ip:default/6.6.6.6", "host_source": "auto"}]
        await shim.event(2, "term.ctx_snapshot", stream_off=10, stack=snap)
        await shim.wait_ack(2)
        assert d.terminals[shim.terminal_id].stack.label() == "10.10.10.3 revshell (auto)"
        # Host des Nutzers geht vor
        await shim.event(3, "req.ctx.set", host="10.10.10.9")
        await shim._wait(lambda: shim.state.get("ctx_version") == 2, 3)
        d._on_ingest_update(IngestUpdate(4, (AutoContext(shim.terminal_id, 10, "ip:default/10.10.10.3"),)))
        assert d.terminals[shim.terminal_id].stack.label() == "10.10.10.9 revshell"
        d.flush()
        for h in headers(d.project.journal, "term.ctx_snapshot"):
            for stage in h["stack"]:
                assert "host_source" not in stage and stage.get("host") != "ip:default/6.6.6.6"
                assert stage.get("host") != "ip:default/10.10.10.3"
        await shim.close()

    run(paths, operator, scenario)


def test_status_shows_terminal_states(paths, operator):
    async def scenario(d: Daemon) -> None:
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="preroll")
        await shim.outx(1, 0, b"x\r\n")
        await shim.event(2, "req.status", mux=True)
        await shim.wait_ack(2)
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["rec"] is False and st["project"] is None and st["active"] is None
        ts = st["terminal_states"][0]
        assert ts["state"] == "preroll" and ts["mux"] is True and ts["preroll_s"] >= 0
        assert st["preroll"]["terminals"] == 1 and st["preroll"]["window_s"] == 15 * 60
        terms = await ctl_ok(paths.ctl_sock, "terminals")
        assert terms["terminals"][0]["state"] == "preroll" and terms["terminals"][0]["mux"] is True
        await shim.close()

    run(paths, operator, scenario)


def test_daemon_restart_reads_active_and_clock_check(paths, operator):
    async def first(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])

    async def second(d: Daemon) -> None:
        assert d.active is not None and d.active["slug"] == "lame"
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="locked")
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["active"] == {"slug": "lame", "stopped": False} and st["locked"] is True
        await shim.close()

    run(paths, operator, first)
    run(paths, None, second)
