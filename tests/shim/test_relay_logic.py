"""Aufnahme-Logik, Marker, Eingaben, Pause, Multiplexer und Titel des Relays, ohne PTY
(Transport als Attrappe)."""

from __future__ import annotations

import time

import pytest

from ariadne._shim.hotkey import Forward
from ariadne._shim.launch import Spawned
from ariadne._shim.markers import MarkerValidator
from ariadne._shim.relay import Shim

NONCE = "0123456789abcdef0123456789abcdef"
F12 = b"\x1b[24~"


class StubTransport:
    def __init__(self) -> None:
        self.connected = True
        self.ready = False
        self.state: dict = {}
        self.events: list[tuple[str, dict]] = []
        self.outs: list[tuple[bytes, int]] = []
        self.out_times: list[tuple[int, int]] = []
        self.inputs: list[dict] = []
        self.dropped = 0
        self.rewound = 0
        self.sock = None

    def add_event(self, kind, fields):
        self.events.append((kind, fields))

    def add_out(self, data, off, wall, mono, now):
        self.outs.append((data, off))
        self.out_times.append((wall, mono))

    def add_input(self, data, off, out_end, wall, mono, tix=(), *, paste=False):
        self.inputs.append({"data": data, "off": off, "out_end": out_end, "wall": wall, "mono": mono,
                            "tix": tix, "paste": paste})
        return len(self.inputs)

    def flush_out(self):
        pass

    def deadline(self):
        return None

    def tick(self, now):
        pass

    def wants_write(self):
        return False

    def drop_unacked(self):
        self.dropped += 1
        return 3

    def rewind(self):
        self.rewound += 1

    def kinds(self):
        return [k for k, _ in self.events]

    def state_msg(self, shim, first, **st):
        self.ready = True
        self.state = st
        shim._on_state_cb(st, first)


def make_shim() -> tuple[Shim, StubTransport]:
    sp = Spawned(["/bin/zsh", "-i"], {"ARIADNE_HOTKEY": "f12"}, -1, 4242, "/dev/pts/7", [], 24, 80,
                 "term-1", NONCE)
    shim = Shim(sp)
    t = StubTransport()
    shim.transport = t  # type: ignore[assignment]
    shim.validator = MarkerValidator(NONCE, 4242, -1, tcgetpgrp=lambda fd: 4242, getpgid=lambda p: 4242,
                                     comm=lambda p: "zsh", descends=lambda p, a: True)
    shim._title_live = True
    shim.titles.interval = 0.0  # Callbacks nutzen die echte Uhr, die Tests feste Zeiten
    return shim, t


def marker(mark: str, fields: str, ctr: int) -> bytes:
    return f"\x1b]7701;ariadne;v1;{NONCE};4242:{ctr};{mark};{fields}\x07".encode()


def test_provisional_capture_then_off_drops_and_gaps_later():
    shim, t = make_shim()
    shim._update_capture(0.0)
    assert shim.capture and t.kinds() == ["term.resize", "term.ctx_snapshot"]
    shim._on_output(b"0123456789", 0.0)
    assert t.outs == [(b"0123456789", 0)]
    t.state_msg(shim, True, rec="off", project=None)
    assert t.dropped == 1 and not shim.capture
    assert shim._lost_since == 3 and shim._lost_reason == "no_project"
    shim._on_output(b"secret", 0.1)
    assert len(t.outs) == 1  # keine Aufnahme: kein Inhalt
    assert shim.scanner.offset == 16  # Offset zählt weiter
    t.state_msg(shim, False, rec="on", project="lame")
    gap = [f for k, f in t.events if k == "term.gap"][0]
    assert gap["stream_off"] == 3 and gap["reason"] == "no_project" and gap["bytes_lost"] == 13
    assert t.kinds()[-2:] == ["term.resize", "term.ctx_snapshot"]
    assert b"\x1b]2;[REC lame] kali" in shim._disp


@pytest.mark.parametrize("rec,capture", [("on", True), ("preroll", True), ("locked", True),
                                         ("waiting", True), ("paused", False), ("held", False),
                                         ("off", False)])
def test_capture_rule_per_state(rec, capture):
    shim, t = make_shim()
    until = time.time_ns() + 60_000_000_000 if rec == "paused" else None
    t.state_msg(shim, True, rec=rec, project="lame", pause_until_ns=until, preroll_minutes=15)
    assert shim.capture is capture


def test_locked_title_and_no_rewind_in_v2():
    shim, t = make_shim()
    shim._update_capture(0.0)
    t.state_msg(shim, True, rec="locked", project=None)
    assert shim.capture and t.dropped == 0
    shim._refresh_title(time.monotonic())
    assert b"[gesperrt: ariadne start]" in shim._disp
    t.state_msg(shim, False, rec="on", project="lame")
    assert t.rewound == 0  # der Daemon hat den Vorlauf schon bestätigt
    t.state_msg(shim, False, rec="waiting", project="lame")  # Daemon v1
    t.state_msg(shim, False, rec="on", project="lame")
    assert t.rewound == 1


def test_pause_stops_capture_and_gap_pause_even_without_bytes():
    shim, t = make_shim()
    t.state_msg(shim, True, rec="on", project="lame")
    t.events.clear()
    until = time.time_ns() + 9 * 60_000_000_000 - 1
    t.state_msg(shim, False, rec="paused", project="lame", pause_until_ns=until)
    assert not shim.capture and shim._lost_reason == "pause"
    shim._refresh_title(time.monotonic())
    assert b"[PAUSE 9 min lame]" in shim._disp
    assert shim._hello()["pause_until_ns"] == until  # übersteht einen Daemon-Neustart
    t.state_msg(shim, False, rec="on", project="lame", pause_until_ns=None)
    gap = [f for k, f in t.events if k == "term.gap"]
    assert gap and gap[0]["reason"] == "pause" and gap[0]["bytes_lost"] == 0
    assert t.kinds()[-2:] == ["term.resize", "term.ctx_snapshot"]
    assert shim._hello()["pause_until_ns"] is None


def test_local_pause_expires_without_new_state():
    shim, t = make_shim()
    t.state_msg(shim, True, rec="on", project="lame")
    t.state_msg(shim, False, rec="paused", project="lame", pause_until_ns=time.time_ns() + 50_000_000)
    assert not shim.capture
    shim._on_output(b"waehrend der Pause", 0.0)
    assert t.outs == []
    deadline = shim._timeout(time.monotonic())
    assert deadline is not None and deadline <= 0.06
    time.sleep(0.08)
    shim._tick(time.monotonic())
    assert shim.capture  # Daemon noch "paused", aber lokal abgelaufen
    gap = [f for k, f in t.events if k == "term.gap"][-1]
    assert gap["reason"] == "pause" and gap["bytes_lost"] == len(b"waehrend der Pause")


def test_hotkey_r_requests_pause_toggle():
    shim, t = make_shim()
    shim._hotkey("r", 0.0)
    assert t.events == [] and shim._notice == "Daemon nicht erreichbar"
    t.state_msg(shim, True, rec="on", project="lame")
    t.events.clear()
    shim._hotkey("r", 1.0)
    assert t.events[-1] == ("req.pause", {"terminal_id": "term-1", "stream_off": 0, "minutes": None})


def test_held_sends_rebind_at_prompt_or_after_next_a_marker():
    shim, t = make_shim()
    t.state_msg(shim, True, rec="on", project="alpha", project_id="pa-00000001",
                bound_project_id="pa-00000001", ctx_version=0)
    shim._on_output(marker("A", "", 1) + b"$ " + marker("C", "cmd=ssh%20root%4010.10.10.5", 2), 0.0)
    t.events.clear()
    # Projektwechsel: Remote-Sitzung läuft, der Stapel ist nicht nur lokal
    t.state_msg(shim, False, rec="held", project="beta", project_id="pb-00000002",
                bound_project_id="pa-00000001", bound_slug="alpha")
    assert not shim.capture and "req.rebind" not in t.kinds()
    shim._refresh_title(time.monotonic())
    assert b"[Remote alpha: nicht gespeichert]" in shim._disp
    n_out = len(t.outs)
    shim._on_output(b"remote output", 0.1)
    shim._on_action(Forward(b"id\r"), 0.1)
    assert len(t.outs) == n_out and t.inputs == []
    shim._on_output(marker("D", "exit=0", 3) + marker("A", "", 4), 0.2)
    rb = [f for k, f in t.events if k == "req.rebind"]
    assert len(rb) == 1 and rb[0]["stream_off"] == shim._offset()
    # Schon am Prompt mit lokalem Stapel: sofort
    shim2, t2 = make_shim()
    t2.state_msg(shim2, True, rec="on", project="alpha")
    shim2._on_output(marker("A", "", 1), 0.0)
    t2.state_msg(shim2, False, rec="held", project=None, bound_project_id="pa-00000001",
                 bound_slug="alpha")
    assert "req.rebind" in t2.kinds()


def test_inputs_only_forwarded_bytes_with_time_and_offset():
    shim, t = make_shim()
    t.state_msg(shim, True, rec="on", project="lame")
    shim._on_output(b"$ ", 0.0)
    for chunk, now in ((b"l", 1.0), (b"s", 1.01), (b"\r", 1.02)):
        shim._read_t = (int(now * 1e9), int(now * 1e9))
        for act in shim.input.feed(chunk, now):
            shim._on_action(act, now)
    assert [i["data"] for i in t.inputs] == [b"ls\r"]
    first = t.inputs[0]
    assert (first["off"], first["out_end"], first["wall"]) == (2, 2, 1_000_000_000)
    assert first["tix"] == ((1, 10000), (2, 20000))
    # F12 r: weder Präfix noch Taste gehen ans Kind oder in die Aufnahme
    for chunk, now in ((F12, 2.0), (b"r", 2.2)):
        for act in shim.input.feed(chunk, now):
            shim._on_action(act, now)
    assert len(t.inputs) == 1 and b"\x1b[24~" not in bytes(shim._to_child)
    # Mini-Prompt: Eingaben bleiben bei Ariadne
    shim._hotkey("h", 3.0)
    shim._prompt_input(b"10.10.10.3\r", 3.1)
    assert len(t.inputs) == 1
    # ohne Aufnahme keine Eingaben
    t.state_msg(shim, False, rec="paused", project="lame", pause_until_ns=time.time_ns() + 10**11)
    for act in shim.input.feed(b"geheim\r", 4.0):
        shim._on_action(act, 4.0)
    assert len(t.inputs) == 1 and bytes(shim._to_child).endswith(b"geheim\r")


def test_pending_input_flushed_before_requests_and_at_deadline():
    shim, t = make_shim()
    t.state_msg(shim, True, rec="on", project="lame")
    shim._on_action(Forward(b"halb"), 0.0)
    assert t.inputs == []
    shim._hotkey("s", 0.1)
    assert t.inputs[0]["data"] == b"halb" and t.kinds()[-1] == "req.shot"
    shim._on_action(Forward(b"x"), 1.0)
    shim._tick(2.1)  # 1 s nach dem ersten Byte
    assert t.inputs[-1]["data"] == b"x"


def test_multiplexer_suppresses_output_and_input_and_reports_status():
    shim, t = make_shim()
    t.state_msg(shim, True, rec="on", project="lame")
    shim._on_output(b"vorher", 0.0)
    t.events.clear()
    shim._multiplexer_fg = lambda: True  # type: ignore[method-assign]
    shim._on_output(b"tmux zeichnet", 0.1)
    shim._on_action(Forward(b"ls\r"), 0.2)
    assert t.outs == [(b"vorher", 0)] and t.inputs == []
    assert ("req.status", {"terminal_id": "term-1", "mux": True}) in t.events
    shim._refresh_title(time.monotonic())
    assert b"[Multiplexer: Panes nehmen auf]" in shim._disp
    shim._multiplexer_fg = lambda: False  # type: ignore[method-assign]
    shim._on_output(b"nachher", 0.3)
    gap = [f for k, f in t.events if k == "term.gap"][0]
    assert gap["reason"] == "multiplexer" and gap["stream_off"] == 6 and gap["bytes_lost"] == 13
    assert ("req.status", {"terminal_id": "term-1", "mux": False}) in t.events


def test_events_carry_shim_time_of_read():
    shim, t = make_shim()
    t.state_msg(shim, True, rec="on", project="lame")
    t.events.clear()
    shim._read_t = (111, 222)
    shim._on_output(b"$ " + marker("C", "cmd=id", 1), 0.0)
    mark = [f for k, f in t.events if k == "term.mark"][0]
    assert (mark["t_shim_ns"], mark["mono_ns"]) == (111, 222)
    assert t.out_times[-1] == (111, 222)


def test_auto_host_in_title_but_not_in_snapshot():
    shim, t = make_shim()
    t.state_msg(shim, True, rec="on", project="lame", ctx_version=0)
    shim._on_output(marker("C", "cmd=nc%20-lvnp%204444", 1), 0.0)
    auto = shim.stack.snapshot()
    auto[-1].update(host="ip:default/10.10.10.3", host_source="auto")
    t.state_msg(shim, False, rec="on", project="lame", stack=auto, ctx_version=1)
    assert shim.stack.label() == "10.10.10.3 revshell (auto)"
    shim._refresh_title(time.monotonic())
    assert b"10.10.10.3 revshell (auto)" in shim._disp
    assert shim._hello()["stack"][-1]["host_source"] == "auto"  # Neustart: der Daemon kennt ihn
    t.state_msg(shim, False, rec="paused", project="lame", pause_until_ns=time.time_ns() + 10**11)
    t.state_msg(shim, False, rec="on", project="lame", pause_until_ns=None)
    snap = [f for k, f in t.events if k == "term.ctx_snapshot"][-1]
    assert "host" not in snap["stack"][-1] and "host_source" not in snap["stack"][-1]


def test_disconnect_keeps_buffering_only_if_rec_was_on():
    shim, t = make_shim()
    shim._update_capture(0.0)
    t.state_msg(shim, True, rec="on")
    t.connected = t.ready = False
    shim._on_disconnect_cb()
    assert shim.capture  # zuletzt on: weiter puffern
    shim._refresh_title(time.monotonic())
    assert b"[ariadne offline]" in shim._disp
    t.connected = True
    t.state_msg(shim, True, rec="off")
    t.connected = t.ready = False
    shim._on_disconnect_cb()
    assert not shim.capture


def test_markers_update_stack_and_events():
    shim, t = make_shim()
    shim._update_capture(0.0)
    t.state_msg(shim, True, rec="on", project="lame")
    t.events.clear()
    shim._on_output(b"$ " + marker("C", "cmd=ssh%20root%4010.10.10.5", 1) + b"Password:", 0.0)
    assert shim.stack.top().kind == "ssh" and shim.stack.top().candidate == "10.10.10.5"
    mark = [f for k, f in t.events if k == "term.mark"][0]
    assert mark["stream_off"] == 2 and mark["cmd_typed"] == "ssh root@10.10.10.5"
    # gefälschter D-Marker (falsche Nonce) schliesst die Stufe nicht
    forged = marker("D", "exit=0", 2).replace(NONCE.encode(), b"f" * 32)
    shim._on_output(forged, 0.1)
    assert shim.stack.top().kind == "ssh"
    assert [f["reason"] for k, f in t.events if k == "term.marker_forged"] == ["bad_nonce"]
    # Wiederholung des echten C-Markers
    shim._on_output(marker("C", "cmd=ls", 1), 0.2)
    assert [f["reason"] for k, f in t.events if k == "term.marker_forged"][-1] == "replay"
    # gültiger D-Marker, aber nicht im Vordergrund: Stufe bleibt
    shim.validator._tcgetpgrp = lambda fd: 9999
    shim._on_output(marker("D", "exit=0", 3), 0.3)
    assert shim.stack.top().kind == "ssh"
    shim.validator._tcgetpgrp = lambda fd: 4242
    shim._on_output(marker("D", "exit=0", 4), 0.4)
    assert shim.stack.top().kind == "local"


def test_titles_osc52_and_daemon_stack_override():
    shim, t = make_shim()
    shim._update_capture(0.0)
    web01 = [{"kind": "local", "host": "local", "opened_at": 0},
             {"kind": "ssh", "host": "name:web01", "user": "root", "opened_at": 5}]
    t.state_msg(shim, True, rec="on", project="lame", stack=web01, ctx_version=0)
    assert shim.stack.label() == "kali"  # erster STATE: der eigene Stapel gilt
    t.state_msg(shim, False, rec="on", project="lame", stack=web01, ctx_version=1)  # Entscheid
    assert shim.stack.label() == "web01 root"
    t.state_msg(shim, False, rec="on", project="lame", stack=[{"kind": "bogus"}], ctx_version=2)
    assert shim.stack.label() == "web01 root"  # ungültig: ignoriert
    shim._disp.clear()
    hostile = "evil \u202e[REC fake]\x01\x9b2J".encode()
    shim._on_output(b"\x1b]0;" + hostile + b"\x07\x1b]52;c;ZXZpbA==\x07", time.monotonic())
    title = bytes(shim._disp)
    assert title.startswith(b"\x1b]2;[REC lame] web01 root | evil <U+202E>[REC fake]<0x01>??2J")  # C1 ersetzt
    assert title.count(b"\x1b") == 1 and title.endswith(b"\x07")
    osc = [f for k, f in t.events if k == "term.osc52_blocked"]
    assert osc and (osc[0]["stream_off"], osc[0]["length"], osc[0]["terminal_id"]) == (28, 16, "term-1")


def _stack_kinds(stack) -> list[str]:
    return [st["kind"] for st in stack]


def test_shim_stack_survives_rec_on_and_is_synced():
    """REC aus: der Daemon sieht keine Marker. Sein veralteter Stapel darf den des Shims
    beim Einschalten nicht überschreiben (Befund: Reverse Shell landet bei Kali)."""
    shim, t = make_shim()
    t.state_msg(shim, True, rec="off", project="lame", ctx_version=0,
                stack=[{"kind": "local", "host": "local", "opened_at": 0}])
    assert not shim.capture
    t.events.clear()
    shim._on_output(b"$ " + marker("C", "cmd=listen&cmdx=rlwrap%20nc%20-lvnp%204444", 1), 0.0)
    assert shim.stack.top().kind == "revshell"  # Alias: zählt wie im Daemon cmd_expanded
    sync = [f for k, f in t.events if k == "req.ctx.sync"]
    assert sync and _stack_kinds(sync[-1]["stack"]) == ["local", "revshell"]
    # REC an: Daemon schickt seinen (alten) Stapel ohne neuen Entscheid
    t.state_msg(shim, False, rec="on", project="lame", ctx_version=0,
                stack=[{"kind": "local", "host": "local", "opened_at": 0}])
    assert shim.capture and shim.stack.top().kind == "revshell"
    snap = [f for k, f in t.events if k == "term.ctx_snapshot"][-1]
    assert _stack_kinds(snap["stack"]) == ["local", "revshell"]


def test_hello_carries_stack_and_binding():
    shim, t = make_shim()
    t.state_msg(shim, True, rec="on", project="lame", project_id="p-alpha-0001",
                bound_project_id="p-alpha-0001", ctx_version=0)
    shim._on_output(marker("C", "cmd=ssh%20root%4010.10.10.5", 1), 0.0)
    hello = shim._hello()
    assert _stack_kinds(hello["stack"]) == ["local", "ssh"]
    assert hello["bound_project_id"] == "p-alpha-0001" and hello["bound_slug"] == "lame"


def test_daemon_restart_gap_reason_is_daemon_down():
    shim, t = make_shim()
    shim._update_capture(0.0)
    t.state_msg(shim, True, rec="on", project="lame", daemon_id="aaaa")
    shim._on_output(b"vorher", 0.0)
    t.connected = t.ready = False
    shim._on_disconnect_cb()
    assert shim.capture  # puffert weiter
    shim._on_output(b"waehrend", 0.1)
    t.connected = True
    t.state_msg(shim, True, rec="off", daemon_id="bbbb")  # neuer Daemon ohne Vorlauf
    assert not shim.capture and shim._lost_reason == "daemon_down"
    shim2, tt = make_shim()
    shim2._update_capture(0.0)  # vorläufig an, bis der erste STATE kommt
    tt.state_msg(shim2, True, rec="off", daemon_id="aaaa")
    assert shim2._lost_reason == "no_project"
