"""REC-Logik, Marker-Verarbeitung und Titel des Relays, ohne PTY (Transport als Attrappe)."""

from __future__ import annotations

import time

from ariadne._shim.launch import Spawned
from ariadne._shim.markers import MarkerValidator
from ariadne._shim.relay import Shim

NONCE = "0123456789abcdef0123456789abcdef"


class StubTransport:
    def __init__(self) -> None:
        self.connected = True
        self.ready = False
        self.state: dict = {}
        self.events: list[tuple[str, dict]] = []
        self.outs: list[tuple[bytes, int]] = []
        self.dropped = 0
        self.rewound = 0
        self.sock = None

    def add_event(self, kind, fields):
        self.events.append((kind, fields))

    def add_out(self, data, off, wall, mono, now):
        self.outs.append((data, off))

    def flush_out(self):
        pass

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


def test_provisional_capture_then_rec_off_drops_and_gaps_later():
    shim, t = make_shim()
    shim._update_capture(0.0)
    assert shim.capture and t.kinds() == ["term.resize", "term.ctx_snapshot"]
    shim._on_output(b"0123456789", 0.0)
    assert t.outs == [(b"0123456789", 0)]
    t.state_msg(shim, True, rec="off", project="lame")
    assert t.dropped == 1 and not shim.capture
    assert shim._lost_since == 3 and shim._lost_reason == "rec_off"
    shim._on_output(b"secret", 0.1)
    assert len(t.outs) == 1  # REC aus: kein Inhalt
    assert shim.scanner.offset == 16  # Offset zählt weiter
    t.state_msg(shim, False, rec="on", project="lame")
    gap = [f for k, f in t.events if k == "term.gap"][0]
    assert gap == {"stream_off": 3, "reason": "rec_off", "bytes_lost": 13, "terminal_id": "term-1"}
    assert t.kinds()[-2:] == ["term.resize", "term.ctx_snapshot"]
    assert b"\x1b]2;[REC lame] kali" in shim._disp


def test_waiting_buffers_and_rewinds_on_unlock():
    shim, t = make_shim()
    shim._update_capture(0.0)
    t.state_msg(shim, True, rec="waiting", project="lame")
    assert shim.capture and t.dropped == 0
    shim._refresh_title(time.monotonic())
    assert b"[REC! gesperrt]" in shim._disp
    t.state_msg(shim, False, rec="on", project="lame")
    assert t.rewound == 1


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
    t.state_msg(shim, True, rec="on", project="lame",
                stack=[{"kind": "local", "host": "local", "opened_at": 0},
                       {"kind": "ssh", "host": "name:web01", "user": "root", "opened_at": 5}])
    assert shim.stack.label() == "web01 root"
    t.state_msg(shim, False, rec="on", project="lame", stack=[{"kind": "bogus"}])  # ungültig: ignoriert
    assert shim.stack.label() == "web01 root"
    shim._disp.clear()
    hostile = "evil \u202e[REC fake]\x01\x9b2J".encode()
    shim._on_output(b"\x1b]0;" + hostile + b"\x07\x1b]52;c;ZXZpbA==\x07", time.monotonic())
    title = bytes(shim._disp)
    assert title.startswith(b"\x1b]2;[REC lame] web01 root | evil <U+202E>[REC fake]<0x01><0x9B>2J")
    assert title.count(b"\x1b") == 1 and title.endswith(b"\x07")
    assert ("term.osc52_blocked", {"stream_off": 28, "length": 16, "terminal_id": "term-1"}) in t.events


def test_hotkey_request_requires_daemon():
    shim, t = make_shim()
    shim._hotkey("r", 0.0)
    assert t.events == [] and shim._notice == "Daemon nicht erreichbar"
    t.state_msg(shim, True, rec="off")
    shim._hotkey("r", 1.0)
    assert t.events[-1] == ("req.rec", {"terminal_id": "term-1", "stream_off": 0, "on": None})
