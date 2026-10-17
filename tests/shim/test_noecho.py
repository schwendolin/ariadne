"""E104 im Shim: Passwortmodus des Kindes erkennen und am INPUT-Rahmen markieren.

``ECHO`` aus und ``ICANON`` an ist das ``getpass``-Muster (sudo, ssh, su, mysql).
Zeileneditoren (ZLE, readline) schalten beides aus; das ist kein Passwort.
"""

from __future__ import annotations

import os
import pty
import termios
import time

import pytest

from ariadne._shim import protocol as P
from ariadne._shim.hotkey import Forward
from ariadne._shim.inputrec import InputRecorder
from ariadne._shim.relay import password_mode
from tests.shim.conftest import PROMPT, available_shells
from tests.shim.fake_daemon import FakeDaemon
from tests.shim.test_pty_e2e import finish, run_cmd, spawn
from tests.shim.test_relay_logic import make_shim

MS = 1_000_000


@pytest.fixture
def ptypair():
    m, s = pty.openpty()
    yield m, s
    os.close(m)
    os.close(s)


def _mode(fd: int, *, echo: bool, icanon: bool) -> None:
    a = termios.tcgetattr(fd)
    a[3] = (a[3] | termios.ECHO) if echo else (a[3] & ~termios.ECHO)
    a[3] = (a[3] | termios.ICANON) if icanon else (a[3] & ~termios.ICANON)
    termios.tcsetattr(fd, termios.TCSANOW, a)


def test_password_mode_only_for_getpass_pattern(ptypair):
    m, s = ptypair
    _mode(s, echo=True, icanon=True)
    assert password_mode(m) is False  # normale Shell im Kanonmodus (read, cat)
    _mode(s, echo=False, icanon=True)
    assert password_mode(m) is True  # getpass: sudo, ssh, su, mysql
    _mode(s, echo=False, icanon=False)
    assert password_mode(m) is False  # ZLE, readline, Raw-Modus: kein Passwort
    assert password_mode(-1) is False and password_mode(10_000) is False  # kein Terminal: nie Abbruch


def test_recorder_marks_bundle_and_resets():
    out: list[tuple[bytes, bool]] = []

    def emit(data, off, out_end, wall, mono, tix, paste, no_echo=False):
        out.append((data, no_echo))

    r = InputRecorder(emit)
    r.feed(b"sudo ls\r", 0, 1 * MS, 1 * MS, 0.0)
    r.feed(b"geh", 9, 2 * MS, 2 * MS, 0.1, no_echo=True)
    r.feed(b"eim\r", 9, 3 * MS, 3 * MS, 0.2, no_echo=False)  # ein Byte genügt: ganzes Bündel
    r.feed(b"id\r", 20, 4 * MS, 4 * MS, 0.3)
    assert out == [(b"sudo ls\r", False), (b"geheim\r", True), (b"id\r", False)]


def test_recorder_keeps_old_seven_parameter_callbacks():
    out = []
    r = InputRecorder(lambda *a: out.append(a))
    r.feed(b"ls\r", 0, 1, 1, 0.0)
    assert len(out) == 1 and len(out[0]) == 7


def test_input_frame_flag_roundtrip_and_independent_of_paste():
    for paste in (False, True):
        for no_echo in (False, True):
            fr = P.encode_input(7, 10, 12, 1, 2, b"x\r", paste=paste, no_echo=no_echo)
            dec = P.FrameDecoder().feed(fr)[0]
            inp = P.decode_input(dec.payload)
            assert (inp.paste, inp.no_echo, inp.data) == (paste, no_echo, b"x\r")
    # ein alter Shim ohne Flag ergibt False
    old = P.decode_input(P.FrameDecoder().feed(P.encode_input(1, 0, 0, 1, 2, b"a"))[0].payload)
    assert old.no_echo is False


def test_relay_reads_mode_of_child_when_recording(ptypair):
    m, s = ptypair
    shim, t = make_shim()
    shim.master = m
    t.state_msg(shim, True, rec="on", project="lame")
    _mode(s, echo=False, icanon=True)
    shim._on_action(Forward(b"hunter2\r"), 1.0)
    _mode(s, echo=False, icanon=False)  # Shell mit Zeileneditor
    shim._on_action(Forward(b"id\r"), 2.0)
    assert [(i["data"], i["no_echo"]) for i in t.inputs] == [(b"hunter2\r", True), (b"id\r", False)]


@pytest.mark.pty
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")
@pytest.mark.parametrize("shell", available_shells())
def test_real_shell_password_prompt_is_flagged(shell, box_factory):
    """Echte Shell: ``read -s`` schaltet ECHO aus und lässt ICANON an (wie getpass); die Eingabe
    kommt mit Flag, ein normaler Befehl am Zeileneditor ohne."""
    box = box_factory(shell=shell)
    with FakeDaemon(box.sock) as d:
        c = spawn(box, shell)
        c.sendline("printf 'P''W: '; read -s PW; echo; echo laenge-${#PW}")  # Echo enthält «PW: » nicht
        c.expect_exact("PW: ")
        time.sleep(0.5)  # read -s schaltet den Modus erst nach dem printf um
        c.sendline("hunter2")
        c.expect_exact("laenge-7")
        c.expect_exact(PROMPT)
        run_cmd(c, "echo sichtbar")
        flagged = d.wait_for(lambda: [f for f in d.inputs() if f.data.startswith(b"hunter2")])
        assert flagged[0].no_echo is True
        plain = d.wait_for(lambda: [f for f in d.inputs() if f.data.startswith(b"echo sichtbar")])
        assert plain[0].no_echo is False
        finish(c)
