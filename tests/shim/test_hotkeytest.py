"""``run_hotkey_test``: zeigt Bytes pro Taste, erkennt Präfix und Taste, Ende mit q."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pexpect
import pytest

from ariadne._shim.hotkey import Armed, Forward, Key
from ariadne._shim.hotkeytest import describe_chunk
from tests.shim.conftest import SRC

CODE = (
    "import sys; sys.path.append(sys.argv[1]);"
    "from ariadne._shim.hotkeytest import run_hotkey_test;"
    "raise SystemExit(run_hotkey_test())"
)


def test_describe_chunk_is_term_safe():
    line = describe_chunk(b"\x1b]0;x\x07", [Forward(b"\x1b]0;x\x07")])
    assert "\x1b" not in line and "\x07" not in line and "1b 5d 30" in line
    assert "Präfix erkannt" in describe_chunk(b"\x1b[24~", [Armed()])
    assert "REC umschalten" in describe_chunk(b"r", [Key("r")])


@pytest.mark.pty
def test_run_hotkey_test_in_pty():
    env = {"PATH": os.environ["PATH"], "TERM": "xterm", "LANG": "C.UTF-8"}
    c = pexpect.spawn(sys.executable, ["-I", "-S", "-c", CODE, str(SRC)], env=env, timeout=10)
    c.expect_exact("q beendet")
    c.send(b"\x1b[24~")
    c.expect_exact("Präfix erkannt".encode())
    time.sleep(0.1)
    c.send(b"r")
    c.expect_exact(b"Hotkey r: REC umschalten")
    c.send(b"hallo")
    c.expect_exact(b"Burst, 5 Bytes")
    time.sleep(0.1)
    c.send(b"q")
    c.expect(pexpect.EOF)
    c.close()
    assert c.exitstatus == 0


def test_run_hotkey_test_without_tty():
    r = subprocess.run([sys.executable, "-I", "-S", "-c", CODE, str(SRC)], stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=10)
    assert r.returncode == 2
