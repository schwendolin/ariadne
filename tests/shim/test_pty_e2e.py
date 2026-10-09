"""PTY-E2E: echte Shells über Launcher und Shim gegen den Fake-Daemon.

Jeder Test startet die Shell so, wie ein Terminal es tut (``zsh -i`` bzw.
``bash -i``). Die RC-Zeile liest ``init.<shell>``, das per exec den Launcher
und damit den Shim startet; innen installiert dieselbe Datei die Hooks.
"""

from __future__ import annotations

import re
import shutil
import time

import pexpect
import pytest

from ariadne._shim import protocol as P
from tests.shim.conftest import PROMPT, available_shells, shell_kind
from tests.shim.fake_daemon import FakeDaemon

pytestmark = [
    pytest.mark.pty,
    # Der Fake-Daemon läuft in einem Thread; pexpect ruft danach sofort exec auf.
    pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning"),
]

F12 = b"\x1b[24~"
SHELLS = available_shells()


def spawn(box, shell: str, rows: int = 24, cols: int = 80) -> pexpect.spawn:
    env = dict(box.env, SHELL=shell)
    c = pexpect.spawn(shell, ["-i"], env=env, cwd=str(box.home), timeout=10, dimensions=(rows, cols))
    c.expect_exact(PROMPT)
    return c


def run_cmd(c: pexpect.spawn, cmd: str) -> bytes:
    c.sendline(cmd)
    c.expect_exact(PROMPT)
    return c.before


def is_bash_pre53(c: pexpect.spawn) -> bool:
    out = run_cmd(c, 'echo "BV=${BASH_VERSINFO[0]}${BASH_VERSINFO[1]}"')
    m = re.search(rb"BV=(\d+)", out)
    return bool(m) and int(m.group(1)) < 53


def finish(c: pexpect.spawn, code: int = 0) -> None:
    c.sendline(f"exit {code}")
    c.expect(pexpect.EOF)
    c.close()
    assert c.exitstatus == code


@pytest.mark.parametrize("shell", SHELLS)
def test_session_markers_and_recording(shell, box_factory):
    box = box_factory(shell=shell)
    with FakeDaemon(box.sock) as d:
        c = spawn(box, shell)
        old_bash = shell_kind(shell) == "bash" and is_bash_pre53(c)
        hello = d.wait_for(lambda: d.hellos())[0]
        assert hello["shell"] == shell and hello["rows"] == 24

        # Shim läuft für dieses TTY, Shell sieht ihre Variablen
        out = run_cmd(c, 'echo "tty=$ARIADNE_SHIM_TTY failed=${ARIADNE_SHIM_FAILED:-none}"')
        assert b"failed=none" in out and b"tty=/dev/pts/" in out

        # echo hello landet im aufgezeichneten Strom
        run_cmd(c, "echo hello-$((40+2))")
        assert d.wait_for(lambda: b"hello-42" in d.out_bytes())

        # C- und D-Marker mit Exit-Code
        run_cmd(c, "false")
        dm = d.wait_for(lambda: [m for m in d.marks("D") if m.get("exit") == 1])
        assert dm[-1]["fg_shell"] is True and dm[-1]["pipestatus"] == [1]
        src = dm[-1] if old_bash else d.marks("C")[-1]
        assert src.get("cmd_typed") == "false"
        assert all(b"7701" not in r.obj[4] for r in d.frames(P.OUT))

        # yes | head ohne Broken pipe (SIGPIPE im Kind auf SIG_DFL)
        out = run_cmd(c, "yes | head -1")
        assert b"Broken pipe" not in out and b"y\r\n" in out

        # $? bleibt erhalten
        run_cmd(c, "(exit 7)")
        assert b"rc=7" in run_cmd(c, 'echo "rc=$?"')

        # gefälschter Marker mit falscher Nonce: entfernt und gemeldet
        forge = box.home / "forge.sh"
        forge.write_text(
            "printf 'a\\033]7701;ariadne;v1;%s;1:99999999999;D;exit=0\\007b\\n' "
            "ffffffffffffffffffffffffffffffff\necho forge-done\n"
        )
        out = run_cmd(c, "sh ~/forge.sh")
        assert b"forge-done" in out and b"ab" in out and b"7701" not in out
        forged = d.wait_for(lambda: d.events("term.marker_forged"))
        assert forged[-1]["reason"] == "bad_nonce"
        assert b"7701" not in d.out_bytes()

        # Grösse ändern: term.resize und neue Grösse in der Shell
        c.setwinsize(30, 100)
        time.sleep(0.2)
        c.sendline("stty size; echo size-done")
        c.expect(rb"(\d+) (\d+)\r\nsize-done")
        assert c.match.group(1, 2) == (b"30", b"100")
        c.expect_exact(PROMPT)
        assert d.wait_for(lambda: [e for e in d.events("term.resize") if (e["rows"], e["cols"]) == (30, 100)])

        # Unter-Shell: Hooks ja, zweiter Shim nein
        c.sendline(shell)
        c.expect_exact(PROMPT)
        out = run_cmd(c, 'echo "sub=$$ shim=$ARIADNE_SHIM_PID"')
        sub_pid = int(re.search(rb"sub=(\d+)", out).group(1))
        run_cmd(c, "exit")
        assert d.wait_for(lambda: [m for m in d.marks() if m["shell_pid"] == sub_pid])
        assert len(d.hellos()) == 1

        # Ctrl-Z ergibt D mit 148
        c.sendline("sleep 30")
        time.sleep(0.4)
        c.sendcontrol("z")
        c.expect_exact(PROMPT)
        assert d.wait_for(lambda: [m for m in d.marks("D") if m.get("exit") == 148])
        run_cmd(c, "kill -9 %1")

        # F12 und r: req.rec an den Daemon, r erreicht die Shell nicht
        c.send(F12)
        time.sleep(0.3)
        c.send(b"r")
        assert d.wait_for(lambda: d.events("req.rec"))
        assert d.events("req.rec")[0]["on"] is None
        c.expect_exact(b"\x1b]2;[-- lame]")
        out = run_cmd(c, "echo after-hotkey")
        assert b"after-hotkey" in out and b"not found" not in out

        finish(c, 3)
        assert d.wait_for(lambda: d.frames(P.BYE))
        assert d.frames(P.BYE)[0].obj == {"exit_code": 3}


@pytest.mark.parametrize("shell", SHELLS)
def test_daemon_unreachable_shell_works_and_title_offline(shell, box_factory):
    box = box_factory(shell=shell)
    c = spawn(box, shell)
    out = run_cmd(c, 'echo "ok-$ARIADNE_SHIM_FAILED-${ARIADNE_SHIM_TTY:+wrapped}"')
    assert b"ok--wrapped" in out
    c.expect_exact(b"\x1b]2;[ariadne offline]", timeout=3)
    finish(c)


@pytest.mark.parametrize("shell", SHELLS)
def test_broken_interpreter_still_starts_shell(shell, box_factory):
    box = box_factory(shell=shell, python="/nonexistent/python3")
    c = spawn(box, shell)
    out = run_cmd(c, 'echo "f=$ARIADNE_SHIM_FAILED t=${ARIADNE_SHIM_TTY:-none}"')
    assert b"f=interpreter t=none" in out
    finish(c)


@pytest.mark.parametrize("shell", SHELLS)
def test_disable_file_skips_shim(shell, box_factory):
    box = box_factory(shell=shell)
    (box.home / ".config" / "ariadne").mkdir(parents=True)
    (box.home / ".config" / "ariadne" / "disable").touch()
    c = spawn(box, shell)
    out = run_cmd(c, 'echo "t=${ARIADNE_SHIM_TTY:-none}"')
    assert b"t=none" in out
    finish(c)


def test_host_prompt_sets_context(box_factory):
    shell = SHELLS[0]
    box = box_factory(shell=shell)
    with FakeDaemon(box.sock, hosts=["web01", "web02"]) as d:
        c = spawn(box, shell)
        d.wait_for(lambda: d.hellos())
        time.sleep(0.2)
        c.send(F12)
        time.sleep(0.3)
        c.send(b"h")
        c.expect_exact(b"\x1b[6n")
        c.send(b"\x1b[5;10R")  # Antwort eines Terminals auf die Cursor-Abfrage
        c.expect_exact(b"[ariadne] Host")
        for ch in b"root@w":
            c.send(bytes([ch]))
            time.sleep(0.02)
        c.send(b"\t")
        c.expect_exact(b"[web01 web02]")
        c.send(b"1")
        time.sleep(0.05)
        c.send(b"\r")
        c.expect_exact(b"\x1b[5;10H")  # Cursor zurück an die alte Stelle
        ev = d.wait_for(lambda: d.events("req.ctx.set"))[0]
        assert ev["host"] == "web01" and ev["user"] == "root"
        c.expect(re.compile(rb"\x1b\]2;\[REC lame\][^\x07]*web01 root"))
        out = run_cmd(c, "echo still-ok")
        assert b"still-ok" in out and b"root@web01" not in out
        finish(c)


def test_exit_code_and_hangup(box_factory):
    shell = SHELLS[0]
    box = box_factory(shell=shell)
    with FakeDaemon(box.sock) as d:
        c = spawn(box, shell)
        d.wait_for(lambda: d.hellos())
        c.close(force=True)  # Terminal geht zu: SIGHUP an den Shim
        assert d.wait_for(lambda: d.frames(P.BYE), timeout=5)


def test_rec_off_sends_no_content_then_gap_on_rec_on(box_factory):
    shell = SHELLS[0]
    box = box_factory(shell=shell)
    with FakeDaemon(box.sock, rec="off") as d:
        c = spawn(box, shell)
        d.wait_for(lambda: d.hellos())
        run_cmd(c, "echo secret-while-off")
        time.sleep(0.3)
        assert d.frames(P.OUT) == [] and d.events("term.mark") == []
        d.send_state(rec="on")
        assert d.wait_for(lambda: d.events("term.ctx_snapshot"))
        run_cmd(c, "echo now-recording")
        assert d.wait_for(lambda: b"now-recording" in d.out_bytes())
        assert b"secret-while-off" not in d.out_bytes()
        gap = d.events("term.gap")[0]
        assert gap["reason"] == "rec_off" and gap["bytes_lost"] > 0
        first_out = min(r.obj[1] for r in d.frames(P.OUT))
        assert gap["stream_off"] + gap["bytes_lost"] == first_out
        finish(c)


def test_daemon_restart_resends_buffer(box_factory):
    shell = SHELLS[0]
    box = box_factory(shell=shell)
    d1 = FakeDaemon(box.sock, ack=False).start()
    c = spawn(box, shell)
    d1.wait_for(lambda: d1.hellos())
    run_cmd(c, "echo before-crash")
    assert d1.wait_for(lambda: b"before-crash" in d1.out_bytes())
    d1.stop()
    out = run_cmd(c, "echo while-offline")
    assert b"while-offline" in out
    c.expect_exact(b"\x1b]2;[ariadne offline]", timeout=3)
    with FakeDaemon(box.sock) as d2:
        assert d2.wait_for(lambda: d2.hellos(), timeout=3)
        assert d2.hellos()[0]["resume_from_seq"] == 1
        data = d2.wait_for(lambda: b"while-offline" in d2.out_bytes() and d2.out_bytes())
        assert b"before-crash" in data  # unbestätigt, daher erneut gesendet
        finish(c)


@pytest.mark.parametrize("shell", SHELLS)
def test_nested_shell_without_shim_tty_is_not_wrapped(shell, box_factory):
    """Wie ``sudo -i``: Umgebung ohne ARIADNE_SHIM_TTY, Vorfahre ist ein Shim."""
    box = box_factory(shell=shell)
    with FakeDaemon(box.sock) as d:
        c = spawn(box, shell)
        d.wait_for(lambda: d.hellos())
        c.sendline(f"env -u ARIADNE_SHIM_TTY -u ARIADNE_NONCE {shell} -i")
        c.expect_exact(PROMPT)
        out = run_cmd(c, 'echo "nested=$ARIADNE_SHIM_FAILED"')
        assert b"nested=nested" in out
        run_cmd(c, "exit")
        time.sleep(0.2)
        assert len(d.hellos()) == 1
        finish(c)


@pytest.mark.parametrize("shell", SHELLS)
def test_exec_shell_keeps_counter_monotonic(shell, box_factory):
    box = box_factory(shell=shell)
    with FakeDaemon(box.sock) as d:
        c = spawn(box, shell)
        run_cmd(c, "true")
        c.sendline(f"exec {shell}")
        c.expect_exact(PROMPT)
        run_cmd(c, "(exit 5)")
        assert d.wait_for(lambda: [m for m in d.marks("D") if m.get("exit") == 5])
        assert d.events("term.marker_forged") == []
        finish(c)


@pytest.mark.skipif(not shutil.which("tmux"), reason="tmux fehlt")
def test_tmux_pane_gets_own_shim(box_factory, tmp_path_factory):
    shell = SHELLS[0]
    box = box_factory(shell=shell)
    sock = tmp_path_factory.mktemp("tm") / "s"
    with FakeDaemon(box.sock) as d:
        c = spawn(box, shell)
        d.wait_for(lambda: d.hellos())
        try:
            run_cmd(c, f"tmux -S {sock} -f /dev/null new-session -d -x 80 -y 20")
            hellos = d.wait_for(lambda: len(d.hellos()) >= 2 and d.hellos(), timeout=8)
            assert len(hellos) == 2
            assert hellos[1]["tmux_pane"] and hellos[1]["tty"] != hellos[0]["tty"]
        finally:
            run_cmd(c, f"tmux -S {sock} kill-server")
        finish(c)


def test_hotkeys_keystep_shot_pop_and_alt_screen(box_factory):
    shell = SHELLS[0]
    box = box_factory(shell=shell)

    def hotkey(c, key: bytes) -> None:
        c.send(F12)
        time.sleep(0.25)
        c.send(key)

    with FakeDaemon(box.sock) as d:
        c = spawn(box, shell)
        d.wait_for(lambda: d.hellos())
        time.sleep(0.2)
        hotkey(c, b"k")
        c.expect_exact(b"[ariadne] Schl")
        c.send(b"f")
        c.expect_exact(b"Notiz")
        for ch in "root über ftp":
            c.send(ch.encode())
            time.sleep(0.01)
        c.send(b"\r")
        ev = d.wait_for(lambda: d.events("req.keystep"))[0]
        assert ev["step"] == "foothold" and ev["note"] == "root über ftp"
        hotkey(c, b"s")
        assert d.wait_for(lambda: d.events("req.shot"))[0]["mode"] == "window"
        hotkey(c, b"b")
        assert d.wait_for(lambda: d.events("req.ctx.pop"))
        # Im Alternate Screen kein Mini-Prompt, nur Titel
        run_cmd(c, "printf '\\033[?1049h'")
        time.sleep(0.2)
        hotkey(c, b"h")
        c.expect_exact(b"ariadne: im Vollbild")
        run_cmd(c, "printf '\\033[?1049l'")
        assert b"[ariadne] Host" not in c.before
        finish(c)
