"""CLI per Subprozess mit isolierten XDG-Ordnern, Passphrasen nur über ``--passphrase-fd``.

Bedienung seit E22: ``start``, ``stop``, ``pause``, ``resume``, ``status``; ``rec`` ist nur
noch ein Hinweis.

Enthält den Canary-Test: Nach Aufnahme markierter Werte und ``close`` steht keiner
davon im Klartext unter dem tmp-HOME oder im Runtime-Ordner.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from ariadne.daemon.client import CtlClient
from ariadne.ids import new_id
from ariadne.paths import default_paths
from tests.core.conftest import make_env

PW = "cli-passphrase-1234"


def _cli(env: dict[str, str], *args: str, secret: str | None = None, fd_flag: str = "--passphrase-fd",
         timeout: float = 60) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, "-m", "ariadne.cli.main", *args]
    pass_fds: tuple[int, ...] = ()
    r = w = None
    if secret is not None:
        r, w = os.pipe()
        os.write(w, secret.encode() + b"\n")
        os.close(w)
        argv += [fd_flag, str(r)]
        pass_fds = (r,)
    try:
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout,
                              pass_fds=pass_fds, stdin=subprocess.DEVNULL, check=False)
    finally:
        if r is not None:
            os.close(r)


@pytest.fixture(scope="module")
def cli_env(tmp_path_factory):
    base = tmp_path_factory.mktemp("cli")
    env = make_env(base)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    env["LANG"] = "C.UTF-8"
    yield base, env
    paths = default_paths(env)
    client = CtlClient(paths.ctl_sock, timeout=5)
    with contextlib.suppress(Exception):
        client.call("shutdown")
    lock = paths.runtime_dir / "daemon.lock"
    with contextlib.suppress(Exception):
        time.sleep(0.3)
        pid = int(lock.read_text().strip())
        os.kill(pid, signal.SIGTERM)


FAKE_SHIM = textwrap.dedent("""
    import ctypes, socket, sys, time
    ctypes.CDLL(None).prctl(15, b"ariadne-shim", 0, 0, 0)  # PR_SET_NAME wie der echte Shim
    from ariadne._shim import protocol as P
    from ariadne.paths import default_paths
    canary = sys.stdin.readline().strip().encode()
    own = sys.stdin.readline().strip().encode()
    tid = sys.argv[1]
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(str(default_paths().term_sock))
    dec = P.FrameDecoder()
    state, acked = {}, 0
    def pump(pred):
        global state, acked
        end = time.time() + 10
        while not pred():
            if time.time() > end:
                sys.exit("timeout")
            for fr in dec.feed(s.recv(65536)):
                obj = P.decode_json(fr.payload)
                if fr.type == P.STATE:
                    state = obj
                elif fr.type == P.ACK:
                    acked = obj["seq"]
    s.sendall(P.encode_json(P.HELLO, {"proto": 1, "terminal_id": tid, "shell": "zsh", "rows": 24,
                                      "cols": 80, "shim_version": "fake", "pid": 1}))
    pump(lambda: state.get("rec") == "on")
    data = b"$ cat loot.txt\\r\\n" + canary + b"\\r\\n$ echo " + own + b"\\r\\n"
    s.sendall(P.encode_out(1, 0, time.time_ns(), time.monotonic_ns(), data))
    s.sendall(P.encode_json(P.EVENT, {"seq": 2, "kind": "term.mark", "stream_off": len(data),
                                      "mark": "A", "counter": 1, "fg_shell": True}))
    pump(lambda: acked >= 2)
    s.sendall(P.encode_json(P.BYE, {"exit_code": 0}))
    print("ok")
""")


def _scan(roots: list[Path], needles: list[bytes]) -> list[str]:
    hits = []
    for root in roots:
        for f in root.rglob("*"):
            if f.is_file() and not f.is_symlink():
                data = f.read_bytes()
                hits += [f"{f}: {n[:12]!r}" for n in needles if n in data]
    return hits


def test_cli_full_flow_and_canary(cli_env, tmp_path):
    base, env = cli_env
    paths = default_paths(env)
    canary = f"KANARIENVOGEL-{new_id()}"
    own = f"EIGENES-{new_id()[-12:]}"

    res = _cli(env, "init", "--handle", "tester", secret=PW)
    assert res.returncode == 0, res.stderr
    m = re.search(r"([0-9A-Z]{4}(?:-[0-9A-Z]{4}){6})", res.stdout)
    assert m, res.stdout
    recovery = m.group(1)
    assert PW not in res.stdout + res.stderr

    res = _cli(env, "status")
    assert "entsperrt (tester)" in res.stdout and "Projekt:  -" in res.stdout

    res = _cli(env, "secrets", "add", "eigen", secret=own, fd_flag="--value-fd")
    assert res.returncode == 0 and "eigen" in res.stdout and own not in res.stdout
    assert "werden vor KI, Export und Bericht ersetzt" in _cli(env, "--help").stdout

    res = _cli(env, "start")
    assert res.returncode == 1 and "Kein aktives Projekt. ariadne start <slug> --target <ziel>" in res.stderr
    res = _cli(env, "start", "lame", "--target", "10.10.10.3", "--name", "HTB Lame")
    assert res.returncode == 0, res.stderr
    assert "Projekt lame angelegt" in res.stdout and "Aufnahme läuft" in res.stdout
    res = _cli(env, "start", "evil", "--target", "8.8.8.8")
    assert res.returncode == 1 and "Allowlist" in res.stdout and "--not-customer" in res.stdout

    res = _cli(env, "rec", "on")
    assert res.returncode == 1 and "REC gibt es nicht mehr" in res.stdout and "ariadne pause" in res.stdout

    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "fakeshim.py").write_text(FAKE_SHIM)
    shim = subprocess.run([sys.executable, str(tools / "fakeshim.py"), new_id()], env=env, text=True,
                          input=f"{canary}\n{own}\n", capture_output=True, timeout=30, check=False)
    assert shim.returncode == 0 and shim.stdout.strip() == "ok", shim.stderr

    res = _cli(env, "status")
    assert "Projekt:  lame (lab), Aufnahme läuft" in res.stdout and "Leerlauf: 0 h 0" in res.stdout
    assert "Ende nach 12 h" in res.stdout

    res = _cli(env, "verify")
    assert res.returncode == 0 and "in Ordnung" in res.stdout, res.stdout + res.stderr

    res = _cli(env, "ctx", "show")
    assert res.returncode == 1 and "ARIADNE_TERMINAL_ID" in res.stderr
    res = _cli(env, "pause")
    assert res.returncode == 1 and "ARIADNE_TERMINAL_ID" in res.stderr

    res = _cli(env, "lock")
    assert res.returncode == 0 and "Gesperrt" in res.stdout and "Weiter mit ariadne start" in res.stdout
    res = _cli(env, "status")
    assert "gesperrt" in res.stdout and "lame aktiv, gesperrt" in res.stdout

    res = _cli(env, "start", secret=PW)  # gesperrt: Passphrase per Deskriptor, Projekt ohne Slug
    assert res.returncode == 0 and "Entsperrt." in res.stdout and "Projekt lame geöffnet" in res.stdout, \
        res.stdout + res.stderr

    res = _cli(env, "stop")
    assert res.returncode == 0 and "Projekt lame beendet und gesperrt. Kettenkopf: seq" in res.stdout
    res = _cli(env, "start", secret=PW)
    assert res.returncode == 1 and "Kein aktives Projekt" in res.stderr
    res = _cli(env, "start", "nix", secret=PW)  # gescheiterter Start lässt den Tresor nicht offen
    assert res.returncode == 1 and "existiert nicht" in res.stderr
    assert "Tresor:   gesperrt" in _cli(env, "status").stdout
    res = _cli(env, "start", "lame", secret=PW + "x")
    assert res.returncode == 1 and "Passphrase falsch" in res.stderr
    res = _cli(env, "project", "list")
    assert "lame" in res.stdout and "evil" not in res.stdout

    CtlClient(paths.ctl_sock).call("shutdown")
    for _ in range(50):
        if not paths.ctl_sock.exists():
            break
        time.sleep(0.05)

    # Canary: nichts im Klartext unter HOME und Runtime-Ordner, auch nicht im Daemon-Log.
    # Seit E72 steht das eigene Secret im Journal, aber nur verschlüsselt.
    log = paths.state_dir / "ariadned.log"
    assert log.exists() and "bereit" in log.read_text()
    roots = [Path(env["HOME"]), Path(env["XDG_RUNTIME_DIR"])]
    needles = [canary.encode(), own.encode(), PW.encode(), recovery.encode(),
               recovery.replace("-", "").encode(), b"HTB Lame", b"10.10.10.3"]
    assert _scan(roots, needles) == []


LIVE_SHIM = textwrap.dedent("""
    import ctypes, select, socket, sys, time
    ctypes.CDLL(None).prctl(15, b"ariadne-shim", 0, 0, 0)  # PR_SET_NAME wie der echte Shim
    from ariadne._shim import protocol as P
    from ariadne.paths import default_paths
    tid, text = sys.argv[1], sys.argv[2].encode()
    s = socket.socket(socket.AF_UNIX)
    s.connect(str(default_paths().term_sock))
    s.sendall(P.encode_json(P.HELLO, {"proto": 2, "terminal_id": tid, "shell": "zsh", "tty": "/dev/pts/9",
                                      "rows": 24, "cols": 80, "shim_version": "fake", "pid": 1}))
    dec = P.FrameDecoder()
    sent = False
    while True:
        r, _, _ = select.select([s, sys.stdin], [], [], 10)
        if not r:
            sys.exit("timeout")
        if sys.stdin in r and not sys.stdin.readline():
            s.sendall(P.encode_json(P.BYE, {"exit_code": 0}))
            break
        if s in r:
            data = s.recv(65536)
            if not data:
                break
            for fr in dec.feed(data):
                if fr.type == P.STATE:
                    st = P.decode_json(fr.payload)
                    print("STATE", st["rec"], flush=True)
                    if not sent and st["rec"] in P.CAPTURE_STATES:
                        s.sendall(P.encode_outx(1, 0, time.time_ns(), time.monotonic_ns(), text))
                        sent = True
                elif fr.type == P.ACK:
                    print("ACK", P.decode_json(fr.payload)["seq"], flush=True)
""")


def _wait_line(proc: subprocess.Popen[str], needle: str, timeout: float = 10) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        line = proc.stdout.readline() if proc.stdout else ""
        if not line:
            raise AssertionError(f"Fake-Shim beendet, {needle!r} fehlt")
        if needle in line:
            return
    raise AssertionError(f"{needle!r} kam nicht")


def test_cli_preroll_pause_resume_status(tmp_path):
    env = make_env(tmp_path)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    env["LANG"] = "C.UTF-8"
    paths = default_paths(env)
    (tmp_path / "live.py").write_text(LIVE_SHIM)
    tid = new_id()
    proc = None
    try:
        assert _cli(env, "init", secret=PW).returncode == 0
        proc = subprocess.Popen([sys.executable, str(tmp_path / "live.py"), tid, "vorher-getippt\r\n"],
                                env=env, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        _wait_line(proc, "STATE preroll")
        _wait_line(proc, "ACK 1")
        res = _cli(env, "status")
        assert "Vorlauf:  1 min aus 1 Terminals" in res.stdout and "Vorlauf 1 min" in res.stdout, res.stdout
        res = _cli(env, "start", "lame", "--target", "10.10.10.3", "--preroll", "yes")
        assert res.returncode == 0 and "Vorlauf übernommen: 1 min aus 1 Terminals." in res.stdout, \
            res.stdout + res.stderr
        _wait_line(proc, "STATE on")
        short = tid[-8:]
        res = _cli(env, "status")
        assert re.search(rf"^  {short}  /dev/pts/9\s+nimmt auf", res.stdout, re.M), res.stdout
        res = _cli(env, "pause", "--terminal", short, "--minutes", "5")
        assert res.returncode == 0, res.stderr
        assert re.search(r"Pause bis \d\d:\d\d \(1 Terminal\)", res.stdout), res.stdout
        _wait_line(proc, "STATE paused")
        assert re.search(rf"^  {short}  /dev/pts/9\s+Pause bis \d\d:\d\d", _cli(env, "status").stdout, re.M)
        res = _cli({**env, "ARIADNE_TERMINAL_ID": tid}, "resume")
        assert res.returncode == 0 and "Aufnahme läuft weiter (1 Terminal)." in res.stdout
        _wait_line(proc, "STATE on")
        res = _cli(env, "pause", "--terminal", "zzzz")
        assert res.returncode == 1 and "unbekannt" in res.stderr
        res = _cli(env, "pause", "--all")
        assert "1 Terminal" in res.stdout
        res = _cli(env, "resume", "--all")
        assert "Aufnahme läuft weiter (1 Terminal)." in res.stdout
        assert "beendet und gesperrt" in _cli(env, "stop").stdout
        _wait_line(proc, "STATE held")
    finally:
        if proc is not None:
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=10)
            if proc.stdout:
                proc.stdout.close()
        with contextlib.suppress(Exception):
            CtlClient(paths.ctl_sock, timeout=5).call("shutdown")
        time.sleep(0.3)


def test_cli_misc_without_daemon(tmp_path):
    env = make_env(tmp_path)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    res = _cli(env, "status")
    assert res.returncode == 0 and "Daemon:   aus" in res.stdout and "fehlt" in res.stdout
    res = _cli(env, "init")  # ohne TTY und ohne --passphrase-fd
    assert res.returncode == 1 and "passphrase-fd" in res.stderr
    res = _cli(env, "init", "--passphrase", "x")  # Passphrasen nie als Argument
    assert res.returncode == 2
    res = _cli(env, "unlock", secret="egal")
    assert res.returncode == 1 and "ariadne init" in res.stderr
    res = _cli(env, "rec", "status")
    assert res.returncode == 1 and "REC gibt es nicht mehr" in res.stdout
    res = _cli(env, "stop")
    assert res.returncode == 0 and "nichts aktiv" in res.stdout
    res = _cli(env, "lock")
    assert res.returncode == 0
    res = _cli(env, "ui")
    assert "Web-UI" in res.stdout
    res = _cli(env, "project", "list")
    assert "Keine Projekte" in res.stdout
    res = _cli(env, "doctor")
    assert "[ok] Python" in res.stdout and "ptrace_scope" in res.stdout
    assert not Path(env["XDG_RUNTIME_DIR"], "ariadne", "ctl.sock").exists()


def _daemon_down(paths) -> None:
    with contextlib.suppress(Exception):
        CtlClient(paths.ctl_sock, timeout=5).call("shutdown")
    end = time.monotonic() + 10
    while time.monotonic() < end and CtlClient(paths.ctl_sock, timeout=1).ping():
        time.sleep(0.05)


def test_cli_start_stop_messages_from_review(tmp_path):
    """Befunde F5, F6, F7, F8 (Entscheidtreue) und F11 (Tests): ehrliche Meldungen zu Vorlauf,
    beendetem und gelöschtem Projekt, Wechsel und ``stop`` ohne laufenden Daemon."""
    from ariadne.daemon.active import read_active

    env = make_env(tmp_path)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    env["LANG"] = "C.UTF-8"
    paths = default_paths(env)
    (tmp_path / "live.py").write_text(LIVE_SHIM)
    proc = None
    try:
        assert _cli(env, "init", secret=PW).returncode == 0
        proc = subprocess.Popen([sys.executable, str(tmp_path / "live.py"), new_id(), "vorlauf\r\n"],
                                env=env, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        _wait_line(proc, "STATE preroll")
        _wait_line(proc, "ACK 1")
        res = _cli(env, "start", "lame", "--target", "10.10.10.3")  # ohne TTY: keine Frage
        assert res.returncode == 0, res.stderr
        assert "Vorlauf verworfen: 1 min aus 1 Terminals" in res.stdout and "--preroll yes" in res.stdout
        _wait_line(proc, "STATE on")
        assert "beendet und gesperrt" in _cli(env, "stop").stdout
        _wait_line(proc, "STATE held")
        res = _cli(env, "start")
        assert res.returncode == 1, res.stdout
        assert "Projekt lame ist beendet mit ariadne stop. Weiter: ariadne start lame" in res.stderr
        res = _cli(env, "start", "beta", "--target", "10.10.10.4", secret=PW)
        assert res.returncode == 0, res.stderr
        assert "(0 Terminals; 1 wechseln an der nächsten lokalen Eingabeaufforderung)" in res.stdout
        assert _cli(env, "lock").returncode == 0
        assert _cli(env, "unlock", secret=PW).returncode == 0
        out = _cli(env, "status").stdout  # Befund F3 (Entscheidtreue): nicht «gesperrt» nach unlock
        assert "Tresor:   entsperrt" in out and "beta aktiv, nicht geöffnet (weiter mit ariadne start)" in out
        proc.stdin.close()  # type: ignore[union-attr]
        proc.wait(timeout=10)
        # Daemon aus, Projekt aktiv: stop startet ihn und beendet das Projekt wirklich
        _daemon_down(paths)
        res = _cli(env, "stop")
        assert res.returncode == 0 and "Projekt beta beendet und gesperrt" in res.stdout, res.stdout
        assert read_active(paths.active_file)["stopped"] is True
        # aktives Projekt gelöscht: start ohne Slug sagt es und bleibt nicht «gesperrt»
        res = _cli(env, "start", "gamma", "--target", "10.10.10.5", secret=PW)
        ws = re.search(r"angelegt \(lab\) in (\S+)", res.stdout)
        assert ws, res.stdout
        _daemon_down(paths)
        shutil.rmtree(ws.group(1))
        res = _cli(env, "start", secret=PW)
        assert res.returncode == 1 and "Projekt gamma gibt es nicht mehr" in res.stderr, res.stderr
        assert "None" not in res.stderr
        out = _cli(env, "status").stdout
        assert "Projekt:  - " in out and "gesperrt (weiter" not in out, out
        assert "Projekt gamma gibt es nicht mehr (Ordner fehlt)" in _cli(env, "start").stderr
    finally:
        if proc is not None:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
            proc.wait(timeout=10)
            if proc.stdout:
                proc.stdout.close()
        _daemon_down(paths)
