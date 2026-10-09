"""CLI per Subprozess mit isolierten XDG-Ordnern, Passphrasen nur über ``--passphrase-fd``.

Enthält den Canary-Test: Nach Aufnahme markierter Werte und ``close`` steht keiner
davon im Klartext unter dem tmp-HOME oder im Runtime-Ordner.
"""

from __future__ import annotations

import contextlib
import os
import re
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
    assert "entsperrt (tester)" in res.stdout and "REC:      aus" in res.stdout

    res = _cli(env, "secrets", "add", "eigen", secret=own, fd_flag="--value-fd")
    assert res.returncode == 0 and "eigen" in res.stdout and own not in res.stdout

    res = _cli(env, "project", "new", "lame", "--target", "10.10.10.3", "--name", "HTB Lame")
    assert res.returncode == 0, res.stderr
    res = _cli(env, "project", "new", "evil", "--target", "8.8.8.8")
    assert res.returncode == 1 and "Allowlist" in res.stdout and "--not-customer" in res.stdout

    res = _cli(env, "rec", "on")
    assert res.returncode == 0 and "REC: an [lame]" in res.stdout

    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "fakeshim.py").write_text(FAKE_SHIM)
    shim = subprocess.run([sys.executable, str(tools / "fakeshim.py"), new_id()], env=env, text=True,
                          input=f"{canary}\n{own}\n", capture_output=True, timeout=30, check=False)
    assert shim.returncode == 0 and shim.stdout.strip() == "ok", shim.stderr

    res = _cli(env, "verify")
    assert res.returncode == 0 and "in Ordnung" in res.stdout, res.stdout + res.stderr

    res = _cli(env, "ctx", "show")
    assert res.returncode == 1 and "ARIADNE_TERMINAL_ID" in res.stderr

    res = _cli(env, "lock")
    assert res.returncode == 0 and "Gesperrt" in res.stdout
    res = _cli(env, "status")
    assert "gesperrt" in res.stdout and "wartet" in res.stdout

    res = _cli(env, "unlock", secret=PW)
    assert res.returncode == 0 and "wieder geöffnet: lame" in res.stdout, res.stdout + res.stderr

    res = _cli(env, "project", "close")
    assert res.returncode == 0 and "Kettenkopf" in res.stdout
    res = _cli(env, "project", "list")
    assert "lame" in res.stdout and "evil" not in res.stdout

    CtlClient(paths.ctl_sock).call("shutdown")
    for _ in range(50):
        if not paths.ctl_sock.exists():
            break
        time.sleep(0.05)

    # Canary: nichts im Klartext unter HOME und Runtime-Ordner, auch nicht im Daemon-Log
    log = paths.state_dir / "ariadned.log"
    assert log.exists() and "bereit" in log.read_text()
    roots = [Path(env["HOME"]), Path(env["XDG_RUNTIME_DIR"])]
    needles = [canary.encode(), own.encode(), PW.encode(), recovery.encode(),
               recovery.replace("-", "").encode(), b"HTB Lame", b"10.10.10.3"]
    assert _scan(roots, needles) == []


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
    assert "Daemon läuft nicht" in res.stdout
    res = _cli(env, "lock")
    assert res.returncode == 0
    res = _cli(env, "ui")
    assert "Web-UI" in res.stdout
    res = _cli(env, "project", "list")
    assert "Keine Projekte" in res.stdout
    res = _cli(env, "doctor")
    assert "[ok] Python" in res.stdout and "ptrace_scope" in res.stdout
    assert not Path(env["XDG_RUNTIME_DIR"], "ariadne", "ctl.sock").exists()
