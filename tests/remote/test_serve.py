"""T12 ``ariadne remote serve`` (R5, R11): feste Befehlsliste, nichts sonst wird ausgeführt.

Im Prozess mit Attrappen für ctl, Sicherung und Halten; dazu echte Prozesse unter einer
sshd-Attrappe (``sh`` unter dem Namen ``sshd``) gegen einen Daemon mit echtem Web-Server."""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from ariadne.cli.common import CliError
from ariadne.daemon.client import CtlError
from ariadne.remote import check, serve
from ariadne.web.integration import WebExtension
from ariadne.web.peer import PeerInfo
from tests.core.test_daemon import run
from tests.remote.helpers import age_recipient, base_root, free_port, install_keys, keypair, run_setup

SERVE = "import sys; from ariadne.cli.main import main; sys.exit(main(['remote', 'serve']))"
LONG_CODE = re.compile(r"\A[A-Za-z0-9_-]{22}\Z")


class Stream(io.StringIO):
    def __init__(self, tty: bool = False, data: bytes = b"") -> None:
        super().__init__()
        self._tty = tty
        self.buffer = io.BytesIO(data)
        self.read_attempted = False

    def isatty(self) -> bool:
        return self._tty


class NoRead(io.BytesIO):
    """stdin, das nie gelesen werden darf."""

    def read(self, *a: Any) -> bytes:
        raise AssertionError("stdin gelesen")

    readinto = readline = read  # type: ignore[assignment]


class FakeClient:
    def __init__(self, result: Any = None, error: CtlError | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.result = result
        self.error = error

    def call(self, op: str, timeout: float | None = None, **args: Any) -> Any:
        self.calls.append((op, args))
        if self.error is not None:
            raise self.error
        return self.result


@pytest.fixture
def io_streams(monkeypatch):
    """Ersetzt stdin, stdout und stderr; im Testkörper aufrufen (pytest tauscht sie vor dem Aufruf)."""

    def make() -> tuple[Stream, Stream, Stream]:
        out, err, inp = Stream(), Stream(), Stream()
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", err)
        monkeypatch.setattr(sys, "stdin", inp)
        return out, err, inp

    return make


@pytest.fixture
def spies(monkeypatch):
    """Alle Befehle durch Spione ersetzen: Ablehnungen dürfen keinen erreichen."""
    called: list[str] = []
    for name in serve.ALLOWED:
        monkeypatch.setitem(serve.HANDLERS, name, lambda p, e, n=name: called.append(n) or 0)
    return called


def env(cmd: str | None, **extra: str) -> dict[str, str]:
    e = {"XDG_RUNTIME_DIR": "/run/user/1000", **extra}
    if cmd is not None:
        e["SSH_ORIGINAL_COMMAND"] = cmd
    return e


@pytest.mark.parametrize(
    "cmd",
    [
        None,
        "",
        "id",
        "code; id",
        "code id",
        "code\nid",
        " code",
        "code ",
        "CODE",
        "code&",
        "$(id)",
        "`id`",
        "scp -t /",
        "scp -f ~/.ssh/id_ed25519",
        "internal-sftp",
        "/usr/lib/openssh/sftp-server",
        "sftp",
        "rsync --server -vlogDtpre.iLsfxC . /tmp",
        "bash",
        "sh -c id",
        "git-upload-pack 'x'",
        "code\x00id",
    ],
)
def test_t12_rejects_everything_else(paths, io_streams, spies, cmd):
    out, err, _ = io_streams()
    assert serve.main(paths, env(cmd)) == serve.EXIT_REFUSED
    assert spies == []
    assert out.getvalue() == ""
    assert err.getvalue().startswith("Abgelehnt:") and "Nichts ausgeführt." in err.getvalue()
    assert "code, unlock, lock, revoke, backup, restore, check" in err.getvalue()


def test_allowed_words_reach_their_handler(paths, io_streams, spies):
    io_streams()
    for name in serve.ALLOWED:
        assert serve.main(paths, env(name)) == 0
    assert spies == list(serve.ALLOWED)


def test_daemon_commands_need_runtime_dir(paths, io_streams, spies):
    _, err, _ = io_streams()
    for name in ("code", "unlock", "lock", "revoke"):
        assert serve.main(paths, {"SSH_ORIGINAL_COMMAND": name}) == serve.EXIT_UNREADY
    assert spies == [] and "Runtime-Ordner" in err.getvalue()
    for name in ("backup", "restore", "check"):
        assert serve.main(paths, {"SSH_ORIGINAL_COMMAND": name}) == 0
    assert spies == ["backup", "restore", "check"]


def test_t12_restore_refused_when_vault_exists_before_reading(paths, operator, io_streams, monkeypatch):
    _, err, _ = io_streams()
    monkeypatch.setattr(sys, "stdin", Stream(data=b""))
    sys.stdin.buffer = NoRead()  # type: ignore[attr-defined]
    called = []
    monkeypatch.setattr("ariadne.backup.api.restore_from_stream", lambda *a, **k: called.append(1))
    assert serve.main(paths, env("restore")) == serve.EXIT_REFUSED
    assert called == [] and "Operator-Tresor" in err.getvalue()


def test_restore_from_pipe_without_vault(paths, io_streams, monkeypatch):
    from ariadne.backup.api import RestoreResult

    out, _, _ = io_streams()
    monkeypatch.setattr(sys, "stdin", Stream(data=b"klartext-strom"))
    seen = []

    def fake_restore(inp, p):
        seen.append(inp.read())
        return RestoreResult(projects=("htb-lame",), operator_restored=True)

    monkeypatch.setattr("ariadne.backup.api.restore_from_stream", fake_restore)
    assert serve.main(paths, env("restore")) == 0
    assert seen == [b"klartext-strom"]
    assert "htb-lame" in out.getvalue() and "ssh -t kali-sl unlock" in out.getvalue()
    assert "ariadne project open htb-lame" in out.getvalue()
    monkeypatch.setattr(sys, "stdin", Stream(tty=True))
    assert serve.main(paths, env("restore")) == serve.EXIT_REFUSED


def test_t12_unlock_needs_terminal(paths, io_streams, monkeypatch):
    _, err, _ = io_streams()
    called = []
    monkeypatch.setattr("ariadne.cli.main.main", lambda argv: called.append(argv) or 0)
    assert serve.main(paths, env("unlock")) == serve.EXIT_REFUSED
    assert called == [] and "ssh -t kali-sl unlock" in err.getvalue()
    monkeypatch.setattr(sys, "stdin", Stream(tty=True))
    assert serve.main(paths, env("unlock")) == 0
    assert called == [["unlock"]]


def test_t12_backup_refuses_terminal_stdout(paths, io_streams, monkeypatch):
    _, err, _ = io_streams()
    called = []
    monkeypatch.setattr("ariadne.backup.api.backup_to_stream", lambda *a, **k: called.append(1))
    monkeypatch.setattr(sys, "stdout", Stream(tty=True))
    assert serve.main(paths, env("backup")) == serve.EXIT_REFUSED
    assert called == [] and "gehört in eine Datei" in err.getvalue()


def test_backup_stream_on_stdout_messages_on_stderr(paths, io_streams, monkeypatch):
    from ariadne.backup.api import BackupError, BackupResult

    out, err, _ = io_streams()

    def fake_backup(stream, p, **kw):
        stream.write(b"age-encryption.org/v1\n...")
        return BackupResult(bytes_written=25, projects=("htb-lame",), chain_heads={"htb-lame": "ab" * 32})

    monkeypatch.setattr("ariadne.backup.api.backup_to_stream", fake_backup)
    assert serve.main(paths, env("backup")) == 0
    assert out.buffer.getvalue() == b"age-encryption.org/v1\n..." and out.getvalue() == ""
    assert "Sicherung geschrieben" in err.getvalue() and "Kettenkopf htb-lame" in err.getvalue()

    def open_project(stream, p, **kw):
        raise BackupError("project_open", "Projekt offen: zuerst ariadne lock oder ariadne stop")

    monkeypatch.setattr("ariadne.backup.api.backup_to_stream", open_project)
    assert serve.main(paths, env("backup")) == serve.EXIT_ERROR
    assert "ssh kali-sl lock" in err.getvalue()


def test_lock_and_revoke(paths, io_streams, monkeypatch):
    out, _, _ = io_streams()
    client = FakeClient(result={"closed_project": True})
    monkeypatch.setattr("ariadne.cli.common._client", lambda p, start=True: client)
    assert serve.main(paths, env("lock")) == 0
    client.result = {"revoked": 2}
    assert serve.main(paths, env("revoke")) == 0
    assert client.calls == [("lock", {}), ("ui.revoke", {})]
    assert "Gesperrt." in out.getvalue() and "Widerrufen: 2 Sitzungen." in out.getvalue()
    client.error = CtlError("unknown_op", "unbekannte Operation")
    assert serve.main(paths, env("revoke")) == 0

    def no_daemon(p, start=True):
        assert start is False  # lock und revoke starten nie einen Daemon
        raise CliError("Daemon läuft nicht")

    monkeypatch.setattr("ariadne.cli.common._client", no_daemon)
    assert serve.main(paths, env("lock")) == 0 and serve.main(paths, env("revoke")) == 0
    assert "Daemon läuft nicht, nichts entsperrt." in out.getvalue()


def test_check_prints_like_doctor(paths, io_streams, monkeypatch):
    out, _, _ = io_streams()
    monkeypatch.setattr(check, "run_checks", lambda p, **k: [check.Check(check.FAIL, "x")])
    assert serve.main(paths, env("check")) == 1
    assert out.getvalue() == "[!!] x\n"


# --------------------------------------------------------------------------- #
# code im Prozess
# --------------------------------------------------------------------------- #


def _code_setup(monkeypatch, client: FakeClient, *, ok: bool = True) -> list[int]:
    held: list[int] = []
    monkeypatch.setattr(check, "quick_ok", lambda p, system=None: ok)
    monkeypatch.setattr("ariadne.cli.common._client", lambda p, start=True: client)
    monkeypatch.setattr(serve, "HOLD", lambda ppid: held.append(ppid) or 0)
    return held


def test_t12_code_without_terminal_prints_one_line_then_holds(paths, io_streams, monkeypatch):
    out, err, _ = io_streams()
    client = FakeClient(
        result={
            "code": "A" * 22,
            "display": "A" * 22,
            "expires_in": 60,
            "port": 7330,
            "url": "http://127.0.0.1:7330/#c=" + "A" * 22,
            "via": "sshd",
        }
    )
    held = _code_setup(monkeypatch, client)
    monkeypatch.setattr(serve, "_silence_stdout", lambda: None)
    assert serve.main(paths, env("code")) == 0
    assert client.calls == [("ui.code", {"typed": False, "via": "sshd"})]
    assert out.getvalue() == "A" * 22 + "\n" and err.getvalue() == ""
    assert held == [os.getppid()]


def test_t12_code_with_terminal_is_typed(paths, io_streams, monkeypatch):
    out, _, _ = io_streams()
    monkeypatch.setattr(sys, "stdin", Stream(tty=True))
    client = FakeClient(
        result={
            "code": "ABCDEFGHJK",
            "display": "ABCDE-FGHJK",
            "expires_in": 120,
            "port": 7330,
            "url": None,
            "via": "sshd",
        }
    )
    held = _code_setup(monkeypatch, client)
    assert serve.main(paths, env("code")) == 0
    assert client.calls == [("ui.code", {"typed": True, "via": "sshd"})]
    assert "Code: ABCDE-FGHJK" in out.getvalue() and "Ctrl-C beendet den Zugang" in out.getvalue()
    assert len(held) == 1


def test_t12_code_refused_when_quick_check_fails(paths, io_streams, monkeypatch):
    _, err, _ = io_streams()
    client = FakeClient(result={"code": "x"})
    held = _code_setup(monkeypatch, client, ok=False)
    assert serve.main(paths, env("code")) == serve.EXIT_UNREADY
    assert client.calls == [] and held == []
    assert "Fernzugriff nicht sicher eingerichtet (ariadne remote check)" in err.getvalue()
    # echte Schnellprüfung ohne Einrichtung: Gründe stehen in der Meldung
    monkeypatch.undo()
    out, err2, _ = Stream(), Stream(), Stream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err2)
    monkeypatch.setattr(sys, "stdin", Stream())
    monkeypatch.setattr("ariadne.cli.common._client", lambda p, start=True: client)
    assert serve.main(paths, env("code", ARIADNE_SETUP_ROOT="/nonexistent")) == serve.EXIT_UNREADY
    assert "Hostkey-Marker fehlt" in err2.getvalue() and client.calls == []


@pytest.mark.parametrize("code", ["ui_off", "not_sshd", "unknown_op"])
def test_code_errors_from_daemon(paths, io_streams, monkeypatch, code):
    _, err, _ = io_streams()
    client = FakeClient(error=CtlError(code, "Web-Oberfläche aus: Port belegt"))
    held = _code_setup(monkeypatch, client)
    assert serve.main(paths, env("code")) == serve.EXIT_UNREADY
    assert held == [] and "Kein Code" in err.getvalue()


def test_hold_returns_on_signal_and_on_parent_change():
    old = signal.pthread_sigmask(signal.SIG_BLOCK, serve.HOLD_SIGNALS)
    try:
        os.kill(os.getpid(), signal.SIGHUP)
        t0 = time.monotonic()
        assert serve.hold(os.getppid(), interval=0.05) == 0
        assert time.monotonic() - t0 < 1
        t0 = time.monotonic()
        assert serve.hold(-1, interval=0.05) == 0  # Eltern schon «anders»
        assert time.monotonic() - t0 < 1
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


def test_parse_command_is_exact():
    assert serve.parse_command("code") == "code"
    for bad in (None, "", "code ", "Code", "code;", "check --full"):
        assert serve.parse_command(bad) is None


# --------------------------------------------------------------------------- #
# Echte Prozesse
# --------------------------------------------------------------------------- #


def _proc_env(xdg: dict[str, str], cmd: str, **extra: str) -> dict[str, str]:
    e = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C.UTF-8",
        **xdg,
        "SSH_ORIGINAL_COMMAND": cmd,
    }
    e.pop("ARIADNE_WEB", None)
    e.update(extra)
    return e


def test_t12_subprocess_rejects_and_runs_nothing(xdg, tmp_path):
    marker = tmp_path / "ausgefuehrt"
    for cmd in (f"touch {marker}", f"code; touch {marker}", "id"):
        res = subprocess.run(
            [sys.executable, "-I", "-c", SERVE],
            capture_output=True,
            text=True,
            env=_proc_env(xdg, cmd),
            timeout=60,
            check=False,
        )
        assert res.returncode == 2 and res.stdout == "" and "Abgelehnt" in res.stderr
    assert not marker.exists()


def _ready_setup(tmp_path: Path, paths, port: int) -> Path:
    """Wegwerf-Root wie nach kali-setup.sh, Schlüsselzeile im Test-Home, Web-Port in config.toml."""
    root = base_root(tmp_path / "root")
    pub = keypair(tmp_path / "mac", passphrase="Mac-Passphrase-1")
    res = run_setup(root, "--key-line", pub, "--port", str(port), "--recipient", age_recipient())
    assert res.returncode == 0, res.stderr
    install_keys(root, paths.home)
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(f"[ui]\nport = {port}\n")
    return root


async def _under_fake_sshd(
    tmp_path: Path, argv: list[str], env_: dict[str, str]
) -> asyncio.subprocess.Process:
    link = tmp_path / "sshd"
    if not link.exists():
        link.symlink_to("/bin/sh")
    return await asyncio.create_subprocess_exec(
        str(link),
        "-c",
        '"$@"; sleep 60',
        "sshd",
        *argv,
        env=env_,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )


def _children(pid: int) -> list[int]:
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as fh:
            return [int(x) for x in fh.read().split()]
    except OSError:
        return []


async def _wait_exit(pid: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/stat") as fh:
                if fh.read().rsplit(")", 1)[1].split()[0] == "Z":
                    return True
        except OSError:
            return True
        await asyncio.sleep(0.05)
    return False


@pytest.mark.web
@pytest.mark.parametrize("end", ["parent", "sighup"])
def test_t12_code_real_daemon_bound_to_sshd_and_holds(paths, operator, xdg, tmp_path, end):
    port = free_port()
    root = _ready_setup(tmp_path, paths, port)
    ext = WebExtension(paths)
    proc_env = _proc_env(xdg, "code", ARIADNE_SETUP_ROOT=str(root))

    async def scenario(d) -> None:
        assert ext.running and ext.server is not None and ext.server.port == port
        proc = await _under_fake_sshd(tmp_path, [sys.executable, "-I", "-c", SERVE], proc_env)
        try:
            assert proc.stdout is not None and proc.stderr is not None
            line = await asyncio.wait_for(proc.stdout.readline(), 20)
            code = line.decode().rstrip("\n")
            assert LONG_CODE.match(code), (line, await proc.stderr.read())
            # danach kommt nichts mehr auf stdout
            with contextlib.suppress(TimeoutError):
                extra = await asyncio.wait_for(proc.stdout.read(1), 0.5)
                assert extra == b""
            # der Code gilt nur über eine Verbindung ohne lesbaren Prozess bzw. vom sshd-Prozess
            uid = os.getuid()
            ext.gate.resolver = lambda client, server: PeerInfo(uid=uid, inode=1, pids=())
            import httpx

            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=10) as c:
                r = await c.post(
                    "/api/v1/session", json={"code": code}, headers={"Origin": f"http://127.0.0.1:{port}"}
                )
            assert r.status_code == 200, r.text
            rows = (await d.call("ui.sessions", {}))["result"]["sessions"]
            assert rows[0]["origin"] == "sshd" and rows[0]["peer_pid"] == proc.pid
            kids = _children(proc.pid)
            assert len(kids) == 1
            serve_pid = kids[0]
            await asyncio.sleep(0.3)
            assert not await _wait_exit(serve_pid, 0.2)  # hält
            if end == "parent":
                os.kill(proc.pid, signal.SIGKILL)  # die Eltern-sshd endet (Tunnel zu)
            else:
                os.kill(serve_pid, signal.SIGHUP)
            assert await _wait_exit(serve_pid, 3), "remote serve code hält nach Ende der Verbindung weiter"
            if end == "sighup":
                os.kill(proc.pid, signal.SIGKILL)
            await asyncio.sleep(2.5)
            ext.check_now()
            rows = (await d.call("ui.sessions", {}))["result"]["sessions"]
            assert rows == []  # Ende der sshd-Attrappe beendet die Sitzung (R6)
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            await proc.wait()

    run(paths, operator, scenario, extensions=[ext], ingest=False)


@pytest.mark.web
def test_t12_code_with_terminal_real_daemon(paths, operator, xdg, tmp_path):
    """``ssh -t kali-sl code``: stdin ist ein Terminal, also ein kurzer Tippcode; SIGINT beendet."""
    port = free_port()
    root = _ready_setup(tmp_path, paths, port)
    ext = WebExtension(paths)
    proc_env = _proc_env(xdg, "code", ARIADNE_SETUP_ROOT=str(root), TERM="dumb")
    link = tmp_path / "sshd"
    link.symlink_to("/bin/sh")

    async def scenario(d) -> None:
        master, slave = os.openpty()
        proc = await asyncio.create_subprocess_exec(
            str(link),
            "-c",
            '"$@"; sleep 60',
            "sshd",
            sys.executable,
            "-I",
            "-c",
            SERVE,
            env=proc_env,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
        )
        os.close(slave)
        try:
            text = ""
            deadline = time.monotonic() + 20
            while "Ctrl-C beendet den Zugang" not in text and time.monotonic() < deadline:
                ready = await asyncio.to_thread(select.select, [master], [], [], 0.5)
                if ready[0]:
                    text += os.read(master, 4096).decode("utf-8", "replace")
            m = re.search(r"Code: ([0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}) ", text)
            assert m, text
            assert "http://127.0.0.1:" in text
            serve_pid = _children(proc.pid)[0]
            os.kill(serve_pid, signal.SIGINT)  # Ctrl-C im Terminal des Macs
            assert await _wait_exit(serve_pid, 3)
            assert (await d.call("ui.status", {}))["result"]["running"]
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            await proc.wait()
            os.close(master)

    run(paths, operator, scenario, extensions=[ext], ingest=False)
