"""T13 Ende zu Ende über einen echten SSH-Tunnel (R2, R5, R6, R11, E89, E94).

Ein eigener sshd (eigener Port, eigene Konfiguration, nie der System-sshd) mit dem Drop-in aus
``kali-setup.sh`` und dem eingeschränkten Schlüssel aus ``authorized_keys``; der Client spielt
den Mac. Geprüft: Shell, ``ssh … id``, Passwort, ``-W``, ``-L`` auf andere Ports, ``-D``, ``-R``
und ``-A`` werden abgelehnt; ``ssh -n -L … kali-sl code`` holt den Code und hält den Tunnel;
Anmeldung, ``/status`` und SSE über den Tunnel; Tunnel weg, dann 401 innerhalb von 3 s;
Neuanmeldung über einen neuen Tunnel geht.

Als root im Container gibt es keinen Privilegien-Benutzer ``sshd``; dann laufen sshd, Daemon und
Ordner unter einem unprivilegierten Benutzer (``ARIADNE_TEST_SSH_USER``, sonst der erste mit UID
ab 1000 und Login-Shell) in einem eigenen Ordner unter ``/tmp`` (``tmp_path`` gehört root mit 0700).

**Abweichungen vom Drop-in** (im Test sichtbar, Vertrag 5 T13): ``Port``, ``ListenAddress``
(Loopback), ``HostKey`` und ``AuthorizedKeysFile`` im Testordner, ``PidFile``, ``AllowUsers``
(``USER@127.0.0.1`` statt Tailnet), ``StrictModes no``, ``UsePAM no``; dazu ``SetEnv`` für ein
isoliertes HOME und XDG (sonst nähme der Test echte Benutzerdateien), ``LogLevel DEBUG1`` (um die
Ablehnung von ``-A`` im Log zu sehen) und ``Subsystem sftp`` wie in Debians ``sshd_config``.
``PermitOpen``/``permitopen`` nennen den freien Web-Port statt 7330 (``kali-setup.sh --port``).
"""

from __future__ import annotations

import contextlib
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from tests.remote.helpers import KALI_SETUP, free_port

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
ARIADNE = Path(sys.executable).parent / "ariadne"
LONG_CODE = re.compile(r"\A[A-Za-z0-9_-]{22}\Z")

pytestmark = [
    pytest.mark.remote,
    pytest.mark.web,
    pytest.mark.skipif(SSHD is None or shutil.which("ssh") is None, reason="sshd oder ssh fehlt"),
    pytest.mark.skipif(not ARIADNE.is_file(), reason="Programm ariadne im venv fehlt"),
]

# Zeilen des Drop-ins, die der Test ersetzt (sichtbare Abweichungen).
REPLACED = ("AllowUsers ", "HostKey ")


def _login_shells() -> set[str]:
    try:
        return {ln.strip() for ln in Path("/etc/shells").read_text().splitlines() if ln.startswith("/")}
    except OSError:
        return set()


def _test_user() -> pwd.struct_passwd | None:
    if os.getuid() != 0:
        return pwd.getpwuid(os.getuid())
    want = os.environ.get("ARIADNE_TEST_SSH_USER")
    if want:
        try:
            return pwd.getpwnam(want)
        except KeyError:
            return None
    shells = _login_shells()
    for pw in sorted(pwd.getpwall(), key=lambda p: p.pw_uid):
        if pw.pw_uid >= 1000 and pw.pw_uid != 65534 and pw.pw_shell in shells:
            return pw
    return None


class Kali:
    """Die «Kali»: Wegwerf-Root, Home, Runtime-Ordner und sshd unter dem Testbenutzer."""

    def __init__(self, pw: pwd.struct_passwd, client_dir: Path) -> None:
        self.pw = pw
        self.base = Path(tempfile.mkdtemp(prefix="ariadne-t13-", dir="/tmp"))
        self.root = self.base / "root"
        self.home = self.root / "home" / pw.pw_name
        self.run_dir = self.base / "run"
        self.web_port = free_port()
        self.ssh_port = free_port()
        self.client_dir = client_dir
        self.sshd: subprocess.Popen[bytes] | None = None
        self.sshd_log = self.base / "sshd.log"

    @property
    def operator_dir(self) -> Path:
        return self.home / ".local" / "share" / "ariadne" / "operator"

    def as_user(self, argv: list[str]) -> list[str]:
        if os.getuid() == 0:
            return ["runuser", "-u", self.pw.pw_name, "--", *argv]
        return argv

    # ---------------------------------------------------------------- Aufbau
    def build(self, *, recipient: str | None = None, operator_dir: Path | None = None) -> None:
        (self.root / "etc" / "ssh").mkdir(parents=True)
        (self.root / "etc" / "ssh" / "sshd_config").write_text(
            "Include /etc/ssh/sshd_config.d/*.conf\nSubsystem sftp /usr/lib/openssh/sftp-server\n"
        )
        self.run_dir.mkdir(mode=0o700)
        key = self.client_dir / "mac"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "mac-kali-smartlearn", "-f", str(key)],
            check=True,
        )
        res = subprocess.run(
            [
                "sh",
                str(KALI_SETUP),
                "--weg",
                "b",
                "--user",
                self.pw.pw_name,
                "--home",
                f"/home/{self.pw.pw_name}",
                "--key",
                f"{key}.pub",
                "--ariadne",
                str(ARIADNE),
                "--port",
                str(self.web_port),
                *(["--recipient", recipient] if recipient else []),
                "--yes",
            ],
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "LC_ALL": "C.UTF-8",
                "ARIADNE_SETUP_ROOT": str(self.root),
            },
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert res.returncode == 0, res.stdout + res.stderr
        cfg = self.home / ".config" / "ariadne"
        cfg.mkdir(parents=True, exist_ok=True, mode=0o700)
        (cfg / "config.toml").write_text(f"[ui]\nport = {self.web_port}\n")
        if operator_dir is not None:  # Operator-Tresor aus der Vorlage (ohne scrypt), wie nach ariadne init
            shutil.copytree(operator_dir, self.operator_dir)
        self.write_sshd_config()
        self.write_client_config(key)
        if os.getuid() == 0:
            subprocess.run(["chown", "-R", f"{self.pw.pw_uid}:{self.pw.pw_gid}", str(self.base)], check=True)
        os.chmod(self.base, 0o700)

    def dropin_lines(self) -> list[str]:
        text = (self.root / "etc/ssh/sshd_config.d/10-ariadne.conf").read_text()
        return [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]

    def write_sshd_config(self) -> None:
        home = self.home
        env = {
            "HOME": home,
            "XDG_CONFIG_HOME": home / ".config",
            "XDG_DATA_HOME": home / ".local/share",
            "XDG_STATE_HOME": home / ".local/state",
            "XDG_CACHE_HOME": home / ".cache",
            "XDG_RUNTIME_DIR": self.run_dir,
            "ARIADNE_PROJECTS_ROOT": home / "ariadne",
            "ARIADNE_SETUP_ROOT": self.root,
        }
        deviations = [
            "# T13: Abweichungen vom Drop-in (Vertrag 5, T13)",
            f"Port {self.ssh_port}",
            "ListenAddress 127.0.0.1",
            f"HostKey {self.root}/etc/ssh/ssh_host_ed25519_key",
            f"PidFile {self.base}/sshd.pid",
            f"AuthorizedKeysFile {home}/.ssh/authorized_keys",
            f"AllowUsers {self.pw.pw_name}@127.0.0.1",
            "StrictModes no",
            "UsePAM no",
            "SetEnv " + " ".join(f"{k}={v}" for k, v in env.items()),
            "LogLevel DEBUG1",
            "# Drop-in aus kali-setup.sh, unverändert bis auf die ersetzten Zeilen",
        ]
        kept = [ln for ln in self.dropin_lines() if not ln.startswith(REPLACED)]
        main = ["# wie Debians sshd_config", "Subsystem sftp /usr/lib/openssh/sftp-server"]
        (self.base / "sshd_config").write_text("\n".join([*deviations, *kept, *main]) + "\n")

    def write_client_config(self, key: Path) -> None:
        pub = (self.root / "etc/ssh/ssh_host_ed25519_key.pub").read_text().split()
        known = self.client_dir / "known_hosts"
        known.write_text(f"kali-smartlearn {pub[0]} {pub[1]}\n")
        # wie ~/.ssh/ariadne.conf aus dem Konzept 4.2
        (self.client_dir / "ariadne.conf").write_text(f"""Host kali-sl
  HostName 127.0.0.1
  Port {self.ssh_port}
  User {self.pw.pw_name}
  IdentityFile {key}
  IdentitiesOnly yes
  HostKeyAlias kali-smartlearn
  HostKeyAlgorithms ssh-ed25519
  StrictHostKeyChecking yes
  UserKnownHostsFile {known}
  ControlMaster no
  ControlPath none
  ForwardAgent no
  ForwardX11 no
  BatchMode yes
  ServerAliveInterval 15
  ConnectTimeout 10
""")

    # ---------------------------------------------------------------- Betrieb
    def start_sshd(self) -> None:
        log = open(self.sshd_log, "ab")  # noqa: SIM115
        try:
            self.sshd = subprocess.Popen(
                self.as_user([SSHD, "-D", "-e", "-f", str(self.base / "sshd_config")]),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
            )
        finally:
            log.close()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.sshd.poll() is not None:
                raise AssertionError("sshd startet nicht: " + self.sshd_log.read_text(errors="replace"))
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", self.ssh_port), 0.2):
                return
            time.sleep(0.05)
        raise AssertionError("sshd lauscht nicht")

    def ssh(
        self, *args: str, timeout: float = 30, input_: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["ssh", "-F", str(self.client_dir / "ariadne.conf"), *args],
            capture_output=True,
            timeout=timeout,
            input=input_,
            check=False,
        )

    def popen_ssh(self, *args: str) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            ["ssh", "-F", str(self.client_dir / "ariadne.conf"), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def ctl(self, op: str) -> None:
        script = (
            "import json, socket, sys\n"
            "s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(sys.argv[1])\n"
            "s.sendall(json.dumps({'op': sys.argv[2], 'args': {}}).encode() + b'\\n'); s.recv(65536)\n"
        )
        with contextlib.suppress(Exception):
            subprocess.run(
                self.as_user(
                    [sys.executable, "-I", "-c", script, str(self.run_dir / "ariadne" / "ctl.sock"), op]
                ),
                capture_output=True,
                timeout=20,
                check=False,
            )

    def daemon_pids(self) -> list[int]:
        out = []
        needle = f"XDG_RUNTIME_DIR={self.run_dir}".encode()
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                if os.stat(f"/proc/{entry}").st_uid != self.pw.pw_uid:
                    continue
                with open(f"/proc/{entry}/environ", "rb") as fh:
                    if needle in fh.read().split(b"\0"):
                        out.append(int(entry))
            except OSError:
                continue
        return out

    def daemon_signal_mask(self) -> int | None:
        """SigBlk des Daemons (nur der Prozess ``-m ariadne.daemon``)."""
        for pid in self.daemon_pids():
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    if b"ariadne.daemon" not in fh.read():
                        continue
                with open(f"/proc/{pid}/status") as fh:
                    for line in fh:
                        if line.startswith("SigBlk:"):
                            return int(line.split()[1], 16)
            except OSError:
                continue
        return None

    def close(self) -> None:
        self.ctl("shutdown")
        if self.sshd is not None:
            with contextlib.suppress(ProcessLookupError):
                self.sshd.terminate()
            try:
                self.sshd.wait(5)
            except subprocess.TimeoutExpired:
                self.sshd.kill()
                self.sshd.wait(5)
        deadline = time.monotonic() + 5
        while self.daemon_pids() and time.monotonic() < deadline:
            time.sleep(0.1)
        for pid in self.daemon_pids():
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        shutil.rmtree(self.base, ignore_errors=True)


def _kali(tmp_path: Path, **build: object) -> Iterator[Kali]:
    pw = _test_user()
    if pw is None:
        pytest.skip("kein unprivilegierter Benutzer mit Login-Shell für sshd (ARIADNE_TEST_SSH_USER)")
    k = Kali(pw, tmp_path)
    try:
        k.build(**build)  # type: ignore[arg-type]
        k.start_sshd()
        yield k
    finally:
        k.close()


@pytest.fixture
def kali(tmp_path) -> Iterator[Kali]:
    yield from _kali(tmp_path)


@pytest.fixture
def backup_identity():
    from pyrage import x25519

    return x25519.Identity.generate()


@pytest.fixture
def kali_vault(tmp_path, operator_template, backup_identity) -> Iterator[Kali]:
    yield from _kali(
        tmp_path, recipient=str(backup_identity.to_public()), operator_dir=operator_template.directory
    )


def _read_code(proc: subprocess.Popen[bytes], seconds: float = 40) -> str:
    assert proc.stdout is not None
    box: list[bytes] = []
    t = threading.Thread(target=lambda: box.append(proc.stdout.readline()), daemon=True)  # type: ignore[union-attr]
    t.start()
    t.join(seconds)
    line = box[0] if box else b""
    return line.decode("ascii", "replace").rstrip("\n")


def _tunnel(kali: Kali, local: int) -> tuple[subprocess.Popen[bytes], str]:
    """Eine Verbindung für Code und Tunnel, wie ariadne-mac start (Vertrag 1.4 Punkt 10)."""
    for _ in range(2):  # der erste Aufruf startet den Daemon; braucht er länger, hilft ein zweiter
        proc = kali.popen_ssh(
            "-n",
            "-o",
            "ExitOnForwardFailure=yes",
            "-L",
            f"127.0.0.1:{local}:127.0.0.1:{kali.web_port}",
            "kali-sl",
            "code",
        )
        code = _read_code(proc)
        if LONG_CODE.match(code):
            return proc, code
        _stop(proc)
        assert proc.stderr is not None
        err = proc.stderr.read().decode(errors="replace")
        if "Daemon" not in err:
            raise AssertionError(
                f"kein Code: {code!r} {err} {kali.sshd_log.read_text(errors='replace')[-3000:]}"
            )
    raise AssertionError("kein Code nach zwei Versuchen")


def _stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()


def _client(kali: Kali, local: int) -> httpx.Client:
    # Der Browser auf dem Mac schickt Host 127.0.0.1:7330; hier ist der Port der des Web-Servers.
    origin = f"http://127.0.0.1:{kali.web_port}"
    return httpx.Client(
        base_url=f"http://127.0.0.1:{local}",
        timeout=10,
        headers={"Host": f"127.0.0.1:{kali.web_port}", "Origin": origin},
    )


def _login(kali: Kali, local: int, code: str) -> str:
    with _client(kali, local) as c:
        r = c.post("/api/v1/session", json={"code": code})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_t13_restricted_key_refuses_everything_but_the_tunnel(kali):
    # ssh … id, Shell, scp, sftp: remote serve lehnt ab, nichts läuft
    res = kali.ssh("kali-sl", "id")
    assert res.returncode == 2 and res.stdout == b"" and b"Abgelehnt" in res.stderr
    # Shell ohne Befehl (ohne Terminal: ein unprivilegierter sshd kann kein PTY übergeben, chown scheitert)
    res = kali.ssh("-T", "kali-sl")
    assert res.returncode == 2 and b"keine Shell" in res.stderr
    res = kali.ssh("kali-sl", "code; id")
    assert res.returncode == 2 and b"uid=" not in res.stdout
    res = kali.ssh("-s", "kali-sl", "sftp")
    assert res.returncode != 0 and b"uid=" not in res.stdout
    # Passwort: nur Schlüssel
    res = kali.ssh(
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "PreferredAuthentications=password,keyboard-interactive",
        "kali-sl",
        "check",
    )
    assert res.returncode == 255 and b"Permission denied (publickey)" in res.stderr
    # -W und -L auf einen anderen Port (sshd selbst): administratively prohibited
    res = kali.ssh("-W", f"127.0.0.1:{kali.ssh_port}", "kali-sl", timeout=20)
    assert res.returncode == 255 and b"administratively prohibited" in res.stderr
    other = free_port()
    proc = kali.popen_ssh("-N", "-L", f"127.0.0.1:{other}:127.0.0.1:{kali.ssh_port}", "kali-sl")
    try:
        _wait_port(other)
        with socket.create_connection(("127.0.0.1", other), 5) as s:
            s.settimeout(5)
            assert s.recv(64) == b""  # kein SSH-Banner: die Weiterleitung wurde verweigert
    finally:
        _stop(proc)
    # -D: SOCKS zu einem fremden Ziel wird verweigert
    socks = free_port()
    proc = kali.popen_ssh("-N", "-D", f"127.0.0.1:{socks}", "kali-sl")
    try:
        _wait_port(socks)
        assert not _socks_connect(socks, "127.0.0.1", kali.ssh_port)
    finally:
        _stop(proc)
    # -R: keine Weiterleitung von der Kali zum Mac
    res = kali.ssh(
        "-o", "ExitOnForwardFailure=yes", "-R", f"127.0.0.1:{free_port()}:127.0.0.1:22", "kali-sl", "check"
    )
    assert res.returncode == 255 and b"remote port forwarding failed" in res.stderr
    # -A: Agent-Weiterleitung abgeschaltet (Log des sshd)
    agent = subprocess.run(["ssh-agent", "-s"], capture_output=True, text=True, check=False)
    m = re.search(r"SSH_AUTH_SOCK=([^;]+);.*SSH_AGENT_PID=(\d+);", agent.stdout, re.S)
    if m:
        try:
            env = dict(os.environ, SSH_AUTH_SOCK=m.group(1))
            subprocess.run(
                ["ssh", "-F", str(kali.client_dir / "ariadne.conf"), "-A", "kali-sl", "check"],
                capture_output=True,
                env=env,
                timeout=30,
                check=False,
            )
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(m.group(2)), signal.SIGTERM)
        assert _wait(lambda: "agent forwarding disabled" in kali.sshd_log.read_text(errors="replace"), 5)


def test_t13_code_tunnel_status_sse_and_end_with_tunnel(kali):
    local = free_port()
    tunnel, code = _tunnel(kali, local)
    try:
        # remote serve code hat den Daemon gestartet: ohne geerbte Signalsperre (SIGTERM, SIGHUP wirken)
        mask = kali.daemon_signal_mask()
        assert mask is not None and not mask & ((1 << (signal.SIGTERM - 1)) | (1 << (signal.SIGHUP - 1)))
        token = _login(kali, local, code)
        auth = {"Authorization": f"Bearer {token}"}
        with _client(kali, local) as c:
            r = c.get("/api/v1/status", headers=auth)
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["api_version"] == 2
            assert body["session"]["origin"] == "sshd"  # Herkunft der Sitzung (E60, R7)
            # ohne Token und mit fremdem Host: wie ohne Tunnel
            assert c.get("/api/v1/status").status_code == 401
            assert c.get("/api/v1/status", headers={**auth, "Host": "localhost:1"}).status_code == 421
        events = _sse_presentation(kali, local, token)
        assert "event: presentation" in events and '"on":true' in events
    finally:
        _stop(tunnel)  # Tunnel weg (Mac zugeklappt, ariadne-mac stop)
    t_end = time.monotonic()
    timing: dict[str, float] = {}
    # neue Verbindung, altes Token: spätestens nach 3 s ungültig, weil der gebundene sshd-Prozess weg ist
    local2 = free_port()
    tunnel2, code2 = _tunnel(kali, local2)
    timing["tunnel2"] = time.monotonic() - t_end
    try:
        with _client(kali, local2) as c:
            status = 0
            while time.monotonic() - t_end < 6:
                status = c.get("/api/v1/status", headers={"Authorization": f"Bearer {token}"}).status_code
                if status == 401:
                    timing["401"] = time.monotonic() - t_end
                    break
                time.sleep(0.2)
            assert status == 401
            # 3 s für das Ende der Sitzung (Prüfung alle 2 s), dazu der Aufbau der zweiten Verbindung
            assert timing["401"] < 3.0 + timing["tunnel2"], timing
            token2 = _login(kali, local2, code2)
            assert c.get("/api/v1/status", headers={"Authorization": f"Bearer {token2}"}).status_code == 200
            # derselbe Code gilt nur einmal
            assert c.post("/api/v1/session", json={"code": code2}).status_code == 401
            # ssh kali-sl revoke beendet alle Sitzungen (R7), lock und check gehen über denselben Schlüssel
            res = kali.ssh("kali-sl", "revoke")
            assert res.returncode == 0 and re.match(rb"Widerrufen: [1-9][0-9]* Sitzungen\.", res.stdout), res
            assert c.get("/api/v1/status", headers={"Authorization": f"Bearer {token2}"}).status_code == 401
            res = kali.ssh("kali-sl", "lock")
            assert res.returncode == 0 and b"Gesperrt." in res.stdout, res.stderr
            res = kali.ssh("kali-sl", "check")
            assert res.returncode in (0, 1) and b"[ok] Hostkeys selbst erzeugt" in res.stdout
            assert b"[ok] authorized_keys: ein eingeschr" in res.stdout
    finally:
        _stop(tunnel2)


def _sse_presentation(kali: Kali, local: int, token: str) -> str:
    """Öffnet den Ereignisstrom über den Tunnel, schaltet den Präsentationsmodus und liest mit."""
    chunks: list[str] = []
    opened = threading.Event()
    stop = threading.Event()

    def reader() -> None:
        with contextlib.suppress(httpx.HTTPError), _client(kali, local) as c:
            with c.stream(
                "GET",
                "/api/v1/events",
                headers={"Authorization": f"Bearer {token}", "Accept": "text/event-stream"},
                timeout=httpx.Timeout(10, read=8),
            ) as r:
                assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
                opened.set()
                for text in r.iter_text():
                    chunks.append(text)
                    if stop.is_set() or "event: presentation" in "".join(chunks):
                        return

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    assert opened.wait(10)
    time.sleep(0.3)
    with _client(kali, local) as c:
        r = c.put("/api/v1/presentation", json={"on": True}, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 202, r.text
    t.join(8)
    stop.set()
    with _client(kali, local) as c:
        c.put("/api/v1/presentation", json={"on": False}, headers={"Authorization": f"Bearer {token}"})
    return "".join(chunks)


def _wait(cond, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.1)
    return cond()


def _wait_port(port: int, seconds: float = 15) -> None:
    def up() -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return True
        except OSError:
            return False

    assert _wait(up, seconds), f"Port {port} nicht offen"


def _socks_connect(port: int, host: str, dport: int) -> bool:
    """SOCKS5-CONNECT über ssh -D; wahr nur, wenn ssh die Verbindung aufbaut."""
    with socket.create_connection(("127.0.0.1", port), 5) as s:
        s.settimeout(10)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return False
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + dport.to_bytes(2, "big"))
        try:
            reply = s.recv(10)
        except OSError:
            return False
        return len(reply) >= 2 and reply[1] == 0


def test_t13_backup_and_restore_over_ssh(kali_vault, backup_identity):
    """``ssh kali-sl backup > datei.age`` und ``age -d … | ssh kali-sl restore`` (Konzept 6.4, 6.5)."""
    import io
    import tarfile

    import pyrage

    from ariadne.backup import api as backup_api

    if backup_api.STUB:
        pytest.skip("Teil «backup» noch nicht gebaut")
    kali = kali_vault
    res = kali.ssh("kali-sl", "backup", timeout=120)
    assert res.returncode == 0, res.stderr
    assert res.stdout.startswith(b"age-encryption.org/v1")  # nur der Strom auf stdout
    assert b"Sicherung geschrieben" in res.stderr
    inner = pyrage.decrypt(res.stdout, [backup_identity])
    with tarfile.open(fileobj=io.BytesIO(inner), mode="r|") as tar:
        names = [m.name for m in tar]
    assert names[0] == "ariadne-backup.json" and any(n.startswith("operator/") for n in names)
    before = {
        p.relative_to(kali.operator_dir): p.read_bytes() for p in kali.operator_dir.rglob("*") if p.is_file()
    }
    # Tresor vorhanden: abgelehnt, bevor stdin gelesen wird
    res = kali.ssh("kali-sl", "restore", input_=inner, timeout=120)
    assert res.returncode == 2 and b"Operator-Tresor" in res.stderr
    # frische Installation (Tresor weg): zurückspielen, Inhalt gleich
    shutil.rmtree(kali.operator_dir)
    res = kali.ssh("kali-sl", "restore", input_=inner, timeout=120)
    assert res.returncode == 0, res.stderr
    assert "Zurückgespielt".encode() in res.stdout and b"ssh -t kali-sl unlock" in res.stdout
    after = {
        p.relative_to(kali.operator_dir): p.read_bytes() for p in kali.operator_dir.rglob("*") if p.is_file()
    }
    assert after == before
    assert kali.operator_dir.stat().st_mode & 0o777 == 0o700
    # verschlüsselte Sicherung ohne Entschlüsseln: kein gültiger Klartext-Strom, nichts geschrieben
    shutil.rmtree(kali.operator_dir)
    res = kali.ssh("kali-sl", "restore", input_=b"age-encryption.org/v1\nkaputt", timeout=120)
    assert res.returncode == 1 and not kali.operator_dir.exists()
