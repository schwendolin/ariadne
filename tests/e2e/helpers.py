"""Gemeinsame Hilfen der E2E-Tests: isoliertes Lab mit Daemon-Prozess, CLI per Subprozess,
nachgestellte Tools (``nmap``, ``nc``, ``ip``) und zsh-Terminals per pexpect.

Kein Netz, keine echten Benutzerdateien: HOME, alle ``XDG_*`` und der Projektordner
liegen unter ``tmp_path``. Die Tools geben nur Fixture-Daten aus.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pexpect
import pytest

from ariadne.daemon.client import CtlClient
from ariadne.paths import default_paths
from ariadne.sources.localaddr import read_local_addrs

PROMPT = "PRMT> "
PASSPHRASE = "e2e-Passphrase-lang-genug"
SECRET = "Kanarien-Geheimnis-8472"
F12 = b"\x1b[24~"

FAKE_NMAP = """#!{python} -I
import sys
args = sys.argv[1:]
data = {data!r}
if "-oA" in args:
    base = args[args.index("-oA") + 1]
    for ext, src in ((".xml", "scan.xml"), (".nmap", "scan.txt"), (".gnmap", None)):
        with open(base + ext, "wb") as fh:
            fh.write(open(data + "/" + src, "rb").read() if src else b"# Nmap done\\n")
sys.stdout.buffer.write(open(data + "/scan.txt", "rb").read())
"""

FAKE_NC = """#!{python} -I
import sys
print("listening on [any] 4444 ...", flush=True)
print("connect to [{lhost}] from (UNKNOWN) [{target}] 49152", flush=True)
answers = {{"id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)", "hostname": "lame"}}
while True:
    sys.stdout.write("$ ")
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line or line.strip() == "exit":
        break
    print(answers.get(line.strip(), "sh: 1: not found"), flush=True)
"""

FAKE_IP = """#!/bin/sh
echo "$3 via 10.0.2.2 dev tun0 src {lhost} uid 1000"
echo "    cache"
"""

TITLE = re.compile(rb"\x1b\]2;([^\x07]*)\x07")


class Lab:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.home = base / "h"
        self.run = base / "r"
        self.bin = base / "bin"
        self.data = base / "data"
        for d in (self.home, self.bin, self.data):
            d.mkdir()
        self.run.mkdir(mode=0o700)
        self.env = {
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_DATA_HOME": str(self.home / ".local" / "share"),
            "XDG_STATE_HOME": str(self.home / ".local" / "state"),
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_RUNTIME_DIR": str(self.run),
            "ARIADNE_PROJECTS_ROOT": str(self.home / "ariadne"),
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "LANG": "C.UTF-8",
            "TERM": "xterm-256color",
            "SHELL": shutil.which("zsh") or "/bin/zsh",
        }
        self.paths = default_paths(self.env)
        self.daemon: subprocess.Popen[bytes] | None = None
        self.terms: list[pexpect.spawn] = []

    def tools(self, xml: bytes, text: bytes, *, target: str, lhost: str) -> None:
        """Fake-Tools: ``nmap`` gibt ``text`` aus und schreibt bei ``-oA`` ``xml``; ``nc -lvnp``
        meldet einen Callback von ``target``; ``ip route get`` nennt ``lhost`` als Quelle."""
        skip_if_own_address(target)
        (self.data / "scan.xml").write_bytes(xml)
        (self.data / "scan.txt").write_bytes(text)
        for name, body in (("nmap", FAKE_NMAP.format(python=sys.executable, data=str(self.data))),
                           ("nc", FAKE_NC.format(python=sys.executable, lhost=lhost, target=target)),
                           ("ip", FAKE_IP.format(lhost=lhost))):
            f = self.bin / name
            f.write_text(body)
            f.chmod(0o755)

    def cli(self, *args: str, secret: str | None = None, fd_flag: str = "--passphrase-fd",
            check: bool = True) -> str:
        argv = [sys.executable, "-m", "ariadne.cli.main", *args]
        pass_fds: tuple[int, ...] = ()
        r = None
        if secret is not None:
            r, w = os.pipe()
            os.write(w, secret.encode() + b"\n")
            os.close(w)
            argv += [fd_flag, str(r)]
            pass_fds = (r,)
        try:
            res = subprocess.run(argv, env=self.env, capture_output=True, text=True, timeout=120,
                                 pass_fds=pass_fds, stdin=subprocess.DEVNULL, check=False)
        finally:
            if r is not None:
                os.close(r)
        if check:
            assert res.returncode == 0, f"ariadne {' '.join(args)}: {res.stdout}{res.stderr}"
        return res.stdout + res.stderr

    def setup(self) -> None:
        """``ariadne setup`` mit eigener ``.zshrc``, Daemon starten, Tresor anlegen (Passphrase per fd)."""
        (self.home / ".zshrc").write_text(f"PS1='{PROMPT}'\nunset HISTFILE\n")
        assert "Setup abgeschlossen" in self.cli("setup", "--no-systemd")
        self.start_daemon()
        out = self.cli("init", "--handle", "e2e", secret=PASSPHRASE)
        assert "Recovery-Code" in out and PASSPHRASE not in out

    def start_daemon(self) -> None:
        self.paths.state_dir.mkdir(parents=True, exist_ok=True)
        log = open(self.paths.state_dir / "e2e-daemon.log", "ab")  # noqa: SIM115
        self.daemon = subprocess.Popen([sys.executable, "-m", "ariadne.daemon"], env=self.env,
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd="/",
                                       start_new_session=True)
        log.close()
        client = CtlClient(self.paths.ctl_sock, timeout=5)
        deadline = time.monotonic() + 10
        while not client.ping():
            assert self.daemon.poll() is None, "Daemon beendet sich sofort"
            assert time.monotonic() < deadline, "Daemon antwortet nicht"
            time.sleep(0.05)

    def stop_daemon(self) -> int | None:
        """``ariadne daemon stop``, notfalls SIGTERM. Gibt den Exit-Code zurück."""
        if self.daemon is None:
            return None
        with contextlib.suppress(Exception):
            self.cli("daemon", "stop", check=False)
        try:
            rc = self.daemon.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.daemon.send_signal(signal.SIGTERM)
            rc = self.daemon.wait(timeout=10)
        self.daemon = None
        return rc

    def wait_status(self, needle: str, timeout: float = 10.0) -> str:
        deadline = time.monotonic() + timeout
        while True:
            out = self.cli("status")
            if needle in out:
                return out
            assert time.monotonic() < deadline, out
            time.sleep(0.1)

    def terminal(self) -> pexpect.spawn:
        """Neues zsh-Terminal mit den echten RC-Zeilen (Launcher, Shim, Marker-Hooks)."""
        c = pexpect.spawn(self.env["SHELL"], ["-i"], env=self.env, cwd=str(self.home), timeout=20,
                          dimensions=(40, 160))
        c.logfile_read = io.BytesIO()  # alles Gelesene, für den aktuellen Titel
        self.terms.append(c)
        c.expect_exact(PROMPT)
        return c

    def close_terminals(self) -> None:
        for c in self.terms:
            c.close(force=True)
        self.terms = []


def skip_if_own_address(*ips: str) -> None:
    """Der E2E-Daemon liest die eigenen Adressen dieses Rechners aus /proc (A5). Hat der
    Testrechner selbst eine Ziel-Adresse des Fixture-Netzes (VirtualBox vergibt im
    Host-only-Netz oft .101 zuerst), wäre das Ziel «eigene Adresse»: dann überspringen."""
    own = set(read_local_addrs() or ())
    hit = sorted(own & set(ips))
    if hit:
        pytest.skip(f"Testrechner hat die Fixture-Adresse {hit[0]} selbst (eigene Adresse, A5)")


def run_cmd(c: pexpect.spawn, cmd: str, timeout: float = 30) -> str:
    c.sendline(cmd)
    c.expect_exact(PROMPT, timeout=timeout)
    return c.before.decode("utf-8", "replace")


def hotkey(c: pexpect.spawn, key: bytes) -> None:
    """``F12`` und eine Taste, mit Pause dazwischen wie beim Tippen."""
    c.send(F12)
    time.sleep(0.3)
    c.send(key)


def current_title(c: pexpect.spawn) -> bytes | None:
    """Zuletzt gesetzter Fenstertitel (OSC 2) eines Terminals aus :meth:`Lab.terminal`."""
    titles = TITLE.findall(c.logfile_read.getvalue())
    return titles[-1] if titles else None


def expect_title(c: pexpect.spawn, pattern: bytes, timeout: float = 20) -> None:
    """Wartet, bis der aktuelle Fenstertitel ``pattern`` (Regex) enthält.

    Liest dabei nur in den Puffer von pexpect (``expect`` mit TIMEOUT), damit spätere
    ``expect`` nichts verpassen; Titel und Prompt dürfen in beliebiger Reihenfolge kommen.
    """
    rx = re.compile(pattern)
    deadline = time.monotonic() + timeout
    while True:
        title = current_title(c)
        if title is not None and rx.search(title):
            return
        assert time.monotonic() < deadline, f"Titel {title!r} passt nicht zu {pattern!r}"
        c.expect([pexpect.TIMEOUT, pexpect.EOF], timeout=0.2)


def scan(root: Path, needles: list[bytes]) -> list[str]:
    hits = []
    for f in root.rglob("*"):
        if f.is_file() and not f.is_symlink():
            data = f.read_bytes()
            hits += [f"{f}: {n[:8]!r}" for n in needles if n in data]
    return hits
