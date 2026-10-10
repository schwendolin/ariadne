"""End-to-End: Flugschreiber mit echter Shell, echtem Shim, echtem Daemon und Auswertung.

Ablauf wie in der Vision (Abschnitt «Zielbild»), mit nachgestellten Tools:

1. Isoliertes HOME/XDG, ``ariadne setup --no-systemd``, ``ariadne init`` und
   ``ariadne secrets add`` nur über Dateideskriptoren, Projekt ``lame``.
2. Daemon als eigener Prozess, zsh per pexpect mit den echten RC-Zeilen
   (Launcher, Shim, Marker-Hooks), REC per CLI.
3. Ein Fake-``nmap`` schreibt bei ``-oA`` die Golden-XML des Metasploitable2-Falls
   und gibt die Normalausgabe aus; ein eigenes Secret wird per ``echo`` ausgegeben.
4. Ein Fake-``nc -lvnp`` meldet einen Callback und ahmt eine Remote-Shell nach;
   mit ``F12 h`` wird der Host gesetzt, danach gehören Ausgaben zu diesem Host.
5. Prüfung über die CLI (``show``, ``search``, ``confirm``, ``mark``, ``verify``,
   ``reparse``), danach über das Journal selbst und ein Canary-Scan unter HOME.

Ein Fake-``ip`` liefert die Quell-IP für ``ip route get`` (es wird nichts gesendet).
"""

from __future__ import annotations

import contextlib
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

from ariadne.crypto.vault import OperatorVault
from ariadne.daemon.client import CtlClient
from ariadne.paths import default_paths
from ariadne.project.service import ProjectService
from tests.integration.helpers import LHOST, TARGET, ms2

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.pty,
    pytest.mark.skipif(shutil.which("zsh") is None, reason="zsh fehlt"),
]

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
    for ext, src in ((".xml", "lame.xml"), (".nmap", "lame.txt"), (".gnmap", None)):
        with open(base + ext, "wb") as fh:
            fh.write(open(data + "/" + src, "rb").read() if src else b"# Nmap done\\n")
sys.stdout.buffer.write(open(data + "/lame.txt", "rb").read())
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

    def tools(self) -> None:
        (self.data / "lame.xml").write_bytes(ms2("xml"))
        (self.data / "lame.txt").write_bytes(ms2("text"))
        for name, text in (("nmap", FAKE_NMAP.format(python=sys.executable, data=str(self.data))),
                           ("nc", FAKE_NC.format(python=sys.executable, lhost=LHOST, target=TARGET)),
                           ("ip", FAKE_IP.format(lhost=LHOST))):
            f = self.bin / name
            f.write_text(text)
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

    def stop_daemon(self) -> None:
        if self.daemon is None:
            return
        with contextlib.suppress(Exception):
            self.cli("daemon", "stop", check=False)
        try:
            self.daemon.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.daemon.send_signal(signal.SIGTERM)
            self.daemon.wait(timeout=10)
        self.daemon = None

    def wait_status(self, needle: str, timeout: float = 10.0) -> str:
        deadline = time.monotonic() + timeout
        while True:
            out = self.cli("status")
            if needle in out:
                return out
            assert time.monotonic() < deadline, out
            time.sleep(0.1)


def run_cmd(c: pexpect.spawn, cmd: str, timeout: float = 30) -> str:
    c.sendline(cmd)
    c.expect_exact(PROMPT, timeout=timeout)
    return c.before.decode("utf-8", "replace")


def scan(root: Path, needles: list[bytes]) -> list[str]:
    hits = []
    for f in root.rglob("*"):
        if f.is_file() and not f.is_symlink():
            data = f.read_bytes()
            hits += [f"{f}: {n[:8]!r}" for n in needles if n in data]
    return hits


@pytest.fixture
def lab(tmp_path_factory: pytest.TempPathFactory):
    lab = Lab(tmp_path_factory.mktemp("e2e"))  # kurzer Pfad: AF_UNIX-Grenze
    lab.tools()
    try:
        yield lab
    finally:
        lab.stop_daemon()


def test_flight_recorder(lab: Lab) -> None:
    # ---- Einrichten ------------------------------------------------------------
    (lab.home / ".zshrc").write_text(f"PS1='{PROMPT}'\nunset HISTFILE\n")
    out = lab.cli("setup", "--no-systemd")
    assert "Setup abgeschlossen" in out
    assert (lab.home / ".zshrc").read_text().startswith("# >>> ariadne >>>")
    lab.start_daemon()
    out = lab.cli("init", "--handle", "e2e", secret=PASSPHRASE)
    assert "Recovery-Code" in out and PASSPHRASE not in out
    out = lab.cli("secrets", "add", "canary", secret=SECRET, fd_flag="--value-fd")
    assert "canary" in out and SECRET not in out
    out = lab.cli("project", "new", "lame", "--target", TARGET)
    assert "Projekt lame angelegt" in out
    workspace = lab.home / "ariadne" / "lame"

    # ---- Terminal mit Shim ---------------------------------------------------------
    c = pexpect.spawn(lab.env["SHELL"], ["-i"], env=lab.env, cwd=str(lab.home), timeout=20,
                      dimensions=(40, 160))
    try:
        c.expect_exact(PROMPT)
        lab.wait_status("Terminals: 1 verbunden")
        assert "REC: an [lame]" in lab.cli("rec", "on")
        lab.wait_status("1 nehmen auf")
        c.expect(re.compile(rb"\x1b\]2;\[REC lame\]"))

        run_cmd(c, "cd ~/ariadne/lame")
        out = run_cmd(c, f"nmap -sV -oA scans/lame {TARGET}")
        assert "vsftpd 2.3.4" in out
        assert (workspace / "scans" / "lame.xml").exists()
        out = run_cmd(c, f"echo {SECRET}")
        assert SECRET in out  # der Bildschirm zeigt es, gespeichert wird es geschwärzt

        # Listener mit Callback, Remote-Shell nachgeahmt, Host per F12 h
        c.sendline("nc -lvnp 4444")
        c.expect_exact(f"from (UNKNOWN) [{TARGET}] 49152")
        c.expect_exact("$ ")
        time.sleep(0.3)
        c.send(F12)
        time.sleep(0.3)
        c.send(b"h")
        c.expect_exact(b"\x1b[6n")
        c.send(b"\x1b[5;10R")  # Antwort des Terminals auf die Cursor-Abfrage
        c.expect_exact(b"[ariadne] Host")
        for ch in TARGET.encode():
            c.send(bytes([ch]))
            time.sleep(0.02)
        c.send(b"\r")
        c.expect(re.compile(rb"\x1b\]2;\[REC lame\][^\x07]*" + re.escape(TARGET.encode())))
        c.sendline("id")
        c.expect_exact("uid=33(www-data)")
        c.expect_exact("$ ")
        c.sendline("hostname")
        c.expect_exact("lame")
        c.expect_exact("$ ")
        c.sendline("exit")
        c.expect_exact(PROMPT)

        out = lab.cli("mark", "foothold", "--host", TARGET, "--note", "Callback über nc")
        assert f"Schlüsselschritt foothold gespeichert für {TARGET}." in out

        # ---- Auswertung über die CLI -------------------------------------------------
        hosts = lab.cli("show", "hosts")
        assert re.search(rf"^{re.escape(TARGET)}  \[Kandidat, in Scope\]", hosts, re.M), hosts
        assert re.search(r"^  21/tcp\s+open\s+ftp\s+vsftpd 2\.3\.4", hosts, re.M), hosts
        assert re.search(r"^  22/tcp\s+open\s+ssh\s+OpenSSH 4\.7p1", hosts, re.M), hosts
        assert "Zugriff: user" in hosts

        inbox = lab.cli("show", "inbox")
        group = rf"^\[(g[0-9a-f]{{8}})\] [^\n]*nmap -sV -oA scans/lame {re.escape(TARGET)}"
        m = re.search(group, inbox, re.M)
        assert m, inbox
        assert "Callback" in inbox or "access.callback" in inbox

        timeline = lab.cli("show", "timeline")
        assert re.search(rf"Befehl\s+Kali\s+nmap -sV -oA scans/lame {re.escape(TARGET)}\s+\[exit 0; Quelle "
                         rf"{re.escape(LHOST)}\]", timeline), timeline
        assert re.search(rf"Segment\s+{re.escape(TARGET)} \[revshell\]", timeline), timeline
        assert "Datei" in timeline and "scans/lame.xml" in timeline

        # Ausgaben nach F12 h gehören zum Host
        hits = lab.cli("search", "uid=33")
        assert re.search(rf"{re.escape(TARGET)} \[revshell\]\s+uid=33\(www-data\)", hits), hits
        hits = lab.cli("search", "lame")
        assert re.search(rf"{re.escape(TARGET)} \[revshell\]\s+lame\s*$", hits, re.M), hits

        out = lab.cli("confirm", m.group(1))
        assert re.search(r"^\d+ Claim\(s\) bestätigt", out, re.M), out
        assert re.search(rf"^{re.escape(TARGET)}  \[bestätigt, in Scope\]", lab.cli("show", "hosts"), re.M)
        ks = lab.cli("show", "keysteps")
        assert re.search(rf"foothold\s+{re.escape(TARGET)}\s+Callback über nc", ks), ks

        assert "in Ordnung" in lab.cli("verify")
        rep = lab.cli("reparse")
        assert "Neu: 0, entfallen: 0, geändert: 0" in rep and "Verwaiste Entscheide: keine" in rep, rep
        for view in ("hosts", "services", "inbox", "timeline", "keysteps", "pending"):
            assert SECRET not in lab.cli("show", view)
        assert "Keine Treffer" in lab.cli("search", SECRET)

        c.sendline("exit")
        c.expect(pexpect.EOF)
    finally:
        c.close(force=True)

    assert "Projekt geschlossen" in lab.cli("project", "close")
    lab.stop_daemon()

    # ---- Journal direkt prüfen (eigene Entsperrung, Daemon ist aus) ---------------
    op = OperatorVault(lab.paths.operator_dir).unlock(PASSPHRASE)
    try:
        project = ProjectService(lab.paths, op).open("lame")
        try:
            j = project.journal
            assert j.verify().ok
            outs = list(j.iter_events(kinds=["term.out"]))
            stream = b"".join(r.body or b"" for r in sorted(outs, key=lambda r: r.stream_off))
            assert SECRET.encode() not in stream
            assert b"*" * len(SECRET) in stream
            reds = [x for r in outs for x in r.header.get("redactions", [])]
            assert {x["label"] for x in reds} >= {"canary"}
            files = {r.header["path"]: r.header for r in j.iter_events(kinds=["file.observed"])}
            assert files["scans/lame.xml"]["origin"] == "companion"
            assert files["scans/lame.xml"]["produced_by_cmd"]
            ctx = [r.header for r in j.iter_events(kinds=["d.ctx.set"])]
            assert ctx and ctx[0]["host"] == f"ip:default/{TARGET}"
            routes = [r.header for r in j.iter_events(kinds=["net.route"])]
            assert routes and routes[0]["src_ip"] == LHOST
            marks = [r.header for r in j.iter_events(kinds=["term.mark"]) if r.header["mark"] == "C"]
            assert not any(SECRET in (h.get("cmd_typed") or "") for h in marks)
            kinds = {r.kind for r in j.iter_events()}
            assert {"term.open", "term.bind", "term.close", "d.claim.confirm", "d.keystep.mark"} <= kinds
        finally:
            project.close()
    finally:
        op.wipe()

    # ---- Canary: kein Klartext unter HOME und im Runtime-Ordner -------------------
    hits = scan(lab.home, [SECRET.encode(), PASSPHRASE.encode()]) + scan(lab.run, [SECRET.encode()])
    assert hits == []
