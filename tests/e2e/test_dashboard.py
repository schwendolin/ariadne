"""End-to-End: das Dashboard als Nutzer, in der Kali (Weg E) und vom «Mac» über den Tunnel (Weg B).

Integration des Baus v0.1-Server (K1 bis K5). Alles mit echten Prozessen: CLI per Subprozess,
Daemon mit Web-Server auf einem freien Loopback-Port, zsh mit Shim im PTY, Auswertung mit
Parsern im Worker. Der «Browser» ist ``httpx``; er schickt die Fetch-Metadaten, die ein Browser
schicken würde (Navigation von der Startdatei: ``cross-site``, danach ``same-origin``).

* :func:`test_dashboard_local_from_start_file_to_unlock` (Weg E): ``setup``, ``init``, ``start``
  mit dem Fixture-Netz Metasploitable2, nmap im aufgezeichneten Terminal, Passwortabfragen mit
  ``read -s`` (zsh) und ``getpass`` (Python), ``ariadne ui --no-open`` (Startdatei mit Code im
  Fragment), Anmeldung, ``/status``, Karte, Zeitachse mit verdeckten Eingaben (E104), SSE nach
  einem Entscheid, ``lock`` beendet Sitzung und Strom, ``unlock`` öffnet das Projekt wieder
  (E101), neue Anmeldung, ``stop`` mit Sicherungshinweis, ``backup --to-file`` (E91).
* :func:`test_dashboard_over_tunnel_with_mac_helper` (Weg B, Marker ``remote``): sshd im
  Testordner mit dem Drop-in aus ``kali-setup.sh`` und dem eingeschränkten Schlüssel (wie T13),
  Daemon und Projekt unter dem Kali-Benutzer, ``packaging/mac/ariadne-mac start`` unter zsh
  (echtes ``ssh``, ``ssh-agent`` mit Schlüssel mit Passphrase, echtes ``lsof``; Attrappen nur für
  ``open``, ``fdesetup`` und ``sleep``), Anmeldung über den Tunnel mit Herkunft «über sshd», Karte
  und SSE, ``ariadne-mac stop`` (widerrufen, sperren, Sicherung auf den «Mac», Tunnel zu), altes
  Token 401, ``remote serve unlock`` mit Terminal öffnet das Projekt wieder (E101), ohne Terminal
  abgelehnt.

Abweichungen vom echten Betrieb (sichtbar): Mac und Kali sind derselbe Rechner, darum nimmt der
Tunnel lokal einen anderen Port (``ARIADNE_MAC_LOCAL_PORT``) und der «Browser» schickt den Host
der Kali; sshd läuft wie in T13 unter einem unprivilegierten Benutzer, darum kein ``ssh -t``
(das PTY für ``unlock`` kommt direkt aus pexpect).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pexpect
import pytest

from tests.e2e.helpers import PASSPHRASE, PROMPT, Lab, expect_title, run_cmd
from tests.integration.helpers import GOLDEN
from tests.remote.helpers import MAC_HELPER, free_port

NET = "192.168.56.0/24"
TARGET = "192.168.56.101"
KALI_IP = "192.168.56.102"
PW_READ = "Ziel-Passwort-read-s-731"
PW_GETPASS = "Ziel-Passwort-getpass-942"
MASK = "••••••••"
NAV = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
SAME = {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}
START_URL = re.compile(r'url=(http://127\.0\.0\.1:(\d+)/#c=([A-Za-z0-9_-]{16,64}))"')

GETPASS_SCRIPT = """#!{python} -I
import getpass
pw = getpass.getpass("Passwort: ")
print("angenommen", len(pw))
"""


# --------------------------------------------------------------------------- #
# Browser-Attrappe
# --------------------------------------------------------------------------- #


class Browser:
    """Ein Tab: Startdatei öffnen (Navigation), Code tauschen, Token nur im Speicher."""

    def __init__(self, base: str, host_port: int) -> None:
        self.base = base
        self.host = f"127.0.0.1:{host_port}"
        self.origin = f"http://{self.host}"
        self.token: str | None = None

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base, timeout=20, headers={"Host": self.host})

    def open_start_file(self, html: str) -> str:
        """Folgt der Weiterleitung der Startdatei: lädt die Shell als fremde Navigation (E115)
        und gibt den Code aus dem Fragment zurück (das Fragment geht nie an den Server)."""
        m = START_URL.search(html)
        assert m, html
        with self.client() as c:
            r = c.get("/", headers=NAV)
        assert r.status_code == 200, r.text
        assert r.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in r.headers[
            "content-security-policy"]
        return m.group(3)

    def login(self, code: str) -> dict[str, Any]:
        with self.client() as c:
            r = c.post("/api/v1/session", json={"code": code}, headers={**SAME, "Origin": self.origin})
        assert r.status_code == 200, r.text
        body = r.json()
        self.token = body["token"]
        return body

    def get(self, path: str, *, token: str | None = None, **params: Any) -> httpx.Response:
        with self.client() as c:
            return c.get(path, params=params or None,
                         headers={**SAME, "Authorization": f"Bearer {token or self.token}"})

    def post(self, path: str, body: Any) -> httpx.Response:
        with self.client() as c:
            return c.post(path, json=body, headers={**SAME, "Origin": self.origin,
                                                    "Authorization": f"Bearer {self.token}"})

    def ok(self, path: str, **params: Any) -> Any:
        r = self.get(path, **params)
        assert r.status_code == 200, (path, r.status_code, r.text)
        return r.json()


class Stream:
    """SSE-Strom in einem Thread (wie der ``fetch``-Leser der UI)."""

    def __init__(self, browser: Browser) -> None:
        self.browser = browser
        self.text = ""
        self.opened = threading.Event()
        self.ended = threading.Event()
        self._lock = threading.Lock()
        self.status = 0
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        assert self.opened.wait(15) and self.status == 200, "Ereignisstrom öffnet nicht"

    def _run(self) -> None:
        try:
            with self.browser.client() as c, c.stream(
                    "GET", "/api/v1/events", timeout=httpx.Timeout(20, read=60),
                    headers={**SAME, "Accept": "text/event-stream",
                             "Authorization": f"Bearer {self.browser.token}"}) as r:
                self.status = r.status_code
                self._resp = r
                self.opened.set()
                for chunk in r.iter_text():
                    with self._lock:
                        self.text += chunk
        except Exception:  # noqa: BLE001 - Strom zu (Server oder close() von aussen)
            pass
        finally:
            self.opened.set()
            self.ended.set()

    def close(self) -> None:
        """Den Tab schliessen: Verbindung zu, Thread beendet."""
        resp = getattr(self, "_resp", None)
        if resp is not None and not self.ended.is_set():
            with contextlib.suppress(Exception):
                resp.close()
        self._t.join(10)

    def events(self) -> list[tuple[str, dict[str, Any]]]:
        with self._lock:
            text = self.text
        out = []
        for block in text.split("\n\n"):
            name = data = None
            for line in block.splitlines():
                if line.startswith("event: "):
                    name = line[7:]
                elif line.startswith("data: "):
                    data = line[6:]
            if name:
                out.append((name, json.loads(data) if data else {}))
        return out

    def wait_for(self, name: str, seconds: float = 20) -> dict[str, Any]:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            for ev, data in self.events():
                if ev == name:
                    return data
            time.sleep(0.1)
        raise AssertionError(f"kein Ereignis {name}: {self.events()}")


def _wait(cond: Callable[[], Any], seconds: float, what: str) -> Any:
    deadline = time.monotonic() + seconds
    while True:
        val = cond()
        if val:
            return val
        assert time.monotonic() < deadline, what
        time.sleep(0.2)


def _host(graph: dict[str, Any], ip: str) -> dict[str, Any] | None:
    for n in graph.get("nodes") or []:
        if n.get("kind") == "host" and ip in (n.get("addresses") or []):
            return n
    return None


def _check_dashboard(b: Browser, *, origin: str, slug: str) -> tuple[dict[str, Any], str]:
    """Status, Karte und Zeitachse wie die UI nach der Anmeldung; gibt (Status, host_id)."""
    st = b.ok("/api/v1/status")
    assert st["api_version"] == 2 and st["session"]["origin"] == origin
    assert st["project"]["slug"] == slug and st["locked"] is False and st["operator"]["unlocked"]
    pid = st["project"]["id"]
    graph = _wait(lambda: (g := b.ok(f"/api/v1/p/{pid}/graph")) and _host(g, TARGET) and g, 60,
                  "Host aus nmap fehlt auf der Karte")
    host = _host(graph, TARGET)
    assert host is not None
    detail = b.ok(f"/api/v1/p/{pid}/hosts/{host['id']}")
    ports = json.dumps(detail.get("services"), ensure_ascii=False)
    assert '"port": 21' in ports or '"port":21' in ports, detail
    return st, host["id"]


def _decision_changes(b: Browser, pid: str, host_id: str) -> None:
    """Ein Entscheid über den einzigen Schreibweg, danach kommt ``changes`` im Strom."""
    stream = Stream(b)
    try:
        time.sleep(0.3)
        r = b.post(f"/api/v1/p/{pid}/decisions",
                   {"decisions": [{"kind": "d.note.set",
                                   "payload": {"subject": host_id, "text": "FTP zuerst prüfen"}}]})
        assert r.status_code == 201, r.text
        assert r.json()["results"][0]["decision_id"]
        data = stream.wait_for("changes")
        assert data.get("project_id") == pid
    finally:
        stream.close()


# --------------------------------------------------------------------------- #
# Weg E: Browser in der Kali
# --------------------------------------------------------------------------- #


@pytest.fixture
def web_lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    lab = Lab(tmp_path_factory.mktemp("dash"))
    lab.env.pop("ARIADNE_WEB")  # dieser Test braucht den Web-Server (auf einem freien Port)
    lab.port = free_port()  # type: ignore[attr-defined]
    lab.paths.config_dir.mkdir(parents=True, exist_ok=True)
    lab.paths.config_file.write_text(f"[ui]\nport = {lab.port}\n")  # type: ignore[attr-defined]
    try:
        yield lab
    finally:
        lab.close_terminals()
        lab.stop_daemon()


def _start_file(out: str) -> Path:
    m = re.search(r"Startdatei: file://(\S+)", out)
    assert m, out
    path = Path(m.group(1))
    assert path.stat().st_mode & 0o777 == 0o600
    return path


def _ui_login(lab: Lab, b: Browser) -> dict[str, Any]:
    out = lab.cli("ui", "--no-open")
    path = _start_file(out)
    code = b.open_start_file(path.read_text())
    assert code not in out  # der Code steht nur in der Datei, nie auf dem Terminal
    return b.login(code)


@pytest.mark.e2e
@pytest.mark.pty
@pytest.mark.web
@pytest.mark.skipif(shutil.which("zsh") is None, reason="zsh fehlt")
def test_dashboard_local_from_start_file_to_unlock(web_lab: Lab) -> None:
    from pyrage import decrypt, x25519

    lab = web_lab
    port: int = lab.port  # type: ignore[attr-defined]
    ident = x25519.Identity.generate()
    lab.tools((GOLDEN / "nmap.xml" / "ms2_sv_sc" / "input.xml").read_bytes(),
              (GOLDEN / "nmap.text" / "ms2_sv_sc" / "input.txt").read_bytes(), target=TARGET, lhost=KALI_IP)
    (lab.bin / "frag").write_text(GETPASS_SCRIPT.format(python=sys.executable))
    (lab.bin / "frag").chmod(0o755)
    lab.setup()
    rec = lab.paths.config_dir / "backup-recipients.txt"
    rec.write_text(f"# Mac\n{ident.to_public()}\n")
    rec.chmod(0o600)

    # ---- Session beginnen und arbeiten ----------------------------------------------
    out = lab.cli("start", "lab1", "--target", NET, "--preroll", "no", secret=PASSPHRASE)
    assert "Projekt lab1 angelegt" in out and "Aufnahme läuft" in out, out
    t = lab.terminal()
    expect_title(t, rb"\[REC lab1\]")
    run_cmd(t, "cd ~/ariadne/lab1")
    assert "vsftpd 2.3.4" in run_cmd(t, f"nmap -sV -sC -oA scans/ms2 {TARGET}")
    t.sendline("printf 'P''W: '; read -s PW; echo; echo laenge-${#PW}")
    time.sleep(0.5)  # read -s schaltet den Modus erst nach dem printf um
    t.sendline(PW_READ)
    t.expect_exact(f"laenge-{len(PW_READ)}")
    t.expect_exact(PROMPT)
    t.sendline("frag")
    t.expect_exact("Passwort: ")
    t.sendline(PW_GETPASS)
    t.expect_exact(f"angenommen {len(PW_GETPASS)}")
    t.expect_exact(PROMPT)

    # ---- ariadne ui: Startdatei, Navigation, Anmeldung ---------------------------------
    b = Browser(f"http://127.0.0.1:{port}", port)
    session = _ui_login(lab, b)
    assert session["session"]["origin"] == "local"
    sessions = lab.cli("ui", "--sessions")
    assert "lokal" in sessions and b.token not in sessions
    st, host_id = _check_dashboard(b, origin="local", slug="lab1")
    pid = st["project"]["id"]
    term = [x for x in st["terminals"] if x["state"] == "on"]
    assert term, st["terminals"]

    # ---- Zeitachse: Befehl mit übernommenen Werten, Eingaben ohne Echo verdeckt (E104) ----
    tl = b.ok(f"/api/v1/p/{pid}/timeline")
    nmap = [i for i in tl["items"] if i["type"] == "command" and "nmap" in json.dumps(i["cmd"])]
    assert nmap and nmap[0]["adopted"] > 0 and nmap[0]["cmd"]

    def hidden_inputs() -> list[dict[str, Any]]:
        page = b.ok(f"/api/v1/p/{pid}/timeline", types="input", limit=1000)
        return [i["input"] for i in page["items"] if i["type"] == "input" and i["input"]["hidden"]]

    hidden = _wait(lambda: len(hidden_inputs()) >= 2 and hidden_inputs(), 20, "Eingaben fehlen")
    assert all(i["text"] == MASK for i in hidden)
    assert {i["reason"] for i in hidden} == {"tty_no_echo"}  # der Shim sah den Passwortmodus
    inputs = b.ok(f"/api/v1/p/{pid}/inputs")
    everything = json.dumps([tl, inputs, hidden_inputs(), b.ok(f"/api/v1/p/{pid}/graph")], ensure_ascii=False)
    assert PW_READ not in everything and PW_GETPASS not in everything and PASSPHRASE not in everything
    cli_inputs = lab.cli("show", "inputs")
    assert MASK in cli_inputs and PW_READ not in cli_inputs and PW_GETPASS not in cli_inputs
    # Aufdecken nur einzeln und ausdrücklich (Profil lab)
    revealed = set()
    for item in hidden:
        r = b.post(f"/api/v1/p/{pid}/secrets/reveal", {"ref": "input", "seq": item["seq"]})
        assert r.status_code == 200, r.text
        revealed.add(r.json()["value"])
    assert {PW_READ, PW_GETPASS} <= revealed, revealed

    # ---- Entscheid, danach changes im Strom ----------------------------------------------
    _decision_changes(b, pid, host_id)

    # ---- lock beendet Sitzung und Strom, unlock öffnet das Projekt wieder (E101, E103) --
    stream = Stream(b)
    assert "Gesperrt." in lab.cli("lock")
    assert stream.ended.wait(3), "Strom endet nach lock nicht"
    stream.close()
    assert b.get("/api/v1/status").status_code == 401
    expect_title(t, rb"gesperrt")
    out = lab.cli("unlock", secret=PASSPHRASE)
    assert "Projekt lab1 geöffnet" in out and "Aufnahme läuft" in out, out
    expect_title(t, rb"\[REC lab1\]")
    assert "nimmt auf" in lab.wait_status("1 nehmen auf")
    b2 = Browser(f"http://127.0.0.1:{port}", port)
    _ui_login(lab, b2)
    st2 = b2.ok("/api/v1/status")
    assert st2["project"]["slug"] == "lab1" and st2["locked"] is False
    assert b.get("/api/v1/status").status_code == 401  # das alte Token bleibt ungültig

    # ---- stop mit Sicherungshinweis, dann Sicherung (E91) --------------------------------
    out = lab.cli("stop")
    assert "Projekt lab1 beendet" in out and "Sicherung" in out, out
    assert b2.get("/api/v1/status").status_code == 401
    target = lab.base / "abgabe" / "lab1.age"
    target.parent.mkdir()
    out = lab.cli("backup", "--to-file", str(target), "--project", "lab1")
    assert target.stat().st_mode & 0o777 == 0o600
    inner = decrypt(target.read_bytes(), [ident])
    with tarfile.open(fileobj=io.BytesIO(inner), mode="r|") as tar:
        names = [m.name for m in tar]
    assert names[0] == "ariadne-backup.json" and any(n.startswith("projects/lab1/.vault/") for n in names)
    assert PW_READ.encode() not in target.read_bytes()


# --------------------------------------------------------------------------- #
# Weg B: Mac über Tunnel mit dem Mac-Helfer
# --------------------------------------------------------------------------- #

MAC_PASS = "Mac-Schluessel-Passphrase-5"

FAKE_OPEN = """#!/bin/sh
cp "$1" "$FAKE_DIR/opened.html"
"""
FAKE_FDESETUP = """#!/bin/sh
echo "FileVault is On."
"""
FAKE_SLEEP = """#!/bin/sh
case $1 in 0.*) exec {sleep} "$1" ;; esac
exec {sleep} 0.3
"""


class Agent:
    """``ssh-agent`` des «Macs» mit dem Kali-Schlüssel (Passphrase per SSH_ASKPASS)."""

    def __init__(self, base: Path, key: Path) -> None:
        out = subprocess.run(["ssh-agent", "-s", "-a", str(base / "agent.sock")], capture_output=True,
                             text=True, check=True).stdout
        m = re.search(r"SSH_AGENT_PID=(\d+);", out)
        assert m, out
        self.pid = int(m.group(1))
        self.sock = str(base / "agent.sock")
        askpass = base / "askpass"
        askpass.write_text(f"#!/bin/sh\necho '{MAC_PASS}'\n")
        askpass.chmod(0o700)
        env = dict(os.environ, SSH_AUTH_SOCK=self.sock, SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force",
                   DISPLAY=":0")
        subprocess.run(["ssh-add", str(key)], env=env, stdin=subprocess.DEVNULL, capture_output=True,
                       check=True, timeout=20)

    def close(self) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.kill(self.pid, signal.SIGTERM)


def _kali_env(kali: Any) -> dict[str, str]:
    home = kali.home
    return {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_STATE_HOME": str(home / ".local/state"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_RUNTIME_DIR": str(kali.run_dir),
        "ARIADNE_PROJECTS_ROOT": str(home / "ariadne"),
        "ARIADNE_SETUP_ROOT": str(kali.root),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
    }


def _kali_cli(kali: Any, *args: str, stdin: str | None = None) -> str:
    from tests.remote.test_tunnel_e2e import ARIADNE

    env = [f"{k}={v}" for k, v in _kali_env(kali).items()]
    res = subprocess.run(kali.as_user(["env", "-i", *env, str(ARIADNE), *args]), input=stdin,
                         capture_output=True, text=True, timeout=120, check=False)
    assert res.returncode == 0, f"ariadne {' '.join(args)}: {res.stdout}{res.stderr}"
    return res.stdout + res.stderr


class Mac:
    def __init__(self, base: Path, kali: Any, agent: Agent, local_port: int) -> None:
        self.base = base
        self.home = base / "home"
        self.shim = base / "shim"
        self.fake = base / "fake"
        self.tmp = base / "tmp"
        for d in (self.home, self.shim, self.fake, self.tmp):
            d.mkdir(parents=True)
        sleep = shutil.which("sleep") or "/bin/sleep"
        for name, text in (("open", FAKE_OPEN), ("fdesetup", FAKE_FDESETUP),
                           ("sleep", FAKE_SLEEP.format(sleep=sleep))):
            (self.shim / name).write_text(text)
            (self.shim / name).chmod(0o755)
        self.backups = self.home / "Ariadne-Backups"
        self.state = self.home / "state"
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.home),
            "TMPDIR": str(self.tmp),
            "LC_ALL": "C.UTF-8",
            "SSH_AUTH_SOCK": agent.sock,
            "ARIADNE_MAC_SHIM_DIR": str(self.shim),
            "ARIADNE_MAC_SSH_CONFIG": str(kali.client_dir / "ariadne.conf"),
            "ARIADNE_MAC_STATE_DIR": str(self.state),
            "ARIADNE_MAC_BACKUP_DIR": str(self.backups),
            "ARIADNE_MAC_KEY": str(self.home / "mac.key.age"),
            "ARIADNE_MAC_PORT": str(kali.web_port),
            "ARIADNE_MAC_LOCAL_PORT": str(local_port),
            "FAKE_DIR": str(self.fake),
        }

    def run(self, *args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["zsh", str(MAC_HELPER), *args], env=self.env, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout, check=False)

    def tunnel_pid(self) -> int | None:
        p = self.state / "tunnel.pid"
        return int(p.read_text()) if p.exists() else None


def _port_closed(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), 0.5):
            return False
    except OSError:
        return True


@pytest.mark.e2e
@pytest.mark.remote
@pytest.mark.web
@pytest.mark.skipif(shutil.which("zsh") is None or shutil.which("lsof") is None, reason="zsh oder lsof fehlt")
def test_dashboard_over_tunnel_with_mac_helper(tmp_path: Path, operator_template: Any,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    from pyrage import decrypt, x25519

    from tests.core.conftest import PASSPHRASE as OP_PASSPHRASE
    from tests.remote import test_tunnel_e2e as t13

    if t13.SSHD is None or shutil.which("ssh") is None or not t13.ARIADNE.is_file():
        pytest.skip("sshd, ssh oder ariadne im venv fehlt")
    pw = t13._test_user()
    if pw is None:
        pytest.skip("kein unprivilegierter Benutzer mit Login-Shell für sshd (ARIADNE_TEST_SSH_USER)")
    ident = x25519.Identity.generate()
    client_dir = tmp_path / "mac-ssh"
    client_dir.mkdir()
    kali = t13.Kali(pw, client_dir)
    agent: Agent | None = None
    mac: Mac | None = None
    tunnel2: subprocess.Popen[bytes] | None = None
    try:
        kali.build(recipient=str(ident.to_public()), operator_dir=operator_template.directory)
        kali.start_sshd()
        # Der Mac-Schlüssel bekommt eine Passphrase (R13), der Agent hält ihn wie AddKeysToAgent
        key = client_dir / "mac"
        subprocess.run(["ssh-keygen", "-q", "-p", "-P", "", "-N", MAC_PASS, "-f", str(key)], check=True)
        agent = Agent(tmp_path, key)
        monkeypatch.setenv("SSH_AUTH_SOCK", agent.sock)  # auch für ssh aus dem Test (T13-Hilfen)

        # ---- in der Kali: Session wie immer mit ariadne start, nmap-Ergebnis importieren ----
        out = _kali_cli(kali, "start", "lab1", "--target", NET, "--preroll", "no", "--passphrase-fd", "0",
                        stdin=OP_PASSPHRASE + "\n")
        assert "Projekt lab1 angelegt" in out, out
        scan = kali.home / "ariadne" / "lab1" / "scans" / "ms2.xml"
        scan.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(GOLDEN / "nmap.xml" / "ms2_sv_sc" / "input.xml", scan)
        if os.getuid() == 0:
            os.chown(scan.parent, pw.pw_uid, pw.pw_gid)
            os.chown(scan, pw.pw_uid, pw.pw_gid)
        _kali_cli(kali, "import", str(scan))

        # ---- Mac: ariadne-mac start ----------------------------------------------------
        local = free_port()
        mac = Mac(tmp_path / "mac", kali, agent, local)
        res = mac.run("start")
        assert res.returncode == 0, res.stdout + res.stderr
        assert "[ok] Schlüssel mit Passphrase" in res.stdout and "[ok] Hostkey der Kali bekannt" in res.stdout
        assert "Dashboard im Standardbrowser geöffnet" in res.stdout
        tunnel = mac.tunnel_pid()
        assert tunnel is not None
        html = (mac.fake / "opened.html").read_text()
        b = Browser(f"http://127.0.0.1:{local}", kali.web_port)
        code = b.open_start_file(html)
        assert code not in res.stdout + res.stderr
        assert b.login(code)["session"]["origin"] == "sshd"
        st, host_id = _check_dashboard(b, origin="sshd", slug="lab1")
        _decision_changes(b, st["project"]["id"], host_id)
        sessions = _kali_cli(kali, "ui", "--sessions")
        assert "über sshd" in sessions and b.token not in sessions

        # ---- ariadne-mac stop: widerrufen, sperren, Sicherung, Tunnel zu ----------------
        res = mac.run("stop")
        assert res.returncode == 0, res.stdout + res.stderr
        assert "Widerrufen: 1 Sitzungen." in res.stdout and "Gesperrt." in res.stdout
        assert "Tunnel geschlossen." in res.stdout and "Kettenkopf" in res.stderr
        _wait(lambda: _port_closed(local), 10, "Tunnel noch offen")
        files = list(mac.backups.glob("kali-sl-*.age"))
        assert len(files) == 1 and files[0].stat().st_mode & 0o777 == 0o600
        inner = decrypt(files[0].read_bytes(), [ident])
        with tarfile.open(fileobj=io.BytesIO(inner), mode="r|") as tar:
            names = [m.name for m in tar]
        assert any(n.startswith("operator/") for n in names)
        assert any(n.startswith("projects/lab1/.vault/") for n in names)

        # ---- neuer Tunnel von Hand: altes Token 401, Projekt gesperrt, aber aktiv (E103) ---
        local2 = free_port()
        tunnel2, code2 = t13._tunnel(kali, local2)
        b2 = Browser(f"http://127.0.0.1:{local2}", kali.web_port)
        assert b2.get("/api/v1/status", token=b.token).status_code == 401
        b2.login(code2)
        st2 = b2.ok("/api/v1/status")
        assert st2["locked"] is True and st2["project"] is None
        assert st2["active"]["slug"] == "lab1" and st2["active"]["stopped"] is False

        # ---- unlock: ohne Terminal abgelehnt, mit Terminal öffnet es das Projekt (E101) ----
        res2 = kali.ssh("kali-sl", "unlock")
        assert res2.returncode == 2 and b"Terminal" in res2.stderr
        env = [f"{k}={v}" for k, v in _kali_env(kali).items()] + ["SSH_ORIGINAL_COMMAND=unlock"]
        argv = kali.as_user(["env", "-i", *env, str(t13.ARIADNE), "remote", "serve"])
        child = pexpect.spawn(argv[0], argv[1:], timeout=60, encoding="utf-8")
        try:
            child.expect_exact("Passphrase: ")
            child.sendline(OP_PASSPHRASE)
            child.expect_exact("Projekt lab1 geöffnet")
            child.expect(pexpect.EOF)
        finally:
            child.close()
        assert child.exitstatus == 0, child.before
        st3 = b2.ok("/api/v1/status")  # die Anmeldung überlebt das Entsperren
        assert st3["locked"] is False and st3["project"]["slug"] == "lab1"
    finally:
        if tunnel2 is not None:
            t13._stop(tunnel2)
        if mac is not None and mac.tunnel_pid():
            with contextlib.suppress(Exception):
                mac.run("stop", "--no-backup", timeout=60)
        if agent is not None:
            agent.close()
        kali.close()
