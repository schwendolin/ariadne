"""T15 ``packaging/mac/ariadne-mac`` (R13, E93) unter Linux mit zsh und Attrappen.

Attrappen in ``ARIADNE_MAC_SHIM_DIR`` (vorne im PATH): ``ssh`` (spielt die Kali und protokolliert
jeden Aufruf), ``open``, ``fdesetup``, ``lsof``, ``sleep`` (lange Pausen sofort), ``age``.
``ssh-keygen`` ist echt: Schlüssel mit und ohne Passphrase, ``known_hosts`` mit Alias."""

from __future__ import annotations

import os
import pty
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

from tests.remote.helpers import MAC_HELPER, keypair

pytestmark = pytest.mark.skipif(shutil.which("zsh") is None, reason="zsh fehlt")

CODE = "AbCdEfGhIjKlMnOpQrStUv"
SEP = "\x1f"
SLEEP = shutil.which("sleep") or "/bin/sleep"

FAKE_SSH = rf"""#!/bin/sh
for a in "$@"; do printf '%s\037' "$a"; done >> "$FAKE_DIR/ssh.log"
printf '\n' >> "$FAKE_DIR/ssh.log"
for a in "$@"; do [ "$a" = -G ] && {{ cat "$FAKE_DIR/ssh-G"; exit 0; }}; done
for last in "$@"; do :; done
case $last in
    code)
        if [ -n "${{FAKE_SSH_FAIL:-}}" ]; then
            echo "ssh: connect to host kali: Connection refused" >&2
            exit 255
        fi
        echo $$ > "$FAKE_DIR/ssh.pid"
        {SLEEP} 300 &
        sp=$!
        trap 'kill $sp 2>/dev/null; exit 0' TERM INT HUP
        printf '%s\n' "${{FAKE_CODE:-{CODE}}}"
        wait $sp ;;
    revoke) echo "Widerrufen: 1 Sitzungen." ;;
    lock) echo "Gesperrt." ;;
    backup)
        if [ -n "${{FAKE_BACKUP_FAIL:-}}" ]; then
            printf 'halb'
            echo "Sicherung fehlgeschlagen" >&2
            exit 1
        fi
        printf 'age-encryption.org/v1\n-> X25519 abc\nxyz' ;;
    restore) cat > "$FAKE_DIR/restore.in"; echo "Wiederhergestellt" ;;
    unlock) echo "Passphrase: (Attrappe)" ;;
    check) echo "[ok] Kali in Ordnung" ;;
    *) echo "Abgelehnt" >&2; exit 2 ;;
esac
"""

FAKE_LSOF = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DIR/lsof.log"
if [ -f "$FAKE_DIR/busy" ]; then cat "$FAKE_DIR/busy"; exit 0; fi
alive() {  # wie lsof: ein beendeter Prozess (auch ein Zombie) lauscht nicht mehr
    kill -0 "$1" 2>/dev/null || return 1
    st=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f1)
    [ "$st" != Z ]
}
if [ -f "$FAKE_DIR/ssh.pid" ] && alive "$(cat "$FAKE_DIR/ssh.pid")"; then
    if [ -f "$FAKE_DIR/steal" ]; then cat "$FAKE_DIR/steal"; else cat "$FAKE_DIR/ssh.pid"; fi
    exit 0
fi
exit 1
"""

FAKE_OPEN = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DIR/open.log"
cp "$1" "$FAKE_DIR/opened.html"
stat -c %a "$1" > "$FAKE_DIR/opened.mode"
stat -c %a "$(dirname "$1")" > "$FAKE_DIR/opened.dirmode"
"""

FAKE_SLEEP = rf"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DIR/sleep.log"
case $1 in 0.*) exec {SLEEP} "$1" ;; esac
exit 0
"""

FAKE_FDESETUP = """#!/bin/sh
echo "${FAKE_FILEVAULT:-FileVault is On.}"
"""

FAKE_SSH_ADD = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DIR/ssh-add.log"
case $1 in
    -T) [ -f "$FAKE_DIR/agent-has-key" ] && exit 0; exit 1 ;;
    -t) [ -n "${FAKE_SSH_ADD_FAIL:-}" ] && exit 1; : > "$FAKE_DIR/agent-has-key"; exit 0 ;;
esac
exit 2
"""

FAKE_AGE = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DIR/age.log"
printf 'klartext-strom'
"""


class Mac:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.home = base / "home"
        self.fake = base / "fake"
        self.shim = base / "shim"
        self.tmp = base / "tmp"
        self.state = base / "state"
        for d in (self.home, self.fake, self.shim, self.tmp):
            d.mkdir(parents=True, exist_ok=True)
        for name, text in (
            ("ssh", FAKE_SSH),
            ("lsof", FAKE_LSOF),
            ("open", FAKE_OPEN),
            ("sleep", FAKE_SLEEP),
            ("fdesetup", FAKE_FDESETUP),
            ("age", FAKE_AGE),
            ("ssh-add", FAKE_SSH_ADD),
        ):
            p = self.shim / name
            p.write_text(text)
            p.chmod(0o755)
        ssh_dir = self.home / ".ssh"
        ssh_dir.mkdir(mode=0o700)
        self.conf = ssh_dir / "ariadne.conf"
        self.conf.write_text("Host kali-sl\n  HostName 100.101.102.103\n  StrictHostKeyChecking yes\n")
        self.key = ssh_dir / "id_ed25519_kali_sl"
        keypair(self.key, passphrase="Mac-Passphrase-1")
        hostkey = base / "hostkey"
        host_pub = keypair(hostkey, comment="")
        self.known = ssh_dir / "known_hosts"
        self.known.write_text(f"kali-smartlearn {host_pub}\n")
        self.backups = self.home / "Ariadne-Backups"
        self.mac_key = self.home / ".config" / "ariadne-backup" / "mac.key.age"
        self.mac_key.parent.mkdir(parents=True)
        self.mac_key.write_bytes(b"age-encryption.org/v1\n-> scrypt abc 18\n")
        self.ssh_g(strict="true")
        (self.fake / "agent-has-key").write_text("")  # Schlüssel schon im Agent (Normalfall)

    def ssh_g(self, *, strict: str = "true", identity: Path | None = None, forward_agent: str = "no") -> None:
        (self.fake / "ssh-G").write_text(
            "user kali\nhostname 100.101.102.103\nport 22\n"
            f"identityfile {identity or self.key}\nhostkeyalias kali-smartlearn\n"
            f"stricthostkeychecking {strict}\nuserknownhostsfile {self.known}\n"
            f"forwardagent {forward_agent}\ncontrolmaster false\n"
        )

    def env(self, **extra: str) -> dict[str, str]:
        e = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.home),
            "TMPDIR": str(self.tmp),
            "LC_ALL": "C.UTF-8",
            "ARIADNE_MAC_SHIM_DIR": str(self.shim),
            "ARIADNE_MAC_SSH_CONFIG": str(self.conf),
            "ARIADNE_MAC_STATE_DIR": str(self.state),
            "ARIADNE_MAC_BACKUP_DIR": str(self.backups),
            "ARIADNE_MAC_KEY": str(self.mac_key),
            "FAKE_DIR": str(self.fake),
        }
        e.update(extra)
        return e

    def run(self, *args: str, stdin: str | None = None, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["zsh", str(MAC_HELPER), *args],
            capture_output=True,
            text=True,
            env=self.env(**extra),
            input=stdin if stdin is not None else "",
            timeout=60,
            check=False,
        )

    def ssh_calls(self) -> list[list[str]]:
        log = self.fake / "ssh.log"
        if not log.exists():
            return []
        return [line.split(SEP)[:-1] for line in log.read_text().splitlines() if line]

    def remote_calls(self) -> list[list[str]]:
        return [c for c in self.ssh_calls() if "-G" not in c]

    def tunnel_pid(self) -> int | None:
        p = self.fake / "ssh.pid"
        return int(p.read_text()) if p.exists() else None

    def cleanup(self) -> None:
        pid = self.tunnel_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


@pytest.fixture
def mac(tmp_path):
    m = Mac(tmp_path / "mac")
    yield m
    m.cleanup()


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def _wait(cond, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def run_tty(mac: Mac, *args: str, answer: str) -> subprocess.CompletedProcess[str]:
    """Wie ``Mac.run``, aber stdin ist ein Terminal (pty), auf dem ``answer`` und Enter stehen."""
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(
            ["zsh", str(MAC_HELPER), *args],
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=mac.env(),
        )
        os.close(slave)
        slave = -1
        os.write(master, (answer + "\n").encode())
        out, err = proc.communicate(timeout=60)
    finally:
        if slave >= 0:
            os.close(slave)
        os.close(master)
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def assert_safe_ssh(mac: Mac) -> None:
    """R13: jedes ssh mit -F ariadne.conf, ControlMaster=no, ControlPath=none, nie -g."""
    calls = mac.ssh_calls()
    assert calls
    for c in calls:
        assert c[:2] == ["-F", str(mac.conf)] or ("-G" in c and "-F" in c), c
        if "-G" in c:
            continue
        joined = " ".join(c)
        assert "-o ControlMaster=no" in joined and "-o ControlPath=none" in joined, c
        assert "-o StrictHostKeyChecking=yes" in joined, c  # SEC-M1: nie ein unbekannter Hostkey
        assert "-g" not in c and "GatewayPorts" not in joined, c


def test_t15_start_one_connection_start_file_and_stop(mac):
    res = mac.run("start")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Dashboard im Standardbrowser geöffnet" in res.stdout
    remote = mac.remote_calls()
    assert len(remote) == 1  # eine Verbindung trägt Code und Tunnel
    c = remote[0]
    assert c[-2:] == ["kali-sl", "code"]
    assert "-n" in c and "-L" in c and c[c.index("-L") + 1] == "127.0.0.1:7330:127.0.0.1:7330"
    assert "ExitOnForwardFailure=yes" in c and "BatchMode=yes" in c  # fragt nie im Hintergrund (F2)
    assert_safe_ssh(mac)
    # Startdatei: 0600 in einem 0700-Ordner unter TMPDIR, Code nur im Fragment, nie in argv
    html = (mac.fake / "opened.html").read_text()
    assert f'content="0;url=http://127.0.0.1:7330/#c={CODE}"' in html
    assert (mac.fake / "opened.mode").read_text().strip() == "600"
    assert (mac.fake / "opened.dirmode").read_text().strip() == "700"
    opened = (mac.fake / "open.log").read_text().strip()
    assert opened.startswith(str(mac.tmp)) and CODE not in opened
    assert all(CODE not in " ".join(call) for call in mac.ssh_calls())
    assert _wait(lambda: not list(mac.tmp.glob("ariadne-*")))  # Code-Datei sofort, Startdatei nach «10 s» weg
    assert "10" in (mac.fake / "sleep.log").read_text().split()
    pid = mac.tunnel_pid()
    assert pid and _alive(pid)
    assert (mac.state / "tunnel.pid").read_text().strip() == str(pid)
    # ein zweites start ohne Terminal: Rückfrage gilt als Nein (E116), nichts ändert sich
    again = mac.run("start")
    assert again.returncode == 0, again.stdout + again.stderr
    assert "Tunnel läuft schon. Neu aufbauen? [j/N]" in again.stderr and "Nichts geändert" in again.stdout
    assert [c[-1] for c in mac.remote_calls()] == ["code"] and _alive(pid)
    # mit Terminal und «n» (oder nur Enter): ebenfalls nichts
    for answer in ("n", ""):
        res = run_tty(mac, "start", answer=answer)
        assert res.returncode == 0 and "Nichts geändert" in res.stdout, res.stdout + res.stderr
    assert [c[-1] for c in mac.remote_calls()] == ["code"] and _alive(pid)
    # mit «j» (Neuanmeldung nach lock oder 12 h, F1): Tunnel neu, ohne revoke und lock
    again = run_tty(mac, "start", answer="j")
    assert again.returncode == 0, again.stdout + again.stderr
    assert "neu aufgebaut (ohne Sperren" in again.stdout
    assert [c[-1] for c in mac.remote_calls()] == ["code", "code"]
    assert _wait(lambda: not _alive(pid))
    pid = mac.tunnel_pid()
    assert pid and _alive(pid)
    # stop: widerrufen, sperren, sichern, Tunnel zu
    res = mac.run("stop")
    assert res.returncode == 0, res.stdout + res.stderr
    cmds = [c[-1] for c in mac.remote_calls()]
    assert cmds == ["code", "code", "revoke", "lock", "backup"]
    for c in mac.remote_calls()[2:]:
        assert "ClearAllForwardings=yes" in c
    assert_safe_ssh(mac)
    files = list(mac.backups.glob("kali-sl-*.age"))
    assert len(files) == 1 and files[0].read_bytes().startswith(b"age-encryption.org/v1")
    assert files[0].stat().st_mode & 0o777 == 0o600 and mac.backups.stat().st_mode & 0o777 == 0o700
    assert _wait(lambda: not _alive(pid))
    assert not (mac.state / "tunnel.pid").exists()
    assert "Tunnel geschlossen." in res.stdout


def test_port_follows_ui_port_of_the_kali(mac):
    """``ARIADNE_MAC_PORT`` = ``[ui] port`` der Kali; lokal derselbe Port (sonst 421 an der Kali).
    ``ARIADNE_MAC_LOCAL_PORT`` nur für Tests mit Mac und Kali auf einem Rechner."""
    res = mac.run("start", ARIADNE_MAC_PORT="7444")
    assert res.returncode == 0, res.stdout + res.stderr
    c = mac.remote_calls()[0]
    assert c[c.index("-L") + 1] == "127.0.0.1:7444:127.0.0.1:7444"
    assert f'url=http://127.0.0.1:7444/#c={CODE}"' in (mac.fake / "opened.html").read_text()
    assert "-iTCP:7444" in (mac.fake / "lsof.log").read_text()
    assert mac.run("stop", "--no-backup", ARIADNE_MAC_PORT="7444").returncode == 0
    for bad in ("80", "70000", "x"):
        res = mac.run("check", ARIADNE_MAC_PORT=bad)
        assert res.returncode == 1 and "ungültig" in res.stderr
    res = mac.run("check", ARIADNE_MAC_LOCAL_PORT="1")
    assert res.returncode == 1 and "ungültig" in res.stderr


def test_t15_port_busy(mac):
    (mac.fake / "busy").write_text("4242\n")
    res = mac.run("start")
    assert res.returncode == 1
    assert "[!!] Port 7330 belegt (PID 4242)" in res.stdout and "kein Tunnel" in res.stderr
    assert mac.remote_calls() == []


def test_t15_hostkey_unknown(mac):
    mac.known.write_text("")
    res = mac.run("start")
    assert res.returncode == 1 and "[!!] Hostkey der Kali unbekannt (kali-smartlearn)" in res.stdout
    assert mac.remote_calls() == []


def test_t15_key_without_passphrase(mac, tmp_path):
    plain = mac.home / ".ssh" / "id_plain"
    keypair(plain)
    mac.ssh_g(identity=plain)
    res = mac.run("start")
    assert res.returncode == 1 and "[!!] Schlüssel ohne Passphrase" in res.stdout
    assert mac.remote_calls() == []


def test_t15_filevault_off_and_strict_and_agent(mac):
    res = mac.run("start", FAKE_FILEVAULT="FileVault is Off.")
    assert res.returncode == 1 and "[!!] FileVault aus" in res.stdout
    mac.ssh_g(strict="ask", forward_agent="yes")
    res = mac.run("start")
    assert res.returncode == 1
    assert "[!!] StrictHostKeyChecking ist nicht yes" in res.stdout and "[!!] ForwardAgent an" in res.stdout
    assert mac.remote_calls() == []


@pytest.mark.parametrize(
    "where",
    [
        "Library/Mobile Documents/com~apple~CloudDocs/Ariadne",
        "Desktop/Sicherung",
        "Documents",
        "Library/CloudStorage/OneDrive-gibb/x",
    ],
)
def test_t15_backup_dir_in_cloud_refused(mac, where):
    target = mac.home / where
    res = mac.run("backup", ARIADNE_MAC_BACKUP_DIR=str(target))
    assert res.returncode == 1 and "iCloud" in res.stderr
    assert mac.remote_calls() == [] and not target.exists()
    res = mac.run("check", ARIADNE_MAC_BACKUP_DIR=str(target))
    assert res.returncode == 1 and "[!!] Sicherungsordner" in res.stdout


def test_backup_dir_symlink_into_icloud_refused(mac):
    cloud = mac.home / "Library" / "Mobile Documents" / "x"
    cloud.mkdir(parents=True)
    link = mac.home / "Sicher"
    link.symlink_to(cloud)
    res = mac.run("backup", ARIADNE_MAC_BACKUP_DIR=str(link))
    assert res.returncode == 1 and mac.remote_calls() == []


def test_backup_failure_leaves_no_file(mac):
    res = mac.run("backup", FAKE_BACKUP_FAIL="1")
    assert res.returncode == 1 and "unvollständige Datei gelöscht" in res.stderr
    assert list(mac.backups.glob("*")) == []
    res = mac.run("backup")
    assert res.returncode == 0, res.stderr
    assert len(list(mac.backups.glob("kali-sl-*.age"))) == 1


def test_no_code_from_kali(mac):
    res = mac.run("start", FAKE_SSH_FAIL="1")
    assert res.returncode == 1 and "kein Code von der Kali" in res.stderr
    assert "Connection refused" in res.stderr
    assert not (mac.state / "tunnel.pid").exists()
    assert not list(mac.tmp.glob("ariadne-*"))


def test_invalid_code_is_not_opened(mac):
    res = mac.run("start", FAKE_CODE="<script>alert(1)</script>")
    assert res.returncode == 1 and "kein Code" in res.stderr
    assert not (mac.fake / "opened.html").exists()


def test_port_taken_by_other_process_after_start(mac):
    (mac.fake / "steal").write_text("4343\n")
    res = mac.run("start")
    assert res.returncode == 1 and "gehört nicht dem Tunnel" in res.stderr
    assert not (mac.fake / "opened.html").exists()
    pid = mac.tunnel_pid()
    assert pid and _wait(lambda: not _alive(pid))


def test_check_mac_and_kali(mac):
    res = mac.run("check")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "[ok] FileVault an" in res.stdout and "[ok] Kali in Ordnung" in res.stdout
    assert "[ok] Sicherungsschlüssel mit Passphrase verschlüsselt" in res.stdout
    mac.mac_key.write_text("AGE-SECRET-KEY-1QQQQQQ\n")
    res = mac.run("check")
    assert res.returncode == 1 and "[!!] Sicherungsschlüssel liegt im Klartext" in res.stdout
    mac.conf.write_text(mac.conf.read_text() + "  UseKeychain yes\n")
    assert "UseKeychain" in mac.run("check").stdout


def test_restore_pipes_decrypted_stream(mac, tmp_path):
    backup = tmp_path / "kali-sl-x.age"
    backup.write_bytes(b"age-encryption.org/v1\n")
    res = mac.run("restore", str(backup), stdin="n\n")
    assert res.returncode == 1 and "abgebrochen" in res.stderr and mac.remote_calls() == []
    res = mac.run("restore", str(backup), "--yes")
    assert res.returncode == 0, res.stderr
    assert (mac.fake / "restore.in").read_text() == "klartext-strom"
    assert (mac.fake / "age.log").read_text().split() == ["-d", "-i", str(mac.mac_key), str(backup)]
    assert mac.remote_calls()[-1][-1] == "restore" and "ClearAllForwardings=yes" in mac.remote_calls()[-1]
    mac.mac_key.write_text("AGE-SECRET-KEY-1QQQQQQ\n")
    res = mac.run("restore", str(backup), "--yes")
    assert res.returncode == 1 and "Klartext" in res.stderr


def test_f2_key_not_in_agent_is_loaded_in_the_foreground_before_the_tunnel(mac):
    """F2 (Anleitung): Ist der Schlüssel nicht im Agent, fragt ssh-add im Vordergrund nach der
    Passphrase, bevor der Tunnel im Hintergrund startet (der fragt nie selbst, BatchMode=yes)."""
    (mac.fake / "agent-has-key").unlink()
    res = mac.run("start", FAKE_SSH_ADD_FAIL="1")
    assert res.returncode == 1 and "Schlüssel nicht geladen" in res.stderr
    assert mac.remote_calls() == []  # kein Tunnel, keine Frist läuft
    res = mac.run("start")
    assert res.returncode == 0, res.stdout + res.stderr
    log = (mac.fake / "ssh-add.log").read_text().splitlines()
    assert log[-1] == f"-t 4h {mac.key}" and log[0] == f"-T {mac.key}.pub"
    assert "Passphrase des Mac-Schlüssels" in res.stdout
    assert mac.run("stop", "--no-backup").returncode == 0


@pytest.mark.parametrize("cmd", ["unlock", "backup", "restore"])
def test_sec_m1_unlock_backup_restore_check_ssh_settings_first(mac, tmp_path, cmd):
    """SEC-M1 (R13): unlock schickt die Passphrase, restore den Klartext der Sicherung; beide (und
    backup) laufen nur mit bekanntem Hostkey und StrictHostKeyChecking yes."""
    backup = tmp_path / "kali-sl-x.age"
    backup.write_bytes(b"age-encryption.org/v1\n")
    args = [cmd, str(backup), "--yes"] if cmd == "restore" else [cmd]
    mac.ssh_g(strict="ask")
    res = mac.run(*args)
    assert res.returncode == 1 and "StrictHostKeyChecking ist nicht yes" in res.stderr
    assert mac.remote_calls() == []
    mac.ssh_g(strict="true")
    mac.known.write_text("")
    res = mac.run(*args)
    assert res.returncode == 1 and "Hostkey der Kali unbekannt" in res.stderr
    assert mac.remote_calls() == []
    assert not (mac.fake / "restore.in").exists()


def test_unlock_uses_terminal(mac):
    res = mac.run("unlock")
    assert res.returncode == 0
    c = mac.remote_calls()[-1]
    assert c[-2:] == ["kali-sl", "unlock"] and "-t" in c
    assert_safe_ssh(mac)


def test_usage_and_unknown(mac):
    res = mac.run("rm")
    assert res.returncode == 2 and "Aufruf" in res.stderr
    assert mac.run("--help").returncode == 0


def test_shellcheck_if_available():
    sc = shutil.which("shellcheck")
    if sc is None:
        pytest.skip("shellcheck fehlt")
    from tests.remote.helpers import KALI_SETUP

    res = subprocess.run([sc, "-s", "sh", str(KALI_SETUP)], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stdout
