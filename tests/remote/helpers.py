"""Hilfen für die Tests des Teils «remote»: Wegwerf-Root mit ``kali-setup.sh``, nachgebautes
``/proc``, Runner mit festen Antworten (Fixtures statt echter Programme)."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

from ariadne.remote.check import RunResult, System

REPO = Path(__file__).resolve().parents[2]
KALI_SETUP = REPO / "packaging" / "smartlearn" / "kali-setup.sh"
MAC_HELPER = REPO / "packaging" / "mac" / "ariadne-mac"
ARIADNE_BIN = "/home/kali/.local/bin/ariadne"

LISTEN = 0x0A
ESTABLISHED = 0x01


def keypair(path: Path, *, passphrase: str = "", comment: str = "mac-kali-smartlearn") -> str:
    """Erzeugt einen ed25519-Schlüssel und gibt die öffentliche Zeile zurück."""
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-C", comment, "-f", str(path)], check=True
    )
    return Path(f"{path}.pub").read_text().strip()


def age_recipient() -> str:
    from pyrage import x25519

    return str(x25519.Identity.generate().to_public())


def run_setup(
    root: Path,
    *args: str,
    user: str = "kali",
    home: str = "/home/kali",
    yes: bool = True,
    stdin: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Startet ``kali-setup.sh`` im Wegwerf-Root (Testmodus, kein root nötig)."""
    root.mkdir(parents=True, exist_ok=True)
    e = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C.UTF-8",
        "ARIADNE_SETUP_ROOT": str(root),
        "HOME": str(root / "nohome"),
    }
    e.update(env or {})
    argv = ["sh", str(KALI_SETUP), "--user", user, "--home", home, "--ariadne", ARIADNE_BIN, *args]
    if yes:
        argv.append("--yes")
    return subprocess.run(argv, capture_output=True, text=True, env=e, input=stdin, timeout=60, check=False)


def base_root(root: Path) -> Path:
    """Wurzel mit einem ``sshd_config`` wie bei Debian (Include ganz oben) und Hostkeys der Vorlage."""
    (root / "etc" / "ssh").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "ssh" / "sshd_config").write_text(
        "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\n"
        "X11Forwarding yes\nAcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n"
    )
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "rsa",
            "-b",
            "1024",
            "-N",
            "",
            "-f",
            str(root / "etc" / "ssh" / "ssh_host_rsa_key"),
        ],
        check=True,
    )
    return root


def snapshot(root: Path) -> dict[str, tuple[str, bytes | None]]:
    """Alle Pfade unter ``root`` mit Rechten und Inhalt (für «zweimal ohne Unterschied»)."""
    out: dict[str, tuple[str, bytes | None]] = {}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        rel = str(p.relative_to(root))
        out[rel] = (oct(st.st_mode), p.read_bytes() if p.is_file() and not p.is_symlink() else None)
    return out


# --------------------------------------------------------------------------- #
# /proc
# --------------------------------------------------------------------------- #


def _hex_addr(host: str, port: int) -> str:
    addr = ipaddress.ip_address(host)
    raw = addr.packed
    if isinstance(addr, ipaddress.IPv4Address):
        return f"{struct.unpack('<I', raw)[0]:08X}:{port:04X}"
    words = "".join(f"{struct.unpack('<I', raw[i : i + 4])[0]:08X}" for i in range(0, 16, 4))
    return f"{words}:{port:04X}"


def proc_net(entries: Iterable[tuple[str, int, int]], *, uid: int = 1000) -> str:
    """``/proc/net/tcp(6)``-Text aus ``(adresse, port, zustand)``; nur Little Endian (x86, arm64)."""
    assert sys.byteorder == "little"
    lines = [
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    ]
    for n, (host, port, state) in enumerate(entries):
        v6 = ":" in host
        remote = _hex_addr("::" if v6 else "0.0.0.0", 0)
        lines.append(
            f"  {n}: {_hex_addr(host, port)} {remote} {state:02X} 00000000:00000000 00:00000000 "
            f"00000000  {uid}        0 {1000 + n} 1 0000000000000000 100 0 0 10 0"
        )
    return "\n".join(lines) + "\n"


def fake_proc(base: Path, listeners: Sequence[tuple[str, int]] = (), swaps: str | None = None) -> Path:
    proc = base / "proc"
    (proc / "net").mkdir(parents=True, exist_ok=True)
    v4 = [(h, p, LISTEN) for h, p in listeners if ":" not in h]
    v6 = [(h, p, LISTEN) for h, p in listeners if ":" in h]
    (proc / "net" / "tcp").write_text(proc_net(v4))
    (proc / "net" / "tcp6").write_text(proc_net(v6))
    (proc / "swaps").write_text(swaps or "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n")
    return proc


# --------------------------------------------------------------------------- #
# Runner mit Fixtures
# --------------------------------------------------------------------------- #

GOOD_PREFS = {
    "ControlURL": "https://controlplane.tailscale.com",
    "RouteAll": False,
    "ExitNodeID": "",
    "ExitNodeIP": "",
    "CorpDNS": False,
    "RunSSH": False,
    "WantRunning": True,
    "AdvertiseRoutes": None,
    "AdvertiseTags": ["tag:kali-lab"],
    "ShieldsUp": False,
}

SSHD_T_GOOD = """port 22
addressfamily any
listenaddress [::]:22
listenaddress 0.0.0.0:22
permitrootlogin no
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
authenticationmethods publickey
allowtcpforwarding local
allowagentforwarding no
allowstreamlocalforwarding no
x11forwarding no
gatewayports no
permittunnel no
permituserenvironment no
allowusers kali@100.64.0.0/10
acceptenv LANG
acceptenv LC_*
hostkey /etc/ssh/ssh_host_ed25519_key
permitopen 127.0.0.1:7330
permitlisten none
"""

NFT_GOOD = """table inet ariadne_ssh {
\tchain input {
\t\ttype filter hook input priority -10; policy accept;
\t\tiifname "lo" accept
\t\tiifname "tailscale0" tcp dport 22 accept
\t\ttcp dport 22 drop
\t}
}
"""


class FakeRunner:
    """Antworten nach dem Programmnamen und den ersten Argumenten; ``None`` = Programm fehlt."""

    def __init__(self, responses: dict[tuple[str, ...], RunResult | None] | None = None) -> None:
        self.responses: dict[tuple[str, ...], RunResult | None] = dict(good_responses())
        self.responses.update(responses or {})
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str]) -> RunResult | None:
        argv = list(argv)
        self.calls.append(argv)
        if argv[:2] == ["sudo", "-n"]:
            argv = argv[2:]
        best: tuple[str, ...] | None = None
        for key in self.responses:
            if tuple(argv[: len(key)]) == key and (best is None or len(key) > len(best)):
                best = key
        return None if best is None else self.responses[best]


def good_responses() -> dict[tuple[str, ...], RunResult | None]:
    return {
        ("systemctl", "is-active", "ariadne-ssh-filter.service"): RunResult(0, "active\n"),
        ("systemctl", "show", "ssh.service", "-p", "Requires", "--value"): RunResult(
            0, "system.slice ariadne-ssh-filter.service sysinit.target\n"
        ),
        ("systemctl", "is-active", "ssh.socket"): RunResult(3, "inactive\n"),
        ("systemctl", "is-enabled", "ssh.socket"): RunResult(1, "disabled\n"),
        ("systemctl", "is-active", "open-vm-tools.service"): RunResult(3, "inactive\n"),
        ("ssh", "-V"): RunResult(0, "", "OpenSSH_10.0p2 Debian-5, OpenSSL 3.5.1 1 Jul 2025\n"),
        ("tailscale", "debug", "prefs"): RunResult(0, json.dumps(GOOD_PREFS)),
        ("tailscale", "serve", "status", "--json"): RunResult(0, "{}\n"),
        ("sshd", "-T"): RunResult(0, SSHD_T_GOOD),
        ("nft", "list", "table", "inet", "ariadne_ssh"): RunResult(0, NFT_GOOD),
    }


def make_system(root: Path, proc: Path, runner: FakeRunner, *, user: str = "kali") -> System:
    linger = root / "var" / "lib" / "systemd" / "linger"
    linger.mkdir(parents=True, exist_ok=True)
    (linger / user).touch()
    return System(
        root=root,
        proc_root=str(proc),
        runner=runner,
        user=user,
        uid=os.getuid(),
        sudo=("sudo", "-n"),
        env={"XDG_RUNTIME_DIR": "/run/user/1000"},
    )


def install_keys(root: Path, home: Path, user_home: str = "/home/kali") -> None:
    """Überträgt die von ``kali-setup.sh`` geschriebenen Benutzerdateien ins Test-Home."""
    src = root / user_home.lstrip("/")
    for rel in (".ssh/authorized_keys", ".config/ariadne/backup-recipients.txt"):
        if (src / rel).exists():
            (home / rel).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(src / rel, home / rel)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
