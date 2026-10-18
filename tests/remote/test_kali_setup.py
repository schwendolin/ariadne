"""``packaging/smartlearn/kali-setup.sh`` im Wegwerf-Root (``ARIADNE_SETUP_ROOT``, Vertrag 3.6).

Zweimal hintereinander ohne Unterschied, jede Änderung vor dem Schreiben gezeigt, Nachfrage,
Trockenlauf, Weg A, B und C, strenge Prüfung der Angaben. Die erzeugten Dateien prüft zusätzlich
``sshd -t`` (als unprivilegierter Benutzer) und ``nft -c``, wenn vorhanden."""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from ariadne.remote import parse as P
from tests.remote.helpers import (
    ARIADNE_BIN,
    KALI_SETUP,
    age_recipient,
    base_root,
    keypair,
    run_setup,
    snapshot,
)

DROPIN = "etc/ssh/sshd_config.d/10-ariadne.conf"
AK = "home/kali/.ssh/authorized_keys"


@pytest.fixture
def root(tmp_path):
    return base_root(tmp_path / "root")


@pytest.fixture
def mac_pub(tmp_path):
    return keypair(tmp_path / "mac", passphrase="Mac-Passphrase-1")


def _fp(pub: Path) -> str:
    out = subprocess.run(["ssh-keygen", "-lf", str(pub)], capture_output=True, text=True, check=True).stdout
    return out.split()[1]


def test_twice_without_difference(root, mac_pub):
    rcp = [age_recipient(), age_recipient()]
    args = ["--weg", "b", "--key-line", mac_pub, "--recipient", rcp[0], "--recipient", rcp[1]]
    first = run_setup(root, *args)
    assert first.returncode == 0, first.stderr
    snap1 = snapshot(root)
    second = run_setup(root, *args)
    assert second.returncode == 0, second.stderr
    assert snapshot(root) == snap1
    assert "Fertig: 0 Änderungen." in second.stdout
    assert "neu:" not in second.stdout and "Änderung:" not in second.stdout
    # dritter Lauf ohne Schlüssel und ohne Empfänger: liest den Schlüssel aus authorized_keys
    third = run_setup(root, "--weg", "b")
    assert third.returncode == 0, third.stderr
    assert snapshot(root) == snap1 and "Fertig: 0 Änderungen." in third.stdout


def test_files_and_modes(root, mac_pub):
    rcp = age_recipient()
    res = run_setup(root, "--weg", "b", "--key-line", mac_pub, "--recipient", rcp)
    assert res.returncode == 0, res.stderr
    # Hostkeys: alte weg, ed25519 neu, Marker mit demselben Fingerprint
    ssh = root / "etc" / "ssh"
    assert not (ssh / "ssh_host_rsa_key").exists() and not (ssh / "ssh_host_rsa_key.pub").exists()
    assert (ssh / "ssh_host_ed25519_key").stat().st_mode & 0o777 == 0o600
    marker = P.parse_marker((ssh / "ariadne-hostkeys.marker").read_text())
    assert marker["fingerprint"] == _fp(ssh / "ssh_host_ed25519_key.pub")
    assert marker["weg"] == "b" and marker["created"].endswith("Z")
    assert marker["fingerprint"] in res.stdout  # zum Notieren gezeigt
    # Drop-in
    cfg = P.parse_sshd_config((root / DROPIN).read_text())
    assert cfg["passwordauthentication"] == ["no"] and cfg["permitopen"] == ["127.0.0.1:7330"]
    assert cfg["allowusers"] == ["kali@100.64.0.0/10"] and cfg["allowtcpforwarding"] == ["local"]
    assert cfg["hostkey"] == ["/etc/ssh/ssh_host_ed25519_key"] and "listenaddress" not in cfg
    # Filter nur über tailscale0, sshd hängt am Filter
    nft = (root / "etc/ariadne/ssh-filter.nft").read_text()
    assert 'iifname "tailscale0" tcp dport 22 accept' in nft and "tcp dport 22 drop" in nft
    dep = (root / "etc/systemd/system/ssh.service.d/ariadne.conf").read_text()
    assert "Requires=ariadne-ssh-filter.service" in dep
    # authorized_keys: genau die Zeile aus R11
    ak = (root / AK).read_text()
    blob = mac_pub.split()[1]
    assert ak == (
        f'restrict,pty,port-forwarding,permitopen="127.0.0.1:7330",command="{ARIADNE_BIN} remote serve" '
        f"ssh-ed25519 {blob} mac-kali-smartlearn\n"
    )
    assert (root / AK).stat().st_mode & 0o777 == 0o600
    assert (root / "home/kali/.ssh").stat().st_mode & 0o777 == 0o700
    rfile = root / "home/kali/.config/ariadne/backup-recipients.txt"
    assert rfile.stat().st_mode & 0o777 == 0o600
    assert [ln for ln in rfile.read_text().splitlines() if not ln.startswith("#")] == [rcp]
    assert (root / "var/lib/systemd/linger/kali").exists()
    # jede Änderung wurde vor dem Schreiben gezeigt
    assert "neu: /etc/ssh/sshd_config.d/10-ariadne.conf" in res.stdout
    assert "  + PasswordAuthentication no" in res.stdout
    assert "Testmodus: sshd -t und systemctl übersprungen." in res.stdout
    # nie Tailscale-Routen oder Exit-Node
    assert "advertise-routes=" not in res.stdout and "Nie --advertise-routes" in res.stdout


def test_answer_no_writes_nothing_and_dry_run(root, mac_pub):
    before = snapshot(root)
    res = run_setup(root, "--key-line", mac_pub, yes=False, stdin="n\n" * 20)
    assert res.returncode == 0, res.stderr
    assert snapshot(root) == before
    assert "übersprungen" in res.stdout and "Fertig: 0 Änderungen." in res.stdout
    res = run_setup(root, "--key-line", mac_pub, "--dry-run", yes=False)
    assert res.returncode == 0, res.stderr
    assert snapshot(root) == before
    assert "Trockenlauf" in res.stdout and "  + PermitOpen 127.0.0.1:7330" in res.stdout


def test_changes_are_shown_as_diff(root, mac_pub):
    assert run_setup(root, "--key-line", mac_pub).returncode == 0
    res = run_setup(root, "--port", "7331")
    assert res.returncode == 0, res.stderr
    assert "Änderung: /etc/ssh/sshd_config.d/10-ariadne.conf" in res.stdout
    assert "-PermitOpen 127.0.0.1:7330" in res.stdout and "+PermitOpen 127.0.0.1:7331" in res.stdout
    assert 'permitopen="127.0.0.1:7331"' in (root / AK).read_text()


def test_hostkeys_only_renewed_on_request(root, mac_pub):
    assert run_setup(root, "--key-line", mac_pub).returncode == 0
    pub = root / "etc/ssh/ssh_host_ed25519_key.pub"
    fp1 = _fp(pub)
    assert run_setup(root).returncode == 0
    assert _fp(pub) == fp1
    res = run_setup(root, "--new-hostkeys")
    assert res.returncode == 0, res.stderr
    fp2 = _fp(pub)
    assert fp2 != fp1
    assert P.parse_marker((root / "etc/ssh/ariadne-hostkeys.marker").read_text())["fingerprint"] == fp2
    # ein von aussen ersetzter Hostkey passt nicht mehr zum Marker: neu erzeugen
    for f in (root / "etc/ssh").glob("ssh_host_ed25519_key*"):
        f.unlink()
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / "etc/ssh/ssh_host_ed25519_key")],
        check=True,
    )
    res = run_setup(root)
    assert "Der Hostkey passt nicht zum Marker" in res.stdout
    assert P.parse_marker((root / "etc/ssh/ariadne-hostkeys.marker").read_text())["fingerprint"] == _fp(pub)


def test_transitional_line_becomes_final_and_ak2_emptied(root, mac_pub):
    ssh_dir = root / "home/kali/.ssh"
    ssh_dir.mkdir(parents=True, mode=0o700)
    (ssh_dir / "authorized_keys").write_text(f"restrict,pty {mac_pub}\n")
    (ssh_dir / "authorized_keys2").write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKk alt\n")
    res = run_setup(root)
    assert res.returncode == 0, res.stderr
    assert "-restrict,pty ssh-ed25519" in res.stdout
    keys = P.parse_authorized_keys((ssh_dir / "authorized_keys").read_text())
    assert len(keys) == 1 and keys[0].values("command") == [f"{ARIADNE_BIN} remote serve"]
    assert P.parse_authorized_keys((ssh_dir / "authorized_keys2").read_text()) == []


def test_two_existing_keys_need_explicit_key(root, mac_pub, tmp_path):
    ssh_dir = root / "home/kali/.ssh"
    ssh_dir.mkdir(parents=True, mode=0o700)
    other = keypair(tmp_path / "other")
    (ssh_dir / "authorized_keys").write_text(f"{mac_pub}\n{other}\n")
    res = run_setup(root)
    assert res.returncode == 1 and "2 Schlüssel" in res.stderr
    res = run_setup(root, "--key-line", mac_pub)
    assert res.returncode == 0, res.stderr
    assert len(P.parse_authorized_keys((ssh_dir / "authorized_keys").read_text())) == 1


def test_symlinked_authorized_keys_is_refused(root, mac_pub, tmp_path):
    ssh_dir = root / "home/kali/.ssh"
    ssh_dir.mkdir(parents=True, mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("nicht anfassen\n")
    (ssh_dir / "authorized_keys").symlink_to(victim)
    res = run_setup(root, "--key-line", mac_pub)
    assert res.returncode == 1 and "Symlink" in res.stderr
    assert victim.read_text() == "nicht anfassen\n"


@pytest.mark.parametrize(
    "args",
    [
        ["--weg", "x"],
        ["--user", "root"],
        ["--user", "Kali;id"],
        ["--ariadne", "/home/kali/bin/my ariadne"],
        ["--ariadne", "/home/kali/bin/evil"],
        ["--port", "80"],
        ["--port", "7330;id"],
        ["--weg", "a"],
        ["--weg", "a", "--allow", "ip saddr 10.0.0.0/8; drop"],
        ["--weg", "c"],
        ["--recipient", "AGE-SECRET-KEY-1QQQ"],
        ["--key-line", "ssh-rsa AAAAB3NzaC1yc2E x"],
        ["--key-line", "ssh-ed25519 AAAA$(id) x"],
        ["--unbekannt"],
    ],
)
def test_bad_arguments_change_nothing(root, args):
    before = snapshot(root)
    res = run_setup(root, *args)
    assert res.returncode != 0
    assert res.stderr.startswith("Fehler:") or "Fehler:" in res.stderr
    assert snapshot(root) == before


def test_missing_include_is_an_error(root, mac_pub):
    (root / "etc/ssh/sshd_config").write_text("PasswordAuthentication yes\n")
    res = run_setup(root, "--key-line", mac_pub)
    assert res.returncode == 1 and "Include" in res.stderr


def test_weg_a_and_c(tmp_path, mac_pub):
    root_a = base_root(tmp_path / "a")
    res = run_setup(root_a, "--weg", "a", "--allow", "ip saddr 10.20.0.0/16", "--key-line", mac_pub)
    assert res.returncode == 0, res.stderr
    assert "ip saddr 10.20.0.0/16 tcp dport 22 accept" in (root_a / "etc/ariadne/ssh-filter.nft").read_text()
    assert P.parse_sshd_config((root_a / DROPIN).read_text())["allowusers"] == ["kali"]
    root_c = base_root(tmp_path / "c")
    res = run_setup(
        root_c,
        "--weg",
        "c",
        "--key-line",
        mac_pub,
        "--server",
        "tunnel@vps.example.org",
        "--server-port",
        "443",
    )
    assert res.returncode == 0, res.stderr
    cfg = P.parse_sshd_config((root_c / DROPIN).read_text())
    assert cfg["listenaddress"] == ["127.0.0.1"] and cfg["allowusers"] == ["kali@127.0.0.1"]
    assert not (root_c / "etc/ariadne/ssh-filter.nft").exists()
    unit = (root_c / "home/kali/.config/systemd/user/ariadne-revtunnel.service").read_text()
    assert "-R 127.0.0.1:2222:127.0.0.1:22 tunnel@vps.example.org" in unit and "-p 443" in unit
    assert "StrictHostKeyChecking=yes" in unit
    assert (root_c / "home/kali/.ssh/id_ed25519_rendezvous").exists()
    assert 'permitlisten="127.0.0.1:2222"' in res.stdout
    snap = snapshot(root_c)
    again = run_setup(root_c, "--weg", "c", "--server", "tunnel@vps.example.org", "--server-port", "443")
    assert again.returncode == 0 and snapshot(root_c) == snap


def test_refuses_without_root_or_test_root(tmp_path):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}
    argv = ["sh", str(KALI_SETUP), "--user", "kali", "--home", "/home/kali", "--dry-run"]
    if os.getuid() == 0:
        if shutil.which("runuser") is None:
            pytest.skip("runuser fehlt")
        argv = ["runuser", "-u", "nobody", "--", *argv]
    res = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30, check=False, cwd="/")
    assert res.returncode == 1 and "sudo" in res.stderr


def _unprivileged() -> str | None:
    if os.getuid() != 0:
        return None
    for name in (os.environ.get("ARIADNE_TEST_SSH_USER"), "ubuntu", "nobody"):
        if not name:
            continue
        try:
            pwd.getpwnam(name)
            return name
        except KeyError:
            continue
    return None


def test_generated_files_pass_sshd_t_and_nft_check(mac_pub):
    """Die Dateien sind für das echte OpenSSH und nft gültig (Syntax), nicht nur für unsere Parser."""
    sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
    if sshd is None:
        pytest.skip("sshd fehlt")
    # tmp_path gehört root mit 0700; sshd -t läuft als unprivilegierter Benutzer in einem eigenen Ordner
    work = Path(tempfile.mkdtemp(prefix="ariadne-sshdt-", dir="/tmp"))
    try:
        _sshd_t_and_nft(work, sshd, mac_pub)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _sshd_t_and_nft(work: Path, sshd: str, mac_pub: str) -> None:
    os.chmod(work, 0o755)
    root = base_root(work / "root")
    assert run_setup(root, "--key-line", mac_pub).returncode == 0
    dropin = (
        (root / DROPIN)
        .read_text()
        .replace("/etc/ssh/ssh_host_ed25519_key", str(root / "etc/ssh/ssh_host_ed25519_key"))
    )
    cfg = work / "sshd_config"
    cfg.write_text(dropin + "Port 22222\nPidFile none\n")
    user = _unprivileged()
    argv = [sshd, "-t", "-f", str(cfg)]
    if user is not None:
        shutil.chown(root / "etc/ssh/ssh_host_ed25519_key", user)
        for p in (work, root, root / "etc", root / "etc/ssh"):
            os.chmod(p, 0o755)
        argv = ["runuser", "-u", user, "--", *argv]
    res = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    assert res.returncode == 0, res.stderr
    nft = shutil.which("nft") or ("/usr/sbin/nft" if os.path.exists("/usr/sbin/nft") else None)
    if nft is None:
        return
    res = subprocess.run(
        [nft, "-c", "-f", str(root / "etc/ariadne/ssh-filter.nft")],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if res.returncode != 0 and ("Operation not permitted" in res.stderr or "Permission denied" in res.stderr):
        return  # ohne CAP_NET_ADMIN prüft nft nicht
    assert res.returncode == 0, res.stderr
