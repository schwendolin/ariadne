"""T14 ``ariadne remote check`` (R10) mit Fixtures: Wegwerf-Root aus ``kali-setup.sh``,
nachgebautes ``/proc``, Runner mit festen Antworten. Nie root, nie echte Systemdateien."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ariadne.cli.doctor import FAIL, OK, WARN
from ariadne.cli.remote import ensure_runtime_dir
from ariadne.remote import check
from ariadne.remote import parse as P
from ariadne.remote.check import RunResult
from tests.remote.helpers import (
    GOOD_PREFS,
    SSHD_T_GOOD,
    FakeRunner,
    age_recipient,
    base_root,
    fake_proc,
    install_keys,
    keypair,
    make_system,
    run_setup,
)

LOOP_ONLY = [("127.0.0.1", 7330), ("0.0.0.0", 22), ("::", 22)]


@pytest.fixture
def kali(tmp_path, paths):
    """Kali nach ``kali-setup.sh --weg b`` im Wegwerf-Root, Benutzerdateien im Test-Home."""
    root = base_root(tmp_path / "root")
    pub = keypair(tmp_path / "mac", passphrase="Mac-Passphrase-1")
    res = run_setup(root, "--weg", "b", "--key-line", pub, "--recipient", age_recipient())
    assert res.returncode == 0, res.stderr
    install_keys(root, paths.home)
    return root


def system_for(kali_root: Path, tmp_path: Path, listeners=LOOP_ONLY):
    runner = FakeRunner()
    proc = fake_proc(tmp_path, listeners)
    return make_system(kali_root, proc, runner), runner


def levels(checks, level):
    return [c.title for c in checks if c.level == level]


def test_good_setup_has_no_fail_and_quick_ok(kali, tmp_path, paths):
    system, runner = system_for(kali, tmp_path)
    checks = check.run_checks(paths, full=True, system=system)
    assert levels(checks, FAIL) == [], checks
    titles = levels(checks, OK)
    assert "Hostkeys selbst erzeugt" in titles
    assert "authorized_keys: ein eingeschränkter Schlüssel" in titles
    assert "Drop-in 10-ariadne.conf vollständig" in titles
    assert "Port 22: Filter-Unit aktiv" in titles  # mit --full, die Tabelle prüft nft
    assert "sshd -T: alle Werte wie erwartet" in titles
    assert "Filter ariadne_ssh geladen" in titles
    assert "Weg B" in titles
    assert check.quick_ok(paths, system)
    # root nur für sshd -T, nft und (mit --full) tailscale, immer über sudo -n
    rooted = [c for c in runner.calls if c[:2] == ["sudo", "-n"]]
    assert {c[2] for c in rooted} == {"sshd", "nft", "tailscale"}
    sshd = next(c for c in rooted if c[2] == "sshd")
    assert sshd[3:5] == ["-T", "-C"] and sshd[5].startswith("user=kali,host=pruefung,addr=")


def test_quick_ok_runs_only_programs_without_root(kali, tmp_path, paths):
    """Die Sperre vor ``code`` nutzt nur Programme ohne root (systemctl, tailscale). Fehlen sie oder
    läuft systemd nicht (Container), warnt sie; lauscht sshd dann auf Port 22 ausserhalb von
    Loopback, ist der Filter nicht bestätigt: fail (fail-closed)."""
    system, runner = system_for(kali, tmp_path)
    assert check.quick_ok(paths, system)
    assert runner.calls and all(c[0] in ("systemctl", "tailscale") for c in runner.calls)
    offline = RunResult(1, "", "System has not been booted with systemd as init system (PID 1).\n")
    for missing in (None, offline):
        system, runner = system_for(kali, tmp_path)
        for key in list(runner.responses):
            if key[0] == "systemctl":
                runner.responses[key] = missing
        checks = check.quick_checks(paths, system)
        assert "systemctl fehlt: Filter und ssh.socket nicht geprüft" in levels(checks, WARN)
        assert "Port 22 offen ohne Filter" in levels(checks, FAIL) and not check.quick_ok(paths, system)


def test_port_22_without_full_is_only_a_warning(kali, tmp_path, paths):
    """F10 (Anleitung): Die Filter-Unit bleibt «active», auch wenn ``nft flush ruleset`` die Tabelle
    löschte. Ohne ``--full`` (ohne root) ist «aktiv» darum kein ok, sondern eine Warnung."""
    system, _ = system_for(kali, tmp_path)
    checks = check.run_checks(paths, system=system)
    assert "Port 22: Filter-Unit aktiv, Tabelle nicht geprüft" in levels(checks, WARN)
    assert not any(t.startswith("Port 22") for t in levels(checks, OK))


@pytest.mark.parametrize(
    ("change", "title"),
    [
        ("dropin_password", "Drop-in unvollständig"),
        ("dropin_streamlocal", "Drop-in unvollständig"),
        ("routes", "Tailscale gibt Routen frei"),
        ("ssh_socket", "ssh.socket aktiv"),
        ("requires", "sshd startet auch ohne Filter"),
        ("earlier_dropin", "Drop-in wird überstimmt"),
    ],
)
def test_r10_quick_ok_refuses_every_fail_without_root(kali, tmp_path, paths, change, title):
    """SEC-R2/F4: R10 «kein Code, solange die Prüfung ohne root fail meldet» gilt für alle Prüfungen
    ohne root, nicht nur für Bindung, Marker und ``authorized_keys``."""
    system, runner = system_for(kali, tmp_path)
    dropin = system.path(check.DROPIN)
    if change == "dropin_password":
        text = dropin.read_text().replace("PasswordAuthentication no", "PasswordAuthentication yes")
        dropin.write_text(text)
    elif change == "dropin_streamlocal":
        dropin.write_text(dropin.read_text().replace("AllowStreamLocalForwarding no",
                                                     "AllowStreamLocalForwarding yes"))
    elif change == "routes":
        runner.responses[("tailscale", "debug", "prefs")] = RunResult(
            0, json.dumps(dict(GOOD_PREFS, AdvertiseRoutes=["192.168.110.0/24"])))
    elif change == "ssh_socket":
        runner.responses[("systemctl", "is-active", "ssh.socket")] = RunResult(0, "active\n")
    elif change == "requires":
        runner.responses[("systemctl", "show", "ssh.service", "-p", "Requires", "--value")] = RunResult(
            0, "system.slice\n")
    else:
        (dropin.parent / "05-andere.conf").write_text("PasswordAuthentication yes\n")
    assert title in levels(check.quick_checks(paths, system), FAIL)
    assert not check.quick_ok(paths, system)


@pytest.mark.parametrize(
    ("key", "value", "title"),
    [
        ("passwordauthentication", "yes", "sshd: passwordauthentication yes"),
        ("allowtcpforwarding", "yes", "sshd: allowtcpforwarding yes"),
        ("permitopen", "any", "sshd: permitopen any"),
        ("x11forwarding", "yes", "sshd: x11forwarding yes"),
        ("permitlisten", "any", "sshd: permitlisten any"),
    ],
)
def test_t14_sshd_t_fixtures_fail(kali, tmp_path, paths, key, value, title):
    lines = [ln for ln in SSHD_T_GOOD.splitlines() if not ln.startswith(key + " ")]
    out = "\n".join([*lines, f"{key} {value}"]) + "\n"
    system, _ = system_for(kali, tmp_path)
    system.runner.responses[("sshd", "-T")] = RunResult(0, out)
    checks = check.run_checks(paths, full=True, system=system)
    assert title in levels(checks, FAIL)


def test_sshd_t_error_and_missing_sudo(kali, tmp_path, paths):
    system, _ = system_for(kali, tmp_path)
    system.runner.responses[("sshd", "-T")] = RunResult(
        255, "", "/etc/ssh/sshd_config line 3: Bad \x1b[31m\n"
    )
    checks = check.run_checks(paths, full=True, system=system)
    bad = [c for c in checks if c.title == "sshd -T meldet einen Fehler"]
    assert bad and "\x1b" not in bad[0].detail  # Ausgabe fremder Programme nur sichtbar gemacht
    system.runner.responses[("sshd", "-T")] = None
    checks = check.run_checks(paths, full=True, system=system)
    assert "sshd -T nicht ausführbar" in levels(checks, WARN)


def test_t14_web_port_on_all_interfaces_fails(kali, tmp_path, paths):
    system, _ = system_for(kali, tmp_path, listeners=[("0.0.0.0", 7330)])
    assert "Port 7330 lauscht nicht nur auf Loopback" in levels(check.run_checks(paths, system=system), FAIL)
    assert not check.quick_ok(paths, system)
    system, _ = system_for(kali, tmp_path, listeners=[("::", 7330), ("::1", 7330)])
    assert not check.quick_ok(paths, system)
    system, _ = system_for(kali, tmp_path, listeners=[("::1", 7330)])
    assert check.quick_ok(paths, system)


def test_t14_web_bind_config_forbidden(kali, tmp_path, paths):
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text('[ui]\nbind = "0.0.0.0"\n')
    system, _ = system_for(kali, tmp_path)
    assert "Web-Oberfläche: Konfiguration [ui] verboten" in levels(
        check.run_checks(paths, system=system), FAIL
    )
    assert not check.quick_ok(paths, system)


def test_t14_port_22_without_filter(kali, tmp_path, paths):
    system, _ = system_for(kali, tmp_path)
    system.runner.responses[("systemctl", "is-active", "ariadne-ssh-filter.service")] = RunResult(
        3, "inactive\n"
    )
    system.runner.responses[("systemctl", "show", "ssh.service", "-p", "Requires", "--value")] = RunResult(
        0, "system.slice sysinit.target\n"
    )
    fails = levels(check.run_checks(paths, system=system), FAIL)
    assert "Port 22 offen ohne Filter" in fails
    assert "sshd startet auch ohne Filter" in fails
    # nicht lauschender sshd ist in Ordnung, die fehlende Abhängigkeit bleibt ein Fehler
    system, _ = system_for(kali, tmp_path, listeners=[("127.0.0.1", 7330)])
    system.runner.responses[("systemctl", "show", "ssh.service", "-p", "Requires", "--value")] = RunResult(
        0, ""
    )
    fails = levels(check.run_checks(paths, system=system), FAIL)
    assert "Port 22 offen ohne Filter" not in fails and "sshd startet auch ohne Filter" in fails


def test_t14_ssh_socket_active(kali, tmp_path, paths):
    system, _ = system_for(kali, tmp_path)
    system.runner.responses[("systemctl", "is-active", "ssh.socket")] = RunResult(0, "active\n")
    assert "ssh.socket aktiv" in levels(check.run_checks(paths, system=system), FAIL)
    system.runner.responses[("systemctl", "is-active", "ssh.socket")] = RunResult(3, "inactive\n")
    system.runner.responses[("systemctl", "is-enabled", "ssh.socket")] = RunResult(0, "enabled\n")
    assert "ssh.socket aktiv" in levels(check.run_checks(paths, system=system), FAIL)


def test_t14_hostkey_without_marker_or_replaced(kali, tmp_path, paths):
    system, _ = system_for(kali, tmp_path)
    marker = kali / "etc/ssh/ariadne-hostkeys.marker"
    text = marker.read_text()
    marker.unlink()
    assert "Hostkey-Marker fehlt" in levels(check.run_checks(paths, system=system), FAIL)
    assert not check.quick_ok(paths, system)
    marker.write_text(text)
    assert check.quick_ok(paths, system)
    # Hostkey ersetzt (z. B. durch die Vorlage): Marker passt nicht mehr
    for f in (kali / "etc/ssh").glob("ssh_host_ed25519_key*"):
        f.unlink()
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(kali / "etc/ssh/ssh_host_ed25519_key")],
        check=True,
    )
    assert "Hostkey passt nicht zum Marker" in levels(check.run_checks(paths, system=system), FAIL)
    assert not check.quick_ok(paths, system)


def test_old_template_hostkeys_warn(kali, tmp_path, paths):
    (kali / "etc/ssh/ssh_host_ecdsa_key.pub").write_text("ecdsa-sha2-nistp256 AAAA x\n")
    system, _ = system_for(kali, tmp_path)
    assert "weitere Hostkeys vorhanden" in levels(check.run_checks(paths, system=system), WARN)


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda line: line.replace("restrict,", ""), "ohne restrict"),
        (lambda line: line.replace('permitopen="127.0.0.1:7330"', 'permitopen="127.0.0.1:22"'), "permitopen"),
        (lambda line: line.replace('permitopen="127.0.0.1:7330",', ""), "permitopen"),
        (
            lambda line: line.replace(
                'permitopen="127.0.0.1:7330"', 'permitopen="127.0.0.1:7330",permitopen="*:*"'
            ),
            "permitopen",
        ),
        (lambda line: line.replace("remote serve", "remote serve; id"), "command"),
        (lambda line: line.replace(',command="/home/kali/.local/bin/ariadne remote serve"', ""), "command"),
        (lambda line: line.replace("pty,", "pty,agent-forwarding,"), "agent-forwarding erlaubt"),
        (lambda line: line.replace("pty,", 'pty,permitlisten="0.0.0.0:80",'), "permitlisten erlaubt"),
        (
            lambda line: (
                line.split(" ssh-ed25519 ", 1)[0][:-1] + " ssh-ed25519 " + line.split(" ssh-ed25519 ", 1)[1]
            ),
            "nicht sauber lesbar",
        ),
    ],
)
def test_t14_authorized_keys_not_restricted(kali, tmp_path, paths, mutate, needle):
    ak = paths.home / ".ssh" / "authorized_keys"
    ak.write_text(mutate(ak.read_text().strip()) + "\n")
    system, _ = system_for(kali, tmp_path)
    bad = [
        c
        for c in check.run_checks(paths, system=system)
        if c.level == FAIL and c.title.startswith("authorized_keys Zeile 1")
    ]
    assert bad and needle in bad[0].detail, bad
    assert not check.quick_ok(paths, system)


def test_t14_second_key_or_authorized_keys2(kali, tmp_path, paths):
    ak = paths.home / ".ssh" / "authorized_keys"
    good = ak.read_text()
    other = keypair(tmp_path / "other")
    ak.write_text(good + other + "\n")
    system, _ = system_for(kali, tmp_path)
    fails = levels(check.run_checks(paths, system=system), FAIL)
    assert "authorized_keys: 2 Schlüssel, erwartet genau einer" in fails
    assert "authorized_keys Zeile 2: nicht eingeschränkt" in fails
    assert not check.quick_ok(paths, system)
    ak.write_text(good)
    (paths.home / ".ssh" / "authorized_keys2").write_text("# leer\n" + other + "\n")
    assert "authorized_keys2 enthält Schlüssel" in levels(check.run_checks(paths, system=system), FAIL)
    (paths.home / ".ssh" / "authorized_keys2").write_text("# nur Kommentar\n")
    assert check.quick_ok(paths, system)
    ak.unlink()
    assert "authorized_keys fehlt" in levels(check.run_checks(paths, system=system), FAIL)


def test_authorized_keys_follows_configured_port(kali, tmp_path, paths):
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("[ui]\nport = 7331\n")
    system, _ = system_for(kali, tmp_path)
    assert not check.quick_ok(paths, system)  # Zeile erlaubt 7330, Daemon nutzt 7331
    ak = paths.home / ".ssh" / "authorized_keys"
    ak.write_text(ak.read_text().replace("127.0.0.1:7330", "127.0.0.1:7331"))
    assert not check.quick_ok(paths, system)  # das Drop-in erlaubt (PermitOpen) noch 7330
    dropin = system.path(check.DROPIN)
    dropin.write_text(dropin.read_text().replace("127.0.0.1:7330", "127.0.0.1:7331"))
    assert check.quick_ok(paths, system)


def test_t14_tailscale_routes_exit_node_ssh_serve(kali, tmp_path, paths):
    for prefs, title in [
        (dict(GOOD_PREFS, AdvertiseRoutes=["192.168.110.0/24"]), "Tailscale gibt Routen frei"),
        (dict(GOOD_PREFS, AdvertiseRoutes=["0.0.0.0/0", "::/0"]), "Tailscale gibt einen Exit-Node frei"),
        (dict(GOOD_PREFS, ExitNodeID="nXYZ"), "Tailscale nutzt einen Exit-Node"),
        (dict(GOOD_PREFS, RunSSH=True), "Tailscale SSH ist an"),
    ]:
        system, _ = system_for(kali, tmp_path)
        system.runner.responses[("tailscale", "debug", "prefs")] = RunResult(0, json.dumps(prefs))
        assert title in levels(check.run_checks(paths, system=system), FAIL)
    system, _ = system_for(kali, tmp_path)
    system.runner.responses[("tailscale", "serve", "status", "--json")] = RunResult(
        0, '{"TCP": {"443": {"HTTPS": true}}}'
    )
    assert "Tailscale Serve oder Funnel aktiv" in levels(check.run_checks(paths, system=system), FAIL)
    system.runner.responses[("tailscale", "debug", "prefs")] = RunResult(
        0, json.dumps(dict(GOOD_PREFS, RouteAll=True))
    )
    system.runner.responses[("tailscale", "serve", "status", "--json")] = RunResult(0, "{}")
    checks = check.run_checks(paths, system=system)
    assert "Tailscale nimmt Routen an" in levels(checks, WARN)
    system.runner.responses[("tailscale", "debug", "prefs")] = None
    assert "Tailscale nicht gefunden" in levels(check.run_checks(paths, system=system), WARN)


def test_t14_openssh_version(kali, tmp_path, paths):
    system, _ = system_for(kali, tmp_path)
    system.runner.responses[("ssh", "-V")] = RunResult(
        0, "", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13\n"
    )
    checks = check.run_checks(paths, system=system)
    assert "OpenSSH 9.6: älter als 9.8" in levels(checks, WARN)
    assert not any("OpenSSH" in t for t in levels(checks, FAIL))
    system.runner.responses[("ssh", "-V")] = RunResult(0, "", "OpenSSH_9.8p1 Debian-1\n")
    assert "OpenSSH 9.8" in levels(check.run_checks(paths, system=system), OK)


def test_dropin_missing_overridden_or_not_included(kali, tmp_path, paths):
    system, _ = system_for(kali, tmp_path)
    early = kali / "etc/ssh/sshd_config.d/05-image.conf"
    early.write_text("PasswordAuthentication yes\n")
    assert "Drop-in wird überstimmt" in levels(check.run_checks(paths, system=system), FAIL)
    early.unlink()
    (kali / "etc/ssh/sshd_config.d/50-cloud-init.conf").write_text("PasswordAuthentication yes\n")
    assert "Drop-in wird überstimmt" not in levels(check.run_checks(paths, system=system), FAIL)
    main = kali / "etc/ssh/sshd_config"
    main.write_text("X11Forwarding yes\n")
    assert "Drop-in wird nicht geladen" in levels(check.run_checks(paths, system=system), FAIL)
    main.write_text("Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\n")
    assert "Include steht nicht ganz oben in sshd_config" in levels(
        check.run_checks(paths, system=system), WARN
    )
    dropin = kali / "etc/ssh/sshd_config.d/10-ariadne.conf"
    dropin.write_text(dropin.read_text().replace("AllowTcpForwarding local", "AllowTcpForwarding yes"))
    assert "Drop-in unvollständig" in levels(check.run_checks(paths, system=system), FAIL)
    dropin.unlink()
    assert "Drop-in 10-ariadne.conf fehlt" in levels(check.run_checks(paths, system=system), FAIL)


def test_weg_c_requires_loopback(tmp_path, paths):
    root = base_root(tmp_path / "root")
    pub = keypair(tmp_path / "mac", passphrase="x-Passphrase")
    res = run_setup(root, "--weg", "c", "--key-line", pub, "--server", "tunnel@example.org")
    assert res.returncode == 0, res.stderr
    install_keys(root, paths.home)
    system, _ = system_for(root, tmp_path, listeners=[("127.0.0.1", 22)])
    checks = check.run_checks(paths, system=system)
    assert levels(checks, FAIL) == [], checks
    assert "sshd nur auf Loopback (Weg C)" in levels(checks, OK)
    system, _ = system_for(root, tmp_path, listeners=[("0.0.0.0", 22)])
    assert "Weg C: sshd lauscht ausserhalb von Loopback" in levels(
        check.run_checks(paths, system=system), FAIL
    )


def test_vm_tools_swap_runtime(kali, tmp_path, paths):
    system, _ = system_for(kali, tmp_path)
    system.runner.responses[("systemctl", "is-active", "open-vm-tools.service")] = RunResult(0, "active\n")
    swaps = "Filename\tType\tSize\tUsed\tPriority\n/dev/sda5\tpartition\t1000\t0\t-2\n"
    system.proc_root = str(fake_proc(tmp_path / "p2", [("127.0.0.1", 7330)], swaps=swaps))
    system.env = {}
    (kali / "var/lib/systemd/linger/kali").unlink()
    warns = levels(check.run_checks(paths, system=system), WARN)
    assert {"open-vm-tools aktiv", "Swap unverschlüsselt", "kein Runtime-Ordner", "kein linger"} <= set(warns)


def test_runner_errors_never_crash(kali, tmp_path, paths):
    def boom(argv):
        raise RuntimeError("kaputt")

    system, _ = system_for(kali, tmp_path)
    system.runner = boom
    checks = check.run_checks(paths, full=True, system=system)
    assert "systemctl fehlt: Filter und ssh.socket nicht geprüft" in levels(checks, WARN)


def test_quick_ok_fails_closed_on_exception(paths, monkeypatch):
    monkeypatch.setattr(check, "quick_checks", lambda *a, **k: 1 / 0)
    assert check.quick_ok(paths) is False


def test_render_like_doctor():
    lines, worst = check.render(
        [check.Check(OK, "a"), check.Check(WARN, "b", "x"), check.Check(FAIL, "c\x1b[2J")]
    )
    assert (
        lines[0] == "[ok] a"
        and lines[1] == "[--] b: x"
        and lines[2].startswith("[!!] c")
        and "\x1b" not in lines[2]
    )
    assert worst == 1
    assert check.render([check.Check(OK, "a")])[1] == 0


def test_cli_remote_check_exit_code(tmp_path, xdg):
    root = tmp_path / "leer"
    root.mkdir()
    env = dict(os.environ, **xdg, ARIADNE_SETUP_ROOT=str(root))
    res = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; from ariadne.cli.main import main; sys.exit(main(sys.argv[1:]))",
            "remote",
            "check",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert res.returncode == 1
    assert "[!!] Hostkey-Marker fehlt" in res.stdout
    assert "[!!] authorized_keys fehlt" in res.stdout


def test_ensure_runtime_dir(tmp_path):
    run = tmp_path / "run"
    (run / str(os.getuid())).mkdir(parents=True, mode=0o700)
    env: dict[str, str] = {}
    assert ensure_runtime_dir(env, run_root=str(run))
    assert env["XDG_RUNTIME_DIR"] == str(run / str(os.getuid()))
    env = {"XDG_RUNTIME_DIR": "/x"}
    assert ensure_runtime_dir(env, run_root=str(run)) and env["XDG_RUNTIME_DIR"] == "/x"
    os.chmod(run / str(os.getuid()), 0o755)
    env = {}
    assert not ensure_runtime_dir(env, run_root=str(run)) and "XDG_RUNTIME_DIR" not in env
    env = {}
    assert not ensure_runtime_dir(env, uid=4242, run_root=str(run))


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def test_parse_authorized_keys_options():
    text = (
        "# Kommentar\n\n"
        'restrict,pty,port-forwarding,permitopen="127.0.0.1:7330",command="/x/ariadne remote serve" '
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxJ mac\n"
        'from="10.0.0.1,10.0.0.2",command="echo \\"a, b\\"" ssh-ed25519 AAAAB x y z\n'
        "ssh-ed25519 AAAAC3 ohne-optionen\n"
        'command="offen ssh-ed25519 AAAA\n'
        "unbekannt AAAA\n"
    )
    keys = P.parse_authorized_keys(text)
    assert len(keys) == 5
    k = keys[0]
    assert k.line_no == 3 and k.keytype == "ssh-ed25519" and k.comment == "mac" and not k.bad_options
    assert k.values("permitopen") == ["127.0.0.1:7330"] and k.values("command") == ["/x/ariadne remote serve"]
    assert k.has("restrict") and k.has("pty")
    assert keys[1].values("from") == ["10.0.0.1,10.0.0.2"] and keys[1].values("command") == ['echo "a, b"']
    assert keys[1].comment == "x y z"
    assert keys[2].options == () and keys[2].comment == "ohne-optionen"
    assert keys[3].bad_options and keys[4].bad_options


def test_fingerprint_matches_ssh_keygen(tmp_path):
    pub = keypair(tmp_path / "k")
    out = subprocess.run(
        ["ssh-keygen", "-lf", str(tmp_path / "k.pub")], capture_output=True, text=True, check=True
    ).stdout.split()[1]
    assert P.pubkey_fingerprint(pub) == ("ssh-ed25519", out)
    assert P.key_fingerprint("nicht base64!") is None


def test_parse_misc():
    assert P.parse_openssh_version("OpenSSH_9.6p1 Ubuntu") == (9, 6)
    assert P.parse_openssh_version("OpenSSH_10.0p2") == (10, 0)
    assert P.parse_openssh_version("nichts") is None
    cfg = P.parse_sshd_config("# x\nAllowUsers\tkali bob\nPermitOpen=127.0.0.1:7330\nX11Forwarding  no\n")
    assert cfg["allowusers"] == ["kali bob"] and cfg["permitopen"] == ["127.0.0.1:7330"]
    assert cfg["x11forwarding"] == ["no"]
    t = P.parse_sshd_t("acceptenv LANG\nacceptenv LC_*\nport 22\n")
    assert t["acceptenv"] == ["LANG", "LC_*"]
    assert P.parse_marker("# c\ncreated=1\nfingerprint=SHA256:x\nweg=b\n") == {
        "created": "1",
        "fingerprint": "SHA256:x",
        "weg": "b",
    }
    assert P.parse_tailscale_prefs("[]") is None and P.parse_tailscale_prefs("{") is None
    assert P.is_loopback("::1") and P.is_loopback("127.0.0.1") and not P.is_loopback("0.0.0.0")
