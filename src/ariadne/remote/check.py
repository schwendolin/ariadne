"""``ariadne remote check``: Systemprüfung für den Fernzugriff (R10, Konzept 5.4, 5.5, 7, T14).

Ariadne prüft und warnt, ändert aber nichts am System (Konzept 7). Ausgabe wie ``ariadne doctor``
(:class:`ariadne.cli.doctor.Check` mit ``ok``, ``warn``, ``fail``).

Ohne root (immer):

* Bindung des Web-Ports (``[ui] port``, Standard 7330) nur auf Loopback (``/proc/net/tcp``, ``tcp6``).
* Hostkey-Marker des Einrichtungsskripts (``/etc/ssh/ariadne-hostkeys.marker``) passt zum
  ed25519-Hostkey; weitere Hostkeys aus der Vorlage.
* ``~/.ssh/authorized_keys``: genau ein Schlüssel mit ``restrict``, genau
  ``permitopen="127.0.0.1:PORT"`` und ``command=".../ariadne remote serve"``; nichts in
  ``authorized_keys2``.
* Drop-in ``/etc/ssh/sshd_config.d/10-ariadne.conf`` vorhanden, eingebunden, nicht von einer
  früher gelesenen Datei überstimmt.
* Port 22 gegen den Filter (``ariadne-ssh-filter.service`` aktiv, ``Requires=`` an ``ssh.service``,
  ``ssh.socket`` aus), OpenSSH-Version (unter 9.8 Warnung, kein Abbruch), Tailscale-Zustand
  (keine Routen, kein Exit-Node, kein Tailscale SSH, kein Serve/Funnel), Swap, open-vm-tools,
  Python, Runtime-Ordner für SSH-Sitzungen.

Mit ``--full`` (einmal ``sudo``): ``sshd -T -C user=…,host=pruefung,addr=…`` und
``nft list table inet ariadne_ssh``.

:func:`quick_ok` ist die schnelle Prüfung vor ``remote serve code`` (ohne root, ohne Programme):
Bindung, Marker, ``authorized_keys``. Alle Programme laufen über einen austauschbaren
:data:`Runner`, alle Dateien unter :attr:`System.root` (Tests mit Fixtures, nie root nötig).
``ARIADNE_SETUP_ROOT`` setzt diese Wurzel wie beim Einrichtungsskript (nur für Tests in einem
Wegwerf-Root; sshd reicht Variablen des Clients nur nach ``AcceptEnv`` durch, das ``--full`` prüft).
"""

from __future__ import annotations

import ipaddress
import os
import pwd
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ariadne.cli.doctor import FAIL, OK, WARN, Check, swap_check
from ariadne.paths import Paths
from ariadne.remote import parse as P
from ariadne.termsafe import term_safe
from ariadne.web.config import DEFAULT_PORT, UiConfigError, load_ui

__all__ = [
    "run_checks",
    "quick_ok",
    "quick_checks",
    "render",
    "System",
    "RunResult",
    "Runner",
    "default_runner",
    "SETUP_ROOT_ENV",
    "MARKER",
    "DROPIN",
    "FILTER_UNIT",
    "MIN_OPENSSH",
    "STUB",
]

STUB = False

SETUP_ROOT_ENV = "ARIADNE_SETUP_ROOT"
MARKER = "etc/ssh/ariadne-hostkeys.marker"
HOSTKEY_PUB = "etc/ssh/ssh_host_ed25519_key.pub"
SSHD_CONFIG = "etc/ssh/sshd_config"
DROPIN_DIR = "etc/ssh/sshd_config.d"
DROPIN_NAME = "10-ariadne.conf"
DROPIN = f"{DROPIN_DIR}/{DROPIN_NAME}"
FILTER_UNIT = "ariadne-ssh-filter.service"
MIN_OPENSSH = (9, 8)
TAILNET = ipaddress.ip_network("100.64.0.0/10")
SBIN = ("/usr/local/sbin", "/usr/sbin", "/sbin")
MAX_FILE = 1 << 20
ACCEPTENV_OK = frozenset({"LANG", "LC_*", "COLORTERM", "NO_COLOR"})
# Werte, die Drop-in und ``sshd -T`` haben müssen (Konzept 4.2, 4.3); PermitOpen hängt am Port.
EXPECT = {
    "passwordauthentication": "no",
    "kbdinteractiveauthentication": "no",
    "permitrootlogin": "no",
    "allowtcpforwarding": "local",
    "permitlisten": "none",
    "gatewayports": "no",
    "x11forwarding": "no",
    "allowagentforwarding": "no",
    "allowstreamlocalforwarding": "no",
    "permittunnel": "no",
}
FORBIDDEN_KEY_OPTIONS = ("agent-forwarding", "x11-forwarding", "user-rc", "permitlisten", "tunnel",
                         "no-restrict")
_WEGE = ("a", "b", "c")


@dataclass(frozen=True)
class RunResult:
    code: int
    out: str
    err: str = ""


# Führt ein Programm aus; ``None``: Programm fehlt oder lief zu lange.
Runner = Callable[[Sequence[str]], "RunResult | None"]


def _search_path() -> str:
    return os.pathsep.join([os.environ.get("PATH") or os.defpath, *SBIN])


def default_runner(argv: Sequence[str]) -> RunResult | None:
    """Startet ``argv`` ohne Shell, ohne stdin, mit fester Umgebung und Zeitlimit."""
    exe = shutil.which(argv[0], path=_search_path())
    if exe is None:
        return None
    env = {"PATH": _search_path(), "LC_ALL": "C", "ARIADNE_DISABLE": "1",
           "HOME": os.environ.get("HOME", "/")}
    try:
        res = subprocess.run([exe, *argv[1:]], capture_output=True, text=True, errors="replace",
                             timeout=8, stdin=subprocess.DEVNULL, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return RunResult(res.returncode, res.stdout[:MAX_FILE], res.stderr[:65536])


def _username() -> str:
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return str(os.getuid())


@dataclass
class System:
    """Was die Prüfung vom System sieht. Tests ersetzen Wurzel, ``/proc`` und Runner."""

    root: Path = Path("/")
    proc_root: str = "/proc"
    runner: Runner = default_runner
    user: str = field(default_factory=_username)
    uid: int = field(default_factory=os.getuid)
    sudo: tuple[str, ...] = ()  # Präfix für Programme, die root brauchen (``--full``)
    env: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **kw: object) -> System:
        env = dict(os.environ if env is None else env)
        raw = env.get(SETUP_ROOT_ENV) or ""
        root = Path(raw) if raw and os.path.isabs(raw) and os.path.isdir(raw) else Path("/")
        return cls(root=root, env=env, **kw)  # type: ignore[arg-type]

    def path(self, rel: str) -> Path:
        return self.root / rel

    def read(self, target: str | Path, limit: int = MAX_FILE) -> str | None:
        p = target if isinstance(target, Path) else self.path(target)
        try:
            with open(p, "rb") as fh:
                return fh.read(limit).decode("utf-8", "replace")
        except OSError:
            return None

    def proc(self, name: str) -> str:
        try:
            with open(f"{self.proc_root}/{name}", encoding="ascii", errors="replace") as fh:
                return fh.read(MAX_FILE)
        except OSError:
            return ""

    def run(self, argv: Sequence[str], *, as_root: bool = False) -> RunResult | None:
        cmd = [*self.sudo, *argv] if as_root else list(argv)
        try:
            return self.runner(cmd)
        except Exception:  # ein Fehler im Runner darf die Prüfung nicht abbrechen
            return None


def _safe(text: object, n: int = 200) -> str:
    return term_safe(text, max_len=n)


# --------------------------------------------------------------------------- #
# Einzelne Prüfungen
# --------------------------------------------------------------------------- #


def _python() -> Check:
    v = sys.version_info
    lvl = OK if v >= (3, 11) else FAIL
    return Check(lvl, f"Python {v.major}.{v.minor}.{v.micro}", "" if lvl == OK else "mindestens 3.11 nötig")


def _ui_port(paths: Paths) -> tuple[int, Check | None, bool]:
    """Port der Web-Oberfläche, ein Fehler der Konfiguration und ob sie eingeschaltet ist."""
    try:
        cfg = load_ui(paths)
    except UiConfigError as exc:
        return DEFAULT_PORT, Check(FAIL, "Web-Oberfläche: Konfiguration [ui] verboten", _safe(exc)), True
    return cfg.port, None, cfg.enabled


def web_binding(paths: Paths, system: System) -> list[Check]:
    """R1: Der Web-Port lauscht nur auf Loopback (oder gar nicht)."""
    port, err, enabled = _ui_port(paths)
    out: list[Check] = [err] if err is not None else []
    if not enabled:
        out.append(Check(WARN, "Web-Oberfläche abgeschaltet", "[ui] enabled = false in config.toml"))
    if port == 0:
        out.append(Check(WARN, "Web-Port 0 (nur für Tests)", "[ui] port in config.toml setzen"))
        return out
    listeners = P.tcp_listeners(system.proc("net/tcp"), system.proc("net/tcp6"), port)
    outside = [a for a in listeners if not P.is_loopback(a)]
    if outside:
        out.append(Check(FAIL, f"Port {port} lauscht nicht nur auf Loopback",
                         ", ".join(outside[:5]) + " (R1: nur 127.0.0.1 oder ::1)"))
    elif listeners:
        out.append(Check(OK, f"Port {port} nur auf Loopback", ", ".join(listeners)))
    else:
        out.append(Check(OK, f"Port {port}: nichts lauscht", "Daemon oder Web-Oberfläche aus"))
    return out


def _weg(system: System) -> str | None:
    text = system.read(MARKER, 4096)
    if text is None:
        return None
    weg = P.parse_marker(text).get("weg", "").lower()
    return weg if weg in _WEGE else None


def hostkey_marker(system: System) -> list[Check]:
    """Hostkeys selbst erzeugt (Konzept 5.3: gleiche Hostkeys aller Kalis eines Mastersets)."""
    text = system.read(MARKER, 4096)
    if text is None:
        return [Check(FAIL, "Hostkey-Marker fehlt", "Hostkeys selbst erzeugen: sudo sh kali-setup.sh")]
    marker = P.parse_marker(text)
    pub = system.read(HOSTKEY_PUB, 65536)
    found = P.pubkey_fingerprint(pub) if pub is not None else None
    if found is None:
        return [Check(FAIL, "ed25519-Hostkey fehlt oder ist unlesbar", str(system.path(HOSTKEY_PUB)))]
    keytype, fp = found
    out: list[Check] = []
    if keytype != "ssh-ed25519" or marker.get("fingerprint") != fp:
        out.append(Check(FAIL, "Hostkey passt nicht zum Marker",
                         "Hostkey ersetzt (Vorlage, Reset?): sudo sh kali-setup.sh --new-hostkeys"))
    else:
        out.append(Check(OK, "Hostkeys selbst erzeugt",
                         f"{_safe(marker.get('created', '?'), 40)}, {fp}"))
    try:
        others = sorted(p.name for p in system.path("etc/ssh").glob("ssh_host_*_key.pub")
                        if p.name != "ssh_host_ed25519_key.pub")
    except OSError:
        others = []
    if others:
        out.append(Check(WARN, "weitere Hostkeys vorhanden", ", ".join(_safe(o, 60) for o in others[:4])
                         + " (aus der Vorlage? kali-setup.sh --new-hostkeys)"))
    return out


def _serve_command(value: str | None) -> bool:
    if not value or not value.endswith(" remote serve"):
        return False
    exe = value[: -len(" remote serve")]
    if not exe.startswith("/") or os.path.basename(exe) != "ariadne":
        return False
    return not any(ch in exe for ch in " \t\"'\\$`;&|<>(){}*?[]!#~\n")


def key_problems(key: P.AuthKey, port: int) -> tuple[list[str], list[str]]:
    """Fehler und Warnungen einer Schlüsselzeile gegen R11."""
    fails: list[str] = []
    warns: list[str] = []
    if key.bad_options or not key.keytype:
        fails.append("Zeile nicht sauber lesbar")
    if not key.has("restrict"):
        fails.append("ohne restrict")
    if key.values("permitopen") != [f"127.0.0.1:{port}"]:
        fails.append(f'permitopen nicht genau "127.0.0.1:{port}"')
    cmds = key.values("command")
    if len(cmds) != 1 or not _serve_command(cmds[0]):
        fails.append('command nicht ".../ariadne remote serve"')
    for opt in FORBIDDEN_KEY_OPTIONS:
        if key.has(opt):
            fails.append(f"{opt} erlaubt")
    if not key.has("port-forwarding"):
        warns.append("ohne port-forwarding (kein Tunnel)")
    if not key.has("pty"):
        warns.append("ohne pty (ssh -t kali-sl unlock geht nicht)")
    return fails, warns


def authorized_keys(paths: Paths, system: System, port: int | None = None) -> list[Check]:
    """R11: genau ein eingeschränkter Schlüssel, nur ``remote serve`` und der Tunnel zum Web-Port."""
    if port is None:
        port = _ui_port(paths)[0]
    ssh_dir = paths.home / ".ssh"
    text = system.read(ssh_dir / "authorized_keys")
    out: list[Check] = []
    if text is None:
        out.append(Check(FAIL, "authorized_keys fehlt",
                         "Schlüssel des Macs eintragen: sudo sh kali-setup.sh --key …"))
    else:
        keys = P.parse_authorized_keys(text)
        if len(keys) != 1:
            out.append(Check(FAIL, f"authorized_keys: {len(keys)} Schlüssel, erwartet genau einer",
                             "jeder weitere Schlüssel öffnet mehr als Ariadne (R11)"))
        for key in keys[:20]:
            fails, warns = key_problems(key, port)
            fp = key.fingerprint or "?"
            if fails:
                out.append(Check(FAIL, f"authorized_keys Zeile {key.line_no}: nicht eingeschränkt",
                                 "; ".join(fails)))
            elif len(keys) == 1:
                out.append(Check(OK, "authorized_keys: ein eingeschränkter Schlüssel", fp))
            if warns:
                out.append(Check(WARN, f"authorized_keys Zeile {key.line_no}", "; ".join(warns)))
    text2 = system.read(ssh_dir / "authorized_keys2")
    if text2 is not None and P.parse_authorized_keys(text2):
        out.append(Check(FAIL, "authorized_keys2 enthält Schlüssel", "Datei leeren oder löschen"))
    for p, label in ((ssh_dir, "~/.ssh"), (ssh_dir / "authorized_keys", "authorized_keys")):
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_mode & 0o022 or st.st_uid != system.uid:
            out.append(Check(WARN, f"{label}: Rechte zu offen oder fremder Besitzer",
                             "chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"))
    return out


def _first_directives(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw[: P.MAX_LINE].strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.replace("\t", " ").partition(" ")
        out.append((key.lower(), value.strip()))
    return out


def sshd_dropin(system: System, weg: str | None, port: int) -> list[Check]:
    """Drop-in vorhanden, eingebunden und nicht von einer früher gelesenen Datei überstimmt."""
    out: list[Check] = []
    main = system.read(SSHD_CONFIG)
    if main is None:
        out.append(Check(WARN, "sshd_config nicht lesbar", str(system.path(SSHD_CONFIG))))
    else:
        directives = _first_directives(main)
        includes = [v for k, v in directives if k == "include" and "sshd_config.d" in v]
        if not includes:
            out.append(Check(FAIL, "Drop-in wird nicht geladen",
                             "sshd_config ohne «Include /etc/ssh/sshd_config.d/*.conf»"))
        elif directives and directives[0][0] != "include":
            out.append(Check(WARN, "Include steht nicht ganz oben in sshd_config",
                             "bei sshd gilt der erste Wert; ariadne remote check --full prüft sshd -T"))
    text = system.read(DROPIN)
    if text is None:
        out.append(Check(FAIL, "Drop-in 10-ariadne.conf fehlt", "sudo sh kali-setup.sh"))
        return out
    cfg = P.parse_sshd_config(text)
    expect = dict(EXPECT, permitopen=f"127.0.0.1:{port}", authenticationmethods="publickey")
    wrong = [k for k, v in expect.items() if (cfg.get(k) or [""])[0].lower() != v.lower()]
    if wrong:
        out.append(Check(FAIL, "Drop-in unvollständig", "falsch oder fehlend: " + ", ".join(sorted(wrong))))
    else:
        out.append(Check(OK, "Drop-in 10-ariadne.conf vollständig"))
    # Bei sshd gilt der erste Wert: Eine früher gelesene Datei überstimmt das Drop-in.
    try:
        earlier = sorted(p for p in system.path(DROPIN_DIR).glob("*.conf") if p.name < DROPIN_NAME)
    except OSError:
        earlier = []
    clash = []
    for p in earlier:
        other = system.read(p)
        if other is None:
            continue
        keys = set(P.parse_sshd_config(other)) & (set(expect) | {"allowusers", "listenaddress", "match"})
        if keys:
            clash.append(f"{p.name} ({', '.join(sorted(keys))})")
    if clash:
        out.append(Check(FAIL, "Drop-in wird überstimmt", "; ".join(_safe(c, 80) for c in clash[:4])))
    allow = cfg.get("allowusers") or []
    want = {"b": f"@{TAILNET}", "c": "@127.0.0.1"}.get(weg or "")
    if want is not None and (not allow or any(not w.endswith(want) for w in " ".join(allow).split())):
        out.append(Check(WARN, f"AllowUsers nicht auf {want[1:]} beschränkt",
                         "kali-setup.sh erneut ausführen"))
    if weg == "c":
        listen = cfg.get("listenaddress") or []
        if not listen or not all(P.is_loopback(a.rsplit(":", 1)[0].strip("[]")) for a in listen):
            out.append(Check(FAIL, "Weg C: ListenAddress nicht nur Loopback", "ListenAddress 127.0.0.1"))
    return out


def _systemctl(system: System, *args: str) -> str | None:
    res = system.run(["systemctl", *args])
    if res is None:
        return None
    return res.out.strip()


def ssh_port(system: System, weg: str | None) -> list[Check]:
    """Port 22 gegen den Filter (R10, P1, P2): Weg A und B nur mit aktivem Filter, Weg C nur Loopback."""
    out: list[Check] = []
    listeners = P.tcp_listeners(system.proc("net/tcp"), system.proc("net/tcp6"), 22)
    outside = [a for a in listeners if not P.is_loopback(a)]
    active = _systemctl(system, "is-active", FILTER_UNIT)
    if active is None:
        out.append(Check(WARN, "systemctl fehlt: Filter und ssh.socket nicht geprüft"))
    if not listeners:
        out.append(Check(OK, "sshd lauscht nicht auf Port 22"))
    elif weg == "c":
        if outside:
            out.append(Check(FAIL, "Weg C: sshd lauscht ausserhalb von Loopback", ", ".join(outside[:5])))
        else:
            out.append(Check(OK, "sshd nur auf Loopback (Weg C)"))
    elif outside:
        if active == "active":
            out.append(Check(OK, "Port 22 nur über den erlaubten Weg", "Filter ariadne-ssh-filter aktiv"))
        else:
            out.append(Check(FAIL, "Port 22 offen ohne Filter", ", ".join(outside[:5])
                             + " (sudo systemctl enable --now ariadne-ssh-filter)"))
    else:
        out.append(Check(OK, "sshd nur auf Loopback"))
    if active is None:
        return out
    if weg in ("a", "b"):
        requires = _systemctl(system, "show", "ssh.service", "-p", "Requires", "--value") or ""
        if FILTER_UNIT not in requires.split():
            out.append(Check(FAIL, "sshd startet auch ohne Filter", "Requires= fehlt (kali-setup.sh)"))
    sock_active = _systemctl(system, "is-active", "ssh.socket")
    sock_enabled = _systemctl(system, "is-enabled", "ssh.socket")
    if sock_active == "active" or sock_enabled == "enabled":
        out.append(Check(FAIL, "ssh.socket aktiv",
                         "umgeht den Filter: sudo systemctl disable --now ssh.socket"))
    return out


def openssh_version(system: System) -> list[Check]:
    res = system.run(["ssh", "-V"])
    ver = P.parse_openssh_version((res.out + res.err) if res is not None else "")
    if ver is None:
        return [Check(WARN, "OpenSSH-Version unbekannt")]
    text = f"OpenSSH {ver[0]}.{ver[1]}"
    if ver < MIN_OPENSSH:
        return [Check(WARN, f"{text}: älter als 9.8",
                      "ohne PerSourcePenalties; Update empfohlen, kein Abbruch")]
    return [Check(OK, text)]


def tailscale(system: System, weg: str | None, *, full: bool = False) -> list[Check]:
    """Weg B: keine Routen, kein Exit-Node, kein Tailscale SSH, kein Serve oder Funnel (Konzept 4.4)."""
    res = system.run(["tailscale", "debug", "prefs"], as_root=full)
    if res is None:
        return [Check(WARN, "Tailscale nicht gefunden", "Weg B braucht Tailscale")] if weg == "b" else []
    prefs = P.parse_tailscale_prefs(res.out) if res.code == 0 else None
    if prefs is None:
        return [Check(WARN, "Tailscale-Einstellungen nicht lesbar", "ariadne remote check --full")]
    out: list[Check] = []
    routes = prefs.get("AdvertiseRoutes")
    if isinstance(routes, list) and routes:
        exit_node = any(r in ("0.0.0.0/0", "::/0") for r in routes)
        out.append(Check(FAIL, "Tailscale gibt " + ("einen Exit-Node" if exit_node else "Routen") + " frei",
                         "nie --advertise-routes oder --advertise-exit-node: "
                         "tailscale set --advertise-routes="))
    if prefs.get("ExitNodeID") or prefs.get("ExitNodeIP"):
        out.append(Check(FAIL, "Tailscale nutzt einen Exit-Node", "tailscale set --exit-node="))
    if prefs.get("RunSSH") is True:
        out.append(Check(FAIL, "Tailscale SSH ist an", "tailscale set --ssh=false"))
    if prefs.get("RouteAll") is True:
        out.append(Check(WARN, "Tailscale nimmt Routen an", "tailscale set --accept-routes=false"))
    if prefs.get("CorpDNS") is True:
        out.append(Check(WARN, "Tailscale übernimmt DNS", "tailscale set --accept-dns=false"))
    serve = system.run(["tailscale", "serve", "status", "--json"], as_root=full)
    if serve is not None and serve.code == 0 and serve.out.strip() not in ("", "{}", "null"):
        out.append(Check(FAIL, "Tailscale Serve oder Funnel aktiv",
                         "tailscale serve reset; tailscale funnel reset"))
    if not any(c.level == FAIL for c in out):
        out.append(Check(OK, "Tailscale: keine Routen, kein Exit-Node, kein Tailscale SSH"))
    return out


def swap(system: System) -> Check:
    def dm_uuid(name: str) -> str | None:
        return (system.read(f"sys/block/{name}/dm/uuid", 256) or "").strip() or None

    def slaves(name: str) -> list[str]:
        try:
            return sorted(p.name for p in system.path(f"sys/block/{name}/slaves").iterdir())
        except OSError:
            return []

    text = system.proc("swaps")
    if not text:
        return Check(WARN, "Swap unbekannt", "/proc/swaps nicht lesbar")
    return swap_check(text, dm_uuid, slaves)


def vm_tools(system: System) -> list[Check]:
    state = _systemctl(system, "is-active", "open-vm-tools.service")
    if state == "active":
        return [Check(WARN, "open-vm-tools aktiv",
                      "der Hypervisor kann Programme starten: eigenes Passwort ist Pflicht")]
    if state is None:
        return []
    return [Check(OK, "open-vm-tools nicht aktiv")]


def runtime_dir(system: System) -> list[Check]:
    """Konzept-Risiko 11: Über SSH fehlt ``XDG_RUNTIME_DIR`` je nach PAM; dann nimmt
    ``remote serve`` ``/run/user/UID`` (wenn sicher), sonst findet es den Daemon nicht."""
    out: list[Check] = []
    if system.env.get("XDG_RUNTIME_DIR"):
        out.append(Check(OK, "Runtime-Ordner gesetzt (XDG_RUNTIME_DIR)"))
    else:
        d = system.path(f"run/user/{system.uid}")
        try:
            st = os.lstat(d)
            ok = stat.S_ISDIR(st.st_mode) and st.st_uid == system.uid and not st.st_mode & 0o077
        except OSError:
            ok = False
        if ok:
            out.append(Check(OK, "Runtime-Ordner /run/user/UID nutzbar"))
        else:
            out.append(Check(WARN, "kein Runtime-Ordner", "ssh kali-sl code findet den Daemon nicht: "
                             "in der Kali anmelden oder sudo loginctl enable-linger $USER"))
    if not system.path(f"var/lib/systemd/linger/{system.user}").exists():
        out.append(Check(WARN, "kein linger",
                         "nach einem Neustart erst nach Anmeldung in der Kali erreichbar "
                         "(sudo loginctl enable-linger $USER)"))
    return out


def sshd_effective(system: System, weg: str | None, port: int) -> list[Check]:
    """``sshd -T -C …`` (root): die Werte, die wirklich gelten, auch nach ``Match``-Blöcken."""
    addr = {"b": "100.100.100.100", "c": "127.0.0.1"}.get(weg or "", "192.0.2.1")
    res = system.run(["sshd", "-T", "-C", f"user={system.user},host=pruefung,addr={addr}"], as_root=True)
    if res is None:
        return [Check(WARN, "sshd -T nicht ausführbar", "sshd fehlt oder sudo verweigert")]
    if res.code != 0:
        first = (res.err.strip().splitlines() or ["?"])[0]
        return [Check(FAIL, "sshd -T meldet einen Fehler", _safe(first, 200))]
    eff = P.parse_sshd_t(res.out)
    out: list[Check] = []
    for key, want in EXPECT.items():
        got = " ".join(eff.get(key) or ["?"]).lower()
        if got != want:
            out.append(Check(FAIL, f"sshd: {key} {_safe(got, 60)}", f"erwartet {want}"))
    permitopen = " ".join(eff.get("permitopen") or ["?"]).split()
    if permitopen != [f"127.0.0.1:{port}"]:
        out.append(Check(FAIL, f"sshd: permitopen {_safe(' '.join(permitopen), 80)}",
                         f"erwartet 127.0.0.1:{port}"))
    methods = " ".join(eff.get("authenticationmethods") or ["?"]).lower()
    if "password" in methods or "keyboard-interactive" in methods:
        out.append(Check(FAIL, f"sshd: authenticationmethods {_safe(methods, 60)}", "erwartet publickey"))
    elif methods != "publickey":
        out.append(Check(WARN, f"sshd: authenticationmethods {_safe(methods, 60)}", "erwartet publickey"))
    env = set(" ".join(eff.get("acceptenv") or []).split())
    if env - ACCEPTENV_OK:
        out.append(Check(WARN, "sshd: AcceptEnv nimmt mehr als LANG und LC_*",
                         _safe(", ".join(sorted(env - ACCEPTENV_OK)), 120)))
    if eff.get("permituserenvironment", ["no"])[0].lower() != "no":
        out.append(Check(FAIL, "sshd: PermitUserEnvironment an", "erwartet no"))
    keys = [k for k in eff.get("hostkey") or [] if not k.endswith("ssh_host_ed25519_key")]
    if keys:
        out.append(Check(WARN, "sshd: weitere Hostkeys", _safe(", ".join(keys), 160)))
    if weg == "c":
        listen = eff.get("listenaddress") or []
        if not all(P.is_loopback(a.rsplit(":", 1)[0].strip("[]")) for a in listen):
            out.append(Check(FAIL, "sshd: ListenAddress nicht nur Loopback (Weg C)",
                             _safe(" ".join(listen), 120)))
    if not out:
        out.append(Check(OK, "sshd -T: alle Werte wie erwartet"))
    return out


def nft_filter(system: System, weg: str | None) -> list[Check]:
    if weg not in ("a", "b"):
        return []
    res = system.run(["nft", "list", "table", "inet", "ariadne_ssh"], as_root=True)
    if res is None:
        return [Check(WARN, "nft nicht ausführbar")]
    text = " ".join(res.out.split())
    if res.code != 0 or "tcp dport 22 drop" not in text:
        return [Check(FAIL, "Filter-Tabelle ariadne_ssh fehlt",
                      "sudo systemctl enable --now ariadne-ssh-filter")]
    if weg == "b" and 'iifname "tailscale0" tcp dport 22 accept' not in text:
        return [Check(FAIL, "Filter lässt Port 22 nicht nur über tailscale0 zu")]
    return [Check(OK, "Filter ariadne_ssh geladen")]


# --------------------------------------------------------------------------- #
# Einstiegspunkte
# --------------------------------------------------------------------------- #


def quick_checks(paths: Paths, system: System | None = None) -> list[Check]:
    """Schnellprüfung ohne root und ohne Programme: Bindung, Marker, ``authorized_keys``."""
    system = system or System.from_env()
    port = _ui_port(paths)[0]
    return [*web_binding(paths, system), *hostkey_marker(system), *authorized_keys(paths, system, port)]


def quick_ok(paths: Paths, system: System | None = None) -> bool:
    """Schnellprüfung vor ``remote serve code`` (ohne root): ``False`` bei einem ``fail``."""
    try:
        return not any(c.level == FAIL for c in quick_checks(paths, system))
    except Exception:  # fail-closed
        return False


def run_checks(paths: Paths, *, full: bool = False, system: System | None = None) -> list[Check]:
    """Alle Prüfungen für ``ariadne remote check``; ``full`` mit ``sudo`` für ``sshd -T`` und ``nft``."""
    if system is None:
        system = System.from_env()
        if full and os.getuid() != 0:
            system.sudo = ("sudo", "-n")
    weg = _weg(system)
    port = _ui_port(paths)[0]
    out: list[Check] = [_python()]
    out.append(Check(OK, f"Weg {weg.upper()}") if weg else
               Check(WARN, "Weg unbekannt", "kein Marker mit weg= (sudo sh kali-setup.sh --weg b)"))
    out += web_binding(paths, system)
    out += hostkey_marker(system)
    out += authorized_keys(paths, system, port)
    out += sshd_dropin(system, weg, port)
    out += ssh_port(system, weg)
    out += openssh_version(system)
    out += tailscale(system, weg, full=full)
    out += runtime_dir(system)
    out.append(swap(system))
    out += vm_tools(system)
    if full:
        out += sshd_effective(system, weg, port)
        out += nft_filter(system, weg)
    return out


def render(checks: Sequence[Check]) -> tuple[list[str], int]:
    """Zeilen wie ``ariadne doctor`` und der Exit-Code (1 bei einem ``fail``)."""
    lines: list[str] = []
    worst = 0
    for c in checks:
        tag = {OK: "[ok]", FAIL: "[!!]"}.get(c.level, "[--]")
        lines.append(f"{tag} {_safe(c.title)}" + (f": {_safe(c.detail, 300)}" if c.detail else ""))
        if c.level == FAIL:
            worst = 1
    return lines, worst
