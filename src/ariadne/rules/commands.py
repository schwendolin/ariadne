"""Erkenner: Welche Prüfung hat ein aufgenommener Befehl schon gemacht? (Architektur 6.1)

Die Regeln fragen nur «ist die Prüfung X für diesen Host bzw. Dienst schon erfolgt?»; das Wissen
über Werkzeuge, Optionen und nmap-Skripte steht hier. Ein Befehl wird nie ausgeführt, nur gelesen
(Befehlstext aus ``obs_unit.title``, zerlegt wie von der Shell ohne Expansion).

* :func:`parse` zerlegt eine Befehlszeile in einfache Befehle (``a && b`` ergibt zwei), entfernt
  Vorsätze wie ``sudo`` oder ``proxychains4`` und bestimmt das Werkzeug.
* :class:`NmapOpts` liest die Optionen von nmap: Skripte (``-sC``, ``-A``, ``--script`` mit Namen,
  Kategorien und Mustern), UDP (``-sU``), alle TCP-Ports (``-p-``, ``-p 1-65535``).
* :func:`targets` findet die Ziele eines Befehls (IP, Name, Netz, Bereich ``a.b.c.10-20``),
  :func:`ports` die ausdrücklich genannten Ports.

Stand der Skript-Kategorien: nmap 7.94.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache

from ariadne.ctxrules import command_argvs, strip_prefixes

__all__ = [
    "Cmd",
    "NmapOpts",
    "parse",
    "nmap_opts",
    "runs_script",
    "SCRIPT_CATEGORIES",
    "targets",
    "ports",
    "Target",
]

# Kategorien der nmap-Skripte, die eine Regel als Prüfung zählt (nmap 7.94).
SCRIPT_CATEGORIES: dict[str, frozenset[str]] = {
    k: frozenset(v)
    for k, v in {
        "ftp-anon": ("default", "auth", "safe"),
        "smb-security-mode": ("default", "discovery", "safe"),
        "smb-os-discovery": ("default", "discovery", "safe"),
        "smb-enum-shares": ("discovery", "intrusive"),
        "smb-enum-users": ("auth", "intrusive"),
        "nfs-showmount": ("discovery", "safe"),
        "nfs-ls": ("discovery", "safe"),
        "http-enum": ("discovery", "intrusive", "vuln"),
        "smtp-enum-users": ("auth", "external", "intrusive"),
        "http-default-accounts": ("discovery", "auth", "intrusive"),
        "mysql-empty-password": ("intrusive", "auth"),
        "mysql-brute": ("intrusive", "brute"),
        "pgsql-brute": ("intrusive", "brute"),
        "ms-sql-empty-password": ("auth", "intrusive"),
        "redis-info": ("discovery", "safe"),
        "mongodb-info": ("default", "discovery", "safe"),
        "vnc-brute": ("intrusive", "brute"),
        "telnet-brute": ("intrusive", "brute"),
        "snmp-brute": ("intrusive", "brute"),
        "vulners": ("vuln", "safe", "external"),
    }.items()
}

_IPV4_IN = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2})|-(\d{1,3}))?(?![0-9])")
_NAME = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?)+"
)
_PORT_OPTS = {"-p", "-P", "--port", "-port", "--ports"}
_PORT_OPTS_BY_TOOL = {"hydra": {"-s"}}  # nur dort heisst -s Port


@dataclass(frozen=True)
class Cmd:
    """Ein einfacher Befehl: Werkzeug (Basisname, ``impacket-`` und ``.py`` entfernt) und Argumente."""

    tool: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class NmapOpts:
    default_scripts: bool = False
    scripts: frozenset[str] = field(default_factory=frozenset)
    udp: bool = False
    full_tcp: bool = False


@dataclass(frozen=True)
class Target:
    """Ziele eines Befehls: Adressen, Netze (inklusive Bereiche) und Namen (klein)."""

    addrs: frozenset[str] = field(default_factory=frozenset)
    nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    ranges: tuple[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address], ...] = ()
    names: frozenset[str] = field(default_factory=frozenset)

    def hits(self, addrs: Iterable[str], names: Iterable[str]) -> bool:
        for a in addrs:
            if a in self.addrs:
                return True
            if self.nets or self.ranges:
                try:
                    ip = ipaddress.ip_address(a)
                except ValueError:
                    continue
                if any(ip in n for n in self.nets if n.version == ip.version):
                    return True
                if ip.version == 4 and any(lo <= ip <= hi for lo, hi in self.ranges):  # type: ignore[operator]
                    return True
        return any(n.lower() in self.names for n in names)


def _tool(argv: Sequence[str]) -> Cmd | None:
    args = strip_prefixes(argv)
    if not args:
        return None
    head = os.path.basename(args[0])
    rest = list(args[1:])
    if head.startswith("python") and rest and rest[0].endswith(".py"):
        head, rest = os.path.basename(rest[0]), rest[1:]
    head = head.removesuffix(".py").removeprefix("impacket-")
    return Cmd(head.lower(), tuple(rest))


@lru_cache(maxsize=8192)
def parse(text: str) -> tuple[Cmd, ...]:
    """Alle einfachen Befehle einer Zeile (``sudo nmap …; smbclient …``), ohne Vorsätze."""
    if not text or len(text) > 8192:
        return ()
    out = []
    for argv in command_argvs(text):
        c = _tool(argv)
        if c is not None:
            out.append(c)
    return tuple(out)


def _script_entries(spec: str) -> set[str] | None:
    """Einträge einer ``--script``-Angabe; ``None`` bei Ausdrücken mit ``not`` (vorsichtig: nichts)."""
    words = [w for w in re.split(r"[,\s()]+", spec.strip("'\"")) if w]
    if any(w == "not" for w in words):
        return None
    out = set()
    for w in words:
        if w in ("and", "or"):
            continue
        w = os.path.basename(w).removesuffix(".nse").lstrip("+")
        if w:
            out.add(w)
    return out


def _full_spec(spec: str) -> bool:
    for part in spec.split(","):
        p = part.strip()
        if p.upper().startswith("T:"):
            p = p[2:]
        if p in ("-", "1-65535", "0-65535", "-65535", "1-", "0-"):
            return True
    return False


@lru_cache(maxsize=4096)
def nmap_opts(args: tuple[str, ...]) -> NmapOpts:
    """Optionen eines nmap-Aufrufs, soweit die Regeln sie brauchen."""
    default = udp = full = False
    scripts: set[str] = set()
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if a == "-A":
            default = True
        elif re.fullmatch(r"-s[A-Za-z]+", a):
            default = default or "C" in a[2:]
            udp = udp or "U" in a[2:]
        elif a == "--script" and nxt is not None:
            got = _script_entries(nxt)
            scripts |= got or set()
            i += 1
        elif a.startswith("--script="):
            scripts |= _script_entries(a[len("--script=") :]) or set()
        elif a == "-p" and nxt is not None:
            full = full or _full_spec(nxt)
            udp = udp or "U:" in nxt.upper()
            i += 1
        elif a.startswith("-p") and len(a) > 2 and a[2] not in "nN":
            full = full or _full_spec(a[2:])
        elif a == "--top-ports" and nxt is not None:
            full = full or (nxt.isdigit() and int(nxt) >= 65535)
            i += 1
        i += 1
    return NmapOpts(default, frozenset(scripts), udp, full)


def runs_script(opts: NmapOpts, script: str) -> bool:
    """Führt ein nmap-Aufruf mit diesen Optionen das Skript ``script`` aus (wenn der Port passt)?"""
    cats = SCRIPT_CATEGORIES.get(script, frozenset())
    if opts.default_scripts and "default" in cats:
        return True
    for entry in opts.scripts:
        if entry == "all" or entry in cats or entry == script:
            return True
        if any(ch in entry for ch in "*?[") and fnmatch.fnmatchcase(script, entry):
            return True
    return False


@lru_cache(maxsize=8192)
def targets(args: tuple[str, ...]) -> Target:
    """Ziele in den Argumenten: IPv4 (auch in ``//IP/``, ``http://IP:80``, ``user@IP``), IPv6,
    Netze ``a.b.c.d/n``, Bereiche ``a.b.c.10-20`` und Namen (``host.domain``)."""
    addrs: set[str] = set()
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    ranges: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = []
    names: set[str] = set()
    for tok in args:
        if len(tok) > 512:
            continue
        for m in _IPV4_IN.finditer(tok):
            try:
                ip = ipaddress.IPv4Address(m.group(1))
            except ValueError:
                continue
            if m.group(2) is not None:
                try:
                    nets.append(ipaddress.ip_network(f"{ip}/{m.group(2)}", strict=False))
                except ValueError:
                    pass
            elif m.group(3) is not None:
                last = int(m.group(3))
                if ip.packed[3] <= last <= 255:
                    ranges.append((ip, ipaddress.IPv4Address(ip.packed[:3] + bytes([last]))))
                addrs.add(str(ip))
            else:
                addrs.add(str(ip))
        if ":" in tok:
            for cand in re.split(r"[\[\]/@ ]+", tok):
                cand = cand.split("%", 1)[0]
                if cand.count(":") >= 2:
                    try:
                        addrs.add(ipaddress.IPv6Address(cand).compressed)
                    except ValueError:
                        pass
        for m in _NAME.finditer(tok):
            names.add(m.group(0).lower())
    return Target(frozenset(addrs), tuple(nets), tuple(ranges), frozenset(names))


@lru_cache(maxsize=8192)
def ports(args: tuple[str, ...], tool: str = "") -> frozenset[int]:
    """Ausdrücklich genannte Ports: ``-p 2121``, ``-P 3306``, ``-s 8180`` (hydra), ``--port=8080``,
    ``host:8180`` und eine Zahl direkt hinter einem Ziel (``ftp 10.10.10.3 2121``, ``telnet host 2323``)."""
    out: set[int] = set()

    def add(text: str) -> None:
        for p in re.split(r"[,\s]+", text):
            if p.isdigit() and 0 < int(p) <= 65535:
                out.add(int(p))

    opts = _PORT_OPTS | _PORT_OPTS_BY_TOOL.get(tool, set())
    i = 0
    while i < len(args):
        a = args[i]
        if a in opts and i + 1 < len(args):
            add(args[i + 1])
            i += 2
            continue
        for opt in opts:
            if a.startswith(opt + "="):
                add(a[len(opt) + 1 :])
        if re.fullmatch(r"-[pP]\d{1,5}", a):
            add(a[2:])
        for m in re.finditer(r"(?<=[0-9A-Za-z\]:]):(\d{1,5})(?![0-9])", a):
            if a.count(":") <= 2:  # nicht in IPv6-Adressen
                add(m.group(1))
        if a.isdigit() and i > 0 and not args[i - 1].startswith("-") and _looks_like_target(args[i - 1]):
            add(a)
        i += 1
    return frozenset(out)


def _looks_like_target(token: str) -> bool:
    t = targets((token,))
    return bool(t.addrs or t.names or t.nets or t.ranges)
