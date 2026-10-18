"""Lab-Leitplanke (Architektur 8.1).

Ein lab-Projekt darf nur Ziele aus der Lab-Allowlist haben: private Netze und
typische Lab-Domains. Alles andere ist nur mit der ausdrücklichen Bestätigung
«Das ist kein Kundenauftrag» erlaubt (Entscheid ``d.lab.not_customer``).

Ziele werden nur syntaktisch geprüft, nie per DNS aufgelöst.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ariadne.scope.matcher import _RANGE, _range_nets
from ariadne.scope.normalize import has_idna_deviation

__all__ = [
    "DEFAULT_NETWORKS",
    "DEFAULT_SUFFIXES",
    "NON_PUBLIC_SUFFIXES",
    "is_public_name",
    "InvalidTarget",
    "Target",
    "LabAllowlist",
    "parse_target",
    "split_targets",
]

DEFAULT_NETWORKS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "10.10.0.0/16",
    "10.129.0.0/16",
    "100.64.0.0/10",
)
# Lab-Allowlist: typische Lab-Domains (E132: wie vor Praxis 1). Andere Namen, auch ``.internal`` oder
# ``.test``, brauchen wie öffentliche Ziele die Bestätigung «kein Kundenauftrag».
DEFAULT_SUFFIXES = (".htb", ".local", ".lab", ".thm", ".vl")
# Endungen, die es im öffentlichen DNS nicht gibt (E130/E132): nur für den Warnhinweis «öffentliche
# Endung» (:func:`is_public_name`), getrennt von der Allowlist.
NON_PUBLIC_SUFFIXES = (".htb", ".local", ".lab", ".thm", ".vl", ".internal", ".test", ".lan", ".home",
                       ".localdomain", ".home.arpa", ".example", ".invalid", ".localhost")

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class InvalidTarget(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    kind: Literal["ip", "cidr", "range", "name"]
    value: str  # normalisiert: IP, CIDR, IPv4-Bereich ``a.b.c.d-e.f.g.h`` oder Name (ggf. mit ``*.``)

    def __str__(self) -> str:
        return self.value


def _normalize_name(raw: str) -> str:
    name = raw.lower().rstrip(".")
    wildcard = name.startswith("*.")
    base = name[2:] if wildcard else name
    if not base.isascii():
        if has_idna_deviation(base):
            raise InvalidTarget("Name mit ß, ς oder ZWJ/ZWNJ: bitte in der xn--Form angeben "
                                "(IDNA2003 und curl/Browser lesen ihn verschieden)")
        try:
            base = base.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise InvalidTarget("Name lässt sich nicht nach IDNA kodieren") from exc
    if len(base) > 253:
        raise InvalidTarget("Name zu lang")
    labels = base.split(".")
    if not all(_LABEL_RE.match(lb) for lb in labels):
        raise InvalidTarget("ungültiger Hostname")
    if labels[-1].isdigit():
        raise InvalidTarget("mehrdeutige IP-Schreibweise, bitte als a.b.c.d angeben")
    return ("*." if wildcard else "") + base


def parse_target(raw: str) -> Target:
    """IP, CIDR, IPv4-Bereich oder Hostname (auch ``*.domain``). Kurz-, Dezimal- und Hex-IPs werden
    abgelehnt. Einen Bereich (``10.0.0.1-50`` oder ``10.0.0.1-10.0.0.50``) liest der ScopeMatcher als
    Bereich; hier gilt dieselbe Lesart (früher: als Name), gespeichert in der langen Form."""
    s = raw.strip()
    if not s or len(s) > 260 or any(ord(c) < 0x21 or ord(c) == 0x7F for c in s):
        raise InvalidTarget("leeres oder ungültiges Ziel")
    try:
        return Target("ip", str(ipaddress.ip_address(s)))
    except ValueError:
        pass
    if "/" in s:
        try:
            return Target("cidr", str(ipaddress.ip_network(s, strict=False)))
        except ValueError as exc:
            raise InvalidTarget("ungültiges Netz") from exc
    if _RANGE.fullmatch(s):
        nets = _range_nets(s)
        if not nets:
            raise InvalidTarget("ungültiger IP-Bereich (a.b.c.d-e, aufsteigend)")
        return Target("range", f"{nets[0].network_address}-{nets[-1].broadcast_address}")
    return Target("name", _normalize_name(s))


@dataclass(frozen=True)
class LabAllowlist:
    networks: tuple[Network, ...]
    suffixes: tuple[str, ...]

    @classmethod
    def default(cls) -> LabAllowlist:
        return cls(tuple(ipaddress.ip_network(n) for n in DEFAULT_NETWORKS), DEFAULT_SUFFIXES)

    @classmethod
    def from_config(cls, config_file: Path | None) -> LabAllowlist:
        """Standardliste plus ``[lab] extra_networks`` und ``extra_suffixes`` aus config.toml."""
        base = cls.default()
        if config_file is None or not config_file.is_file():
            return base
        try:
            data = tomllib.loads(config_file.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            return base
        lab = data.get("lab", {}) if isinstance(data, dict) else {}
        nets = list(base.networks)
        for n in lab.get("extra_networks", []) or []:
            try:
                nets.append(ipaddress.ip_network(str(n), strict=False))
            except ValueError:
                continue
        sufs = list(base.suffixes)
        for s in lab.get("extra_suffixes", []) or []:
            s = str(s).lower()
            sufs.append(s if s.startswith(".") else "." + s)
        return cls(tuple(nets), tuple(sufs))

    def allows(self, target: Target) -> bool:
        if target.kind == "ip":
            ip = ipaddress.ip_address(target.value)
            return any(ip.version == n.version and ip in n for n in self.networks)
        if target.kind == "cidr":
            net = ipaddress.ip_network(target.value)
            return any(net.version == n.version and net.subnet_of(n) for n in self.networks)  # type: ignore[arg-type]
        if target.kind == "range":
            parts = _range_nets(target.value)
            return bool(parts) and all(
                any(p.version == n.version and p.subnet_of(n) for n in self.networks)  # type: ignore[arg-type]
                for p in parts)
        name = target.value[2:] if target.value.startswith("*.") else target.value
        return any(name.endswith(s) and len(name) > len(s) for s in self.suffixes)


def split_targets(raw: Iterable[str], allowlist: LabAllowlist) -> tuple[list[Target], list[Target]]:
    """Parst Ziele und liefert ``(alle, ausserhalb der Allowlist)``. Doppelte fallen weg."""
    seen: dict[str, Target] = {}
    for r in raw:
        t = parse_target(r)
        seen.setdefault(t.value, t)
    targets: Sequence[Target] = list(seen.values())
    return list(targets), [t for t in targets if not allowlist.allows(t)]


def is_public_name(name: str) -> bool:
    """Name (auch ``*.domain``) mit öffentlicher Endung, also nicht aus :data:`NON_PUBLIC_SUFFIXES`
    (E130, E132: zusätzlicher Warnhinweis). Nur syntaktisch, nie DNS."""
    n = name.lower().rstrip(".")
    n = n[2:] if n.startswith("*.") else n
    return not any(n.endswith(s) and len(n) > len(s) for s in NON_PUBLIC_SUFFIXES)
