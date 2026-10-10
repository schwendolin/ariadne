"""ScopeMatcher: die einzige Scope-Funktion im System (Architektur 5.8).

Regeln:

* Ausschluss schlägt Einschluss.
* IP-Regeln als Adresse, CIDR oder IPv4-Bereich (``10.0.0.1-50``), Namen exakt
  oder als Wildcard ``*.lame.htb`` (nur an Label-Grenzen, der Name selbst
  gehört nicht dazu), URL-Regeln als Präfix an Pfadgrenzen.
* ``0.0.0.0/8``, ``::``, Loopback, Link-Local, Multicast und Broadcast sind nie
  implizit ``in``, nur als exakt gelistete Adresse.
* URL- und ``svc:``-Kennungen werden über ihren Host geprüft.
* Mehrdeutige Schreibweisen: das strengste Urteil aller Lesarten gilt.
* Zeitfenster nur, wenn ``at_utc_ns`` gegeben ist; ``in`` ausserhalb aller
  Fenster wird ``outside_window``. Ungültige Fenster passen nie (fail-closed).

Keine DNS-Auflösung. Namen erhalten Scope nur über eigene Regeln.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from ariadne.scope.api import Verdict, VerdictKind
from ariadne.scope.normalize import (
    has_control,
    ipv4_candidates,
    normalize_hostname,
    normalize_ip,
    normalize_url,
    split_host_port,
)

__all__ = ["ScopeMatcher", "RANK", "strictest"]

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address

RANK: dict[str, int] = {"in": 0, "outside_window": 1, "unknown": 2, "out": 3, "excluded": 4}

_SPECIAL: tuple[tuple[str, IPNet], ...] = tuple(
    (name, ipaddress.ip_network(net))
    for name, net in (
        ("unspecified", "0.0.0.0/8"),
        ("loopback", "127.0.0.0/8"),
        ("link_local", "169.254.0.0/16"),
        ("multicast", "224.0.0.0/4"),
        ("broadcast", "255.255.255.255/32"),
        ("unspecified", "::/128"),
        ("loopback", "::1/128"),
        ("link_local", "fe80::/10"),
        ("multicast", "ff00::/8"),
    )
)
_RANGE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})")
_DAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
_HHMM = re.compile(r"([01]?\d|2[0-3]):([0-5]\d)|(24):(00)")


def strictest(verdicts: Iterable[tuple[VerdictKind, str | None]]) -> tuple[VerdictKind, str | None]:
    best: tuple[VerdictKind, str | None] | None = None
    for v in verdicts:
        if best is None or RANK[v[0]] > RANK[best[0]]:
            best = v
    return best if best is not None else ("unknown", None)


@dataclass(frozen=True)
class _Rule:
    entry: str
    nets: tuple[IPNet, ...] = ()
    exact: IPAddr | None = None  # einzelne, exakt gelistete Adresse
    name: str | None = None
    wildcard: str | None = None  # Suffix ohne "*."
    url: str | None = None


@dataclass(frozen=True)
class _Window:
    days: frozenset[int]
    start: int  # Minuten seit Mitternacht
    end: int
    tz: ZoneInfo

    def contains(self, at_utc_ns: int) -> bool:
        local = datetime.fromtimestamp(at_utc_ns // 1_000_000_000, tz=UTC).astimezone(self.tz)
        minute = local.hour * 60 + local.minute
        day = local.weekday()
        if self.start == 0 and self.end == 24 * 60:
            return day in self.days
        if self.start == self.end:
            return False
        if self.start < self.end:
            return day in self.days and self.start <= minute < self.end
        # über Mitternacht: Start-Tag zählt
        if minute >= self.start:
            return day in self.days
        prev = (local - timedelta(days=1)).weekday()
        return minute < self.end and prev in self.days


@dataclass(frozen=True)
class _Target:
    """Was geprüft wird: Adress-Lesarten, Netze, ein Name und/oder eine URL."""

    addrs: tuple[IPAddr | None, ...] = ()  # None = unlesbare Schreibweise
    nets: tuple[IPNet, ...] = ()
    name: str | None = None
    url: str | None = None


@dataclass
class ScopeMatcher:
    """Implementiert ``ariadne.scope.api.ScopeChecker``."""

    include: Sequence[str] = ()
    exclude: Sequence[str] = ()
    windows: Sequence[Mapping[str, Any]] = ()
    version: int = 1
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._inc = [r for r in (self._rule(e, "include") for e in self.include) if r]
        self._exc = [r for r in (self._rule(e, "exclude") for e in self.exclude) if r]
        self._win: list[_Window] = []
        for i, w in enumerate(self.windows):
            parsed = _parse_window(w)
            if parsed is None:
                self.errors.append(f"windows[{i}]: ungültig")
            else:
                self._win.append(parsed)

    # ------------------------------------------------------------------ #
    @classmethod
    def from_settings(cls, settings: Mapping[str, Any] | str, version: int) -> ScopeMatcher:
        """Aus dem Projekt-TOML (Text oder Dict mit ``[scope]``) bzw. nur der Scope-Tabelle."""
        if isinstance(settings, str):
            settings = tomllib.loads(settings)
        scope = settings.get("scope", settings)
        if not isinstance(scope, Mapping):
            scope = {}

        def _list(key: str) -> list[Any]:
            v = scope.get(key, [])
            return list(v) if isinstance(v, list | tuple) else []

        # Nicht-Text-Einträge gehen mit, damit _rule sie als Fehler meldet
        return cls(_list("include"), _list("exclude"), _list("windows"), version)

    # ------------------------------------------------------------------ #
    def _rule(self, entry: Any, where: str) -> _Rule | None:
        if not isinstance(entry, str):
            self.errors.append(f"{where}: kein Text")
            return None
        e = entry.strip()
        for prefix in ("ip:default/", "fqdn:", "name:", "url:"):
            if e.startswith(prefix):
                e = e[len(prefix) :]
        rule: _Rule | None = None
        if not e or has_control(e):
            rule = None
        elif e.startswith("*."):
            suffix = normalize_hostname(e[2:])
            rule = _Rule(entry, wildcard=suffix) if suffix else None
        elif "://" in e:
            u = normalize_url(e)
            rule = _Rule(entry, url=u) if u else None
        elif "/" in e:
            try:
                net = ipaddress.ip_network(e, strict=False)
            except ValueError:
                net = None
            if net is not None:
                exact = net.network_address if net.num_addresses == 1 else None
                rule = _Rule(entry, nets=(net,), exact=exact)
        elif _RANGE.fullmatch(e):
            nets = _range_nets(e)
            rule = _Rule(entry, nets=nets) if nets else None
        else:
            ip = normalize_ip(e)
            if ip is not None:
                addr = ipaddress.ip_address(ip)
                rule = _Rule(entry, nets=(ipaddress.ip_network(addr),), exact=addr)
            else:
                name = normalize_hostname(e)
                rule = _Rule(entry, name=name) if name else None
        if rule is None:
            self.errors.append(f"{where}: ungültiger Eintrag")
        return rule

    # ------------------------------------------------------------------ #
    def check(self, identifier: str, at_utc_ns: int | None = None) -> Verdict:
        target = _parse_target(identifier) if isinstance(identifier, str) else None
        if target is None:
            return Verdict("unknown", None, self.version)
        kind, rule = self._judge(target)
        if kind == "in" and at_utc_ns is not None and self.windows:
            if not any(w.contains(at_utc_ns) for w in self._win):
                return Verdict("outside_window", "window", self.version)
        return Verdict(kind, rule, self.version)

    def _judge(self, t: _Target) -> tuple[VerdictKind, str | None]:
        results: list[tuple[VerdictKind, str | None]] = []
        if t.url is not None:
            results.append(self._judge_url(t))
        else:
            for a in t.addrs:
                results.append(self._judge_addr(a) if a is not None else ("unknown", None))
            for n in t.nets:
                results.append(self._judge_net(n))
            if t.name is not None:
                results.append(self._judge_name(t.name))
        return strictest(results)

    def _judge_addr(self, a: IPAddr) -> tuple[VerdictKind, str | None]:
        for r in self._exc:
            if any(a in n for n in r.nets):
                return "excluded", f"exclude:{r.entry}"
        special = next((name for name, net in _SPECIAL if a.version == net.version and a in net), None)
        if special is not None:
            for r in self._inc:
                if r.exact is not None and r.exact == a:
                    return "in", f"include:{r.entry}"
            return "out", f"special:{special}"
        for r in self._inc:
            if any(a in n for n in r.nets):
                return "in", f"include:{r.entry}"
        return "out", None

    def _judge_net(self, net: IPNet) -> tuple[VerdictKind, str | None]:
        if net.num_addresses == 1:
            return self._judge_addr(net.network_address)
        for r in self._exc:
            if any(n.version == net.version and n.overlaps(net) for n in r.nets):
                return "excluded", f"exclude:{r.entry}"
        for name, sp in _SPECIAL:
            if sp.version == net.version and sp.overlaps(net):
                return "out", f"special:{name}"
        for r in self._inc:
            if any(n.version == net.version and net.subnet_of(n) for n in r.nets):  # type: ignore[arg-type]
                return "in", f"include:{r.entry}"
        return "out", None

    def _judge_name(self, name: str) -> tuple[VerdictKind, str | None]:
        for r in self._exc:
            if _name_hit(r, name):
                return "excluded", f"exclude:{r.entry}"
        for r in self._inc:
            if _name_hit(r, name):
                return "in", f"include:{r.entry}"
        return "out", None

    def _judge_url(self, t: _Target) -> tuple[VerdictKind, str | None]:
        url = t.url or ""
        for r in self._exc:
            if r.url and _url_prefix(r.url, url):
                return "excluded", f"exclude:{r.entry}"
        host = _Target(addrs=t.addrs, name=t.name)
        host_v = self._judge(host)
        if host_v[0] in ("excluded", "unknown"):
            return host_v
        for r in self._inc:
            if r.url and _url_prefix(r.url, url):
                return "in", f"include:{r.entry}"
        return host_v


# --------------------------------------------------------------------------- Helfer


def _name_hit(r: _Rule, name: str) -> bool:
    if r.name is not None:
        return r.name == name
    if r.wildcard is not None:
        return name.endswith("." + r.wildcard)
    return False


def _url_prefix(rule_url: str, url: str) -> bool:
    if url == rule_url:
        return True
    if rule_url.endswith("/"):
        return url.startswith(rule_url)
    return url.startswith(rule_url + "/") or url.startswith(rule_url + "?")


def _range_nets(text: str) -> tuple[IPNet, ...]:
    m = _RANGE.fullmatch(text)
    if not m:
        return ()
    first_s, last_s = m.group(1), m.group(2)
    if "." not in last_s:
        last_s = first_s.rsplit(".", 1)[0] + "." + last_s
    try:
        first = ipaddress.IPv4Address(first_s)
        last = ipaddress.IPv4Address(last_s)
    except ValueError:
        return ()
    if last < first:
        return ()
    return tuple(ipaddress.summarize_address_range(first, last))


def _addr_target(text: str) -> _Target | None:
    """IP-Adresse (alle Lesarten) aus einem Rohwert; ``None``, wenn es keine IP ist."""
    s = text.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    if ":" in s:
        ip = normalize_ip(s)
        return _Target(addrs=(ipaddress.ip_address(ip),)) if ip else _Target(addrs=(None,))
    cands = ipv4_candidates(s)
    if cands is None:
        return None
    return _Target(addrs=tuple(ipaddress.ip_address(c) if c else None for c in cands))


def _host_target(text: str) -> _Target | None:
    t = _addr_target(text)
    if t is not None:
        return t
    name = normalize_hostname(text)
    return _Target(name=name) if name else None


def _url_target(text: str) -> _Target | None:
    u = normalize_url(text)
    if u is None:
        return None
    rest = u.split("://", 1)[1]
    authority = re.split(r"[/?]", rest, maxsplit=1)[0]
    hp = split_host_port(authority)
    if hp is None:
        return None
    host = _host_target(hp[0])
    if host is None:
        return None
    return _Target(addrs=host.addrs, name=host.name, url=u)


def _parse_target(identifier: str) -> _Target | None:
    s = identifier.strip()
    if not s or len(s) > 8192 or has_control(s):
        return None
    if s.startswith("svc:"):
        host = s[4:].rsplit("|", 1)[0]
        return _parse_target(host) if host else None
    if s.startswith("ip:"):
        space, sep, addr = s[3:].partition("/")
        if not sep or space != "default":
            return None
        ip = normalize_ip(addr)
        return _Target(addrs=(ipaddress.ip_address(ip),)) if ip else None
    if s.startswith(("fqdn:", "name:")):
        name = normalize_hostname(s.split(":", 1)[1])
        return _Target(name=name) if name else None
    if s.startswith("url:"):
        return _url_target(s[4:])
    if "://" in s:
        return _url_target(s)
    if re.fullmatch(r"[0-9a-fA-F:.]+/\d{1,3}", s):
        try:
            return _Target(nets=(ipaddress.ip_network(s, strict=False),))
        except ValueError:
            return None
    if _RANGE.fullmatch(s):
        nets = _range_nets(s)
        return _Target(nets=nets) if nets else None
    hp = (s, None) if s.count(":") > 1 and not s.startswith("[") else split_host_port(s)
    if hp is None:
        return None
    host, _port = hp
    return _host_target(host)


def _parse_days(value: Any) -> frozenset[int] | None:
    if value is None or value in ("*", "daily", "all"):
        return frozenset(range(7))
    items: list[str]
    if isinstance(value, str):
        items = [p.strip() for p in value.lower().split(",") if p.strip()]
    elif isinstance(value, list | tuple):
        items = [str(p).strip().lower() for p in value]
    else:
        return None
    days: set[int] = set()
    for item in items:
        if "-" in item:
            a, _, b = item.partition("-")
            if a[:3] not in _DAYS or b[:3] not in _DAYS:
                return None
            i, j = _DAYS[a[:3]], _DAYS[b[:3]]
            while True:
                days.add(i)
                if i == j:
                    break
                i = (i + 1) % 7
        elif item[:3] in _DAYS:
            days.add(_DAYS[item[:3]])
        else:
            return None
    return frozenset(days) if days else None


def _minutes(value: Any, *, allow_24: bool = False) -> int | None:
    if not isinstance(value, str):
        return None
    m = _HHMM.fullmatch(value.strip())
    if not m:
        return None
    if m.group(3) is not None:
        return 24 * 60 if allow_24 else None
    return int(m.group(1)) * 60 + int(m.group(2))


def _parse_window(w: Any) -> _Window | None:
    if not isinstance(w, Mapping):
        return None
    days = _parse_days(w.get("days"))
    start = _minutes(w.get("from", "00:00"))
    end = _minutes(w.get("to", "24:00"), allow_24=True)
    tz_name = w.get("tz", "UTC")
    if days is None or start is None or end is None or not isinstance(tz_name, str):
        return None
    try:
        tz = ZoneInfo(tz_name)
    except (ValueError, KeyError, OSError):
        return None
    return _Window(days, start, end, tz)
