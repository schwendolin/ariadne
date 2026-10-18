"""Fakten für die Regeln: ein schmaler, nur lesender Blick auf die Projektion in ``derived.db``.

Gelesen werden nur Sichten und Tabellen der Auswertung (``v_host``, ``v_service``, ``identifier``,
``claim``, ``claim_source``, ``obs_unit``, ``own_addr``, ``secret_value`` zum Maskieren), jede Abfrage
mit eigener Grenze (``LIMIT``). Rohdaten, Journal und Klartext von Secrets sieht keine Regel.

Was zählt (Ausschlüsse für alle Regeln):

* Werte nur in den Zuständen ``auto`` und ``confirmed``, nicht abgelöst (``history = 0``), keine
  Secrets. Vorschläge (``candidate``), verworfene Werte und stille Heuristiken lösen nichts aus.
* Hosts im Scope (``in``), nicht im Nebel (``claim_state`` ``auto`` oder ``confirmed``), nicht als
  Sackgasse, erledigt oder ausserhalb markiert; eigene Adressen von Kali sind nie Hosts.
* Dienste im Scope mit Zustand ``open``, Arbeitsstand wie bei Hosts.
* Ein Einwertiges Prädikat mit zwei gültigen Werten (offener Widerspruch) gilt als unbekannt.
* Quellen aus misstrauten Befehlen (``d.unit.distrust``) zählen nicht als Beobachter.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from ariadne.rules.commands import Cmd, nmap_opts, parse, runs_script, targets

__all__ = ["ClaimRef", "Service", "Host", "Unit", "Facts", "load", "EXCLUDED_WORK", "TOOL_WORDS"]

EXCLUDED_WORK = frozenset({"dead_end", "done", "out_of_scope"})
_OK_CLAIM_STATES = ("auto", "confirmed")
_PREDICATES = (
    "service.name",
    "service.product",
    "service.version",
    "service.state",
    "service.tunnel",
    "service.script",
    "host.script",
    "host.smb_os",
    "host.state",
)
_MANY = frozenset({"service.script", "host.script"})
_LIMIT_HOSTS = 5000
_LIMIT_SERVICES = 100_000
_LIMIT_ROWS = 500_000
_LIMIT_UNITS = 20_000
_STATE_PREDICATES = frozenset({"service.state", "host.state"})

# Werkzeuge, deren Befehle ein Erkenner liest (Vorfilter, damit nicht jeder Befehl zerlegt wird).
TOOL_WORDS = (
    "nmap masscan rustscan naabu udpx unicornscan ftp lftp ncftp curl wget nxc netexec crackmapexec cme "
    "smbclient rpcclient smbmap enum4linux enum4linux-ng showmount mount gobuster feroxbuster dirb "
    "dirsearch ffuf wfuzz nikto whatweb wpscan httpx katana hakrawler eyewitness aquatone hydra medusa "
    "ncrack patator vncviewer xtightvncviewer xvncviewer telnet snmpwalk snmpget snmpbulkwalk onesixtyone "
    "snmp-check smtp-user-enum ismtp mysql mariadb psql mssqlclient sqsh sqlcmd redis-cli mongo mongosh "
    "odat sqlplus searchsploit"
).split()
_TOOL_RE = re.compile(
    r"(?<![\w-])(?:"
    + "|".join(re.escape(t) for t in sorted(TOOL_WORDS, key=len, reverse=True))
    + r")(?![\w-])"
)


class ClaimRef(NamedTuple):
    """Ein gültiger Wert (Claim) als Beleg und Auslöser."""

    claim_key: str
    predicate: str
    value: str
    from_target: bool
    suspect: bool
    last_ts: int | None


class _Owner:
    """Gemeinsames von Host und Dienst: Werte je Prädikat, Skripte, beobachtende Einheiten."""

    __slots__ = ("claims", "scripts", "observers", "single")

    def __init__(self) -> None:
        self.claims: dict[str, list[ClaimRef]] = defaultdict(list)
        self.scripts: dict[str, ClaimRef] = {}
        self.observers: set[str] = set()
        self.single: dict[str, ClaimRef] = {}

    def finish(self) -> None:
        self.single = {p: v[0] for p, v in self.claims.items() if len(v) == 1}

    def one(self, predicate: str) -> ClaimRef | None:
        """Der Wert eines einwertigen Prädikats; ``None`` ohne Wert oder bei Widerspruch (zwei Werte)."""
        return self.single.get(predicate)

    def value(self, predicate: str) -> str | None:
        c = self.single.get(predicate)
        return c.value if c is not None else None


class Service(_Owner):
    __slots__ = ("service_id", "host_id", "proto", "port", "eligible", "name")

    def __init__(self, service_id: str, host_id: str, proto: str, port: int) -> None:
        super().__init__()
        self.service_id, self.host_id, self.proto, self.port = service_id, host_id, proto, port
        self.eligible = False
        self.name: str | None = None

    def finish(self) -> None:
        super().finish()
        v = self.value("service.name")
        self.name = v.lower() if v is not None else None


class Host(_Owner):
    __slots__ = (
        "host_id",
        "label",
        "eligible",
        "addrs",
        "names",
        "idents",
        "services",
        "open_services",
        "ip",
    )

    def __init__(self, host_id: str, label: str) -> None:
        super().__init__()
        self.host_id, self.label = host_id, label
        self.eligible = False
        self.addrs: list[tuple[str, str | None]] = []  # (kanonisch, Urteil)
        self.names: list[tuple[str, str | None]] = []
        self.idents: list[str] = []
        self.services: list[Service] = []
        self.open_services: list[Service] = []
        self.ip: str | None = None

    def finish(self) -> None:
        super().finish()
        for s in self.services:
            s.finish()
        self.services.sort(key=lambda x: (x.proto, x.port))
        self.open_services = [
            s for s in self.services if self.eligible and s.eligible and s.value("service.state") == "open"
        ]
        # Adresse für Vorlagen: zuerst die Adresse der Kennung, dann IPv4 vor IPv6, jeweils im Scope; ohne
        # Adresse im Scope die erste bekannte (der Encoder sperrt sie dann).
        ranked = sorted(
            self.addrs, key=lambda a: (a[1] != "in", f"ip:default/{a[0]}" != self.host_id, ":" in a[0], a[0])
        )
        self.ip = ranked[0][0] if ranked else None

    def addr_names(self) -> tuple[list[str], list[str]]:
        return [a for a, _ in self.addrs], [n for n, _ in self.names]


class Unit(NamedTuple):
    unit_id: str
    kind: str
    cmd_id: str | None
    title: str | None
    path: str | None
    ts: int | None


@dataclass
class Facts:
    hosts: dict[str, Host]
    services: dict[str, Service]
    units: dict[str, Unit]
    ip_verdict: dict[str, str | None]
    name_verdict: dict[str, str | None]
    known_secrets: list[str]
    has_unit_line: bool
    _cmd_by_id: dict[str, Unit] = field(default_factory=dict)
    _commands: list[tuple[Unit, Cmd]] | None = None
    _by_host: dict[str, list[Cmd]] | None = None
    _ss_args: list[str] | None = None
    _ran: dict[tuple[str, str], bool] = field(default_factory=dict)
    memo: dict[str, Any] = field(default_factory=dict)  # Zwischenergebnisse der Regeln (pro Anfrage)

    def commands(self) -> list[tuple[Unit, Cmd]]:
        """Alle einfachen Befehle mit einem bekannten Werkzeug (vorgefiltert, zerlegt mit Cache)."""
        if self._commands is None:
            out: list[tuple[Unit, Cmd]] = []
            for u in self.units.values():
                if u.kind != "command" or not u.title or not _TOOL_RE.search(u.title):
                    continue
                for c in parse(u.title):
                    out.append((u, c))
            self._commands = out
        return self._commands

    def host_cmds(self, host_id: str) -> list[Cmd]:
        """Befehle, die diesen Host als Ziel nennen (Adresse, Name, Netz oder Bereich); einmal indexiert."""
        if self._by_host is None:
            self._by_host = _index_commands(self.commands(), self.hosts)
        return self._by_host.get(host_id, [])

    def searchsploit_args(self) -> list[str]:
        """Argumente aller ``searchsploit``-Aufrufe (klein), für die Erkennung «Version recherchiert»."""
        if self._ss_args is None:
            self._ss_args = [
                a.lower() for _u, c in self.commands() if c.tool == "searchsploit" for a in c.args
            ]
        return self._ss_args

    def ran_script(self, unit_id: str, script: str) -> bool:
        """Hat der nmap-Lauf hinter dieser Einheit das Skript ausgeführt (``-sC``, ``--script …``)?"""
        key = (unit_id, script)
        hit = self._ran.get(key)
        if hit is None:
            hit = any(
                c.tool == "nmap" and runs_script(nmap_opts(c.args), script) for c in self.unit_cmds(unit_id)
            )
            self._ran[key] = hit
        return hit

    def unit_cmds(self, unit_id: str) -> tuple[Cmd, ...]:
        """Befehle hinter einer Einheit: der Befehl selbst oder bei Dateien der erzeugende Befehl."""
        u = self.units.get(unit_id)
        if u is None:
            return ()
        if u.kind != "command" and u.cmd_id:
            u = self._cmd_by_id.get(u.cmd_id) or u
        if u.kind != "command" or not u.title:
            return ()
        return parse(u.title)


def _index_commands(commands: list[tuple[Unit, Cmd]], hosts: dict[str, Host]) -> dict[str, list[Cmd]]:
    by_addr: dict[str, str] = {}
    by_name: dict[str, str] = {}
    parsed: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, str]] = []
    for h in hosts.values():
        for a, _v in h.addrs:
            by_addr.setdefault(a, h.host_id)
            try:
                parsed.append((ipaddress.ip_address(a), h.host_id))
            except ValueError:
                pass
        for n, _v in h.names:
            by_name.setdefault(n, h.host_id)
    out: dict[str, list[Cmd]] = defaultdict(list)
    for _u, c in commands:
        t = targets(c.args)
        hit = {by_addr[a] for a in t.addrs if a in by_addr} | {by_name[n] for n in t.names if n in by_name}
        if t.nets or t.ranges:
            for ip, hid in parsed:
                if any(ip.version == n.version and ip in n for n in t.nets) or (
                    ip.version == 4 and any(lo <= ip <= hi for lo, hi in t.ranges)  # type: ignore[operator]
                ):
                    hit.add(hid)
        for hid in hit:
            out[hid].append(c)
    return out


def _has_table(conn: Any, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name = ?", (name,))
    return row.fetchone() is not None


_IPV4 = re.compile(r"(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}")


def _canon_ip(text: str) -> str | None:
    if _IPV4.fullmatch(text):  # schneller Weg: die Projektion speichert IPv4 schon kanonisch
        return text if all(int(p) < 256 for p in text.split(".")) else None
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return None


def _known_secrets(conn: Any) -> list[str]:
    vals = [
        str(r[0]) for r in conn.execute("SELECT value FROM secret_value LIMIT 10000") if isinstance(r[0], str)
    ]
    return sorted({v for v in vals if len(v) >= 4}, key=len, reverse=True)


def _chunks(seq: list[Any], n: int = 500) -> Iterable[list[Any]]:
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def load(conn: Any) -> Facts:
    """Liest die Projektion (nur lesend, mit Grenzen) in :class:`Facts`."""
    own = {str(r[0]) for r in conn.execute("SELECT addr FROM own_addr LIMIT 1000")}
    hosts: dict[str, Host] = {}
    for hid, label, scope, cstate, work in conn.execute(
        "SELECT host_id, label, scope, claim_state, work FROM v_host LIMIT ?", (_LIMIT_HOSTS,)
    ):
        h = Host(str(hid), str(label or hid))
        h.eligible = scope == "in" and cstate in _OK_CLAIM_STATES and work not in EXCLUDED_WORK
        hosts[h.host_id] = h
    services: dict[str, Service] = {}
    # Dienste direkt aus ``entity`` (wie ``v_service``, ohne json_extract): Die Kennung eines Dienstes ist
    # ``svc:<Host-Entität>|<proto>/<port>``; Dienste eigener Adressen fallen weg, weil ihr Host fehlt.
    for sid, scope, cstate, work in conn.execute(
        "SELECT entity_id, scope, claim_state, work FROM entity WHERE type = 'service' LIMIT ?",
        (_LIMIT_SERVICES,),
    ):
        hid, _, pp = sid[4:].rpartition("|")
        proto, _, port_s = pp.partition("/")
        h = hosts.get(hid)
        if h is None or not port_s.isdigit():
            continue
        s = Service(sid, h.host_id, proto or "tcp", int(port_s))
        s.eligible = h.eligible and scope == "in" and cstate in _OK_CLAIM_STATES and work not in EXCLUDED_WORK
        services[s.service_id] = s
        h.services.append(s)
    ip_verdict: dict[str, str | None] = {}
    name_verdict: dict[str, str | None] = {}
    for key, typ, eid, verdict in conn.execute(
        "SELECT key, type, entity_id, scope_verdict FROM identifier WHERE entity_id IS NOT NULL LIMIT ?",
        (_LIMIT_ROWS,),
    ):
        key, eid = str(key), str(eid)
        target = hosts.get(eid)
        if typ == "ip":
            addr = _canon_ip(key.split("/", 1)[-1])
            if addr is None:
                continue
            v = "own" if addr in own else verdict
            ip_verdict[addr] = v
            if target is not None:
                target.addrs.append((addr, v))
        elif typ == "fqdn":
            name = key.split(":", 1)[-1].lower()
            name_verdict[name] = verdict
            if target is not None:
                target.names.append((name, verdict))
        if target is not None:
            target.idents.append(key)
    # Werte; bei Zustandswerten (``service.state``, ``host.state``) zugleich die beobachtenden Einheiten:
    # mit höchstens zwei Quellen sind das ``first_unit`` und ``last_unit``, sonst gezielt aus
    # ``claim_source`` (über den Index auf ``claim_key``). Misstraute Einheiten fallen später weg.
    marks = ",".join("?" * len(_PREDICATES))
    more: dict[str, _Owner] = {}
    owners: dict[str, _Owner] = {**hosts, **services}
    for ck, eid, pred, value, ft, sus, last_ts, first_u, last_u, nsrc in conn.execute(
        "SELECT claim_key, entity_id, predicate, value_text, from_target, suspect, last_ts, first_unit, "  # noqa: S608
        f"last_unit, sources FROM claim WHERE predicate IN ({marks}) AND state IN ('auto','confirmed') "
        "AND history = 0 AND is_secret = 0 LIMIT ?",
        (*_PREDICATES, _LIMIT_ROWS),
    ).fetchall():
        owner = owners.get(eid)
        if owner is None or value.__class__ is not str:
            continue
        ref = ClaimRef(ck, pred, value, ft == 1, sus == 1, last_ts if last_ts.__class__ is int else None)
        if pred in _MANY:
            owner.scripts[value.lower()] = ref
            continue
        owner.claims[pred].append(ref)
        if pred in _STATE_PREDICATES:
            obs = owner.observers
            if first_u is not None:
                obs.add(first_u)
            if last_u is not None:
                obs.add(last_u)
            if nsrc.__class__ is int and nsrc > 2:
                more[ck] = owner
    for part in _chunks(sorted(more)):
        q = ",".join("?" * len(part))
        for ck, unit_id in conn.execute(
            f"SELECT claim_key, unit_id FROM claim_source WHERE claim_key IN ({q}) "  # noqa: S608
            "AND unit_id IS NOT NULL AND distrusted = 0",
            tuple(part),
        ):
            more[ck].observers.add(unit_id)
    for svc in services.values():  # Beobachter eines Dienstes beobachten auch seinen Host
        if svc.observers:
            hosts[svc.host_id].observers |= svc.observers
    # Befehle: im echten ``derived.db`` aus ``unit`` (jeder Befehl, auch ohne Parser-Treffer), sonst
    # (Projektion ohne Einheiten-Tabellen) aus ``obs_unit``. Misstraute Befehle zählen nicht.
    distrusted = {str(r[0]) for r in conn.execute("SELECT cmd_id FROM unit_distrust LIMIT 100000")}
    if _has_table(conn, "unit"):
        title, table, order = "cmd_text", "unit", "ts_utc_ns DESC"
    else:
        title, table, order = "title", "obs_unit", "journal_seq DESC"
    cols = f"unit_id, kind, cmd_id, {title}, path, ts_utc_ns"

    def add(rows: Iterable[tuple[Any, ...]], into: dict[str, Unit]) -> None:
        for uid, kind, cmd_id, title, path, ts in rows:
            if cmd_id is not None and str(cmd_id) in distrusted:
                continue
            into[str(uid)] = Unit(
                str(uid), str(kind), cmd_id, title, path, ts if isinstance(ts, int) else None
            )

    units: dict[str, Unit] = {}
    add(conn.execute(f"SELECT {cols} FROM {table} ORDER BY {order} LIMIT ?", (_LIMIT_UNITS,)), units)  # noqa: S608
    # Beobachter, die nicht unter den jüngsten Einheiten sind, gezielt nachladen
    missing = sorted({u for h in hosts.values() for u in h.observers} - set(units))
    for part in _chunks(missing):
        q = ",".join("?" * len(part))
        add(conn.execute(f"SELECT {cols} FROM {table} WHERE unit_id IN ({q})", tuple(part)), units)  # noqa: S608
    by_cmd = {u.cmd_id: u for u in units.values() if u.kind == "command" and u.cmd_id}
    need = sorted({u.cmd_id for u in units.values() if u.kind != "command" and u.cmd_id} - set(by_cmd))
    for part in _chunks(need):
        q = ",".join("?" * len(part))
        extra: dict[str, Unit] = {}
        add(
            conn.execute(
                f"SELECT {cols} FROM {table} WHERE kind = 'command' AND cmd_id IN ({q})",  # noqa: S608
                tuple(part),
            ),
            extra,
        )
        by_cmd.update({u.cmd_id: u for u in extra.values() if u.cmd_id})
    for h in hosts.values():
        h.finish()
    return Facts(
        hosts=hosts,
        services=services,
        units=units,
        ip_verdict=ip_verdict,
        name_verdict=name_verdict,
        known_secrets=_known_secrets(conn),
        has_unit_line=_has_table(conn, "unit_line"),
        _cmd_by_id=by_cmd,
    )
