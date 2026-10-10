"""Kennungen und Identitäten (Architektur 5.8).

* :func:`normalize_identifier` bringt Kennungen in kanonische Form
  (``ip:default/10.0.0.5``, ``mac:..``, ``svc:<host>|tcp/22``). Secrets werden
  über ``ariadne.store.chain.secret_key`` zu ``secret:<art>|h:<hmac>``.
* :class:`IdentityGraph` fasst Kennungen per Union-Find zu Entitäten zusammen:
  automatisch nur über gleiche starke Kennungen (IP im selben Adressraum, MAC,
  SSH-Hostkey, Maschinen-SID) und nur, wenn alle beteiligten Kennungen mit
  Scope-Urteil dasselbe Urteil haben; sonst entsteht ein Merge-Vorschlag.
  Schwache Kennungen (FQDN, NetBIOS) verbinden nie zwei Hosts, sie hängen nur
  an einem Host, wenn genau einer sie trägt.
* Nutzerentscheide: ``d.entity.merge`` erzwingt (Muss), ``d.entity.split``
  verbietet (Darf-nicht).

Keine Regex: Kennungen stammen aus Zieldaten und werden mit String-Operationen
und ``ipaddress`` geprüft.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ariadne.store.chain import secret_key

__all__ = [
    "HOST_TYPES",
    "STRONG_TYPES",
    "WEAK_TYPES",
    "SCOPED_TYPES",
    "id_type",
    "strength",
    "canon_ip",
    "canon_mac",
    "canon_hostname",
    "normalize_identifier",
    "host_identifier",
    "host_part",
    "entity_rank",
    "MergeSuggestion",
    "IdentityGraph",
]

HOST_TYPES = frozenset({"ip", "mac", "sshkey", "sid", "fqdn", "netbios", "name", "ctx", "local"})
STRONG_TYPES = frozenset({"ip", "mac", "sshkey", "sid"})
WEAK_TYPES = frozenset({"fqdn", "netbios", "name"})
SCOPED_TYPES = frozenset({"ip", "fqdn", "url", "svc"})
_TYPE_RANK = {"ip": 0, "mac": 1, "sshkey": 2, "sid": 3, "fqdn": 4, "netbios": 5, "name": 6, "local": 7,
              "ctx": 8}
_LABELS = {"ip": "IP-Adresse", "mac": "MAC-Adresse", "sshkey": "SSH-Hostkey", "sid": "Maschinen-SID"}
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
_HEX = frozenset("0123456789abcdef")
_MAX = 2048


def id_type(key: str) -> str:
    return key.split(":", 1)[0]


def strength(key: str) -> str:
    t = id_type(key)
    if t in STRONG_TYPES:
        return "strong"
    if t in WEAK_TYPES:
        return "weak"
    return "none"


def _printable(s: str) -> bool:
    return bool(s) and all(0x21 <= ord(c) <= 0x7E or ord(c) > 0xA0 for c in s)


def canon_ip(text: str) -> str | None:
    s = text.strip()
    if not s or len(s) > 64:
        return None
    if "%" in s:
        s = s.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def canon_mac(text: str) -> str | None:
    s = text.strip().lower().replace("-", ":")
    parts = s.split(":")
    if len(parts) != 6 or any(len(p) != 2 or any(c not in _HEX for c in p) for p in parts):
        return None
    return s


def canon_hostname(text: str) -> str | None:
    s = text.strip().lower().rstrip(".")
    if not s or len(s) > 253 or canon_ip(s) is not None:
        return None
    for label in s.split("."):
        if not label or len(label) > 63 or any(c not in _HOST_CHARS for c in label):
            return None
    return s


def normalize_identifier(key: str, project_key: bytes | None = None, *,
                         secret_sink: Callable[[str, str, str], None] | None = None) -> str | None:
    """Kanonische Kennung oder None, wenn ungültig.

    Secrets im Klartext (``secret:<art>|<wert>``) werden mit ``project_key`` zu
    ``secret:<art>|h:<hmac>``; ``secret_sink(kennung, art, wert)`` bekommt den
    Klartext zum Speichern in ``secret_value``.
    """
    if not isinstance(key, str) or not key or len(key) > _MAX or ":" not in key:
        return None
    t, rest = key.split(":", 1)
    if t == "ip":
        space, sep, addr = rest.partition("/")
        if not sep or not space or len(space) > 32 or not all(c.isalnum() or c in "-_" for c in space):
            return None
        ip = canon_ip(addr)
        return f"ip:{space.lower()}/{ip}" if ip else None
    if t == "mac":
        mac = canon_mac(rest)
        return f"mac:{mac}" if mac else None
    if t == "fqdn":
        name = canon_hostname(rest)
        return f"fqdn:{name}" if name else None
    if t == "netbios":
        nb = rest.strip().upper()
        if not nb or len(nb) > 32 or "|" in nb or not _printable(nb):
            return None
        return f"netbios:{nb}"
    if t == "name":
        name = canon_hostname(rest)
        if name:
            return f"fqdn:{name}"
        nb = rest.strip()
        return f"name:{nb}" if nb and len(nb) <= 253 and _printable(nb) and "|" not in nb else None
    if t == "sshkey":
        ktype, sep, fp = rest.partition(":")
        if not sep or not ktype or len(ktype) > 32 or not fp or len(fp) > 160 or not _printable(fp):
            return None
        if not all(c.isalnum() or c == "-" for c in ktype):
            return None
        return f"sshkey:{ktype.lower()}:{fp}"
    if t == "sid":
        sid = rest.strip().upper()
        parts = sid.split("-")
        if len(parts) < 4 or parts[0] != "S" or not all(p.isdigit() for p in parts[1:]):
            return None
        return f"sid:{sid}"
    if t == "svc":
        host, sep, pp = rest.rpartition("|")
        proto, sep2, port = pp.partition("/")
        if not sep or not sep2 or proto.lower() not in ("tcp", "udp", "sctp") or not port.isdigit():
            return None
        if int(port) > 65535:
            return None
        h = "ctx:host" if host == "ctx:host" else normalize_identifier(host, project_key,
                                                                        secret_sink=secret_sink)
        if h is None or id_type(h) not in HOST_TYPES:
            return None
        return f"svc:{h}|{proto.lower()}/{int(port)}"
    if t == "ctx":
        if rest == "host":
            return "ctx:host"
        return key if _printable(rest) and len(rest) <= 256 else None
    if t == "local":
        return key if _printable(rest) else None
    if t in ("url", "id"):
        val = rest.strip()
        return f"{t}:{val}" if _printable(val.replace(" ", "x")) else None
    if t == "secret":
        kind, sep, value = rest.partition("|")
        if not sep or not kind or len(kind) > 32 or not all(c.isalnum() or c in "-_" for c in kind):
            return None
        if value.startswith("h:") and len(value) == 66 and all(c in _HEX for c in value[2:]):
            return key
        if project_key is None or not value:
            return None
        ident = f"secret:{kind}|h:{secret_key(project_key, kind, value)}"
        if secret_sink is not None:
            secret_sink(ident, kind, value)
        return ident
    return None


def host_identifier(raw: str) -> str | None:
    """Host-Kennung aus Nutzereingaben: mit Typ (``ip:default/..``, ``name:web01``) oder ohne
    (``10.10.10.5``, ``fe80::1``, ``web01.lab``). Nie DNS."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    ident = normalize_identifier(s) if ":" in s else None
    if ident is not None and id_type(ident) in HOST_TYPES:
        return ident
    ip = canon_ip(s)
    if ip:
        return f"ip:default/{ip}"
    name = canon_hostname(s)
    return f"fqdn:{name}" if name else None


def host_part(key: str) -> str | None:
    """Host-Kennung eines Service (``svc:<host>|tcp/22``) oder die Kennung selbst bei Hosts."""
    t = id_type(key)
    if t == "svc":
        return key[4:].rpartition("|")[0]
    if t in HOST_TYPES:
        return key
    return None


def entity_rank(key: str, verdicts: dict[str, str | None]) -> tuple:
    """Sortierschlüssel für die stärkste Kennung einer Entität (kleiner ist stärker)."""
    t = id_type(key)
    in_scope = 0 if verdicts.get(key) == "in" else 1
    if t == "ip":
        addr = ipaddress.ip_address(key.split("/", 1)[1])
        return (_TYPE_RANK[t], in_scope, addr.version, int(addr), key)
    return (_TYPE_RANK.get(t, 9), in_scope, 0, 0, key)


@dataclass(frozen=True)
class MergeSuggestion:
    key: str  # stabil über die sortierten Kennungen
    identifiers: tuple[str, ...]
    shared: str
    reason: str


@dataclass
class IdentityGraph:
    """Union-Find mit Scope-Regel und Muss/Darf-nicht-Paaren."""

    verdicts: dict[str, str | None]
    parent: dict[str, str] = field(default_factory=dict)
    members: dict[str, set[str]] = field(default_factory=dict)
    cannot: set[frozenset[str]] = field(default_factory=set)
    suggestions: dict[str, MergeSuggestion] = field(default_factory=dict)
    blocked_must: list[tuple[str, ...]] = field(default_factory=list)

    def add(self, key: str) -> None:
        if key not in self.parent:
            self.parent[key] = key
            self.members[key] = {key}

    def find(self, key: str) -> str:
        self.add(key)
        root = key
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[key] != root:
            self.parent[key], key = root, self.parent[key]
        return root

    def group(self, key: str) -> set[str]:
        return self.members[self.find(key)]

    def _violates(self, a: str, b: str) -> bool:
        ga, gb = self.group(a), self.group(b)
        for pair in self.cannot:
            x, y = tuple(pair)
            if (x in ga and y in gb) or (x in gb and y in ga):
                return True
        return False

    def _verdict_set(self, key: str) -> set[str]:
        return {v for k in self.group(key) if (v := self.verdicts.get(k)) is not None}

    def _union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if len(self.members[ra]) < len(self.members[rb]):
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.members[ra] |= self.members.pop(rb)

    def main(self, key: str) -> str:
        return min(self.group(key), key=lambda k: entity_rank(k, self.verdicts))

    # ---------------------------------------------------------------- Regeln
    def forbid(self, identifiers: Iterable[str]) -> None:
        ids = sorted(set(identifiers))
        for i, x in enumerate(ids):
            for y in ids[i + 1 :]:
                self.cannot.add(frozenset((x, y)))

    def must(self, identifiers: Iterable[str]) -> bool:
        ids = list(dict.fromkeys(identifiers))
        ok = True
        for k in ids:
            self.add(k)
        for x, y in zip(ids, ids[1:], strict=False):
            if self.find(x) == self.find(y):
                continue
            if self._violates(x, y):
                ok = False
                continue
            self._union(x, y)
        if not ok:
            self.blocked_must.append(tuple(ids))
        return ok

    def link_strong(self, a: str, b: str, shared: str) -> bool:
        """Verbindet zwei Kennungen über eine gemeinsame starke Kennung ``shared``."""
        self.add(a)
        self.add(b)
        if self.find(a) == self.find(b):
            return True
        if self._violates(a, b):
            return False
        va, vb = self._verdict_set(a), self._verdict_set(b)
        if va and vb and len(va | vb) > 1:
            self._suggest(a, b, shared)
            return False
        self._union(a, b)
        return True

    def attach_weak(self, weak: str, holders: Iterable[str]) -> bool:
        """Hängt eine schwache Kennung an genau einen Träger; nie zwischen zwei Hosts."""
        self.add(weak)
        roots = {self.find(h) for h in holders}
        if len(roots) != 1 or len(self.group(weak)) != 1:
            return False
        holder = next(iter(roots))
        if self._violates(weak, holder):
            return False
        self._union(weak, holder)
        return True

    def _suggest(self, a: str, b: str, shared: str) -> None:
        ma, mb = self.main(a), self.main(b)
        ids = tuple(sorted({ma, mb, shared}))
        key = "merge:" + "|".join(ids)
        if key in self.suggestions:
            return
        va = self.verdicts.get(ma) or "?"
        vb = self.verdicts.get(mb) or "?"
        label = _LABELS.get(id_type(shared), "Kennung")
        reason = (f"gleiche {label} {_short(shared)} auf {_short(ma)} ({va}) und {_short(mb)} ({vb})")
        self.suggestions[key] = MergeSuggestion(key, ids, shared, reason)

    def roots(self) -> dict[str, str]:
        return {k: self.find(k) for k in list(self.parent)}


def _short(key: str) -> str:
    t = id_type(key)
    if t == "ip":
        return key.split("/", 1)[1]
    return key.split(":", 1)[1] if ":" in key else key
