"""``GET /p/{pid}/graph`` (``docs/web-api.md`` 7): Karte mit Kali, Segmenten, Hosts, Services,
Faden und Out-of-Scope-Rand.

Grundlage sind :func:`ariadne.ingest.queries.hosts` (Hosts mit Services und stillen Zählern) und
die Sichten ``v_host``, ``v_service``, ``v_keystep``. Regeln: Hosts mit Urteil ungleich ``in``
erscheinen nie als Knoten, nur im Rand ``oos``; eigene Adressen von Kali nie als Host (E42);
Kandidaten (Nebel) nur mit der Ebene ``fog``; Kanten zeigen nur auf Knoten derselben Antwort.
"""

from __future__ import annotations

import contextlib
import ipaddress
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import APIRouter, Query
from starlette.responses import Response

from ariadne.ingest import queries
from ariadne.ingest.db import get_meta
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.text import Bag, iso
from ariadne.web.api.views import loads

__all__ = [
    "add_routes",
    "service_class",
    "scope_nets",
    "segment_of",
    "host_data",
    "host_node",
    "thread_edges",
    "LAYERS",
    "SERVICE_CLASSES",
    "TABLE_ONLY_HOSTS",
    "build_graph",
]

LAYERS = ("topology", "services", "thread", "oos", "fog")
SERVICE_CLASSES = ("web", "smb", "db", "remote", "file", "mail", "other")
TABLE_ONLY_HOSTS = 200  # ab so vielen Hosts: Karte als Tabelle (E50)
OOS_MAX = 200

_NAMES = {
    "web": ("http", "https", "http-proxy", "http-alt", "https-alt", "ajp13", "www", "webcache", "http-mgmt"),
    "smb": ("microsoft-ds", "netbios-ssn", "smb", "smbd", "netbios-ns", "netbios-dgm", "samba"),
    "db": (
        "mysql",
        "postgresql",
        "postgres",
        "ms-sql-s",
        "ms-sql",
        "mssql",
        "oracle",
        "oracle-tns",
        "mongodb",
        "mongod",
        "redis",
        "db2",
        "couchdb",
        "cassandra",
        "memcache",
        "memcached",
        "elasticsearch",
    ),
    "remote": (
        "ssh",
        "telnet",
        "ms-wbt-server",
        "rdp",
        "vnc",
        "winrm",
        "wsman",
        "rlogin",
        "rsh",
        "login",
        "exec",
        "shell",
        "bindshell",
        "x11",
        "rexec",
        "distccd",
        "java-rmi",
    ),
    "file": (
        "ftp",
        "ftps",
        "ftp-data",
        "tftp",
        "nfs",
        "nfs_acl",
        "mountd",
        "afp",
        "rsync",
        "ccproxy-ftp",
        "iscsi",
    ),
    "mail": ("smtp", "smtps", "submission", "pop3", "pop3s", "imap", "imaps"),
}
_PORTS = {
    "web": (80, 443, 8000, 8008, 8080, 8180, 8443, 8888),
    "smb": (139, 445),
    "db": (1433, 1521, 3306, 5432, 6379, 27017),
    "remote": (22, 23, 512, 513, 514, 3389, 5900, 5985, 5986),
    "file": (20, 21, 69, 873, 2049, 2121),
    "mail": (25, 110, 143, 465, 587, 993, 995),
}
_BY_NAME = {n: cls for cls, names in _NAMES.items() for n in names}
_BY_PORT = {p: cls for cls, ports in _PORTS.items() for p in ports}


def service_class(name: Any, port: Any) -> str:
    """Klasse eines Service aus Name (Vorrang) oder Port; sonst ``other``."""
    if isinstance(name, str) and name:
        n = name.lower().strip()
        for prefix in ("ssl/", "tls/"):
            if n.startswith(prefix):
                n = n[len(prefix) :]
        if n in _BY_NAME:
            return _BY_NAME[n]
        if n.startswith("http"):
            return "web"
    if isinstance(port, int) and not isinstance(port, bool) and port in _BY_PORT:
        return _BY_PORT[port]
    return "other"


def scope_nets(settings: Any) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    scope = settings.get("scope") if isinstance(settings, Mapping) else None
    include = scope.get("include") if isinstance(scope, Mapping) else None
    nets = []
    for raw in include if isinstance(include, list) else []:
        if isinstance(raw, str) and "/" in raw:
            with contextlib.suppress(ValueError):
                nets.append(ipaddress.ip_network(raw.strip(), strict=False))
    return sorted(set(nets), key=lambda n: (-n.prefixlen, str(n)))


def segment_of(addresses: Iterable[Any], nets: list[Any]) -> tuple[str, str] | None:
    """Segment eines Hosts: das genaueste Scope-Netz, sonst das beobachtete /24 bzw. /64."""
    observed = None
    for a in addresses:
        try:
            ip = ipaddress.ip_address(str(a))
        except ValueError:
            continue
        for n in nets:
            if ip.version == n.version and ip in n:
                return str(n), "scope"
        if observed is None:
            observed = str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False))
    return (observed, "observed") if observed else None


def host_data(conn: Any) -> dict[str, Any]:
    """Alles, was Hostknoten, Host-Tabelle und Host-Detail brauchen (ein Durchgang)."""
    hosts = queries.hosts(conn)
    extra = {
        str(r[0]): {
            "work_reason": r[1],
            "tags": loads(r[2], []) or [],
            "first_seen": r[3],
            "last_seen": r[4],
            "first_unit": r[5],
            "note": r[6],
        }
        for r in conn.execute(
            "SELECT host_id, work_reason, tags_json, first_seen, last_seen, first_unit, note FROM v_host"
        )
    }
    auto = {
        str(r[0])
        for r in conn.execute(
            "SELECT DISTINCT entity_id FROM claim WHERE lane = 'auto' AND entity_id IS NOT NULL"
        )
    }
    thread = {
        str(r[0]) for r in conn.execute("SELECT DISTINCT entity_id FROM keystep WHERE entity_id IS NOT NULL")
    }
    svc_conf = {
        str(r[0]): int(r[1] or 0) for r in conn.execute("SELECT service_id, conflicts FROM v_service")
    }
    rules = {
        str(r[0]): (r[1], r[2]) for r in conn.execute("SELECT key, scope_verdict, scope_rule FROM identifier")
    }
    open_conflicts = int(conn.execute("SELECT COUNT(*) FROM conflict WHERE state = 'open'").fetchone()[0])
    own = sorted(str(r[0]) for r in conn.execute("SELECT addr FROM own_addr"))
    gen = get_meta(conn, "generation")
    return {
        "hosts": hosts,
        "extra": extra,
        "auto": auto,
        "thread": thread,
        "svc_conf": svc_conf,
        "rules": rules,
        "open_conflicts": open_conflicts,
        "own": own,
        "generation": int(gen) if gen is not None and gen.isdigit() else 0,
    }


def host_node(h: Mapping[str, Any], data: Mapping[str, Any], segment: str | None, bag: Bag) -> dict[str, Any]:
    """HostNode (ohne ``kind`` ist es die HostSummary)."""
    b = bag.new()
    hid = str(h.get("host_id"))
    ex = data["extra"].get(hid) or {}
    services = list(h.get("services") or [])
    classes = Counter(service_class(s.get("name"), s.get("port")) for s in services)
    svc_ids = {str(s.get("service_id")) for s in services}
    conflicts = int(h.get("conflicts") or 0)
    auto = hid in data["auto"] or bool(svc_ids & data["auto"])
    total = int(h.get("services_total") or len(services))
    hint = "conflict" if conflicts else ("services" if total else None)
    node = {
        "kind": "host",
        "id": b(hid),
        "segment": segment,
        "label": b(h.get("label")) or "",
        "addresses": b.many(h.get("addresses")),
        "names": b.many(h.get("names")),
        "claim_state": h.get("claim_state") or "candidate",
        "knowledge": h.get("knowledge") or "mentioned",
        "access": h.get("access") or "none",
        "work": h.get("work") or "open",
        "work_reason": b(ex.get("work_reason")),
        "progress": int(h.get("progress") or 0),
        "os": b(h.get("os")),
        "services_total": total,
        "service_classes": {c: classes.get(c, 0) for c in SERVICE_CLASSES},
        "conflicts": conflicts,
        "auto": auto,
        "ai": False,
        "on_thread": hid in data["thread"],
        "hint": hint,
        "tags": b.many(t for t in ex.get("tags") or [] if isinstance(t, str)),
    }
    node["ctrl"] = b.ctrl
    return node


def _service_node(s: Mapping[str, Any], data: Mapping[str, Any], bag: Bag) -> dict[str, Any]:
    b = bag.new()
    sid = str(s.get("service_id"))
    state = s.get("state")
    node = {
        "kind": "service",
        "id": b(sid),
        "host": b(s.get("host_id")),
        "proto": s.get("proto") if s.get("proto") in ("tcp", "udp") else "tcp",
        "port": int(s.get("port") or 0),
        "name": b(s.get("name")),
        "product": b(s.get("product")),
        "version": b(s.get("version")),
        "class": service_class(s.get("name"), s.get("port")),
        "state": state if state in ("open", "filtered", "closed") else None,
        "claim_state": s.get("claim_state") or "candidate",
        "conflicts": data["svc_conf"].get(sid, 0),
    }
    node["ctrl"] = b.ctrl
    return node


def thread_edges(conn: Any, nodes: set[str], bag: Bag) -> list[dict[str, Any]]:
    """Der Faden: Schlüsselschritte in Reihenfolge, von Kali aus; nur Kanten zu Knoten der Antwort."""
    out: list[dict[str, Any]] = []
    prev = "kali"
    for ordinal, decision_id, step, entity_id, note, ts in conn.execute(
        "SELECT ordinal, decision_id, step, entity_id, note, ts_utc_ns FROM v_keystep ORDER BY ordinal"
    ):
        target = str(entity_id) if entity_id is not None and str(entity_id) in nodes else None
        if target is None:
            continue
        b = bag.new()
        edge = {
            "kind": "thread",
            "id": f"t{int(ordinal)}",
            "seq": len(out) + 1,
            "step": step,
            "source": b(prev),
            "target": b(target),
            "ts": iso(ts),
            "note": b(note),
            "decision_id": decision_id,
        }
        edge["ctrl"] = b.ctrl
        out.append(edge)
        prev = target
    return out


def _oos(conn: Any, data: Mapping[str, Any], bag: Bag) -> dict[str, Any]:
    own = set(data["own"])
    host_addrs: set[str] = set()
    items: list[dict[str, Any]] = []
    mentions = {
        str(r[0]): int(r[1])
        for r in conn.execute(
            "SELECT value, COUNT(*) FROM mention WHERE value_type = 'ip' AND value IS NOT NULL GROUP BY value"
        )
    }
    for h in data["hosts"]:
        host_addrs.update(str(a) for a in h.get("addresses") or [])
        if h.get("scope") == "in" or h.get("placeholder"):
            continue
        hid = str(h.get("host_id"))
        verdict = h.get("scope") if h.get("scope") in ("out", "excluded", "outside_window") else "unknown"
        b = bag.new()
        items.append(
            {
                "identifier": b(hid),
                "label": b(h.get("label")) or "",
                "verdict": verdict,
                "rule": b((data["rules"].get(hid) or (None, None))[1]),
                "mentions": sum(mentions.get(str(a), 0) for a in h.get("addresses") or []),
                "first_unit": (data["extra"].get(hid) or {}).get("first_unit"),
                "ctrl": b.ctrl,
            }
        )
    for value, verdict, n, first in conn.execute(
        "SELECT value, scope_verdict, COUNT(*), MIN(unit_id) FROM mention WHERE value_type = 'ip' "
        "AND value IS NOT NULL AND scope_verdict IN ('out', 'excluded', 'outside_window') "
        "GROUP BY value, scope_verdict ORDER BY COUNT(*) DESC LIMIT 5000"
    ):
        if str(value) in own or str(value) in host_addrs:
            continue
        ident = f"ip:default/{value}"
        b = bag.new()
        items.append(
            {
                "identifier": b(ident),
                "label": b(value) or "",
                "verdict": verdict,
                "rule": b((data["rules"].get(ident) or (None, None))[1]),
                "mentions": int(n),
                "first_unit": first,
                "ctrl": b.ctrl,
            }
        )
    items.sort(key=lambda i: (-int(i["mentions"]), str(i["identifier"])))
    return {"total": len(items), "items": items[:OOS_MAX]}


def build_graph(conn: Any, settings: Any, layers: set[str], bag: Bag, project_id: str) -> dict[str, Any]:
    data = host_data(conn)
    nets = scope_nets(settings)
    nodes: list[dict[str, Any]] = [{"kind": "kali", "id": "kali", "label": "Kali", "addresses": data["own"]}]
    edges: list[dict[str, Any]] = []
    segments: dict[str, str] = {str(n): "scope" for n in nets}
    hosts_in = [h for h in data["hosts"] if h.get("scope") == "in" and not h.get("placeholder")]
    fog = sum(1 for h in hosts_in if h.get("claim_state") == "candidate")
    shown = [h for h in hosts_in if "fog" in layers or h.get("claim_state") != "candidate"]
    host_nodes = []
    for h in shown:
        seg = segment_of(h.get("addresses") or [], nets)
        if seg is not None:
            segments.setdefault(seg[0], seg[1])
        host_nodes.append(host_node(h, data, f"seg:{seg[0]}" if seg else None, bag))
    for cidr, origin in sorted(segments.items()):
        nodes.append({"kind": "segment", "id": f"seg:{cidr}", "cidr": cidr, "label": cidr, "origin": origin})
    nodes.extend(host_nodes)
    for n in host_nodes:
        if n["segment"]:
            edges.append({"kind": "member", "id": f"m:{n['id']}", "source": n["id"], "target": n["segment"]})
    if "services" in layers:
        for h in shown:
            for s in h.get("services") or []:
                nodes.append(_service_node(s, data, bag))
    if "thread" in layers:
        ids = {str(h.get("host_id")) for h in shown}
        edges.extend(thread_edges(conn, ids, bag))
    oos = _oos(conn, data, bag) if "oos" in layers else {"total": 0, "items": []}
    return {
        "project_id": project_id,
        "generation": data["generation"],
        "nodes": nodes,
        "edges": edges,
        "oos": oos,
        "summary": {
            "hosts": len(hosts_in),
            "fog": fog,
            "with_access": sum(1 for h in hosts_in if h.get("access") in ("user", "admin")),
            "services": sum(int(h.get("services_total") or 0) for h in hosts_in),
            "conflicts": data["open_conflicts"],
        },
        "table_only": len(hosts_in) >= TABLE_ONLY_HOSTS,
    }


def parse_layers(raw: str | None) -> set[str]:
    if raw is None or not raw.strip():
        return set(LAYERS)
    parts = {x.strip() for x in raw.split(",") if x.strip()}
    if len(raw) > 200 or not parts or not parts <= set(LAYERS):
        raise ApiError("validation", [{"loc": ["query", "layers"], "type": "enum"}])
    return parts | {"topology"}


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/graph", name="graph")
    async def get_graph(pid: str, layers: str | None = Query(default=None, max_length=200)) -> Response:  # noqa: B008
        p = api.project(pid)
        wanted = parse_layers(layers)
        bag = api.bag()
        settings = p.settings
        res = await api.query(p, lambda c: build_graph(c, settings, wanted, bag, p.info.id))
        return await api.respond(res)
