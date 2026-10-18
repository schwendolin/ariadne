"""``GET /p/{pid}/hosts``, ``GET /p/{pid}/hosts/{host_id}`` und ``GET /p/{pid}/services``
(``docs/web-api.md`` 8). Grundlage :func:`ariadne.ingest.queries.hosts` und
:func:`ariadne.ingest.queries.services`; Werte aus ``v_claim`` (Secrets maskiert).

Die Tabelle zeigt wie die Karte nur Hosts im Scope (auch Nebel); das Detail gibt es für jeden
bekannten Host, auch ausserhalb des Scopes (mit Urteil pro Kennung).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Query
from starlette.responses import Response

from ariadne.ingest import queries
from ariadne.ingest.proj_build import display
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.graph import (
    SERVICE_CLASSES,
    host_data,
    host_node,
    scope_nets,
    segment_of,
    service_class,
    thread_edges,
)
from ariadne.web.api.text import Bag, iso
from ariadne.web.api.views import (
    claim_rows,
    command_ref,
    conflict_rows,
    conflict_view,
    fact_view,
    loads,
    with_secrets,
)

__all__ = ["add_routes", "services_view", "FACTS_MAX", "COMMANDS_MAX"]

FACTS_MAX = 2000
COMMANDS_MAX = 50
_HISTORY_PREDICATES = ("service.state", "service.version", "service.product", "service.name")


def _summary(h: Mapping[str, Any], data: Mapping[str, Any], nets: list[Any], bag: Bag) -> dict[str, Any]:
    seg = segment_of(h.get("addresses") or [], nets)
    node = host_node(h, data, f"seg:{seg[0]}" if seg else None, bag)
    node.pop("kind", None)
    ex = data["extra"].get(str(h.get("host_id"))) or {}
    node.update(
        first_seen=iso(ex.get("first_seen")),
        last_seen=iso(ex.get("last_seen")),
        quiet=dict(h.get("quiet") or {}),
    )
    return node


def _hosts(conn: Any, settings: Any, bag: Bag) -> list[dict[str, Any]]:
    data = host_data(conn)
    nets = scope_nets(settings)
    return [
        _summary(h, data, nets, bag)
        for h in data["hosts"]
        if h.get("scope") == "in" and not h.get("placeholder")
    ]


def services_view(
    conn: Any, bag: Bag, *, host_id: str | None = None, cls: str | None = None, in_scope_only: bool = True
) -> list[dict[str, Any]]:
    """ServiceView mit Verlauf (E45): abgelöste Werte von Zustand, Version, Produkt und Name."""
    extra = {str(r[0]): r[1:] for r in conn.execute("SELECT service_id, work, conflicts FROM v_service")}
    history: dict[str, list[dict[str, Any]]] = {}
    marks = ",".join("?" * len(_HISTORY_PREDICATES))
    for eid, pred, value, last, key in conn.execute(
        "SELECT entity_id, predicate, value_text, last_ts, claim_key FROM v_claim WHERE history = 1 "  # noqa: S608
        f"AND predicate IN ({marks}) ORDER BY last_ts LIMIT 20000",
        _HISTORY_PREDICATES,
    ):
        b = bag.new()
        history.setdefault(str(eid), []).append(
            {"predicate": pred, "value": b(value) or "", "ctrl": b.ctrl, "until": iso(last), "claim_key": key}
        )
    out: list[dict[str, Any]] = []
    for s in queries.services(conn, host_id):
        if in_scope_only and s.get("scope") != "in":
            continue
        klass = service_class(s.get("name"), s.get("port"))
        if cls is not None and klass != cls:
            continue
        sid = str(s.get("service_id"))
        work, conflicts = extra.get(sid) or (None, 0)
        b = bag.new()
        state = s.get("state")
        item = {
            "service_id": b(sid),
            "host_id": b(s.get("host_id")),
            "host_label": b(s.get("host")) or "",
            "proto": s.get("proto") if s.get("proto") in ("tcp", "udp") else "tcp",
            "port": int(s.get("port") or 0),
            "name": b(s.get("name")),
            "product": b(s.get("product")),
            "version": b(s.get("version")),
            "class": klass,
            "state": state if state in ("open", "filtered", "closed") else None,
            "claim_state": s.get("claim_state") or "candidate",
            "verdict": s.get("scope"),
            "work": work,
            "conflicts": int(conflicts or 0),
            "cves": b.many(c for c in s.get("cves") or [] if isinstance(c, str)),
            "history": history.get(sid, []),
        }
        item["ctrl"] = b.ctrl
        out.append(item)
    return out


def _entity_of(conn: Any, ident: str) -> str | None:
    row = conn.execute("SELECT entity_id FROM identifier WHERE key = ?", (ident,)).fetchone()
    return str(row[0]) if row and row[0] is not None else None


def _idn(label: str) -> tuple[str, str | None]:
    """Anzeige eines Namens und seine Punycode-Form (Namen liegen kanonisch in ASCII vor)."""
    if "xn--" not in label:
        return label, None
    try:
        return label.encode("ascii").decode("idna"), label
    except UnicodeError:
        return label, label


def _open_items(conn: Any, host: str, idents: set[str]) -> list[str]:
    """Einträge in «Als Nächstes» zu diesem Host (über Entität, Subjekt, Vorschlag oder Kennungen)."""
    svc_prefix = f"svc:{host}|"
    out: list[str] = []
    for key, payload in conn.execute(
        "SELECT item_key, payload_json FROM v_inbox ORDER BY created_ts LIMIT 5000"
    ):
        data = loads(payload, {}) or {}
        refs = [data.get(k) for k in ("entity_id", "subject", "suggested_host", "placeholder_entity")]
        refs += list(data.get("identifiers") or [])
        hit = False
        for r in refs:
            if not isinstance(r, str):
                continue
            if r == host or r.startswith(svc_prefix) or r in idents or _entity_of(conn, r) == host:
                hit = True
                break
        if hit:
            out.append(str(key))
    return out


def _commands(conn: Any, host: str, idents: set[str], bag: Bag) -> list[dict[str, Any]]:
    """Befehle in diesem Kontext (Stufe mit diesem Host, auch Auto-Host), neueste zuerst."""
    bag = with_secrets(bag, conn)  # Befehlstexte maskiert (SEC-W1)
    auto = {
        (str(r[0]), int(r[1])): str(r[2])
        for r in conn.execute("SELECT terminal_id, opened_at, host FROM ctx_auto")
    }
    cache: dict[str, str | None] = {}
    out: list[dict[str, Any]] = []
    for row in conn.execute(
        "SELECT u.unit_id, u.terminal_id, u.cmd_id, u.cmd_text, u.context, u.exit_code, u.ts_utc_ns, "
        "u.ts_end_ns, "
        "a.src_ip FROM unit u LEFT JOIN activity a ON a.cmd_id = u.cmd_id WHERE u.kind = 'command' "
        "ORDER BY u.event_seq DESC LIMIT 20000"
    ):
        ctx = loads(row[4], {}) or {}
        h = ctx.get("host")
        if not isinstance(h, str) or h == "local":
            opened = ctx.get("opened_at")
            h = auto.get((str(row[1]), opened)) if isinstance(opened, int) else None
        if not isinstance(h, str):
            continue
        if h not in cache:
            cache[h] = h if h == host or h in idents else _entity_of(conn, h)
        if cache[h] != host:
            continue
        u = {
            "unit_id": row[0],
            "terminal_id": row[1],
            "cmd_id": row[2],
            "cmd_text": row[3],
            "exit_code": row[5],
            "ts_utc_ns": row[6],
            "ts_end_ns": row[7],
        }
        b = bag.new()
        item = command_ref(u, b, row[8])
        item.update(terminal_id=row[1], unit_id=row[0], ctrl=b.ctrl)
        out.append(item)
        if len(out) >= COMMANDS_MAX:
            break
    return out


def _detail(conn: Any, settings: Any, host_id: str, bag: Bag) -> dict[str, Any] | None:
    data = host_data(conn)
    by_id = {str(h.get("host_id")): h for h in data["hosts"]}
    hid = host_id if host_id in by_id else _entity_of(conn, host_id)
    if hid is None or hid not in by_id:
        return None
    h = by_id[hid]
    out = _summary(h, data, scope_nets(settings), bag)
    idents: set[str] = set()
    ids_out = []
    for key, typ, verdict, rule in conn.execute(
        "SELECT key, type, scope_verdict, scope_rule FROM identifier WHERE entity_id = ? "
        "ORDER BY key LIMIT 500",
        (hid,),
    ):
        idents.add(str(key))
        b = bag.new()
        label, puny = _idn(display(str(key))) if typ in ("fqdn", "name") else (display(str(key)), None)
        ids_out.append(
            {
                "key": b(key),
                "label": b(label) or "",
                "type": typ,
                "verdict": verdict if verdict in ("in", "out", "excluded", "outside_window") else "unknown",
                "rule": b(rule),
                "punycode": puny,
                "ctrl": b.ctrl,
            }
        )
    where = "(entity_id = ? OR substr(entity_id, 1, ?) = ?)"
    prefix = f"svc:{hid}|"
    params = (hid, len(prefix), prefix)
    facts = claim_rows(conn, where, params, FACTS_MAX + 1)
    conflicts = conflict_rows(conn, where, params)
    nodes = {hid}
    thread = [e for e in thread_edges(conn, set(by_id), bag) if e["target"] == hid]
    ex = data["extra"].get(hid) or {}
    nb = bag.new()
    out.update(
        {
            "identifiers": ids_out,
            "services": services_view(conn, bag, host_id=hid, in_scope_only=False),
            "facts": [fact_view(c, bag) for c in facts[:FACTS_MAX]],
            "facts_truncated": len(facts) > FACTS_MAX,
            "conflicts": [conflict_view(conn, k, bag) for k in conflicts],
            "open_items": _open_items(conn, hid, idents | nodes),
            "thread": thread,
            "note": nb(ex.get("note")),
            "commands": _commands(conn, hid, idents, bag),
        }
    )
    out["ctrl"] = bool(out["ctrl"] or nb.ctrl)
    return out


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/hosts", name="hosts")
    async def get_hosts(pid: str) -> Response:
        p = api.project(pid)
        bag = api.bag()
        settings = p.settings
        return await api.respond({"hosts": await api.query(p, lambda c: _hosts(c, settings, bag))})

    @router.get("/p/{pid}/hosts/{host_id:path}", name="host")
    async def get_host(pid: str, host_id: str) -> Response:
        p = api.project(pid)
        if not host_id or len(host_id) > 600:
            raise ApiError("not_found")
        bag = api.bag()
        settings = p.settings
        res = await api.query(p, lambda c: _detail(c, settings, host_id, bag))
        if res is None:
            raise ApiError("not_found")
        return await api.respond(res)

    @router.get("/p/{pid}/services", name="services")
    async def get_services(
        pid: str,
        host: str | None = Query(default=None, max_length=600),  # noqa: B008
        cls: str | None = Query(default=None, alias="class", max_length=16),
    ) -> Response:  # noqa: B008
        p = api.project(pid)
        if cls is not None and cls not in SERVICE_CLASSES:
            raise ApiError("validation", [{"loc": ["query", "class"], "type": "enum"}])
        bag = api.bag()
        res = await api.query(p, lambda c: services_view(c, bag, host_id=host, cls=cls))
        return await api.respond({"services": res})
