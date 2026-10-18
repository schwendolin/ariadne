"""``GET /terminals`` und ``POST /terminals/{tid}/context`` (``docs/web-api.md`` 5).

Zustand und Stapel kommen vom Daemon (ctl ``status``, ``terminals``, ``ctx.show``), letzter
Befehl, Remote-Segment und offener Kontextvorschlag aus der Auswertung. Ein Terminal, das an ein
anderes Projekt gebunden ist (``held``), erscheint ohne Stapel und ohne Befehl (E70).

Kontext setzen geht über ``ctx.set``, ``ctx.push`` und ``ctx.pop`` mit Herkunft ``webui``; der
Daemon schreibt daraus die Entscheide ``d.ctx.*``. Hosts werden nie aufgelöst (E10); Warnungen
nennen Hosts ausserhalb des Scopes, ausgeschlossene, unbekannte und noch nicht bekannte.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Body
from starlette.responses import Response

from ariadne.daemon.terminal import normalize_host
from ariadne.ingest.proj_build import display
from ariadne.ingest.queries import term_refs
from ariadne.scope.matcher import ScopeMatcher
from ariadne.web.api.common import Api, valid_tid
from ariadne.web.api.errors import ApiError
from ariadne.web.api.models import AcceptOp, ContextOp, PopOp, PushOp, SetOp
from ariadne.web.api.status import terminal_state
from ariadne.web.api.text import Bag, iso
from ariadne.web.api.views import command_ref, loads, stack_views, unit_rows, with_secrets

__all__ = ["add_routes", "terminal_extras", "host_warnings"]

_WARN = {
    "out": "scope_out",
    "excluded": "scope_excluded",
    "unknown": "scope_unknown",
    "outside_window": "scope_unknown",
}


def _suggestions(conn: Any) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    out: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for key, payload in conn.execute(
        "SELECT item_key, payload_json FROM v_inbox WHERE kind = 'ctx_suggestion' "
        "ORDER BY created_ts LIMIT 1000"
    ):
        data = loads(payload, {}) or {}
        tid = data.get("terminal_id")
        if isinstance(tid, str):
            out.setdefault(tid, []).append((str(key), data))
    return out


def terminal_extras(conn: Any, tids: list[str], bag: Bag) -> dict[str, dict[str, Any]]:
    """Letzter Befehl, offenes Remote-Segment und Kontextvorschlag pro Terminal."""
    bag = with_secrets(bag, conn)  # letzter Befehl mit maskierten Secrets (SEC-W1)
    sugg = _suggestions(conn)
    out: dict[str, dict[str, Any]] = {}
    for tid in tids:
        last = unit_rows(conn, "kind = 'command' AND terminal_id = ? ORDER BY start_off DESC", (tid,), 1)
        cmd = None
        if last:
            src = conn.execute(
                "SELECT src_ip FROM activity WHERE cmd_id = ?", (last[0]["cmd_id"],)
            ).fetchone()
            cmd = command_ref(last[0], bag, src[0] if src else None)
        seg = unit_rows(
            conn,
            "kind = 'segment' AND terminal_id = ? AND end_off IS NULL ORDER BY start_off DESC",
            (tid,),
            1,
        )
        kind = (loads(seg[0]["context"], {}) or {}).get("kind") if seg else None
        remote = (
            {"since": iso(seg[0]["ts_utc_ns"]), "lines": int(seg[0]["vis_count"] or 0)}
            if seg and kind not in (None, "local", "su")
            else None
        )  # nur eine Remote-Stufe hat ein «rekonstruiertes» Segment
        suggestion = None
        for key, data in sugg.get(tid, [])[-1:]:
            host = data.get("suggested_host")
            off = data.get("from_off")
            if isinstance(host, str) and isinstance(off, int):
                suggestion = {
                    "item_key": key,
                    "from_off": off,
                    "host_id": bag(host),
                    "host_label": bag(display(host)),
                    "reason": bag(data.get("reason")) or "",
                }
        out[tid] = {"last_command": cmd, "remote_segment": remote, "suggestion": suggestion}
    return out


def _find_suggestion(conn: Any, tid: str, item_key: str) -> dict[str, Any] | None:
    for key, data in _suggestions(conn).get(tid, []):
        if key == item_key:
            return data
    return None


def _known_host(conn: Any, ident: str) -> bool:
    keys = [ident]
    if ident.startswith("name:"):
        keys.append("fqdn:" + ident[5:])
    for key in keys:
        row = conn.execute(
            "SELECT i.entity_id FROM identifier i JOIN v_host h ON h.host_id = i.entity_id "
            "WHERE i.key = ? LIMIT 1",
            (key,),
        ).fetchone()
        if row is not None:
            return True
    return False


def host_warnings(settings: Any, ident: str, known: bool) -> list[dict[str, Any]]:
    """Warnungen zu einem eingegebenen Host (Kennung aus ``normalize_host``), ohne Auflösung."""
    raw = ident.split("/", 1)[1] if ident.startswith("ip:") else ident.split(":", 1)[-1]
    try:
        verdict = (
            ScopeMatcher.from_settings(settings if isinstance(settings, dict) else {}, 0).check(raw).verdict
        )
    except Exception:  # noqa: BLE001 - Scope nicht lesbar: lieber warnen
        verdict = "unknown"
    out: list[dict[str, Any]] = []
    if verdict in _WARN:
        out.append({"code": _WARN[verdict], "host": raw})
    if not known:
        out.append({"code": "host_unknown", "host": raw})
    return out


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/terminals", name="terminals")
    async def get_terminals() -> Response:
        st = await api.call("status")
        info = {
            t.get("terminal_id"): t
            for t in (await api.call("terminals")).get("terminals") or []
            if t.get("connected")
        }
        bag = api.bag()
        rows: list[dict[str, Any]] = []
        stacks: dict[str, Any] = {}
        for ts in st.get("terminal_states") or []:
            tid = str(ts.get("terminal_id") or "")
            if ts.get("state") != "held":
                try:
                    stacks[tid] = (await api.call("ctx.show", {"terminal_id": tid})).get("stack")
                except ApiError:
                    stacks[tid] = None
            rows.append(ts)
        d = api.daemon
        p = d.project
        extras: dict[str, dict[str, Any]] = {}
        refs: dict[str, dict[str, Any]] = {}
        local = [
            str(ts.get("terminal_id")) for ts in rows if ts.get("state") not in ("held", "preroll", "off")
        ]
        if p is not None:
            try:
                extras, refs = await api.query(
                    p, lambda c: (terminal_extras(c, local, bag) if local else {}, term_refs(c))
                )
            except Exception:  # noqa: BLE001 - Terminals gehen immer, auch ohne Auswertung
                extras, refs = {}, {}
        out = []
        for ts in rows:
            tid = str(ts.get("terminal_id") or "")
            held = ts.get("state") == "held"
            item = terminal_state(ts, stacks.get(tid), bag, refs)
            b = bag.new()
            ex = extras.get(tid) or {}
            item.update(
                {
                    "shell": b((info.get(tid) or {}).get("shell")),
                    "connected": True,
                    "stack": [] if held else stack_views(stacks.get(tid), b),
                    "last_command": None if held else ex.get("last_command"),
                    "remote_segment": None if held else ex.get("remote_segment"),
                    "suggestion": None if held else ex.get("suggestion"),
                }
            )
            item["ctrl"] = bool(item["ctrl"] or b.ctrl)
            out.append(item)
        return await api.respond({"terminals": out})

    @router.post("/terminals/{tid}/context", name="terminal_context")
    async def set_context(tid: str, body: ContextOp = Body(...)) -> Response:  # noqa: B008
        if not valid_tid(tid):
            raise ApiError("not_found")
        d = api.daemon
        host: str | None = None
        if isinstance(body, AcceptOp):
            p = d.project
            if p is None:
                raise ApiError("no_project")
            data = await api.query(p, lambda c: _find_suggestion(c, tid, body.item_key))
            if (
                data is None
                or not isinstance(data.get("suggested_host"), str)
                or not isinstance(data.get("from_off"), int)
            ):
                if re.fullmatch(r"ctx:" + re.escape(tid) + r"@\d{1,19}", body.item_key):
                    raise ApiError("conflict")  # Vorschlag schon entschieden
                raise ApiError("not_found")
            host = data["suggested_host"]
            res = await api.call(
                "ctx.set", {"terminal_id": tid, "host": host, "from_off": data["from_off"], "source": "webui"}
            )
        elif isinstance(body, SetOp):
            if body.host is None and body.user is None and body.kind is None:
                raise ApiError("validation", [{"loc": ["body", "host"], "type": "missing"}])
            host = body.host
            args: dict[str, Any] = {"terminal_id": tid, "source": "webui"}
            for k in ("host", "user", "kind", "from_off"):
                v = getattr(body, k)
                if v is not None:
                    args[k] = v
            res = await api.call("ctx.set", args)
        elif isinstance(body, PushOp):
            host = body.host
            args = {"terminal_id": tid, "source": "webui"}
            for k in ("host", "user", "kind"):
                v = getattr(body, k)
                if v is not None:
                    args[k] = v
            res = await api.call("ctx.push", args)
        else:
            assert isinstance(body, PopOp)
            stack = (await api.call("ctx.show", {"terminal_id": tid})).get("stack") or []
            if not any(isinstance(st, dict) and st.get("state", "active") == "active" for st in stack[1:]):
                raise ApiError("validation", [{"loc": ["body", "op"], "type": "pop_kali"}])
            res = await api.call("ctx.pop", {"terminal_id": tid, "source": "webui"})
        warnings: list[dict[str, Any]] = []
        p = d.project
        if host is not None and p is not None:
            try:
                ident = normalize_host(host)
            except ValueError:
                ident = None
            if ident is not None:
                try:
                    known = await api.query(p, lambda c: _known_host(c, ident))
                except ApiError:
                    known = True  # ohne Auswertung keine Warnung «unbekannt»
                warnings = host_warnings(p.settings, ident, known)
        bag = api.bag()
        stack_out = res.get("stack") if isinstance(res, dict) else None
        return await api.respond(
            {
                "stored": bool((res or {}).get("stored")),
                "stack": stack_views(stack_out, bag) if isinstance(stack_out, list) else None,
                "warnings": warnings,
            }
        )
