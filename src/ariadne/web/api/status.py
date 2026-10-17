"""``GET /status``, Pause und Fortsetzen pro Terminal, Präsentationsmodus (``docs/web-api.md`` 4).

Pause und Präsentation schreiben über die ctl-Operationen ``term.pause``, ``term.resume`` und
``presentation`` mit Herkunft ``webui``. Den neuen Zustand zeigt die UI erst nach dem SSE-Ereignis
(``terminal`` bzw. ``presentation``), darum antworten diese Routen nur 202.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Request
from starlette.responses import Response

from ariadne import __version__
from ariadne.ingest.db import get_meta
from ariadne.ingest.queries import cmd_ref
from ariadne.web.api.common import Api, session_view, valid_tid
from ariadne.web.api.errors import ApiError
from ariadne.web.api.models import MAX_WEB_PAUSE_MIN, PauseRequest, PresentationRequest
from ariadne.web.api.text import Bag, iso
from ariadne.web.api.views import breadcrumb, loads
from ariadne.web.ctx import session_of

__all__ = ["add_routes", "terminal_state", "project_brief", "DEFAULT_WEB_PAUSE_MIN"]

DEFAULT_WEB_PAUSE_MIN = 10
_STATES = ("paused", "held", "on", "locked", "preroll", "off")


def project_brief(p: Any, bag: Bag) -> dict[str, Any]:
    settings = p.settings if isinstance(p.settings, dict) else {}
    name = (settings.get("project") or {}).get("name") if isinstance(settings.get("project"), dict) else None
    return {
        "id": p.info.id,
        "slug": p.info.slug,
        "name": bag(name if isinstance(name, str) else p.info.slug),
        "profile": p.info.profile,
        "chain_head_ok": bool(p.head_ok),
    }


def terminal_state(ts: dict[str, Any], stack: Any, bag: Bag) -> dict[str, Any]:
    """TerminalState aus ``status.terminal_states`` und dem Stapel aus ``ctx.show``."""
    b = bag.new()
    tid = str(ts.get("terminal_id") or "")
    state = ts.get("state") if ts.get("state") in _STATES else "off"
    held = state == "held"
    out = {
        "terminal_id": tid,
        "short_id": tid[-8:],
        "tty": b(ts.get("tty")),
        "state": state,
        "pause_until": iso(ts.get("pause_until_ns")) if state == "paused" else None,
        "held_slug": b(ts.get("bound_slug")) if held else None,
        "preroll_s": int(ts.get("preroll_s") or 0),
        "mux": bool(ts.get("mux")),
        "context_label": None if held else breadcrumb(stack, b),
    }
    out["ctrl"] = b.ctrl
    return out


def _scope_warning(conn: Any) -> dict[str, Any] | None:
    """Jüngster Befehl mit einem Ziel ausserhalb des Scopes (E67)."""
    for cmd_id, tid, ts, scope in conn.execute(
        "SELECT cmd_id, terminal_id, ts_utc_ns, target_scope FROM activity WHERE target_scope != '[]' "
        "ORDER BY ts_utc_ns DESC LIMIT 500"
    ):
        verdicts = [t.get("verdict") for t in (loads(scope, []) or []) if isinstance(t, dict)]
        if any(v != "in" for v in verdicts):
            return {"cmd_id": cmd_id, "cmd_ref": cmd_ref(cmd_id), "terminal_id": tid, "ts": iso(ts)}
    return None


def _derived_state(conn: Any) -> tuple[int | None, dict[str, Any] | None]:
    gen = get_meta(conn, "generation")
    return (int(gen) if gen is not None and gen.isdigit() else None), _scope_warning(conn)


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/status", name="status")
    async def get_status(request: Request) -> Response:
        session = session_of(request)
        st = await api.call("status")
        d = api.daemon
        p = d.project
        bag = api.bag()
        terms = []
        for ts in st.get("terminal_states") or []:
            stack = None
            if ts.get("state") != "held":
                try:
                    stack = (await api.call("ctx.show", {"terminal_id": ts.get("terminal_id")})).get("stack")
                except ApiError:
                    stack = None  # Terminal gerade beendet
            terms.append(terminal_state(ts, stack, bag))
        rec = {
            "connected": len(terms),
            "on": sum(t["state"] == "on" for t in terms),
            "paused": sum(t["state"] == "paused" for t in terms),
            "held": sum(t["state"] == "held" for t in terms),
            "mux": sum(bool(t["mux"]) for t in terms),
        }
        gen: int | None = None
        warning: dict[str, Any] | None = None
        p_now = d.project
        if p_now is not None and p_now is p:
            try:
                gen, warning = await api.query(p_now, _derived_state)
            except Exception:  # noqa: BLE001 - Status geht immer, auch ohne Auswertung
                gen, warning = None, None
        p = d.project
        a = st.get("active")
        pre = st.get("preroll") or {}
        idle = st.get("idle") or {}
        settings = p.settings if p is not None and isinstance(p.settings, dict) else {}
        llm = settings.get("llm") if isinstance(settings.get("llm"), dict) else {}
        limit = llm.get("monthly_budget_usd")
        ing = st.get("ingest")
        body = {
            "version": __version__,
            "api_version": 2,
            "server_time": iso(api.now_ns()),
            "session": session_view(session),
            "operator": {
                "exists": bool((st.get("operator") or {}).get("exists")),
                "unlocked": bool((st.get("operator") or {}).get("unlocked")),
            },
            "project": project_brief(p, bag) if p is not None else None,
            "active": (
                {
                    "slug": bag(a.get("slug")),
                    "stopped": bool(a.get("stopped")),
                    "end_reason": a.get("end_reason")
                    if a.get("end_reason") in ("stop", "idle", "missing")
                    else None,
                }
                if isinstance(a, dict)
                else None
            ),
            "locked": bool(st.get("locked")),
            "recording": rec,
            "terminals": terms,
            "idle": (
                {"idle_s": int(idle.get("idle_s") or 0), "end_after_s": idle.get("end_after_s")}
                if p is not None
                else None
            ),
            "preroll": {
                k: int(pre.get(k) or 0)
                for k in (
                    "terminals",
                    "seconds",
                    "window_s",
                    "ask_terminals",
                    "ask_seconds",
                    "outage_terminals",
                    "outage_seconds",
                )
            },
            "presentation": bool(d.presentation),
            "llm": {
                "mode": "off",
                "model": None,
                "available": False,
                "budget": (
                    {"month_limit_usd": float(limit), "month_used_usd": 0.0}
                    if p is not None and isinstance(limit, int | float) and not isinstance(limit, bool)
                    else None
                ),
            },
            "generation": gen if p is not None else None,
            "ingest": (
                {
                    "active": bool(ing.get("active")),
                    "last_error": "Auswertung fehlgeschlagen" if ing.get("last_error") else None,
                }
                if isinstance(ing, dict)
                else None
            ),
            "disk_low": False,
            "scope_warning": warning if p is not None else None,
        }
        return await api.respond(body)

    @router.post("/terminals/{tid}/pause", name="terminal_pause", status_code=202)
    async def pause(tid: str, body: PauseRequest | None = Body(default=None)) -> Response:  # noqa: B008
        minutes = body.minutes if body is not None and body.minutes is not None else DEFAULT_WEB_PAUSE_MIN
        if minutes > MAX_WEB_PAUSE_MIN:
            raise ApiError("policy")  # länger nur im Terminal: ariadne pause --minutes N
        args: dict[str, Any] = {"minutes": minutes, "source": "webui"}
        _target(tid, args)
        await api.call("term.pause", args)
        return await api.respond({"accepted": True}, 202)

    @router.post("/terminals/{tid}/resume", name="terminal_resume", status_code=202)
    async def resume(tid: str) -> Response:
        args: dict[str, Any] = {"source": "webui"}
        _target(tid, args)
        await api.call("term.resume", args)
        return await api.respond({"accepted": True}, 202)

    @router.put("/presentation", name="presentation", status_code=202)
    async def presentation(body: PresentationRequest) -> Response:
        await api.call("presentation", {"on": body.on, "source": "webui"})
        return await api.respond({"accepted": True}, 202)


def _target(tid: str, args: dict[str, Any]) -> None:
    if tid == "all":
        args["all"] = True
    elif valid_tid(tid):
        args["terminal_id"] = tid
    else:
        raise ApiError("not_found")
