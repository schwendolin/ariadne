"""``GET /p/{pid}/scope`` und ``POST /p/{pid}/scope/changes`` (``docs/web-api.md`` 20, E129).

Scope ändern geht im Dashboard mit Bestätigungsdialog und im Terminal mit ``ariadne scope``. Beide
Wege laufen über die ctl-Operation ``scope.change`` (Herkunft hier ``webui``): Jede Änderung ist ein
Entscheid ``d.scope.update`` mit neuer Version, lässt sich rückgängig machen (``op: 'revert'``) und
löst eine Neuauswertung aus. Im Profil customer 403 ``policy`` (nur im Terminal), neue Einschlüsse
ausserhalb der Lab-Allowlist ohne Bestätigung «kein Kundenauftrag» 403 ``guardrail`` (die
Bestätigung gibt es nur im Terminal). Nach dem Schreiben folgt das SSE-Ereignis ``scope``.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any, Literal

from fastapi import APIRouter
from pydantic import Field
from starlette.responses import Response

from ariadne.web.api.common import Api
from ariadne.web.api.decisions import IdempotencyCache
from ariadne.web.api.errors import ApiError
from ariadne.web.api.models import _In
from ariadne.web.api.text import iso

__all__ = ["add_routes", "ScopeChangeRequest"]

Entry = Annotated[str, Field(min_length=1, max_length=260)]


class ScopeChangeRequest(_In):
    op: Literal["add", "remove", "exclude", "revert"]
    entries: list[Entry] | None = Field(default=None, min_length=1, max_length=20)
    decision_id: str | None = Field(default=None, min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=500)
    dry_run: bool = False
    client_ref: str | None = Field(default=None, min_length=1, max_length=64)


_LIST_KEYS = ("entries", "include", "exclude", "include_added", "include_removed", "exclude_added",
              "exclude_removed", "outside")


def _strs(v: Any) -> list[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def change_view(res: dict[str, Any]) -> dict[str, Any]:
    verdicts = res.get("verdicts") if isinstance(res.get("verdicts"), dict) else {}
    out: dict[str, Any] = {k: _strs(res.get(k)) for k in _LIST_KEYS}
    out.update(
        decision_id=res.get("decision_id") if isinstance(res.get("decision_id"), str) else None,
        seq=res.get("seq") if isinstance(res.get("seq"), int) else None,
        version=int(res.get("version") or 0),
        op=res.get("op"),
        revert_of=res.get("revert_of") if isinstance(res.get("revert_of"), str) else None,
        dry_run=bool(res.get("dry_run")),
        needs_not_customer=bool(res.get("needs_not_customer")),
        verdicts=[{"entry": str(k), "verdict": str(v)} for k, v in verdicts.items()],
    )
    return out


def scope_view(res: dict[str, Any]) -> dict[str, Any]:
    history = []
    for h in res.get("history") or []:
        if not isinstance(h, dict):
            continue
        history.append({
            "decision_id": h.get("decision_id"),
            "version": h.get("version"),
            "ts": iso(h.get("ts_utc_ns")),
            "origin": h.get("origin") if h.get("origin") in ("cli", "webui") else "cli",
            "op": h.get("op"),
            **{k: _strs(h.get(k)) for k in ("entries", "include_added", "include_removed",
                                             "exclude_added", "exclude_removed")},
            "revert_of": h.get("revert_of") if isinstance(h.get("revert_of"), str) else None,
            "reverted_by": h.get("reverted_by") if isinstance(h.get("reverted_by"), str) else None,
        })
    windows = [
        {k: str(w[k]) if w.get(k) is not None else None for k in ("days", "from", "to", "tz")}
        for w in res.get("windows") or []
        if isinstance(w, dict)
    ]
    profile = res.get("profile") if res.get("profile") in ("lab", "customer") else "lab"
    return {
        "version": int(res.get("version") or 0),
        "profile": profile,
        "include": _strs(res.get("include")),
        "exclude": _strs(res.get("exclude")),
        "windows": windows,
        "not_customer": bool(res.get("not_customer")),
        "change_allowed": profile != "customer",
        "history": history,
    }


def add_routes(router: APIRouter, api: Api) -> None:
    cache = IdempotencyCache()
    locks: dict[str, asyncio.Lock] = {}

    @router.get("/p/{pid}/scope", name="scope")
    async def get_scope(pid: str) -> Response:
        p = api.project(pid)
        res = await api.call("scope.show", {})
        api.same(p)
        if not isinstance(res, dict) or res.get("project_id") != p.info.id:
            raise ApiError("project_mismatch")
        return await api.respond(scope_view(res))

    @router.post("/p/{pid}/scope/changes", name="scope_changes", status_code=201)
    async def post_change(pid: str, body: ScopeChangeRequest) -> Response:
        p = api.project(pid)
        if body.op == "revert":
            if body.decision_id is None or body.entries is not None:
                raise ApiError("validation", [{"loc": ["body", "decision_id"], "type": "revert"}])
        elif body.entries is None or body.decision_id is not None:
            raise ApiError("validation", [{"loc": ["body", "entries"], "type": "missing"}])
        if p.info.profile == "customer":
            raise ApiError("policy")  # E129: im Profil customer nur im Terminal
        hit = cache.get(p.info.id, body.client_ref) if not body.dry_run else None
        if hit is not None:
            return await api.respond(hit, 201)
        args: dict[str, Any] = {"action": body.op, "origin": "webui", "dry_run": body.dry_run}
        if body.entries is not None:
            args["entries"] = list(body.entries)
        if body.decision_id is not None:
            args["decision_id"] = body.decision_id
        if body.reason:
            args["reason"] = body.reason
        lock = locks.setdefault(p.info.id, asyncio.Lock())
        async with lock:
            api.same(p)
            res = await api.call("scope.change", args)
            api.same(p)
        out = change_view(res if isinstance(res, dict) else {})
        if body.dry_run:
            return await api.respond(out, 200)
        cache.put(p.info.id, body.client_ref, out)
        return await api.respond(out, 201)
