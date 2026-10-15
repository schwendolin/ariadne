"""ctl-Operationen der Auswertung: Ansichten, Suche, Entscheide zu Claims, Rückgängig, Reparse.

Gehört dem Teil «auswertung» (Vertrag v0.1-Bedienung). ``daemon/core.py`` nimmt
:data:`OPS` in seine Tabelle auf; neue Operationen der Auswertung kommen nur
hierher. Jede Funktion bekommt den laufenden :class:`~ariadne.daemon.core.Daemon`
und die Argumente und nutzt nur dessen stabile Schnittstelle:
``_require_project()``, ``_sync_ingest()``, ``_ingest_info()``, ``submit()``,
``redactor`` (Ausgangs-API) und ``project``.

Jede Antwort mit Zieldaten geht durch ``redactor.redact_json`` (E72): Eigene
Secrets stehen ungeschwärzt im Journal und werden erst hier ersetzt.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ariadne.daemon.ops_util import OpError, arg_int, arg_str
from ariadne.daemon.sources import list_pending
from ariadne.ingest import queries
from ariadne.store.api import AppendItem

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon

__all__ = ["OPS"]


def _exit(d: Daemon, obj: Any) -> Any:
    """Ausgang zur CLI: eigene Secrets ersetzen (E72, E99 sinngemäss)."""
    redactor = getattr(d, "redactor", None)
    if redactor is None:
        return obj
    out, _labels = redactor.redact_json(obj)
    return out


def _same_project(d: Daemon, p: Any) -> None:
    """Entscheide nur in das Projekt, in dem die Referenz aufgelöst wurde (E70): Während der
    Auflösung (``await``) kann ein anderes ``ariadne start`` das Projekt wechseln."""
    if d.project is not p:
        raise OpError("project_changed", "Projekt wurde währenddessen gewechselt, nichts gespeichert")


async def _resolve(d: Daemon, fn: Callable[[Any], Any]) -> Any:
    ing = await d._sync_ingest()
    try:
        return await ing.query(fn)
    except queries.RefError as exc:
        raise OpError("not_found", str(exc)) from None


async def op_show(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    p = d._require_project()
    what = arg_str(args, "what", max_len=32)
    limit = arg_int(args, "limit", 1, 5000, 200)
    if what == "pending":
        return _exit(d, {"what": what, "items": await asyncio.to_thread(list_pending, p, limit)})
    views: dict[str, Callable[[Any], Any]] = {
        "hosts": queries.hosts, "services": queries.services, "inbox": queries.inbox,
        "keysteps": queries.keysteps, "timeline": lambda c: queries.timeline(c, limit),
    }
    fn = views.get(str(what))
    if fn is None:
        raise OpError("invalid", "unbekannte Ansicht")
    ing = await d._sync_ingest()
    res: dict[str, Any] = {"what": what, "items": await ing.query(fn), "ingest": d._ingest_info()}
    if what == "inbox":
        res["quiet"] = await ing.query(queries.quiet_summary)
    return _exit(d, res)


async def op_search(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    text = arg_str(args, "text", max_len=200) or ""
    limit = arg_int(args, "limit", 1, 500, 50)
    ing = await d._sync_ingest()
    return _exit(d, {"items": await ing.query(lambda c: queries.search(c, text, limit))})


async def op_claim_confirm(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    """Bestätigt einen Claim oder eine Inbox-Gruppe; Sammelbestätigung nur für sichere Werte (E88)."""
    ref = arg_str(args, "ref", max_len=200) or ""
    p = d._require_project()
    plan: dict[str, Any] = await _resolve(d, lambda c: queries.resolve_confirm(c, ref))
    keys: list[str] = plan["keys"]
    _same_project(d, p)
    for k in keys:
        d.submit(AppendItem("d.claim.confirm", {"claim_key": k}, origin="cli"))
    ing = await d._sync_ingest()
    claims = await ing.query(lambda c: queries.claim_snapshot(c, keys[:50]))
    return _exit(d, {"confirmed": len(keys), "claims": claims, "excluded": plan["excluded"],
                     "excluded_sample": plan["excluded_sample"], "group": plan["group"]})


async def op_claim_reject(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    ref = arg_str(args, "ref", max_len=200) or ""
    reason = arg_str(args, "reason", required=False, max_len=500)
    p = d._require_project()
    key: str = await _resolve(d, lambda c: queries.resolve_claim(c, ref))
    header = {"claim_key": key, "reason": reason} if reason else {"claim_key": key}
    _same_project(d, p)
    d.submit(AppendItem("d.claim.reject", header, origin="cli"))
    ing = await d._sync_ingest()
    return _exit(d, {"rejected": 1, "claims": await ing.query(lambda c: queries.claim_snapshot(c, [key]))})


async def op_unit_distrust(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    """Rückgängig pro Befehl (A2): ``d.unit.distrust`` für die Evidenzgruppe des Befehls."""
    ref = arg_str(args, "ref", max_len=200) or ""
    reason = arg_str(args, "reason", required=False, max_len=500)
    p = d._require_project()
    cmd_id: str = await _resolve(d, lambda c: queries.resolve_distrust(c, ref))
    header = {"cmd_id": cmd_id, "reason": reason} if reason else {"cmd_id": cmd_id}
    _same_project(d, p)
    d.submit(AppendItem("d.unit.distrust", header, origin="cli"))
    ing = await d._sync_ingest()
    return _exit(d, await ing.query(lambda c: queries.distrust_result(c, cmd_id)))


async def op_reparse(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    ing = await d._sync_ingest()
    return _exit(d, await ing.reparse())


OPS: dict[str, Callable[[Daemon, dict[str, Any]], Any]] = {
    "show": op_show,
    "search": op_search,
    "claim.confirm": op_claim_confirm,
    "claim.reject": op_claim_reject,
    "unit.distrust": op_unit_distrust,
    "reparse": op_reparse,
}
