"""ctl-Operationen des KI-Gateways (nur CLI über ``ctl.sock``, nie über die Web-API).

``daemon/core.py`` nimmt :data:`OPS` in seine Tabelle auf. Jede Funktion bekommt den laufenden Daemon
und nutzt nur ``operator``, ``project``, ``paths``, ``submit``, ``flush`` und ``_sync_ingest``.

* ``ai.status``: Einstellungen, Schlüssel vorhanden (ja/nein, nie der Wert), Budget, Freigabe des Projekts.
* ``ai.key.set`` ``{value}``: API-Key verschlüsselt in den Operator-Tresor (nie in Datei, Log, Umgebung).
* ``ai.key.remove``: API-Key löschen.
* ``ai.allow_cloud``: Entscheid ``d.ai.allow_cloud`` im offenen Projekt (ausdrückliche Freigabe).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ariadne.ai.budget import Ledger
from ariadne.ai.config import ConfigError, load_config
from ariadne.ai.gateway import KEY_NAME, REASONS, policy_reason, project_flags
from ariadne.daemon.ops_util import OpError
from ariadne.store.api import AppendItem

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon

__all__ = ["OPS"]

_KEY_MAX = 512


def _operator(d: Daemon) -> Any:
    op = getattr(d, "operator", None)
    if op is None:
        raise OpError("locked", "Operator ist gesperrt (ariadne start)")
    return op


async def _flags(d: Daemon) -> dict[str, bool] | None:
    p = getattr(d, "project", None)
    if p is None:
        return None
    ing = await d._sync_ingest()
    profile = p.info.profile
    return await ing.query(lambda c: project_flags(c, profile))


async def op_status(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    try:
        cfg = load_config(d.paths)
        cfg_error = None
    except ConfigError:
        cfg, cfg_error = None, "config"
    op = getattr(d, "operator", None)
    key_present = bool(op is not None and op.get_api_key(KEY_NAME))
    p = getattr(d, "project", None)
    flags = None
    if p is not None:
        try:
            flags = await _flags(d)
        except Exception:  # Auswertung nicht bereit: Freigabe unbekannt
            flags = None
    limit = cfg.monthly_limit_usd if cfg is not None else 20.0
    budget = Ledger(d.paths).state(limit)
    reason = cfg_error or (
        policy_reason(
            cfg,
            key_present=key_present,
            operator_unlocked=op is not None,
            profile=p.info.profile if p is not None else "lab",
            flags=flags or {},
        )
        if cfg is not None
        else "config"
    )
    return {
        "provider": cfg.provider if cfg is not None else None,
        "model": (cfg.model or None) if cfg is not None else None,
        "key_present": key_present,
        "operator_unlocked": op is not None,
        "budget": budget.json(),
        "project": None
        if p is None
        else {
            "slug": p.info.slug,
            "profile": p.info.profile,
            "cloud_allowed": (flags or {}).get("cloud_allowed"),
            "public_scope": (flags or {}).get("public_scope"),
        },
        "ready": reason is None and p is not None,
        "reason": reason,
        "reason_text": REASONS.get(reason) if reason else None,
    }


async def op_key_set(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    op = _operator(d)
    value = args.get("value")
    if not isinstance(value, str) or not value.strip() or len(value) > _KEY_MAX:
        raise OpError("invalid", "API-Key fehlt oder ist zu lang")
    value = value.strip()
    if any(ord(c) < 0x21 or ord(c) > 0x7E for c in value):
        raise OpError("invalid", "API-Key enthält unzulässige Zeichen")
    op.set_api_key(KEY_NAME, value)
    await asyncio.to_thread(op.save)
    return {"key_present": True}


async def op_key_remove(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    op = _operator(d)
    had = bool(op.get_api_key(KEY_NAME))
    if had:
        op.set_api_key(KEY_NAME, None)
        await asyncio.to_thread(op.save)
    return {"removed": had, "key_present": False}


async def op_allow_cloud(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    p = d._require_project()
    if p.info.profile != "lab":
        raise OpError("policy", "Im Profil customer ist die Cloud-KI aus (nur lokal)")
    flags = await _flags(d)
    if d.project is not p:
        raise OpError("project_changed", "Projekt wurde währenddessen gewechselt, nichts gespeichert")
    if flags and flags.get("cloud_allowed"):
        return {"already": True, "decision_id": None}
    d.submit(AppendItem("d.ai.allow_cloud", {"functions": ["denkanstoss"]}, origin="cli"))
    records = d.flush()
    rec = next((r for r in records if r.kind == "d.ai.allow_cloud"), None)
    return {"already": False, "decision_id": rec.id if rec is not None else None}


OPS: dict[str, Callable[[Daemon, dict[str, Any]], Any]] = {
    "ai.status": op_status,
    "ai.key.set": op_key_set,
    "ai.key.remove": op_key_remove,
    "ai.allow_cloud": op_allow_cloud,
}
