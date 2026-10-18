"""ctl-Operationen des Exports (Teil «export»): ``export.run``, ``export.list``, ``export.phases``,
``export.phase``. ``daemon/core.py`` nimmt :data:`OPS` in seine Tabelle auf.

Antworten mit Zieldaten gehen durch ``redactor.redact_json`` (E72). Die Web-API ruft diese
Operationen nicht; sie nutzt :mod:`ariadne.export.service` direkt (ohne Klartext).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ariadne.daemon.ops_util import OpError

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon

__all__ = ["OPS", "phase_rows", "submit_phase"]


def _exit(d: Daemon, obj: Any) -> Any:
    out, _labels = d.redactor.redact_json(obj)
    return out


def _template(args: dict[str, Any]) -> str:
    from ariadne.ingest.proj_phases import TEMPLATES

    t = args.get("template", "cys")
    if t not in TEMPLATES:
        raise OpError("invalid", "unbekannte Vorlage (cys oder htb)")
    return str(t)


async def op_export_run(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    from ariadne.export import service
    from ariadne.export.writer import ExportError

    template = _template(args)
    klartext = args.get("klartext") is True
    try:
        res = await service.run_export(d, template=template, klartext=klartext, confirm=args.get("confirm"))
    except service.ExportBusy:
        raise OpError("conflict", "ein Export läuft schon") from None
    except service.ExportPolicy as exc:
        raise OpError("policy", str(exc)) from None
    except ExportError as exc:
        raise OpError("export_failed", str(exc)) from None
    return _exit(d, res)


async def op_export_list(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    from ariadne.export import service
    from ariadne.export.writer import list_exports

    p = d._require_project()
    items = await asyncio.to_thread(list_exports, p.info.workspace)
    return _exit(d, {"exports": items, **service.job_state(d)})


def phase_rows(conn: Any, template: str, limit: int = 2000) -> list[dict[str, Any]]:
    """Befehle mit Phase für Prüfung und Korrektur (neueste ``limit``), Befehlstext maskiert."""
    from ariadne.ingest import proj_phases, queries

    known = sorted(
        {
            str(r[0])
            for r in conn.execute("SELECT value FROM secret_value LIMIT 10000")
            if isinstance(r[0], str) and len(str(r[0])) >= 4
        },
        key=len,
        reverse=True,
    )
    rows = proj_phases.assign(conn, template, queries.revoked_ids(conn))[-int(limit) :]
    out = []
    for r in rows:
        text = r["cmd_text"] or ""
        for k in known:
            text = text.replace(k, "••••••••")
        out.append(
            {
                "cmd_id": r["cmd_id"],
                "cmd_ref": queries.cmd_ref(r["cmd_id"]),
                "command": text,
                "ts": r["ts"],
                "phase": r["phase"],
                "source": r["source"],
                "decision_id": r["decision_id"],
            }
        )
    return out


async def op_export_phases(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    template = _template(args)
    ing = await d._sync_ingest()
    rows = await ing.query(lambda conn: phase_rows(conn, template))
    return _exit(d, {"template": template, "commands": rows})


async def submit_phase(
    d: Any,
    *,
    template: str,
    ref: str,
    phase: str,
    origin: str,
    query: Callable[[Callable[[Any], Any]], Any] | None = None,
) -> dict[str, Any]:
    """Löst ``ref`` (``cmd_id`` oder Kurzform) auf und schreibt ``d.unit.phase``."""
    from ariadne.ingest import queries
    from ariadne.ingest.proj_phases import valid_phase
    from ariadne.store.api import AppendItem

    if not valid_phase(template, phase):
        raise OpError("invalid", "Phase passt nicht zur Vorlage")
    p = d._require_project()
    ing = await d._sync_ingest()

    def resolve(conn: Any) -> str:
        return queries.resolve_cmd(conn, ref)

    try:
        cmd_id = await (query(resolve) if query is not None else ing.query(resolve))
    except queries.RefError:
        raise OpError("not_found", "Befehl nicht gefunden") from None
    if d.project is not p:
        raise OpError("project_changed", "Projekt wurde währenddessen gewechselt, nichts gespeichert")
    d.submit(
        AppendItem("d.unit.phase", {"cmd_id": cmd_id, "template": template, "phase": phase}, origin=origin)
    )
    recs = d.flush()
    did = next((r.id for r in recs if r.kind == "d.unit.phase"), None)
    await d._sync_ingest()
    return {"decision_id": did, "cmd_id": cmd_id, "template": template, "phase": phase}


async def op_export_phase(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    template = _template(args)
    ref = args.get("cmd_id") or args.get("cmd_ref")
    phase = args.get("phase")
    if not isinstance(ref, str) or not ref or len(ref) > 200 or not isinstance(phase, str):
        raise OpError("invalid", "Befehl und Phase angeben")
    origin = "webui" if args.get("origin") == "webui" else "cli"
    res = await submit_phase(d, template=template, ref=ref, phase=phase, origin=origin)
    return _exit(d, res)


OPS: dict[str, Callable[[Daemon, dict[str, Any]], Any]] = {
    "export.run": op_export_run,
    "export.list": op_export_list,
    "export.phases": op_export_phases,
    "export.phase": op_export_phase,
}
