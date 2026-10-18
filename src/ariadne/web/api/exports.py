"""Bericht-Export über die Web-API (Bau v0.1-Export, E62, Architektur 8.7).

Besitzer: Teil «export». Routen (Entwurf für ``docs/web-api.md``):

* ``POST /p/{pid}/exports`` startet einen Export im Hintergrund (202, ``job_id``); Fortschritt per
  SSE ``progress`` mit ``kind: 'export'`` und festen deutschen Texten. ``klartext: true`` ist hier
  immer 403 ``policy``: Klartext gibt es nur im Terminal (Profil lab, Bestätigung).
* ``GET /p/{pid}/exports`` listet die Exporte im Projektordner und einen laufenden Auftrag.
* ``GET /p/{pid}/exports/phases?template=`` zeigt die Phasen der Befehle zum Prüfen,
  ``POST /p/{pid}/exports/phases`` korrigiert eine Phase per Entscheid ``d.unit.phase`` (Herkunft
  ``webui``).

Antworten gehen wie überall durch ``Api.respond`` (Redaktor, sichtbare Steuerzeichen).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Literal

from fastapi import APIRouter, Body, Query
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import Response

from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.text import iso

__all__ = ["add_routes", "ExportRequest", "PhaseRequest"]

log = logging.getLogger("ariadne.web.api")

_PHASE_KEYS = Literal[
    "recon",
    "scanning",
    "exploitation",
    "post",
    "reporting",
    "enumeration",
    "foothold",
    "privesc",
    "pivot",
    "loot",
    "lessons",
    "omit",
]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ExportRequest(_In):
    template: Literal["cys", "htb"] = "cys"
    klartext: bool = False


class PhaseRequest(_In):
    template: Literal["cys", "htb"]
    cmd_id: str | None = Field(default=None, min_length=3, max_length=200)
    cmd_ref: str | None = Field(default=None, min_length=3, max_length=200)
    phase: _PHASE_KEYS


_TASKS: set[asyncio.Task[Any]] = set()


def add_routes(router: APIRouter, api: Api) -> None:
    from ariadne.daemon.ops_util import OpError
    from ariadne.export import service
    from ariadne.export.ops import phase_rows, submit_phase
    from ariadne.export.writer import list_exports
    from ariadne.ingest.proj_phases import OMIT, PHASE_LABELS, PHASES

    @router.post("/p/{pid}/exports", name="exports_create", status_code=202)
    async def create_export(pid: str, body: ExportRequest | None = Body(default=None)) -> Response:  # noqa: B008
        req = body or ExportRequest()
        p = api.project(pid)
        if req.klartext:
            raise ApiError("policy")
        api._ingest()  # 503, wenn die Auswertung nicht läuft
        d = api.daemon
        try:
            job_id = service.new_job(d, req.template)
        except service.ExportBusy:
            raise ApiError("conflict") from None
        bus = api.ctx.bus

        def progress(status: str, pct: int | None, message: str) -> None:
            bus.publish(
                "progress",
                {"job_id": job_id, "kind": "export", "status": status, "pct": pct, "message": message},
            )

        async def job() -> None:
            try:
                if d.project is not p:
                    raise RuntimeError("Projekt gewechselt")
                await service.run_export(d, template=req.template, job_id=job_id, progress=progress)
            except Exception as exc:  # noqa: BLE001 - nur die Klasse ins Log, nie Inhalte
                log.warning("Export fehlgeschlagen (%s)", type(exc).__name__)
                service.end_job(d, job_id, failed=True)

        progress("running", 0, service.MESSAGES["collect"])
        task = asyncio.ensure_future(job())
        _TASKS.add(task)
        task.add_done_callback(_TASKS.discard)
        return await api.respond({"job_id": job_id, "status": "running", "template": req.template}, 202)

    @router.get("/p/{pid}/exports", name="exports_list")
    async def get_exports(pid: str) -> Response:
        p = api.project(pid)
        items = await asyncio.to_thread(list_exports, p.info.workspace)
        api.same(p)
        return await api.respond({"exports": items, **service.job_state(api.daemon)})

    @router.get("/p/{pid}/exports/phases", name="exports_phases")
    async def get_phases(pid: str, template: str = Query(default="cys", max_length=8)) -> Response:  # noqa: B008
        p = api.project(pid)
        if template not in PHASES:
            raise ApiError("validation", [{"loc": ["query", "template"], "type": "enum"}])
        rows = await api.query(p, lambda c: phase_rows(c, template))
        bag = api.bag()
        commands = []
        for r in rows:
            b = bag.new()
            item = {**r, "command": b(r["command"]), "ts": iso(r["ts"])}
            item["ctrl"] = b.ctrl
            commands.append(item)
        phases = [{"key": k, "label": PHASE_LABELS[k]} for k in (*PHASES[template], OMIT)]
        return await api.respond({"template": template, "phases": phases, "commands": commands})

    @router.post("/p/{pid}/exports/phases", name="exports_phase_set")
    async def set_phase(pid: str, body: PhaseRequest) -> Response:
        p = api.project(pid)
        ref = body.cmd_id or body.cmd_ref
        if not ref:
            raise ApiError("validation", [{"loc": ["body", "cmd_id"], "type": "missing"}])
        if body.phase != OMIT and body.phase not in PHASES[body.template]:
            raise ApiError("validation", [{"loc": ["body", "phase"], "type": "enum"}])
        try:
            res = await submit_phase(
                api.daemon,
                template=body.template,
                ref=ref,
                phase=body.phase,
                origin="webui",
                query=lambda fn: api.query(p, fn),
            )
        except OpError as exc:
            code = {
                "not_found": "not_found",
                "invalid": "validation",
                "no_project": "no_project",
                "project_changed": "conflict",
                "no_ingest": "unavailable",
            }.get(exc.code, "internal")
            raise ApiError(code) from None
        api.same(p)
        return await api.respond(res)
