"""Ablauf eines Exports im Daemon (CLI über ctl, Web-API im Hintergrund).

:func:`run_export` sammelt im Thread der Auswertung (:func:`ariadne.export.collect.collect`),
rendert und schreibt in einem Worker-Thread. Ein Export pro Daemon gleichzeitig. Fortschritt meldet
der optionale Rückruf ``progress(status, pct, message)`` mit festen deutschen Texten.

Klartext (Ziel-Credentials unmaskiert) gibt es nur im Profil ``lab`` und nur, wenn der Aufrufer die
Bestätigung aus dem Terminal mitschickt (``confirm == "KLARTEXT"``); die Web-API lässt ihn nie zu.
"""

from __future__ import annotations

import asyncio
import itertools
import time
import weakref
from collections.abc import Callable
from typing import Any

from ariadne.export import collect as collect_mod
from ariadne.export import render as render_mod
from ariadne.export import writer
from ariadne.ingest.proj_phases import TEMPLATES

__all__ = ["ExportBusy", "ExportPolicy", "run_export", "job_state", "KLARTEXT_CONFIRM", "MESSAGES"]

KLARTEXT_CONFIRM = "KLARTEXT"
MESSAGES = {
    "collect": "Daten sammeln",
    "write": "Dateien schreiben",
    "done": "Export fertig",
    "failed": "Export fehlgeschlagen",
}

_JOBS = itertools.count(1)
_STATE: weakref.WeakKeyDictionary[Any, dict[str, Any]] = weakref.WeakKeyDictionary()

Progress = Callable[[str, int | None, str], None]


class ExportBusy(RuntimeError):
    """Ein Export läuft schon."""


class ExportPolicy(PermissionError):
    """Klartext ist hier nicht erlaubt."""


def job_state(d: Any) -> dict[str, Any]:
    """Zustand für ``GET /exports``: ``running`` und ``last_error`` (nur feste Texte)."""
    st = _STATE.get(d) or {}
    return {"running": st.get("running"), "last_error": st.get("last_error")}


def new_job(d: Any, template: str) -> str:
    """Reserviert den einzigen Platz für einen Export (sonst :class:`ExportBusy`)."""
    st = _STATE.setdefault(d, {})
    if st.get("running"):
        raise ExportBusy("ein Export läuft schon")
    job_id = f"exp-{next(_JOBS)}"
    st["running"] = {"job_id": job_id, "template": template, "status": "running", "pct": 0}
    return job_id


def end_job(d: Any, job_id: str, *, failed: bool) -> None:
    st = _STATE.setdefault(d, {})
    run = st.get("running")
    if run and run.get("job_id") == job_id:
        st["running"] = None
    if failed:
        st["last_error"] = {"job_id": job_id, "message": MESSAGES["failed"]}


def _set_pct(d: Any, job_id: str, pct: int) -> None:
    run = (_STATE.get(d) or {}).get("running")
    if run and run.get("job_id") == job_id:
        run["pct"] = pct


def check_policy(profile: Any, klartext: bool, confirm: Any) -> None:
    if not klartext:
        return
    if profile != "lab":
        raise ExportPolicy("Klartext nur im Profil lab")
    if confirm != KLARTEXT_CONFIRM:
        raise ExportPolicy("Klartext braucht die Bestätigung im Terminal")


async def run_export(d: Any, *, template: str = "cys", klartext: bool = False, confirm: Any = None,
                     job_id: str | None = None, progress: Progress | None = None) -> dict[str, Any]:
    """Führt einen Export aus und gibt das Ergebnis zurück (``export_id``, ``path``, ``files``,
    ``warnings``, ``chain``, ``masked``). ``job_id`` von :func:`new_job`, sonst wird einer reserviert."""
    if template not in TEMPLATES:
        raise ValueError("unbekannte Vorlage")
    p = d._require_project()
    check_policy(p.info.profile, klartext, confirm)
    own_job = job_id is None
    if job_id is None:
        job_id = new_job(d, template)
    failed = True

    def say(status: str, pct: int | None, key: str) -> None:
        if pct is not None:
            _set_pct(d, job_id, pct)
        if progress is not None:
            try:
                progress(status, pct, MESSAGES[key])
            except Exception:  # noqa: BLE001, S110 - Anzeige darf den Export nicht stoppen
                pass

    try:
        say("running", 5, "collect")
        ing = await d._sync_ingest()
        if d.project is not p:
            raise RuntimeError("Projekt gewechselt")
        now = time.time_ns()
        redactor = d.redactor
        project = {"id": p.info.id, "slug": p.info.slug, "profile": p.info.profile, "settings": dict(p.settings)}

        def gather(conn: Any, journal: Any) -> dict[str, Any]:
            jconn = getattr(journal, "conn", None)

            def read_blob(blob_id: str) -> bytes:
                return p.blobs.with_connection(jconn).open_bytes(blob_id)

            return collect_mod.collect(conn, journal, redactor=redactor, template=template, klartext=klartext,
                                       project=project, read_blob=read_blob if jconn is not None else None,
                                       now_ns=now)

        data = await ing.query_journal(gather)
        if d.project is not p:
            raise RuntimeError("Projekt gewechselt")
        say("running", 50, "write")
        workspace = p.info.workspace
        result = await asyncio.to_thread(_render_write, data, workspace, template, now, redactor)
        failed = False
        say("done", 100, "done")
        return result
    finally:
        if failed:
            say("failed", None, "failed")
        end_job(d, job_id, failed=failed)
        _ = own_job


def _render_write(data: dict[str, Any], workspace: Any, template: str, now: int, redactor: Any) -> dict[str, Any]:
    files: dict[str, str | bytes] = dict(render_mod.render(data))
    for im in data["images"]:
        if im.get("data") is not None and im.get("sha256"):
            name = f"Belege/img/{render_mod.slug(im['sha256'])[:16]}.png"
            files[name] = im["data"]
    warnings: set[str] = set()
    if writer.sync_folder(workspace):
        warnings.add("sync_folder")
    if data["meta"]["klartext"]:
        warnings.add("klartext")
    generic: set[str] = set()
    if redactor is not None:
        for content in files.values():
            if isinstance(content, str):
                _own, warns = redactor.scan_outgoing(content)
                generic |= {w.kind for w in warns}
    if generic:
        warnings.add("generic_secret")
    meta = data["meta"]
    evidence = [{"unit_id": b.unit_id, "file": f"Belege/{render_mod.beleg_name(b.unit_id, render_mod._program_of(b))}",
                 "chain": {"seq": b.chain_seq, "hash": b.chain_hash}} for b in data["belege"].values()]
    manifest = {
        "project_id": meta["project_id"], "template": template, "created_at": meta["created_at"],
        "klartext": bool(meta["klartext"]), "chain": {"seq": meta["chain_seq"], "hash": meta["chain_hash"]},
        "evidence": evidence, "warnings": sorted(warnings), "generic_kinds": sorted(generic),
        "masked": int(data.get("masked") or 0),
    }
    res = writer.write_export(workspace, files, template=template, now_ns=now, redactor=redactor, manifest=manifest)
    res.update({"template": template, "warnings": sorted(warnings), "generic_kinds": sorted(generic),
                "chain": manifest["chain"], "created_at": meta["created_at"], "klartext": bool(meta["klartext"]),
                "masked": manifest["masked"]})
    return res
