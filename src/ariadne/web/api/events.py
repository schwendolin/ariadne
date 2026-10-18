"""Ereignisquellen für den SSE-Strom (Vertrag v0.1-Server 3.8, ``docs/web-api.md`` 14).

:func:`attach_sources` meldet einen Listener am Daemon und einen an der Auswertung an. Beide
laufen synchron im Loop-Thread und tun nichts Langsames: Was eine Abfrage braucht (Zahl der offenen
Einträge in «Als Nächstes»), läuft als eigene, gebündelte Aufgabe über ``ingest.query``. Daten sind
nie Zieldaten: nur Kennungen, Zahlen und feste Wörter.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from typing import Any

from ariadne.rules import api as rules_api
from ariadne.web.ctx import WebContext

__all__ = ["attach_sources", "JOB_TEXT"]

log = logging.getLogger("ariadne.web.api")

JOB_TEXT = {"running": "Neuauswertung läuft", "done": "fertig", "failed": "fehlgeschlagen"}
_TERMINAL_CHANGES = ("opened", "closed", "state", "context", "command")


def _count_open(conn: Any) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM v_inbox").fetchone()[0])


def _inbox_keys(conn: Any) -> list[str]:
    rows = conn.execute("SELECT item_key FROM v_inbox ORDER BY created_ts, group_key, item_key LIMIT 2000")
    return [str(r[0]) for r in rows]


def _count_suggestions(conn: Any, profile: str) -> int | None:
    """Zahl offener Denkanstösse (web-api.md 18.9); ``None``, solange die Regel-Engine ein Stub ist."""
    if rules_api.STUB:
        return None
    return int(rules_api.open_count(conn, profile=profile))


class _Sources:
    def __init__(self, ctx: WebContext) -> None:
        self.ctx = ctx
        self.d = ctx.daemon
        self.bus = ctx.bus
        self.pid: str | None = None  # Projekt, zu dem gen und open gehören
        self.gen: int | None = None
        self.open: int | None = None
        self.sugg: int | None = None  # offene Denkanstösse (Ereignis «suggestion»)
        self.task: asyncio.Task[None] | None = None
        self.again = False
        self.closed = False

    def _pub(self, event: str, data: dict[str, Any]) -> None:
        try:
            self.bus.publish(event, data)
        except Exception as exc:  # der Bus darf die Aufnahme nie stören
            log.error("SSE-Ereignis nicht veröffentlicht (%s)", type(exc).__name__)

    def _reset_project(self, pid: str | None) -> None:
        if pid != self.pid:
            # Schnappschuss der Regel-Engine des alten Projekts verwerfen (Projektwechsel, Sperre)
            with contextlib.suppress(Exception):
                rules_api.clear_cache()
        self.pid, self.gen, self.open, self.sugg = pid, None, None, None

    # ------------------------------------------------------------------ Daemon
    def on_daemon(self, kind: str, data: dict[str, Any]) -> None:
        if kind == "terminal":
            change = data.get("change")
            tid = data.get("terminal_id")
            if isinstance(tid, str) and change in _TERMINAL_CHANGES:
                self._pub("terminal", {"terminal_id": tid, "change": change})
        elif kind == "project":
            change = data.get("change")
            if change in ("opened", "closed"):
                pid = data.get("project_id")
                self._reset_project(pid if change == "opened" and isinstance(pid, str) else None)
                self._pub(
                    "project",
                    {"project_id": pid if isinstance(pid, str) else None, "change": change, "locked": False},
                )
        elif kind in ("locked", "unlocked"):
            self._reset_project(None)
            self._pub("project", {"project_id": None, "change": kind, "locked": kind == "locked"})
        elif kind == "presentation":
            self._pub("presentation", {"on": bool(data.get("on"))})
        elif kind == "job":
            status = data.get("status")
            job_kind = data.get("kind")
            if status not in JOB_TEXT or job_kind != "reparse":
                return
            self._pub(
                "progress",
                {
                    "job_id": str(data.get("job_id") or ""),
                    "kind": job_kind,
                    "status": status,
                    "pct": None,
                    "message": JOB_TEXT[status],
                },
            )
            if status == "done":
                self.gen = None
                self._pub("reset", {"reason": "reparse"})

    # ------------------------------------------------------------------ Auswertung
    def on_ingest(self, update: Any) -> None:
        p = self.d.project
        if p is None:
            return
        pid = p.info.id
        if pid != self.pid:
            self._reset_project(pid)
        gen = getattr(update, "generation", None)
        if not isinstance(gen, int):
            return
        if self.gen is not None and gen < self.gen:
            self._pub("reset", {"reason": "reparse"})  # neue derived.db
        elif gen != self.gen:
            self._pub("changes", {"project_id": pid, "generation": gen})
        else:
            return
        self.gen = gen
        self._schedule_inbox()

    def _schedule_inbox(self) -> None:
        if self.closed:
            return
        if self.task is not None and not self.task.done():
            self.again = True
            return
        try:
            self.task = asyncio.get_running_loop().create_task(self._inbox())
        except RuntimeError:
            self.task = None

    async def _inbox(self) -> None:
        while True:
            self.again = False
            p = self.d.project
            ing = self.d.ingest
            if p is None or ing is None or not ing.active:
                return
            profile = p.info.profile
            try:
                n = await ing.query(_count_open)
            except Exception as exc:
                log.error("Zahl der offenen Einträge nicht lesbar (%s)", type(exc).__name__)
                return
            try:
                sugg = await ing.query(lambda c, prof=profile: _count_suggestions(c, prof))
            except Exception as exc:  # Regel-Engine darf das Ereignis «inbox» nie verhindern
                log.error("Zahl der Denkanstösse nicht lesbar (%s)", type(exc).__name__)
                sugg = None
            if self.closed or self.d.project is not p:
                return
            if self.pid != p.info.id:
                self._reset_project(p.info.id)
            await self._ordinals(p, ing)
            if self.closed or self.d.project is not p:
                return
            if n != self.open:
                self.open = n
                self._pub("inbox", {"project_id": p.info.id, "open": n})
            if sugg is not None and sugg != self.sugg:
                self.sugg = sugg
                self._pub("suggestion", {"project_id": p.info.id, "open": sugg})
            if not self.again:
                return

    async def _ordinals(self, p: Any, ing: Any) -> None:
        """Stabile Nummern («K2») für neue Klärungen, sobald sie entstehen, nicht erst beim
        nächsten Abruf von /next (web-api.md 18.12)."""
        from ariadne.web.api.ui_state import item_ordinals

        try:
            keys = await ing.query(_inbox_keys)
            if keys:
                await asyncio.to_thread(item_ordinals, p, keys)
        except Exception as exc:  # Nummern dürfen das Ereignis «inbox» nie verhindern
            log.error("Nummern der Klärungen nicht vergeben (%s)", type(exc).__name__)

    def detach(self) -> None:
        self.closed = True
        with contextlib.suppress(Exception):
            self.d.remove_listener(self.on_daemon)
        ing = self.d.ingest
        if ing is not None:
            with contextlib.suppress(Exception):
                ing.remove_listener(self.on_ingest)
        if self.task is not None and not self.task.done():
            self.task.cancel()


def attach_sources(ctx: WebContext) -> Callable[[], None]:
    """Meldet Daemon- und Auswertungsereignisse auf ``ctx.bus``; gibt eine Abmeldefunktion zurück."""
    src = _Sources(ctx)
    ctx.daemon.add_listener(src.on_daemon)
    if ctx.daemon.ingest is not None:
        ctx.daemon.ingest.add_listener(src.on_ingest)
    return src.detach
