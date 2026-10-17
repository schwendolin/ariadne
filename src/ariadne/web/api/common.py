"""Gemeinsame Bausteine der Routen: Zugriff auf den Daemon nach den Regeln des Vertrags (3.2),
Projektprüfung, Abfragen im Thread der Auswertung, Ausgang mit Redaktor.

Handler nutzen den Daemon nur über :class:`Api`:

* :meth:`Api.call` mit den erlaubten ctl-Operationen (:data:`ALLOWED_OPS`), Herkunft ``webui``
  setzt der Aufrufer in ``args``;
* :meth:`Api.query` und :meth:`Api.query_journal` (``ingest.query``/``query_journal``), danach
  wird geprüft, dass dasselbe Projekt noch offen ist (sonst 409 ``project_mismatch``);
* :meth:`Api.respond` schickt jede Antwort durch ``redactor.redact_json`` (E72) und macht danach
  jeden String sichtbar (zweite Schicht).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar

from ariadne.web.api.errors import ApiError, JsonResponse, from_ctl
from ariadne.web.api.text import Bag, deep_visible, iso
from ariadne.web.ctx import SessionInfo, WebContext

if TYPE_CHECKING:
    from ariadne.project.service import OpenProject

__all__ = ["Api", "ALLOWED_OPS", "session_view", "valid_pid", "valid_tid"]

T = TypeVar("T")

# Vertrag v0.1-Server 3.2: nur diese ctl-Operationen; nie unlock, start, lock, stop, secrets.*, ...
ALLOWED_OPS = frozenset(
    {
        "status",
        "terminals",
        "preroll.info",
        "term.pause",
        "term.resume",
        "ctx.show",
        "ctx.set",
        "ctx.push",
        "ctx.pop",
        "presentation",
        "show",
        "search",
        "claim.confirm",
        "claim.reject",
        "unit.distrust",
        "input.reveal",
    }
)

_HEXDASH = frozenset("0123456789abcdef-")


def valid_pid(pid: str) -> bool:
    return 8 <= len(pid) <= 64 and set(pid.lower()) <= _HEXDASH


def valid_tid(tid: str) -> bool:
    return 8 <= len(tid) <= 64 and set(tid.lower()) <= _HEXDASH


def session_view(s: SessionInfo) -> dict[str, Any]:
    return {
        "session_id": s.session_id,
        "origin": s.origin,
        "created_at": iso(s.created_ns),
        "expires_at": iso(s.expires_ns),
    }


class Api:
    """Zugriff der Routen auf den Daemon (nur die im Vertrag 3.2 erlaubten Wege)."""

    def __init__(self, ctx: WebContext) -> None:
        self.ctx = ctx

    @property
    def daemon(self) -> Any:
        return self.ctx.daemon

    # ------------------------------------------------------------------ ctl
    async def call(self, op: str, args: dict[str, Any] | None = None) -> Any:
        if op not in ALLOWED_OPS:
            raise RuntimeError("ctl-Operation für die Web-API nicht erlaubt")
        res = await self.daemon.call(op, args or {})
        if not isinstance(res, dict) or not res.get("ok"):
            raise from_ctl((res or {}).get("error") if isinstance(res, dict) else None)
        return res.get("result")

    # ------------------------------------------------------------------ Projekt
    def project(self, pid: str) -> OpenProject:
        """Das offene Projekt, wenn es ``pid`` ist. Sonst 423 (gesperrt, Projekt aktiv), 409
        ``no_project`` oder ``project_mismatch``."""
        d = self.daemon
        p = d.project
        if p is None:
            active = d.active
            if isinstance(active, dict) and active.get("stopped") is False:
                raise ApiError("locked")
            raise ApiError("no_project")
        if not valid_pid(pid) or p.info.id != pid:
            raise ApiError("project_mismatch")
        return p

    def same(self, p: OpenProject) -> None:
        """Nach einem ``await``: ist dasselbe Projekt noch offen? (E70: Projekte mischen sich nie)"""
        cur = self.daemon.project
        if cur is not p or getattr(p, "closed", False):
            raise ApiError("project_mismatch")

    def _ingest(self) -> Any:
        ing = self.daemon.ingest
        if ing is None or not ing.active:
            raise ApiError("unavailable")
        return ing

    async def query(self, p: OpenProject, fn: Callable[[Any], T]) -> T:
        """``fn(conn)`` im Thread der Auswertung (nur lesend, mit LIMIT)."""
        ing = self._ingest()
        try:
            res = await ing.query(fn)
        except Exception as exc:
            raise self._failed(p, exc) from None
        self.same(p)
        return res

    async def query_journal(self, p: OpenProject, fn: Callable[[Any, Any], T]) -> T:
        """``fn(conn, journal)`` im Thread der Auswertung (nur lesend)."""
        ing = self._ingest()
        try:
            res = await ing.query_journal(fn)
        except Exception as exc:
            raise self._failed(p, exc) from None
        self.same(p)
        return res

    def _failed(self, p: OpenProject, exc: Exception) -> Exception:
        """Fehler einer Abfrage: Wurde das Projekt inzwischen gewechselt, gilt 409, sonst der
        Fehler der Route (ApiError), 503 bei angehaltener Auswertung oder der Fehler selbst (500)."""
        self.same(p)
        if isinstance(exc, ApiError):
            return exc
        if isinstance(exc, RuntimeError):
            return ApiError("unavailable")
        return exc

    # ------------------------------------------------------------------ Ausgang
    def bag(self) -> Bag:
        return Bag(self.daemon.redactor)

    async def respond(
        self, obj: Any, status: int = 200, headers: dict[str, str] | None = None
    ) -> JsonResponse:
        """Ausgang: eigene Secrets ersetzen (E72), danach jeden String sichtbar machen (zweite Schicht).

        Läuft in einem Thread, damit grosse Antworten (2000 Logzeilen) die Aufnahme nicht aufhalten;
        der Redaktor liest dabei nur seine Muster."""
        body = await asyncio.to_thread(self._finish, obj)
        return JsonResponse(body, status_code=status, headers=headers)

    def _finish(self, obj: Any) -> Any:
        red, _labels = self.daemon.redactor.redact_json(obj)
        return deep_visible(red)

    @staticmethod
    def now_ns() -> int:
        return time.time_ns()
