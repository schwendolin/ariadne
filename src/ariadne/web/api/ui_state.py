"""Zustand der Oberfläche auf dem Server (``docs/web-api.md`` 18.2 bis 18.4, E106, E112).

* ``GET``/``PUT /ui/prefs``: Vorlieben (Theme, Dichte, Lernmodus), global in
  ``state_dir/ui_prefs.json`` (0600, atomar, höchstens 4 KiB). Kein Browser-Speicher (E112). Nach
  jedem ``PUT`` das SSE-Ereignis ``prefs`` an alle Ströme.
* ``GET``/``PUT /p/{pid}/ui/seen``: Bezugspunkt «Neu seit» (E106). ``PUT`` nimmt die Uhrzeit des
  Servers (nie die des Browsers) und speichert sie pro Projekt in ``state.db`` (Tabelle
  ``ui_state``, Schlüssel ``seen_at``). ``GET`` liefert dazu die Kennungen des Neuen aus der
  Projektion (:func:`ariadne.ingest.queries.new_since`).
* ``PUT /p/{pid}/ui/scope-ack``: Scope-Warnung quittieren (Schlüssel ``scope_ack``).

``state.db`` liegt ausserhalb der Hash-Kette; nichts hiervon ist ein Entscheid. Zugriff nur in
``asyncio.to_thread`` mit eigener Verbindung (wie ``ui/positions``).

Besitzer: Teil «backend-ui» des Baus v0.1-Oberfläche.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body
from starlette.responses import Response

from ariadne.crypto.files import read_private, write_private
from ariadne.ingest import queries
from ariadne.paths import UnsafePathError, ensure_private_dir
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.models import PrefsRequest, ScopeAckRequest, SeenRequest
from ariadne.web.api.text import iso

__all__ = [
    "add_routes",
    "DEFAULT_PREFS",
    "PREFS_NAME",
    "PREFS_MAX",
    "UI_STATE_SQL",
    "read_prefs",
    "write_prefs",
    "state_get",
    "state_set",
    "seen_view",
    "item_ordinals",
    "state_call",
]

log = logging.getLogger("ariadne.web.api")

PREFS_NAME = "ui_prefs.json"
PREFS_MAX = 4096
DEFAULT_PREFS: dict[str, Any] = {"theme": "system", "density": "comfortable", "learning": True}
_ALLOWED: dict[str, tuple[Any, ...]] = {
    "theme": ("system", "light", "dark"),
    "density": ("comfortable", "compact"),
    "learning": (True, False),
}
UI_STATE_SQL = (
    "CREATE TABLE IF NOT EXISTS ui_state (key TEXT PRIMARY KEY, value TEXT NOT NULL, "
    "updated_ns INTEGER NOT NULL)"
)


# --------------------------------------------------------------------------- Vorlieben (18.2)


def _valid(key: str, value: Any) -> bool:
    allowed = _ALLOWED.get(key)
    if allowed is None:
        return False
    if key == "learning":
        return isinstance(value, bool)
    return isinstance(value, str) and value in allowed


def read_prefs(state_dir: Path) -> tuple[dict[str, Any], int | None]:
    """Vorlieben aus der Datei; fehlt sie oder ist sie ungültig, gelten die Standardwerte
    (feldweise: ein ungültiges Feld fällt auf seinen Standard zurück)."""
    prefs = dict(DEFAULT_PREFS)
    try:
        raw = json.loads(read_private(state_dir / PREFS_NAME, max_size=PREFS_MAX).decode("utf-8"))
    except FileNotFoundError:
        return prefs, None
    except (OSError, ValueError, UnicodeDecodeError, UnsafePathError):
        log.warning("ui_prefs.json ungültig, Standardwerte")
        return prefs, None
    if not isinstance(raw, dict):
        return prefs, None
    stored = raw.get("prefs")
    if isinstance(stored, dict):
        for key in DEFAULT_PREFS:
            if key in stored and _valid(key, stored[key]):
                prefs[key] = stored[key]
    updated = raw.get("updated_ns")
    ok = isinstance(updated, int) and not isinstance(updated, bool) and updated > 0
    return prefs, (updated if ok else None)


def write_prefs(state_dir: Path, patch: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Setzt die genannten Felder (schon geprüft) und schreibt atomar mit 0600."""
    prefs, _updated = read_prefs(state_dir)
    for key, value in patch.items():
        if not _valid(key, value):
            raise ValueError("ungültige Vorliebe")
        prefs[key] = value
    now = time.time_ns()
    data = json.dumps({"prefs": prefs, "updated_ns": now}, sort_keys=True).encode() + b"\n"
    if len(data) > PREFS_MAX:  # kann bei festen Feldern nicht passieren; trotzdem nie grösser
        raise ValueError("ui_prefs.json zu gross")
    ensure_private_dir(state_dir)
    write_private(state_dir / PREFS_NAME, data)
    return prefs, now


def _prefs_view(prefs: dict[str, Any], updated: int | None) -> dict[str, Any]:
    return {"prefs": dict(prefs), "updated_at": iso(updated)}


# --------------------------------------------------------------------------- state.db (18.3, 18.4)


def state_get(p: Any, key: str) -> str | None:
    """Wert aus ``state.db`` (Tabelle ``ui_state``) oder ``None``."""
    conn = p.connect_state()
    try:
        conn.execute(UI_STATE_SQL)
        row = conn.execute("SELECT value FROM ui_state WHERE key = ?", (key,)).fetchone()
        conn.commit()
    finally:
        conn.close()
    return str(row[0]) if row is not None and isinstance(row[0], str) else None


def state_set(p: Any, key: str, value: str) -> None:
    conn = p.connect_state()
    try:
        conn.execute(UI_STATE_SQL)
        with conn:
            conn.execute(
                "INSERT INTO ui_state (key, value, updated_ns) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE "
                "SET value = excluded.value, updated_ns = excluded.updated_ns",
                (key, value, time.time_ns()),
            )
    finally:
        conn.close()


UI_ITEM_SQL = "CREATE TABLE IF NOT EXISTS ui_item (item_key TEXT PRIMARY KEY, ordinal INTEGER NOT NULL)"
ITEM_KEYS_MAX = 2000
_ITEM_LOCK = threading.Lock()  # zwei Tabs fragen /next gleichzeitig: Nummern nie doppelt vergeben


def item_ordinals(p: Any, keys: list[str]) -> dict[str, int]:
    """Stabile Nummer je Klärung («K2», web-api.md 18.12): beim ersten Auftreten in ``/next`` in der
    Reihenfolge der Liste vergeben und in ``state.db`` (Tabelle ``ui_item``) gemerkt, damit sich die
    Nummer am Ring auf der Karte nicht verschiebt, wenn eine frühere Klärung erledigt ist."""
    keys = [k for k in dict.fromkeys(keys) if isinstance(k, str) and k][:ITEM_KEYS_MAX]
    if not keys:
        return {}
    with _ITEM_LOCK:
        return _item_ordinals(p, keys)


def _item_ordinals(p: Any, keys: list[str]) -> dict[str, int]:
    conn = p.connect_state()
    try:
        conn.execute(UI_ITEM_SQL)
        with conn:
            known: dict[str, int] = {}
            for i in range(0, len(keys), 500):
                part = keys[i : i + 500]
                marks = ",".join("?" * len(part))
                for key, ordinal in conn.execute(
                    f"SELECT item_key, ordinal FROM ui_item WHERE item_key IN ({marks})",  # noqa: S608
                    tuple(part),
                ):
                    known[str(key)] = int(ordinal)
            top = int(conn.execute("SELECT COALESCE(MAX(ordinal), 0) FROM ui_item").fetchone()[0])
            for key in keys:
                if key not in known:
                    top += 1
                    known[key] = top
                    conn.execute("INSERT INTO ui_item (item_key, ordinal) VALUES (?, ?)", (key, top))
    finally:
        conn.close()
    return known


def _seen_ns(raw: str | None) -> int | None:
    if raw is None or not raw.isdigit() or len(raw) > 20:
        return None
    n = int(raw)
    return n if n > 0 else None


def seen_view(seen_ns: int | None, new: dict[str, Any] | None) -> dict[str, Any]:
    """SeenView (18.3): ``new`` ist genau dann ``null``, wenn ``seen_at`` ``null`` ist."""
    if seen_ns is None or new is None:
        return {"seen_at": None, "new": None}
    since = iso(seen_ns)
    return {
        "seen_at": since,
        "new": {
            "since": since,
            "count": int(new.get("count") or 0),
            **{k: list(new.get(k) or []) for k in ("hosts", "access", "services", "items", "keysteps")},
        },
    }


async def state_call(api: Api, p: Any, fn: Any, *args: Any) -> Any:
    """``fn(p, *args)`` mit eigener Verbindung zu ``state.db`` in einem Thread; danach muss
    dasselbe Projekt noch offen sein (E70)."""
    return await _state(api, p, fn, *args)


async def _state(api: Api, p: Any, fn: Any, *args: Any) -> Any:
    try:
        res = await asyncio.to_thread(fn, p, *args)
    except Exception as exc:
        api.same(p)
        raise ApiError("internal") from exc
    api.same(p)
    return res


# --------------------------------------------------------------------------- Routen


def add_routes(router: APIRouter, api: Api) -> None:
    lock = asyncio.Lock()  # PUT liest und schreibt: zwei gleichzeitige Anfragen verlieren nichts

    def state_dir() -> Path:
        return Path(api.daemon.paths.state_dir)

    @router.get("/ui/prefs", name="prefs_get")
    async def get_prefs() -> Response:
        prefs, updated = await asyncio.to_thread(read_prefs, state_dir())
        return await api.respond(_prefs_view(prefs, updated))

    @router.put("/ui/prefs", name="prefs_put")
    async def put_prefs(body: PrefsRequest) -> Response:
        fields = body.model_fields_set
        if not fields:
            raise ApiError("validation", [{"loc": ["body"], "type": "missing"}])
        for key in sorted(fields):
            if getattr(body, key) is None:
                raise ApiError("validation", [{"loc": ["body", key], "type": "null"}])
        patch = {k: getattr(body, k) for k in fields}
        async with lock:
            try:
                prefs, updated = await asyncio.to_thread(write_prefs, state_dir(), patch)
            except (OSError, ValueError, UnsafePathError) as exc:
                raise ApiError("internal") from exc
        try:
            api.ctx.bus.publish("prefs", {})
        except Exception as exc:  # der Bus darf die Antwort nie verhindern
            log.error("SSE-Ereignis prefs nicht veröffentlicht (%s)", type(exc).__name__)
        return await api.respond(_prefs_view(prefs, updated))

    @router.get("/p/{pid}/ui/seen", name="seen_get")
    async def get_seen(pid: str) -> Response:
        p = api.project(pid)
        seen = _seen_ns(await _state(api, p, state_get, "seen_at"))
        new = None
        if seen is not None:
            profile = p.info.profile
            new = await api.query(p, lambda c: queries.new_since(c, seen, profile=profile))
        return await api.respond(seen_view(seen, new))

    @router.put("/p/{pid}/ui/seen", name="seen_put", status_code=202)
    async def put_seen(pid: str, body: SeenRequest | None = Body(default=None)) -> Response:  # noqa: B008
        p = api.project(pid)
        now = api.now_ns()
        await _state(api, p, state_set, "seen_at", str(now))
        return await api.respond({"seen_at": iso(now)}, 202)

    @router.put("/p/{pid}/ui/scope-ack", name="scope_ack", status_code=202)
    async def put_scope_ack(pid: str, body: ScopeAckRequest) -> Response:
        p = api.project(pid)

        def resolve(conn: Any) -> str:
            try:
                return queries.resolve_cmd(conn, body.cmd_id)
            except queries.RefError:
                raise ApiError("not_found") from None

        cmd_id = await api.query(p, resolve)
        await _state(api, p, state_set, "scope_ack", cmd_id)
        return await api.respond({"accepted": True}, 202)
