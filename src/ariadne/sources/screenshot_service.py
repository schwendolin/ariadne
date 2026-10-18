"""Screenshots im Daemon (E32, Architektur 4.3): Auslösen, Kontext, Ablage, Liste.

Drei Auslöser senden nur eine Anfrage, aufgenommen wird immer hier:

* ``F12 s`` im Terminal: der Shim schickt ``req.shot`` (``{"mode"?}``); ``daemon/core.py`` ruft
  :func:`from_hotkey` als Hintergrundaufgabe und zeigt das Ergebnis kurz im Titel.
* ``ariadne shot``: ctl-Operation ``shot.take`` (:data:`OPS`) mit der Sitzungsumgebung der CLI.
* Dashboard-Knopf: ``POST /p/{pid}/screenshots`` ruft :func:`take` direkt (Countdown ``delay_s``).

Ablauf von :func:`take`: Countdown, Sitzung finden (Umgebung der CLI, sonst die aus dem HELLO des
Terminals, sonst die eigene oder die eines Prozesses derselben UID), Aufnahme im Worker
(:func:`ariadne.sources.screenshot.capture`), PNG prüfen, verschlüsselt als Blob
(``kind = "screenshot"``) ablegen, Ereignis ``shot.captured`` mit Kontext (Terminal,
Stromposition, Host der obersten Stufe, Kontextstapel ohne Auto-Hosts) schreiben und
``_notify("screenshot", ...)`` melden. Es läuft immer höchstens eine Aufnahme (sonst ``conflict``).

Besitzer: Teil «screenshots» (Bau v0.1-Screenshots).
"""

from __future__ import annotations

import asyncio
import logging
import time
import weakref
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ariadne.daemon.ops_util import OpError
from ariadne.sources import screenshot as shot
from ariadne.store.api import AppendItem

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon
    from ariadne.daemon.terminal import Terminal

__all__ = ["OPS", "take", "from_hotkey", "list_shots", "is_screenshot_blob", "BLOB_KIND", "MAX_DELAY_S"]

log = logging.getLogger("ariadne.daemon")

BLOB_KIND = "screenshot"
MAX_DELAY_S = 10
NOTE_MAX = 500
TRIGGERS = ("hotkey", "cli", "webui")
_ORIGIN = {"hotkey": "shim", "cli": "cli", "webui": "webui"}
_MODE_TEXT = {"window": "Fenster", "monitor": "Monitor", "region": "Bereich"}

# Für Tests austauschbar: Wurzel für die Suche nach einer grafischen Sitzung derselben UID und die
# Aufnahmefunktion (Signatur wie :func:`ariadne.sources.screenshot.capture`).
PROC_ROOT = Path("/proc")
CAPTURE: Callable[..., Any] = shot.capture

_locks: weakref.WeakKeyDictionary[Any, asyncio.Lock] = weakref.WeakKeyDictionary()


def _lock(d: Daemon) -> asyncio.Lock:
    lk = _locks.get(d)
    if lk is None:
        lk = _locks[d] = asyncio.Lock()
    return lk


def _context_terminal(d: Daemon, terminal_id: str | None) -> Terminal | None:
    """Das genannte Terminal, sonst das zuletzt aktive (jüngster Rahmen, aufnehmende zuerst)."""
    if terminal_id is not None:
        t = d.terminals.get(terminal_id)
        if t is None or t.closed:
            raise OpError("unknown_terminal", "Terminal unbekannt")
        return t
    best: tuple[int, int, Any] | None = None
    for t in d.terminals.values():
        if t.closed:
            continue
        last = t.frame_times[-1][2] if t.frame_times else 0
        key = (1 if t.recording else 0, last)
        if best is None or key > best[:2]:
            best = (key[0], key[1], t)
    return best[2] if best is not None else None


def _session(display: Mapping[str, Any] | None, t: Terminal | None) -> dict[str, str]:
    from ariadne.daemon.clipboard import find_session

    for cand in (display, t.display if t is not None else None):
        env = shot.session_env(cand)
        if "DISPLAY" in env or "WAYLAND_DISPLAY" in env:
            return env
    found = find_session(proc_root=PROC_ROOT)
    return shot.session_env(found) if found else {}


def _context(t: Terminal | None) -> dict[str, Any]:
    if t is None:
        return {}
    out: dict[str, Any] = {"terminal_id": t.terminal_id}
    if t.recording:
        out["stream_off"] = t.recv_end
    top = t.stack.top()
    if top.host and top.host != "local" and top.kind not in ("local", "su"):
        out["host"] = top.host
        out["host_auto"] = top.host_source == "auto"
    out["stack"] = t.stack.journal_snapshot()
    return out


def _check_args(mode: Any, region: Any, delay_s: Any, note: Any, trigger: Any) -> tuple[
        str, tuple[int, int, int, int] | None, float, str | None]:
    if mode not in shot.MODES:
        raise OpError("invalid", "mode muss window, monitor oder region sein")
    reg = None
    if mode == "region":
        if region is None:
            raise OpError("invalid", "Bereich fehlt: x, y, Breite, Höhe")
        try:
            reg = shot.parse_region(region)
        except ValueError:
            raise OpError("invalid", "Bereich ungültig") from None
    elif region is not None:
        raise OpError("invalid", "Bereich nur im Modus region")
    if delay_s is None:
        delay_s = 0
    if type(delay_s) not in (int, float) or not 0 <= delay_s <= MAX_DELAY_S:
        raise OpError("invalid", "delay_s ungültig (0 bis 10)")
    if note is not None and (not isinstance(note, str) or len(note) > NOTE_MAX):
        raise OpError("invalid", "Notiz zu lang")
    if trigger not in TRIGGERS:
        raise OpError("invalid", "Auslöser ungültig")
    return str(mode), reg, float(delay_s), note or None


async def take(d: Daemon, *, mode: str = "window", trigger: str, region: Any = None, delay_s: float = 0,
               terminal_id: str | None = None, display: Mapping[str, Any] | None = None,
               note: str | None = None) -> dict[str, Any]:
    """Nimmt einen Screenshot auf und legt ihn ab. Fehler: :class:`OpError` (``no_project``,
    ``invalid``, ``unknown_terminal``, ``conflict``, ``project_changed``) oder
    :class:`~ariadne.sources.screenshot.ShotError`."""
    mode, reg, delay, note = _check_args(mode, region, delay_s, note, trigger)
    p = d._require_project()
    lock = _lock(d)
    if lock.locked():
        raise OpError("conflict", "ein Screenshot läuft schon")
    async with lock:
        if delay:
            await asyncio.sleep(delay)
        if d.project is not p:
            raise OpError("project_changed", "Projekt wurde währenddessen gewechselt")
        t = _context_terminal(d, terminal_id)
        ctx = _context(t)  # Kontext zum Zeitpunkt der Aufnahme
        env = _session(display, t)
        shot.x11_display(env)  # klare Meldung ohne Worker: kein DISPLAY oder Wayland
        cap = await CAPTURE(env, mode, reg)
        if d.project is not p:
            raise OpError("project_changed", "Projekt wurde währenddessen gewechselt")
        try:
            shot.check_png(cap.png)
        except ValueError:
            raise shot.ShotError("shot_failed") from None
        ref = p.blobs.put_bytes(cap.png, kind=BLOB_KIND)  # Blob-Store nur im Loop-Thread
        header: dict[str, Any] = {
            "blob_id": ref.blob_id, "sha256": ref.sha256, "mode": cap.mode, "backend": cap.backend,
            "trigger": trigger, "width": cap.width, "height": cap.height,
            "window_title": cap.window_title, "wm_class": cap.wm_class, "note": note, "dhash": cap.dhash,
            **ctx,
        }
        header = {k: v for k, v in header.items() if v is not None}
        tid = ctx.get("terminal_id")
        d.submit(AppendItem("shot.captured", header, origin=_ORIGIN[trigger], terminal_id=tid,
                            stream_off=ctx.get("stream_off")))
        recs = d.flush()
        rec = next((r for r in reversed(recs) if r.kind == "shot.captured"), None)
        d._notify("screenshot", project_id=p.info.id, id=rec.id if rec else None, trigger=trigger)
        log.info("Screenshot gespeichert (%s, %dx%d)", cap.mode, cap.width, cap.height)
        out = dict(header)
        out.pop("stack", None)
        if rec is not None:
            out.update(id=rec.id, seq=rec.seq, ts_utc_ns=rec.ts_utc_ns)
        else:  # pragma: no cover - flush schreibt immer
            out.update(id=None, seq=None, ts_utc_ns=time.time_ns())
        return out


async def from_hotkey(d: Daemon, t: Terminal, obj: Mapping[str, Any]) -> None:
    """``req.shot`` vom Shim (F12 s): Ergebnis nur als kurze Meldung im Titel des Terminals."""
    mode = obj.get("mode", "window")
    if mode not in shot.MODES or mode == "region":
        mode = "window"  # Bereich braucht Koordinaten: am Terminal nur Fenster oder Monitor
    try:
        res = await take(d, mode=mode, trigger="hotkey", terminal_id=t.terminal_id)
    except shot.ShotError as exc:
        d._flash(t, f"Kein Screenshot: {shot.SHOT_ERRORS[exc.code]}")
        return
    except OpError as exc:
        text = {"no_project": "kein Projekt offen", "conflict": "läuft schon"}.get(exc.code, "Fehler")
        d._flash(t, f"Kein Screenshot: {text}")
        return
    except Exception as exc:  # nie Text der Ausnahme (kann Zieldaten enthalten)
        log.error("Screenshot fehlgeschlagen (%s)", type(exc).__name__)
        d._flash(t, "Kein Screenshot: Fehler")
        return
    d._flash(t, f"Screenshot gespeichert ({_MODE_TEXT.get(res.get('mode', ''), 'Bild')})")


# --------------------------------------------------------------------------- #
# Liste und Blobs (Web-API)
# --------------------------------------------------------------------------- #


def list_shots(journal: Any, limit: int = 200) -> list[dict[str, Any]]:
    """Alle ``shot.captured`` des Journals, neueste zuerst (höchstens ``limit``)."""
    items: list[dict[str, Any]] = []
    for r in journal.iter_events(kinds=["shot.captured"]):
        h = dict(r.header)
        h.pop("stack", None)
        h.update(id=r.id, seq=r.seq, ts_utc_ns=r.ts_utc_ns)
        items.append(h)
    items.sort(key=lambda h: h["seq"], reverse=True)
    return items[:limit]


def is_screenshot_blob(p: Any, blob_id: str) -> bool:
    """Hat Ariadne diesen Blob selbst als Screenshot abgelegt? (Nur im Loop-Thread.)"""
    conn = getattr(p.blobs, "conn", None)
    if conn is None:
        return False
    row = conn.execute("SELECT kind FROM blob WHERE blob_id = ?", (blob_id,)).fetchone()
    return row is not None and row[0] == BLOB_KIND


# --------------------------------------------------------------------------- #
# ctl
# --------------------------------------------------------------------------- #


async def op_shot_take(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    """``shot.take`` (CLI ``ariadne shot``). Fehler der Aufnahme als ``shot_*``-Code mit festem Text."""
    origin = args.get("origin", "cli")
    if origin not in ("cli",):
        raise OpError("invalid", "origin ungültig")
    display = args.get("display")
    if display is not None and not isinstance(display, dict):
        raise OpError("invalid", "display ungültig")
    tid = args.get("terminal_id")
    if tid is not None and (not isinstance(tid, str) or len(tid) > 64):
        raise OpError("invalid", "terminal_id ungültig")
    known = d.terminals.get(tid) if tid is not None else None
    if known is None or known.closed:
        tid = None  # Terminal ohne Shim-Verbindung: zuletzt aktives nehmen
    try:
        res = await take(d, mode=args.get("mode", "window"), trigger="cli", region=args.get("region"),
                         delay_s=args.get("delay_s", 0), terminal_id=tid, display=display,
                         note=args.get("note"))
    except shot.ShotError as exc:
        raise OpError(exc.code, shot.SHOT_ERRORS[exc.code]) from None
    res = await _mask_known_secrets(d, res)
    out, _labels = d.redactor.redact_json(res)
    return out


async def _mask_known_secrets(d: Daemon, res: dict[str, Any]) -> dict[str, Any]:
    """Fenstertitel und Notiz für die CLI mit den bekannten Secret-Werten maskieren (E99). Ist die
    Auswertung nicht bereit, fallen beide Felder weg (lieber nichts als Klartext)."""
    from ariadne.web.api.text import mask_known
    from ariadne.web.api.views import secret_values

    out = dict(res)
    try:
        ing = await d._sync_ingest()
        known = await ing.query(secret_values)
    except Exception:
        out["window_title"] = out["note"] = None
        return out
    for k in ("window_title", "note"):
        if isinstance(out.get(k), str):
            out[k] = mask_known(out[k], known)
    return out


OPS: dict[str, Callable[[Daemon, dict[str, Any]], Any]] = {"shot.take": op_shot_take}
