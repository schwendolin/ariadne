"""Ereignisstrom der Web-Oberfläche (``GET /api/v1/events``, web-api.md 14, Architektur 7.3).

Der Strom trägt **nie Daten oder Secrets**, nur Hinweise, was neu zu laden ist (R8):

* :class:`EventBus` (erfüllt :class:`ariadne.web.ctx.EventPublisher`) sammelt Ereignisse in
  250-ms-Fenstern und fasst gleichartige zusammen (ein nmap-Import ergibt ein ``changes``).
* Jede Nachricht hat eine aufsteigende ``id`` (pro Daemon-Lauf ab der Startzeit in ms, damit
  eine ID aus einem früheren Lauf als solche erkennbar ist), ``event`` und genau eine
  ``data``-Zeile mit einem JSON-Objekt.
* Ringpuffer der letzten 1000 Nachrichten für ``Last-Event-ID``; liegt die ID ausserhalb,
  kommt zuerst ``reset`` (``buffer`` bzw. ``restart``).
* Herzschlag alle 15 s als Kommentar ``: hb``. Höchstens 8 Ströme pro Sitzung; der neunte
  ersetzt den ältesten. Endet die Sitzung, schliesst der Strom sofort und ohne eigenes Ereignis.

Alles läuft im Loop des Daemons: ``publish`` ist synchron und blockiert nie.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from ariadne.web.ctx import SSE_EVENTS

__all__ = ["EventBus", "Subscription", "encode_event", "WINDOW_S", "HEARTBEAT_S", "RING_SIZE", "MAX_STREAMS"]

WINDOW_S = 0.25
HEARTBEAT_S = 15.0
RING_SIZE = 1000
MAX_STREAMS = 8
QUEUE_SIZE = 512
_MAX_DATA = 4096  # ein Ereignis ist klein; grössere Daten sind ein Programmfehler


def encode_event(event_id: int, event: str, data: Mapping[str, Any]) -> bytes:
    payload = json.dumps(dict(data), ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return f"id: {event_id}\nevent: {event}\ndata: {payload}\n\n".encode("ascii")


def _key(event: str, data: Mapping[str, Any]) -> tuple[Any, ...] | None:
    """Schlüssel zum Zusammenfassen innerhalb eines Fensters; ``None`` = nie zusammenfassen."""
    if event in ("changes", "inbox", "suggestion"):
        return (event, data.get("project_id"))
    if event == "terminal":
        return (event, data.get("terminal_id"), data.get("change"))
    if event == "presentation":
        return (event,)
    if event == "progress":
        return (event, data.get("job_id"))
    return None


def _merge(event: str, old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    if event != "changes":
        return new
    out = dict(new)
    gens = [g for g in (old.get("generation"), new.get("generation")) if isinstance(g, int)]
    if gens:
        out["generation"] = max(gens)
    a, b = old.get("entities"), new.get("entities")
    if isinstance(a, dict) and isinstance(b, dict):
        merged = dict(a)
        for k, v in b.items():
            if isinstance(v, int) and isinstance(merged.get(k), int):
                merged[k] = merged[k] + v
            else:
                merged[k] = v
        out["entities"] = merged
    elif isinstance(a, dict) or isinstance(b, dict):
        out.pop("entities", None)  # unvollständig: lieber ohne Zähler als falsche
    return out


@dataclass(eq=False)
class Subscription:
    session_id: str
    queue: asyncio.Queue[bytes | None]
    initial: list[bytes] = field(default_factory=list)
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        while True:
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self.queue.put_nowait(None)


class EventBus:
    """Bus für SSE. ``publish`` nur im Loop-Thread; Abonnenten über :meth:`subscribe`."""

    def __init__(
        self,
        *,
        window_s: float = WINDOW_S,
        heartbeat_s: float = HEARTBEAT_S,
        ring_size: int = RING_SIZE,
        max_streams: int = MAX_STREAMS,
        queue_size: int = QUEUE_SIZE,
        id_base: int | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self.window_s = window_s
        self.heartbeat_s = heartbeat_s
        self.max_streams = max_streams
        self.queue_size = queue_size
        self.base = int(time.time() * 1000) if id_base is None else int(id_base)
        self._next = self.base + 1
        self._ring: collections.deque[tuple[int, bytes]] = collections.deque(maxlen=ring_size)
        self._pending: list[tuple[str, dict[str, Any]]] = []
        self._handle: asyncio.TimerHandle | None = None
        self._loop = loop
        self._subs: list[Subscription] = []
        self.closed = False

    # ------------------------------------------------------------------ #
    # Veröffentlichen
    # ------------------------------------------------------------------ #
    @property
    def last_id(self) -> int:
        return self._next - 1

    def publish(self, event: str, data: Mapping[str, Any]) -> None:
        """Reiht ein Ereignis ins laufende 250-ms-Fenster. ``event`` aus :data:`SSE_EVENTS`."""
        if event not in SSE_EVENTS:
            raise ValueError("unbekanntes SSE-Ereignis")
        payload = dict(data)
        if len(json.dumps(payload, ensure_ascii=True, default=str)) > _MAX_DATA:
            raise ValueError("SSE-Daten zu gross (nur Kennungen und Zahlen)")
        if self.closed:
            return
        self._pending.append((event, payload))
        if self._handle is None:
            loop = self._loop or asyncio.get_running_loop()
            self._handle = loop.call_later(self.window_s, self.flush)

    def flush(self) -> None:
        """Gibt das laufende Fenster aus (zusammengefasst, in der Reihenfolge des ersten Auftretens)."""
        if self._handle is not None:
            self._handle.cancel()
            self._handle = None
        pending, self._pending = self._pending, []
        out: list[list[Any]] = []
        index: dict[tuple[Any, ...], int] = {}
        for event, data in pending:
            key = _key(event, data)
            if key is not None and key in index:
                slot = out[index[key]]
                slot[1] = _merge(event, slot[1], data)
                continue
            if key is not None:
                index[key] = len(out)
            out.append([event, data])
        for event, data in out:
            eid = self._next
            self._next += 1
            chunk = encode_event(eid, event, data)
            self._ring.append((eid, chunk))
            for sub in list(self._subs):
                self._deliver(sub, chunk)

    def _deliver(self, sub: Subscription, chunk: bytes) -> None:
        if sub.closed:
            return
        try:
            sub.queue.put_nowait(chunk)
        except asyncio.QueueFull:
            # Zu langsamer Leser: Strom schliessen, die UI verbindet mit Last-Event-ID neu.
            self._remove(sub)
            sub.close()

    # ------------------------------------------------------------------ #
    # Abonnieren
    # ------------------------------------------------------------------ #
    def _replay(self, last_event_id: str | None) -> list[bytes]:
        if last_event_id is None or last_event_id.strip() == "":
            return []
        reset_id = self.last_id

        def reset(reason: str) -> list[bytes]:
            return [encode_event(reset_id, "reset", {"reason": reason})]

        text = last_event_id.strip()
        if not text.isdigit() or len(text) > 20:
            return reset("buffer")
        want = int(text)
        if want < self.base or want > self.last_id:
            return reset("restart")
        if want == self.last_id:
            return []
        if not self._ring or want < self._ring[0][0] - 1:
            return reset("buffer")
        return [chunk for eid, chunk in self._ring if eid > want]

    def subscribe(self, session_id: str, last_event_id: str | None = None) -> Subscription:
        """Neuer Strom für eine Sitzung; der neunte ersetzt den ältesten (höchstens 8)."""
        if self.closed:
            sub = Subscription(session_id, asyncio.Queue(maxsize=1))
            sub.close()
            return sub
        mine = [s for s in self._subs if s.session_id == session_id]
        while len(mine) >= self.max_streams:
            oldest = mine.pop(0)
            self._remove(oldest)
            oldest.close()
        sub = Subscription(session_id, asyncio.Queue(maxsize=self.queue_size), self._replay(last_event_id))
        self._subs.append(sub)
        return sub

    def _remove(self, sub: Subscription) -> None:
        with contextlib.suppress(ValueError):
            self._subs.remove(sub)

    def unsubscribe(self, sub: Subscription) -> None:
        self._remove(sub)
        sub.closed = True

    def streams(self, session_id: str | None = None) -> int:
        return sum(1 for s in self._subs if session_id is None or s.session_id == session_id)

    def close_session(self, session_id: str) -> int:
        """Schliesst alle Ströme einer Sitzung sofort (Widerruf, Ablauf, Tunnelende)."""
        subs = [s for s in self._subs if s.session_id == session_id]
        for s in subs:
            self._remove(s)
            s.close()
        return len(subs)

    def close_all(self) -> None:
        """Alle Ströme schliessen und nichts mehr annehmen (Stopp des Web-Servers)."""
        self.closed = True
        if self._handle is not None:
            self._handle.cancel()
            self._handle = None
        self._pending.clear()
        for s in list(self._subs):
            self._remove(s)
            s.close()

    async def iterate(self, sub: Subscription) -> AsyncIterator[bytes]:
        """Bytes für ``StreamingResponse``: Eröffnung, Nachholen, Ereignisse, Herzschlag."""
        try:
            yield b": ok\n\n"
            for chunk in sub.initial:
                yield chunk
            sub.initial = []
            while not sub.closed or not sub.queue.empty():
                try:
                    item = await asyncio.wait_for(sub.queue.get(), self.heartbeat_s)
                except TimeoutError:
                    if sub.closed:
                        return
                    yield b": hb\n\n"
                    continue
                if item is None:
                    return
                yield item
        finally:
            self.unsubscribe(sub)
