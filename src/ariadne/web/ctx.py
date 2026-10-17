"""Gemeinsame Schnittstelle von Server-Kern und API (Vertrag v0.1-Server, Abschnitt 3.1).

Besitzer: Teil «server». Die Form der Klassen hier ist mit Phase 1 festgelegt; Änderungen
nur additiv und nach Absprache (``contract_requests``), denn der Teil «api» baut darauf.

* :class:`WebContext` bekommt jede API-Route über :func:`ariadne.web.api.register`.
* :class:`SessionInfo` legt der Server nach erfolgreicher Prüfung (Host, Fetch-Metadaten,
  Origin, Token, Peer) in ``request.state.session``. Routen lesen sie mit :func:`session_of`.
* :class:`EventPublisher` ist der Ereignisbus für SSE (``GET /api/v1/events``). Die API
  meldet darüber Invalidierungen; Daten holt die Oberfläche immer per REST.

Regeln für alle Routen (Vertrag 3.2): nur ``async def``-Handler (sie laufen im Loop des
Daemons; ``def``-Handler liefen in einem Thread-Pool und dürfen den Daemon nicht anfassen),
Daemon nur über ``daemon.call``, ``daemon.ingest.query``/``query_journal``,
``daemon.submit``/``daemon.flush`` und die im Vertrag 3.2 genannten Felder, nie über private.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon

__all__ = ["SessionInfo", "EventPublisher", "WebContext", "session_of", "SSE_EVENTS", "SessionOrigin"]

SessionOrigin = Literal["local", "sshd"]

# Ereignisse des Stroms (web-api.md Abschnitt 14). Daten sind nie Zieldaten oder Secrets. Endet eine
# Sitzung, schliesst der Server den Strom ohne eigenes Ereignis (die nächste Anfrage ergibt 401).
SSE_EVENTS = ("changes", "terminal", "inbox", "suggestion", "project", "reset", "presentation", "progress")


@dataclass(frozen=True)
class SessionInfo:
    """Eine angemeldete Sitzung, wie sie Routen sehen. Enthält nie das Token oder seinen Hash."""

    session_id: str  # zufällige, kurze Kennung für Anzeige und Widerruf (nicht das Token)
    origin: SessionOrigin  # «lokal» (Browser in der Kali) oder «über sshd» (Mac über den Tunnel)
    created_ns: int  # Wanduhr
    expires_ns: int  # höchstens 12 h nach der Anmeldung (E92)
    peer_pid: int  # gebundener Prozess (R2): lokal der Browser-Prozess, über sshd der sshd-Prozess
    #                der SSH-Verbindung, die den Code geholt hat (Vertrag 3.4)
    peer_comm: str = ""  # Name dieses Prozesses (nur Anzeige, z. B. «sshd-session», «firefox»)


class EventPublisher(Protocol):
    """Bus für SSE. ``publish`` ist nicht blockierend und nur im Loop-Thread aufzurufen.

    ``event`` ist einer aus :data:`SSE_EVENTS`; ``data`` ist ein kleines JSON-Objekt ohne
    Zieldaten. Der Bus bündelt in 250-ms-Fenstern (Architektur 7.3).
    """

    def publish(self, event: str, data: Mapping[str, Any]) -> None: ...


@dataclass
class WebContext:
    """Was eine Route braucht. Der Server legt genau einen pro laufendem Web-Server an."""

    daemon: Daemon
    bus: EventPublisher
    host: str = "127.0.0.1"
    port: int = 7330
    extra: dict[str, Any] = field(default_factory=dict)  # für spätere Erweiterungen, nie Secrets

    @property
    def origin(self) -> str:
        """Erwarteter ``Origin`` bzw. Host-Wert, z. B. ``http://127.0.0.1:7330``."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"


def session_of(request: Any) -> SessionInfo:
    """Sitzung der Anfrage (vom Server gesetzt). Fehlt sie, ist das ein Programmfehler im Server:
    die Route darf dann nichts ausliefern."""
    session = getattr(getattr(request, "state", None), "session", None)
    if not isinstance(session, SessionInfo):
        raise RuntimeError("Anfrage ohne geprüfte Sitzung")
    return session
