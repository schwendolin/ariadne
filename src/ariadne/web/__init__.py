"""Web-Oberfläche: HTTP-Server im Daemon, nur Loopback (Architektur 7, E89, Vertrag v0.1-Server).

Aufteilung (genau ein Besitzer pro Datei, Vertrag v0.1-Server Abschnitt 2):

* Teil «server»: ``config.py``, ``peer.py``, ``sessions.py``, ``security.py``, ``sse.py``,
  ``static.py``, ``app.py``, ``server.py``, ``integration.py``, ``ctx.py``. Kern, Sicherheit
  (R1 bis R3, R6 bis R9, R12), Anmeldung mit Einmal-Code, Sitzungen, SSE-Grundlage, Statik,
  Einbindung in den Daemon.
* Teil «api»: ``api/`` (Routen und Lesemodelle der API v2, ``docs/web-api.md``), Entscheide,
  Ereignisquellen für SSE, Anzeige der Eingaben nach E104.

Gemeinsame Schnittstelle: :mod:`ariadne.web.ctx` (``WebContext``, ``SessionInfo``,
``EventPublisher``) und :func:`ariadne.web.api.register`.

``static/`` ist der Build der Svelte-Oberfläche (``webui/``); er bleibt in diesem Bau, wie er ist.
"""
