"""Öffentliche Schnittstelle der Regel-Engine (Vertrag v0.1-Oberfläche, Abschnitt B2).

Die Web-API (``web/api/next.py``, ``web/api/suggestions.py``, ``web/api/decisions.py``,
``web/api/events.py``) nutzt nur diese Funktionen. Signaturen und die Form der Rückgaben sind fest.

Form einer Suggestion: das JSON-Objekt ``Suggestion`` aus ``docs/web-api.md`` 18.6 als ``dict``.
Alle Strings aus Zieldaten sind sichtbar gemacht (wie ``ariadne.termsafe.visible``, ohne Kürzung) und
die zugehörigen ``ctrl``-Flags gesetzt; bekannte Secret-Werte stehen als ``••••••••``. Die Web-API
wendet trotzdem ihre zweite Schicht und den Redaktor für eigene Secrets an.

Alle Funktionen laufen im Thread der Auswertung (``Api.query``), lesen nur und begrenzen ihre
Abfragen selbst (``LIMIT``). Ariadne führt nie etwas aus, was hier vorgeschlagen wird (E10).

Die Engine hält einen Schnappschuss der Projektion (Fakten und Kandidaten), solange sich ``derived.db``
nicht ändert. :func:`clear_cache` (additiv zum Vertrag) verwirft ihn; der Daemon ruft es beim Schliessen
oder Sperren eines Projekts, damit keine Zieldaten im Speicher bleiben.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any, Literal

from ariadne.rules.engine import clear_cache, evaluate, to_json

__all__ = [
    "STUB",
    "State",
    "RuleRefError",
    "suggestions",
    "open_count",
    "check_decision",
    "clear_cache",
]

STUB = False

State = Literal["open", "done", "dismissed", "all"]
_STATES = ("open", "done", "dismissed", "all")
_KEY = re.compile(r"sg:[0-9a-f]{24}")


class RuleRefError(Exception):
    """Ein Entscheid ``d.suggestion.*`` passt nicht zum Stand.

    ``code``: ``"conflict"`` (Denkanstoss unbekannt oder schon so bzw. anders entschieden, 409) oder
    ``"basis_required"`` (422, ``d.suggestion.done`` ohne ``basis``). Die Web-API übersetzt den Code;
    ``str(exc)`` geht nie an den Browser.
    """

    def __init__(self, code: Literal["conflict", "basis_required"]) -> None:
        super().__init__(code)
        self.code = code


def suggestions(
    conn: sqlite3.Connection,
    *,
    profile: str,
    state: State = "open",
    limit: int = 50,
) -> tuple[list[dict[str, Any]], bool]:
    """Denkanstösse über der Projektion in ``conn`` (``derived.db``, nur lesend).

    Liefert ``(liste, truncated)``: höchstens ``limit`` Einträge mit dem Zustand ``state``, sortiert
    nach Priorität der Regel, dann Host, dann Port. Der Zustand folgt aus den aktiven
    ``d.suggestion.*`` in der Tabelle ``decision`` (ohne widerrufene, ``d.revoke``).
    """
    if state not in _STATES:
        raise ValueError("state")
    f, built = evaluate(conn, profile=profile)
    chosen = [b for b in built if state == "all" or b.state == state]
    n = max(0, int(limit))
    return to_json(conn, f, chosen[:n], profile=profile), len(chosen) > n


def open_count(conn: sqlite3.Connection, *, profile: str) -> int:
    """Zahl offener Denkanstösse (für das SSE-Ereignis ``suggestion``)."""
    _f, built = evaluate(conn, profile=profile)
    return sum(1 for b in built if b.state == "open")


def check_decision(conn: sqlite3.Connection, kind: str, header: dict[str, Any], *, profile: str) -> None:
    """Prüft einen Entscheid ``d.suggestion.done`` oder ``d.suggestion.dismiss`` gegen den Stand.

    * ``d.suggestion.done`` ohne ``basis``: ``basis_required``.
    * Denkanstoss unbekannt (auch über Nebenschlüssel nach einem Merge): ``conflict``.
    * ``done``: ``basis`` passt nicht zum aktuellen Anlass, oder der Denkanstoss ist schon erledigt bzw.
      verworfen: ``conflict`` (die Oberfläche zeigt dann «In einem anderen Tab entschieden»).
    * ``dismiss``: schon verworfen: ``conflict``; ein erledigter darf verworfen werden.

    Andere Arten prüft diese Funktion nicht (kein Fehler).
    """
    if kind not in ("d.suggestion.done", "d.suggestion.dismiss"):
        return
    if kind == "d.suggestion.done" and not header.get("basis"):
        raise RuleRefError("basis_required")
    key = header.get("suggestion_key")
    if not isinstance(key, str) or not _KEY.fullmatch(key):
        raise RuleRefError("conflict")
    _f, built = evaluate(conn, profile=profile)
    match = next((b for b in built if b.key == key), None) or next(
        (b for b in built if key in b.aliases), None
    )
    if match is None:
        raise RuleRefError("conflict")
    if kind == "d.suggestion.dismiss":
        if match.state == "dismissed":
            raise RuleRefError("conflict")
        return
    if header.get("basis") != match.basis or match.state != "open":
        raise RuleRefError("conflict")
