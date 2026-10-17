"""Hinweis nach ``ariadne stop`` (E91, Vertrag v0.1-Server, Abschnitt 3.5).

Besitzer: Teil «backup». **Stub aus Phase 1**: liefert immer den Grundhinweis.

Endzustand: ``after_stop_lines`` liest die Registry (``Paths.registry_file``) und meldet
«Sicherung: ariadne backup», bzw. eine deutlichere Erinnerung, wenn die letzte Sicherung
älter als die gerade beendete Session ist. Darf nie werfen und nie den Daemon brauchen.
"""

from __future__ import annotations

from typing import Any

from ariadne.paths import Paths

__all__ = ["after_stop_lines"]


def after_stop_lines(paths: Paths, stop_result: dict[str, Any] | None = None) -> list[str]:
    """Zeilen, die ``ariadne stop`` nach dem Beenden ausgibt (ohne Zieldaten)."""
    return ["Sicherung: ariadne backup"]
