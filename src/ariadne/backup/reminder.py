"""Hinweis nach ``ariadne stop`` (E91, Vertrag v0.1-Server, Abschnitt 3.5, Konzept 6.6).

``after_stop_lines`` liest die Registry (``Paths.registry_file``) und meldet «Sicherung: ariadne
backup», bzw. eine deutlichere Erinnerung, wenn es keine Sicherung des Projekts gibt oder die
letzte älter ist als die gerade beendete Session (``stop_result["since_utc"]``). Fehlen die
Empfänger, sagt der Hinweis das gleich mit. Wirft nie, braucht keinen Daemon.
"""

from __future__ import annotations

from typing import Any

from ariadne.paths import Paths

__all__ = ["after_stop_lines", "BASIC", "HOW"]

BASIC = "Sicherung: ariadne backup"
HOW = "Sichern: ariadne backup --to-file PFAD.age, vom Mac aus ariadne-mac stop"


def _recipients_missing(paths: Paths) -> bool:
    from ariadne.backup.config import load_recipients
    from ariadne.backup.model import BackupError

    try:
        load_recipients(paths)
    except BackupError as exc:
        return exc.code == "no_recipients"
    return False


def _lines(paths: Paths, stop_result: dict[str, Any] | None) -> list[str]:
    from ariadne.backup.registry import latest, parse_utc

    res = stop_result if isinstance(stop_result, dict) else {}
    slug = res.get("slug") if isinstance(res.get("slug"), str) else None
    since = parse_utc(res.get("since_utc"))
    last = latest(paths, slug)
    lines: list[str]
    if last is None:
        lines = ["Erinnerung: Noch keine Sicherung" + (f" von {slug}" if slug else "") + " (E91).", HOW]
    elif since is not None and (ts := parse_utc(last["ts_utc"])) is not None and ts < since:
        lines = [f"Erinnerung: Die letzte Sicherung ({last['ts_utc']}) ist älter als diese Session.", HOW]
    else:
        lines = [BASIC]
    if _recipients_missing(paths):
        lines.append("Noch keine Empfänger: öffentliche Schlüssel (age1…) in "
                     "~/.config/ariadne/backup-recipients.txt eintragen (Rechte 600).")
    return lines


def after_stop_lines(paths: Paths, stop_result: dict[str, Any] | None = None) -> list[str]:
    """Zeilen, die ``ariadne stop`` nach dem Beenden ausgibt (ohne Zieldaten)."""
    try:
        return _lines(paths, stop_result)
    except Exception:  # noqa: BLE001 (der Hinweis darf stop nie scheitern lassen)
        return [BASIC]
