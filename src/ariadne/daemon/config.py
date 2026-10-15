"""Einstellungen der Aufnahme aus ``~/.config/ariadne/config.toml`` (Tabelle ``[recording]``).

Vertrag v0.1-Bedienung 4.1. Der Daemon liest die Datei beim Start. Fehlende oder
ungültige Werte ergeben den Standard; eine Warnung im Log nennt nur den Schlüssel,
nie einen Wert.

| Schlüssel              | Standard | Bereich        |
|------------------------|----------|----------------|
| ``idle_end_hours``     | 12       | 0 (nie) bis 168 |
| ``pause_minutes``      | 10       | 1 bis 240      |
| ``preroll_minutes``    | 15       | 0 (aus) bis 60 |
| ``preroll_terminal_mib`` | 8      | 1 bis 64       |
| ``preroll_total_mib``  | 64       | 8 bis 512      |
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, fields
from pathlib import Path

__all__ = ["RecordingConfig", "load_recording", "RANGES"]

log = logging.getLogger("ariadne.daemon")

RANGES: dict[str, tuple[int, int]] = {
    "idle_end_hours": (0, 168),
    "pause_minutes": (1, 240),
    "preroll_minutes": (0, 60),
    "preroll_terminal_mib": (1, 64),
    "preroll_total_mib": (8, 512),
}
MAX_CONFIG = 1 << 20


@dataclass(frozen=True)
class RecordingConfig:
    idle_end_hours: int = 12
    pause_minutes: int = 10
    preroll_minutes: int = 15
    preroll_terminal_mib: int = 8
    preroll_total_mib: int = 64

    @property
    def idle_end_s(self) -> int | None:
        """Leerlauf bis zum Projektende in Sekunden, ``None`` = nie."""
        return self.idle_end_hours * 3600 if self.idle_end_hours > 0 else None


def load_recording(path: Path) -> RecordingConfig:
    """Liest ``[recording]``; jeder ungültige Wert fällt einzeln auf den Standard zurück."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CONFIG:
            return RecordingConfig()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return RecordingConfig()
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        log.warning("config.toml nicht lesbar, Standardwerte für [recording]")
        return RecordingConfig()
    table = data.get("recording")
    if table is None:
        return RecordingConfig()
    if not isinstance(table, dict):
        log.warning("config.toml: [recording] ist keine Tabelle, Standardwerte")
        return RecordingConfig()
    values: dict[str, int] = {}
    for f in fields(RecordingConfig):
        if f.name not in table:
            continue
        v = table[f.name]
        lo, hi = RANGES[f.name]
        if type(v) is int and lo <= v <= hi:
            values[f.name] = v
        else:
            log.warning("config.toml: recording.%s ungültig, Standardwert", f.name)
    return RecordingConfig(**values)
