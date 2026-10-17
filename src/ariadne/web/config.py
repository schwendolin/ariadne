"""Einstellungen des Web-Servers aus ``~/.config/ariadne/config.toml`` (Tabelle ``[ui]``).

Vertrag v0.1-Server 3.7, Konzept Fernzugriff R1, E89:

| Schlüssel       | Standard      | Regel                                                        |
|-----------------|---------------|--------------------------------------------------------------|
| ``enabled``     | ``true``      | ``false``: kein Web-Server                                   |
| ``bind``        | ``127.0.0.1`` | nur ``127.0.0.1`` oder ``::1``; alles andere ist ein Fehler  |
| ``port``        | ``7330``      | 1024 bis 65535; ``0`` nur für Tests (freier Port)            |
| ``session_hours`` | ``12``      | 1 bis 12 (E92)                                               |

Fail-closed: Eine Bindung ausserhalb von Loopback und ein ungültiger Port lassen den Web-Server
aus (die Aufnahme läuft weiter); einen Schalter, der das aufhebt, gibt es nicht. Ungültige
übrige Werte fallen auf den Standard zurück; Warnungen nennen nur den Schlüssel, nie den Wert.
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path

from ariadne.paths import Paths

__all__ = ["UiConfig", "UiConfigError", "load_ui", "parse_ui", "ALLOWED_BINDS", "DEFAULT_PORT"]

log = logging.getLogger("ariadne.web")

ALLOWED_BINDS = ("127.0.0.1", "::1")
DEFAULT_PORT = 7330
MAX_CONFIG = 1 << 20


class UiConfigError(ValueError):
    """Die Konfiguration verlangt etwas, das der Web-Server nicht darf (R1). Meldung ohne Wert."""


@dataclass(frozen=True)
class UiConfig:
    enabled: bool = True
    bind: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    session_hours: int = 12


def parse_ui(table: object) -> UiConfig:
    """Prüft eine ``[ui]``-Tabelle. Wirft :class:`UiConfigError` bei Bindung oder Port ausserhalb
    der Regeln; andere ungültige Werte ergeben den Standard."""
    if table is None:
        return UiConfig()
    if not isinstance(table, dict):
        log.warning("config.toml: [ui] ist keine Tabelle, Standardwerte")
        return UiConfig()
    enabled = table.get("enabled", True)
    if type(enabled) is not bool:
        log.warning("config.toml: ui.enabled ungültig, Standardwert")
        enabled = True
    bind = table.get("bind", "127.0.0.1")
    # Exakter Vergleich: kein «localhost», kein 127.0.0.2, kein Name, keine Schreibvarianten.
    if not isinstance(bind, str) or bind not in ALLOWED_BINDS:
        raise UiConfigError("ui.bind erlaubt nur 127.0.0.1 oder ::1 (nur Loopback)")
    port = table.get("port", DEFAULT_PORT)
    if type(port) is not int or not (port == 0 or 1024 <= port <= 65535):
        raise UiConfigError("ui.port muss zwischen 1024 und 65535 liegen")
    hours = table.get("session_hours", 12)
    if type(hours) is not int or not 1 <= hours <= 12:
        log.warning("config.toml: ui.session_hours ungültig, Standardwert")
        hours = 12
    return UiConfig(enabled=enabled, bind=bind, port=port, session_hours=hours)


def _read(path: Path) -> dict[str, object] | None:
    try:
        if path.is_symlink():
            log.warning("config.toml ist ein Symlink, Standardwerte für [ui]")
            return None
        if not path.is_file():
            return None
        if path.stat().st_size > MAX_CONFIG:
            log.warning("config.toml zu gross, Standardwerte für [ui]")
            return None
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        log.warning("config.toml nicht lesbar, Standardwerte für [ui]")
        return None


def load_ui(paths: Paths) -> UiConfig:
    """Liest ``[ui]`` aus ``config.toml``. Fehlt die Datei oder ist sie unlesbar: Standard
    (nur Loopback). Wirft :class:`UiConfigError` bei einer verbotenen Bindung (R1)."""
    data = _read(paths.config_file)
    if data is None:
        return UiConfig()
    return parse_ui(data.get("ui"))
