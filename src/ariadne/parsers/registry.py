"""Parser-Registry (Architektur 5.6, 4.2).

* :data:`ALL_PARSERS`: eingebaute Parser, ``id -> Klasse``, in Prioritätsreihenfolge
  (strukturiert vor Tool-Text vor Heuristik).
* :func:`default_registry`: Instanzen der eingebauten Parser plus Plugins.
  Plugins kommen nur aus der Entry-Point-Gruppe ``ariadne.parsers`` und nur,
  wenn sie in der übergebenen Allowlist stehen (Standard leer). Ein Eintrag ist
  ``"name"`` oder ``"name==version"`` (Version der Distribution). Der Hash des
  Wheels wird in v0.1 noch nicht geprüft.
* :func:`companions_for`: alle Dateien, die ein Befehl laut den Parsern schreibt.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from importlib import metadata
from typing import Any

from ariadne.parsers.api import BASE_CONFIDENCE, Parser
from ariadne.parsers.listener_callback import ListenerCallbackParser
from ariadne.parsers.nmap_text import NmapTextParser
from ariadne.parsers.nmap_xml import NmapXmlParser
from ariadne.parsers.regex_net import RegexNetParser

__all__ = ["ALL_PARSERS", "ENTRY_POINT_GROUP", "PluginError", "default_registry", "load_plugins",
           "companions_for", "validate_parser"]

ENTRY_POINT_GROUP = "ariadne.parsers"
_log = logging.getLogger(__name__)

ALL_PARSERS: dict[str, type] = {
    NmapXmlParser.id: NmapXmlParser,
    NmapTextParser.id: NmapTextParser,
    ListenerCallbackParser.id: ListenerCallbackParser,
    RegexNetParser.id: RegexNetParser,
}

_PLUGIN_TRUST = {"structured", "tool_text", "heuristic", "ai", "ocr"}  # nie "user"


class PluginError(ValueError):
    """Plugin erfüllt die Parser-Schnittstelle nicht."""


def validate_parser(p: Any, *, plugin: bool = False) -> Parser:
    """Prüft die Pflichtattribute eines Parsers."""
    pid = getattr(p, "id", None)
    if not isinstance(pid, str) or not pid or len(pid) > 64 or any(c.isspace() for c in pid):
        raise PluginError("ungültige Parser-ID")
    if plugin and pid in ALL_PARSERS:
        raise PluginError(f"Plugin überschreibt eingebauten Parser {pid}")
    if not isinstance(getattr(p, "version", None), str):
        raise PluginError(f"{pid}: version fehlt")
    trust = getattr(p, "trust", None)
    allowed = _PLUGIN_TRUST if plugin else set(BASE_CONFIDENCE)
    if trust not in allowed:
        raise PluginError(f"{pid}: Vertrauensklasse nicht erlaubt")
    if not isinstance(getattr(p, "auto_eligible", None), bool):
        raise PluginError(f"{pid}: auto_eligible fehlt")
    for name in ("match", "parse", "companions"):
        if not callable(getattr(p, name, None)):
            raise PluginError(f"{pid}: {name}() fehlt")
    return p  # type: ignore[no-any-return]


def _parse_allow(allow: Iterable[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for entry in allow:
        name, sep, ver = str(entry).strip().partition("==")
        if name:
            out[name.strip()] = ver.strip() if sep else None
    return out


def load_plugins(allow: Iterable[str]) -> list[Parser]:
    """Lädt erlaubte Plugins. Nicht erlaubte Entry Points werden nie importiert."""
    wanted = _parse_allow(allow)
    if not wanted:
        return []
    found: list[Parser] = []
    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        if ep.name not in wanted:
            continue
        want_ver = wanted[ep.name]
        dist_ver = ep.dist.version if ep.dist is not None else None
        if want_ver is not None and dist_ver != want_ver:
            _log.warning("Parser-Plugin %s: Version passt nicht zur Allowlist", ep.name)
            continue
        try:
            obj = ep.load()
            inst = obj() if isinstance(obj, type) else obj
            found.append(validate_parser(inst, plugin=True))
        except Exception as exc:  # Plugin defekt: überspringen, nie den Daemon stoppen
            _log.warning("Parser-Plugin %s abgelehnt: %s", ep.name, type(exc).__name__)
    return found


def default_registry(allow: Iterable[str] | None = None) -> list[Parser]:
    """Eingebaute Parser in Prioritätsreihenfolge, danach erlaubte Plugins."""
    parsers: list[Parser] = [validate_parser(cls()) for cls in ALL_PARSERS.values()]
    if allow:
        seen = {p.id for p in parsers}
        for plugin in load_plugins(allow):
            if plugin.id not in seen:
                seen.add(plugin.id)
                parsers.append(plugin)
    return parsers


def companions_for(argv: Sequence[str], cwd: str, parsers: Sequence[Parser] | None = None) -> list[str]:
    """Dateien, die ein Befehl schreibt, über alle Parser, ohne Duplikate."""
    out: list[str] = []
    for p in parsers if parsers is not None else default_registry():
        try:
            paths = p.companions(list(argv), cwd)
        except Exception:  # ein defekter Parser darf die Verknüpfung nicht verhindern
            _log.warning("companions() von %s fehlgeschlagen", p.id)
            continue
        for path in paths:
            if isinstance(path, str) and path and path not in out:
                out.append(path)
    return out
