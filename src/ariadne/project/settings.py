"""Projekteinstellungen als TOML, Schema ``ariadne.project/1`` (Architektur 8.2).

Die Einstellungen liegen als vollständiger Snapshot im Journal
(``d.scope.update``). Die Ansicht ist eine Projektion davon.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import tomlkit

__all__ = ["SCHEMA", "DEFAULT_MODEL", "SettingsError", "default_settings", "parse_settings"]

SCHEMA = "ariadne.project/1"
# Kein Modell im Code: Das Modell setzt der Nutzer mit `ariadne ai setup` (ai.toml, Teil «ki»).
DEFAULT_MODEL = ""


class SettingsError(ValueError):
    pass


def default_settings(*, name: str, profile: str, include: Sequence[str], open_scope: bool = False) -> str:
    doc = tomlkit.document()
    doc.add("schema", SCHEMA)
    project = tomlkit.table()
    project.add("name", name)
    project.add("profile", profile)
    doc.add("project", project)
    scope = tomlkit.table()
    scope.add("include", list(include))
    scope.add("exclude", [])
    scope.add("windows", [])
    if open_scope:  # E131: offener Scope, alles gilt als im Scope ausser Ausschlüssen
        scope.add("open", True)
    doc.add("scope", scope)
    secrets = tomlkit.table()
    secrets.add("use_global", True)
    doc.add("secrets", secrets)
    llm = tomlkit.table()
    llm.add("mode", "cloud")
    llm.add("monthly_budget_usd", 20)
    llm.add("model", DEFAULT_MODEL)
    doc.add("llm", llm)
    automode = tomlkit.table()
    automode.add("enabled", False)
    automode.add("parsers", ["nmap.xml"])
    automode.add("auto_ctx", False)
    doc.add("automode", automode)
    return tomlkit.dumps(doc)


def parse_settings(text: str) -> dict[str, Any]:
    """Parst und prüft die Grundstruktur. Unbekannte Schlüssel bleiben erhalten."""
    try:
        data = tomlkit.parse(text).unwrap()
    except Exception as exc:  # tomlkit wirft verschiedene Fehlerklassen
        raise SettingsError("Einstellungen sind kein gültiges TOML") from exc
    if data.get("schema") != SCHEMA:
        raise SettingsError(f"unbekanntes Schema, erwartet {SCHEMA}")
    project = data.get("project")
    if not isinstance(project, dict) or project.get("profile") not in ("lab", "customer"):
        raise SettingsError("[project] profile fehlt oder ist ungültig")
    scope = data.setdefault("scope", {})
    if not isinstance(scope, dict):
        raise SettingsError("[scope] muss eine Tabelle sein")
    for key in ("include", "exclude", "windows"):
        if not isinstance(scope.setdefault(key, []), list):
            raise SettingsError(f"[scope] {key} muss eine Liste sein")
    if not isinstance(scope.setdefault("open", False), bool):  # E131: nur true oder false
        raise SettingsError("[scope] open muss true oder false sein")
    data.setdefault("secrets", {}).setdefault("use_global", True)
    llm = data.setdefault("llm", {})
    llm.setdefault("mode", "cloud")
    llm.setdefault("monthly_budget_usd", 20)
    llm.setdefault("model", DEFAULT_MODEL)
    auto = data.setdefault("automode", {})
    auto.setdefault("enabled", False)
    auto.setdefault("parsers", [])
    auto.setdefault("auto_ctx", False)
    return data
