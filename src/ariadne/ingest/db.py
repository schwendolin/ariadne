"""Schema-Verwaltung für ``derived.db`` (Architektur 5.1).

:func:`apply_schema` legt die Tabellen der Einheiten-Seite an und danach, falls
importierbar, ``SCHEMA_SQL`` und ``VIEWS_SQL`` aus ``ariadne.ingest.schema_claims``.
Funktioniert mit ``sqlite3``- und ``sqlcipher3``-Verbindungen.

:func:`schema_stale` erkennt eine ``derived.db`` mit älterem Schema; die
Auswertung baut sie dann neu (``CREATE ... IF NOT EXISTS`` ergänzt keine Spalten).
"""

from __future__ import annotations

import importlib
import json
from typing import Any

from ariadne import ontology
from ariadne.ingest.normalizer import NORMALIZER_VERSION
from ariadne.ingest.schema_units import SCHEMA_VERSION, UNITS_SQL

__all__ = ["apply_schema", "get_meta", "set_meta", "get_watermark", "set_watermark", "versions",
           "schema_stale"]


def _claims_version() -> int | None:
    try:
        mod = importlib.import_module("ariadne.ingest.schema_claims")
    except ImportError:
        return None
    v = getattr(mod, "CLAIMS_VERSION", None)
    return v if isinstance(v, int) else None


def schema_stale(conn: Any) -> bool:
    """Hat ``conn`` Tabellen eines älteren Schemas? Eine frische Datei ist nicht veraltet."""
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "meta" not in names:
        return bool(names & {"unit", "claim", "obs_unit"})
    if get_meta(conn, "schema_units_version") != str(SCHEMA_VERSION):
        return True
    cv = _claims_version()
    return cv is not None and "claim" in names and get_meta(conn, "schema_claims_version") != str(cv)


def _claims_sql() -> list[str]:
    try:
        mod = importlib.import_module("ariadne.ingest.schema_claims")
    except ImportError:
        return []
    return [s for s in (getattr(mod, "SCHEMA_SQL", None), getattr(mod, "VIEWS_SQL", None))
            if isinstance(s, str) and s.strip()]


def apply_schema(conn: Any) -> None:
    """Legt alle Tabellen an (idempotent) und schreibt die Versionen in ``meta``."""
    conn.executescript(UNITS_SQL)
    for script in _claims_sql():
        conn.executescript(script)
    set_meta(conn, "schema_units_version", str(SCHEMA_VERSION))
    set_meta(conn, "normalizer_version", str(NORMALIZER_VERSION))
    set_meta(conn, "ontology_version", str(ontology.VERSION))
    cv = _claims_version()
    if cv is not None:
        set_meta(conn, "schema_claims_version", str(cv))
    if get_meta(conn, "generation") is None:
        set_meta(conn, "generation", "0")
    conn.commit()


def get_meta(conn: Any, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else str(row[0])


def set_meta(conn: Any, key: str, value: str) -> None:
    conn.execute("INSERT INTO meta(key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))


def get_watermark(conn: Any, name: str) -> int:
    row = conn.execute("SELECT seq FROM watermark WHERE name = ?", (name,)).fetchone()
    return 0 if row is None else int(row[0])


def set_watermark(conn: Any, name: str, seq: int) -> None:
    conn.execute("INSERT INTO watermark(name, seq) VALUES (?, ?) "
                 "ON CONFLICT(name) DO UPDATE SET seq = excluded.seq", (name, seq))


def versions(conn: Any) -> dict[str, Any]:
    """Versionen aus ``meta`` (Normalizer, Ontologie, Parser, Generation)."""
    out: dict[str, Any] = {}
    for key in ("schema_units_version", "schema_claims_version", "normalizer_version", "ontology_version",
                "generation"):
        v = get_meta(conn, key)
        out[key] = int(v) if v is not None and v.lstrip("-").isdigit() else v
    parsers = get_meta(conn, "parsers")
    out["parsers"] = json.loads(parsers) if parsers else {}
    return out
