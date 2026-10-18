"""Scope ändern (E129): hinzufügen, entfernen, ausschliessen und rückgängig machen.

Reine Funktionen ohne Daemon und ohne Journal. Jede Änderung wird zu einem neuen, vollständigen
Snapshot der Projekteinstellungen (``d.scope.update`` mit ``change``). Geprüft wird wie beim Anlegen
(:func:`ariadne.project.guardrails.parse_target`: IP, CIDR, Name oder ``*.domain``, nie DNS). Ob ein
Ziel danach im Scope liegt, sagt allein :class:`~ariadne.scope.matcher.ScopeMatcher`.

* ``add``: Einträge kommen in ``include``; steht derselbe Eintrag in ``exclude``, fällt er dort weg
  (sonst bliebe er ausgeschlossen, Ausschluss schlägt Einschluss).
* ``remove``: Einträge fallen aus ``include`` und ``exclude``. Mindestens ein Einschluss bleibt.
* ``exclude``: Einträge kommen in ``exclude``.
* Rückgängig: die gespeicherte Änderung umgekehrt auf den aktuellen Stand.

Neue Einschlüsse ausserhalb der Lab-Allowlist nennt :attr:`Plan.outside`; dafür braucht ein
lab-Projekt die Bestätigung «kein Kundenauftrag» wie beim Anlegen.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import tomlkit

from ariadne.project.guardrails import InvalidTarget, LabAllowlist, parse_target
from ariadne.project.settings import SettingsError, parse_settings
from ariadne.scope.matcher import ScopeMatcher

__all__ = [
    "OPS",
    "MAX_ENTRIES",
    "MAX_LIST",
    "ScopeChangeError",
    "Plan",
    "normalize_entries",
    "scope_lists",
    "plan_change",
    "plan_revert",
    "render_toml",
]

OPS = ("add", "remove", "exclude")
MAX_ENTRIES = 20
MAX_LIST = 500


class ScopeChangeError(ValueError):
    """Änderung nicht möglich. ``code``: ``invalid``, ``noop``, ``not_listed``, ``last_include``,
    ``too_many``. Die Meldung kann die Eingabe des Nutzers enthalten (nur fürs Terminal)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Plan:
    op: str
    entries: tuple[str, ...]
    include: list[str]
    exclude: list[str]
    include_added: tuple[str, ...] = ()
    include_removed: tuple[str, ...] = ()
    exclude_added: tuple[str, ...] = ()
    exclude_removed: tuple[str, ...] = ()
    outside: tuple[str, ...] = ()  # neue Einschlüsse ausserhalb der Lab-Allowlist
    revert_of: str | None = None
    verdicts: dict[str, str] = field(default_factory=dict)  # Eintrag -> Urteil nach der Änderung

    def change(self, reason: str | None = None) -> dict[str, Any]:
        """``change`` für ``d.scope.update`` (``events.DScopeChange``)."""
        out: dict[str, Any] = {
            "op": self.op,
            "entries": list(self.entries),
            "include_added": list(self.include_added),
            "include_removed": list(self.include_removed),
            "exclude_added": list(self.exclude_added),
            "exclude_removed": list(self.exclude_removed),
        }
        if self.revert_of is not None:
            out["revert_of"] = self.revert_of
        if reason:
            out["reason"] = reason
        return out

    def view(self) -> dict[str, Any]:
        """Für Antworten und die Rückfrage im Terminal."""
        return {
            "op": self.op,
            "entries": list(self.entries),
            "include": list(self.include),
            "exclude": list(self.exclude),
            "include_added": list(self.include_added),
            "include_removed": list(self.include_removed),
            "exclude_added": list(self.exclude_added),
            "exclude_removed": list(self.exclude_removed),
            "outside": list(self.outside),
            "revert_of": self.revert_of,
            "verdicts": dict(self.verdicts),
        }


def normalize_entries(raw: Iterable[Any]) -> list[str]:
    """Einträge prüfen wie beim Anlegen und normalisieren; doppelte fallen weg."""
    out: list[str] = []
    items = list(raw) if not isinstance(raw, str) else [raw]
    if not items:
        raise ScopeChangeError("invalid", "mindestens ein Ziel nötig")
    if len(items) > MAX_ENTRIES:
        raise ScopeChangeError("too_many", f"höchstens {MAX_ENTRIES} Ziele pro Änderung")
    for r in items:
        if not isinstance(r, str):
            raise ScopeChangeError("invalid", "Ziel ist kein Text")
        if any(unicodedata.category(ch)[0] == "C" or unicodedata.category(ch) in ("Zl", "Zp") for ch in r):
            # strenger als beim Anlegen: kein stilles Abschneiden von Zeilenumbrüchen oder Steuerzeichen
            raise ScopeChangeError("invalid", "Ziel mit Steuerzeichen")
        try:
            t = parse_target(r)
        except InvalidTarget as exc:
            raise ScopeChangeError("invalid", f"ungültiges Ziel: {exc}") from None
        if t.value not in out:
            out.append(t.value)
    return out


def scope_lists(settings: Mapping[str, Any]) -> tuple[list[str], list[str], list[Any]]:
    scope = settings.get("scope") if isinstance(settings, Mapping) else None
    if not isinstance(scope, Mapping):
        return [], [], []

    def strs(v: Any) -> list[str]:
        return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []

    windows = scope.get("windows")
    wins = list(windows) if isinstance(windows, list) else []
    return strs(scope.get("include")), strs(scope.get("exclude")), wins


def _outside(entries: Iterable[str], allowlist: LabAllowlist) -> tuple[str, ...]:
    out = []
    for e in entries:
        try:
            if not allowlist.allows(parse_target(e)):
                out.append(e)
        except InvalidTarget:
            out.append(e)
    return tuple(out)


def _verdicts(entries: Sequence[str], include: list[str], exclude: list[str],
              windows: list[Any]) -> dict[str, str]:
    m = ScopeMatcher(include, exclude, windows)
    out: dict[str, str] = {}
    for e in entries:
        probe = "x" + e[1:] if e.startswith("*.") else e  # Wildcard: ein Name darunter
        out[e] = m.check(probe).verdict
    return out


def _finish(op: str, entries: Sequence[str], inc: list[str], exc: list[str], windows: list[Any],
            new_inc: list[str], new_exc: list[str], allowlist: LabAllowlist,
            revert_of: str | None = None) -> Plan:
    inc_added = tuple(x for x in new_inc if x not in inc)
    inc_removed = tuple(x for x in inc if x not in new_inc)
    exc_added = tuple(x for x in new_exc if x not in exc)
    exc_removed = tuple(x for x in exc if x not in new_exc)
    if not (inc_added or inc_removed or exc_added or exc_removed):
        raise ScopeChangeError("noop", "keine Änderung: steht schon so im Scope")
    if not new_inc:
        raise ScopeChangeError("last_include", "mindestens ein Ziel muss im Scope bleiben")
    if len(new_inc) > MAX_LIST or len(new_exc) > MAX_LIST:
        raise ScopeChangeError("too_many", f"höchstens {MAX_LIST} Einträge pro Liste")
    return Plan(op, tuple(entries), new_inc, new_exc, inc_added, inc_removed, exc_added, exc_removed,
                _outside(inc_added, allowlist), revert_of,
                _verdicts(list(entries), new_inc, new_exc, windows))


def plan_change(settings: Mapping[str, Any], op: str, raw: Iterable[Any], allowlist: LabAllowlist) -> Plan:
    if op not in OPS:
        raise ScopeChangeError("invalid", "Änderung muss add, remove oder exclude sein")
    entries = normalize_entries(raw)
    inc, exc, windows = scope_lists(settings)
    if op == "add":
        new_inc = inc + [e for e in entries if e not in inc]
        new_exc = [x for x in exc if x not in entries]
    elif op == "remove":
        missing = [e for e in entries if e not in inc and e not in exc]
        if missing:
            raise ScopeChangeError("not_listed", "steht nicht im Scope: " + ", ".join(missing))
        new_inc = [x for x in inc if x not in entries]
        new_exc = [x for x in exc if x not in entries]
    else:
        new_inc = list(inc)
        new_exc = exc + [e for e in entries if e not in exc]
    return _finish(op, entries, inc, exc, windows, new_inc, new_exc, allowlist)


def plan_revert(settings: Mapping[str, Any], change: Mapping[str, Any], revert_of: str,
                allowlist: LabAllowlist) -> Plan:
    """Die Änderung ``change`` (aus ``d.scope.update``) umgekehrt auf den aktuellen Stand."""

    def lst(key: str) -> list[str]:
        v = change.get(key)
        return [x for x in v if isinstance(x, str)] if isinstance(v, list | tuple) else []

    inc, exc, windows = scope_lists(settings)
    new_inc = [x for x in inc if x not in lst("include_added")]
    new_inc += [x for x in lst("include_removed") if x not in new_inc]
    new_exc = [x for x in exc if x not in lst("exclude_added")]
    new_exc += [x for x in lst("exclude_removed") if x not in new_exc]
    entries = lst("entries")[:MAX_ENTRIES]
    return _finish("revert", entries, inc, exc, windows, new_inc, new_exc, allowlist, revert_of)


def render_toml(prev_toml: str, include: list[str], exclude: list[str]) -> str:
    """Neuer Snapshot: der bisherige Text mit neuen Listen ``[scope] include`` und ``exclude``; alles
    andere bleibt. Der Text wird danach wie jeder Snapshot geprüft."""
    doc = tomlkit.parse(prev_toml)
    scope = doc.get("scope")
    if scope is None:
        scope = tomlkit.table()
        doc.add("scope", scope)
    scope["include"] = list(include)
    scope["exclude"] = list(exclude)
    text = tomlkit.dumps(doc)
    try:
        parse_settings(text)
    except SettingsError as exc:  # pragma: no cover - der alte Text war gültig
        raise ScopeChangeError("invalid", "Einstellungen ungültig") from exc
    return text
