"""Scope ändern (E129): hinzufügen, entfernen, ausschliessen und rückgängig machen.

Reine Funktionen ohne Daemon und ohne Journal. Jede Änderung wird zu einem neuen, vollständigen
Snapshot der Projekteinstellungen (``d.scope.update`` mit ``change``). Geprüft wird wie beim Anlegen
(:func:`ariadne.project.guardrails.parse_target`: IP, CIDR, Name oder ``*.domain``, nie DNS). Ob ein
Ziel danach im Scope liegt, sagt allein :class:`~ariadne.scope.matcher.ScopeMatcher`.

* ``add``: Einträge kommen in ``include``; steht derselbe Eintrag in ``exclude``, fällt er dort weg
  (sonst bliebe er ausgeschlossen, Ausschluss schlägt Einschluss).
* ``remove``: Einträge fallen aus ``include`` und ``exclude``. Mindestens ein Einschluss bleibt.
* ``exclude``: Einträge kommen in ``exclude``.
* ``open`` / ``close`` (E131): offener Scope an bzw. aus (``[scope] open``), ohne Einträge. Schliessen
  braucht mindestens einen Einschluss (``no_include``); bei offenem Scope darf der letzte Einschluss
  wegfallen. Öffnen gilt wie ein öffentliches Ziel (:attr:`Plan.opens`).
* Rückgängig: die gespeicherte Änderung umgekehrt auf den aktuellen Stand (auch ``open``/``close``,
  über ``open_before``/``open_after`` im ``change``), mit denselben Prüfungen.

Neue Einschlüsse ausserhalb der Lab-Allowlist nennt :attr:`Plan.outside`; dafür braucht ein
lab-Projekt die Bestätigung «kein Kundenauftrag» wie beim Anlegen.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import tomlkit

from ariadne.project.guardrails import InvalidTarget, LabAllowlist, parse_target
from ariadne.project.settings import SettingsError, parse_settings
from ariadne.scope.matcher import ScopeMatcher, _range_nets

__all__ = [
    "OPS",
    "MAX_ENTRIES",
    "MAX_LIST",
    "ScopeChangeError",
    "Plan",
    "normalize_entries",
    "scope_lists",
    "scope_open",
    "is_broad",
    "NO_INCLUDE",
    "plan_change",
    "plan_revert",
    "render_toml",
]

OPS = ("add", "remove", "exclude", "open", "close")
BROAD_V4 = 1 << 16  # E133: IPv4 mit mehr Adressen als ein /16 gilt als sehr breit
BROAD_V6_PREFIX = 48  # E133: IPv6 grösser als /48
MAX_ENTRIES = 20
MAX_LIST = 500


class ScopeChangeError(ValueError):
    """Änderung nicht möglich. ``code``: ``invalid``, ``noop``, ``not_listed``, ``last_include``,
    ``no_include`` (Schliessen ohne Einschluss), ``too_many``. Die Meldung kann die Eingabe des
    Nutzers enthalten (nur fürs Terminal)."""

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
    open_before: bool = False  # E131: offener Scope vor der Änderung
    open_after: bool = False  # und danach

    @property
    def opens(self) -> bool:
        """Die Änderung öffnet den Scope (gilt wie ein öffentliches Ziel)."""
        return self.open_after and not self.open_before

    @property
    def broad(self) -> bool:
        """E133: ein neuer Einschluss umfasst mehr als 65 536 IPv4-Adressen bzw. ist grösser als /48."""
        return any(is_broad(e) for e in self.include_added)

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
        if self.open_before != self.open_after:
            out["open_before"] = self.open_before
            out["open_after"] = self.open_after
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
            "open": self.open_after,
            "open_before": self.open_before,
            "opens": self.opens,
            "broad": self.broad,
        }


def is_broad(entry: str) -> bool:
    """E133: IPv4-Netz oder -Bereich mit mehr als 65 536 Adressen, IPv6-Netz grösser als /48."""
    nets: tuple[Any, ...] = ()
    if "/" in entry:
        try:
            nets = (ipaddress.ip_network(entry, strict=False),)
        except ValueError:
            return False
    elif "-" in entry and ":" not in entry:
        nets = _range_nets(entry)
    total4 = sum(n.num_addresses for n in nets if n.version == 4)
    return total4 > BROAD_V4 or any(n.version == 6 and n.prefixlen < BROAD_V6_PREFIX for n in nets)


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


def scope_open(settings: Mapping[str, Any]) -> bool:
    """E131: ``[scope] open`` (nur ein echtes ``true`` öffnet)."""
    scope = settings.get("scope") if isinstance(settings, Mapping) else None
    return isinstance(scope, Mapping) and scope.get("open") is True


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
              windows: list[Any], open_scope: bool = False) -> dict[str, str]:
    m = ScopeMatcher(include, exclude, windows, open=open_scope)
    out: dict[str, str] = {}
    for e in entries:
        probe = "x" + e[1:] if e.startswith("*.") else e  # Wildcard: ein Name darunter
        out[e] = m.check(probe).verdict
    return out


NO_INCLUDE = "Zuerst einen Eintrag hinzufügen: ariadne scope add <ziel>"


def _finish(op: str, entries: Sequence[str], inc: list[str], exc: list[str], windows: list[Any],
            new_inc: list[str], new_exc: list[str], allowlist: LabAllowlist,
            revert_of: str | None = None, *, open_before: bool = False,
            open_after: bool = False) -> Plan:
    inc_added = tuple(x for x in new_inc if x not in inc)
    inc_removed = tuple(x for x in inc if x not in new_inc)
    exc_added = tuple(x for x in new_exc if x not in exc)
    exc_removed = tuple(x for x in exc if x not in new_exc)
    if not (inc_added or inc_removed or exc_added or exc_removed) and open_before == open_after:
        if op == "open":
            raise ScopeChangeError("noop", "keine Änderung: Scope ist schon offen")
        if op == "close":
            raise ScopeChangeError("noop", "keine Änderung: Scope ist schon geschlossen")
        raise ScopeChangeError("noop", "keine Änderung: steht schon so im Scope")
    if not new_inc and not open_after:
        if open_before:  # Schliessen (auch per Rückgängig) ohne Einschluss
            raise ScopeChangeError("no_include", NO_INCLUDE)
        raise ScopeChangeError("last_include", "mindestens ein Ziel muss im Scope bleiben")
    if len(new_inc) > MAX_LIST or len(new_exc) > MAX_LIST:
        raise ScopeChangeError("too_many", f"höchstens {MAX_LIST} Einträge pro Liste")
    return Plan(op, tuple(entries), new_inc, new_exc, inc_added, inc_removed, exc_added, exc_removed,
                _outside(inc_added, allowlist), revert_of,
                _verdicts(list(entries), new_inc, new_exc, windows, open_after),
                open_before, open_after)


def plan_change(settings: Mapping[str, Any], op: str, raw: Iterable[Any] | None,
                allowlist: LabAllowlist) -> Plan:
    if op not in OPS:
        raise ScopeChangeError("invalid", "Änderung muss add, remove, exclude, open oder close sein")
    inc, exc, windows = scope_lists(settings)
    is_open = scope_open(settings)
    if op in ("open", "close"):  # E131: ohne Einträge
        if raw is not None and (isinstance(raw, str) or list(raw)):
            raise ScopeChangeError("invalid", "open und close ohne Ziele")
        return _finish(op, [], inc, exc, windows, list(inc), list(exc), allowlist,
                       open_before=is_open, open_after=op == "open")
    entries = normalize_entries(raw if raw is not None else [])
    if op == "add":
        broad = [e for e in entries if e.startswith("*.") and "." not in e[2:]]
        if broad:
            # *.com, *.lab, *.internal: ganze Endungen nie per Wildcard (wie E130, wildcard_of);
            # entfernen und ausschliessen bleiben möglich (alte Projekte, Einschränkung)
            raise ScopeChangeError(
                "invalid",
                "Wildcard nur unter einer Domain mit mindestens zwei Labels (z. B. *.vantis.internal), "
                "nie für eine ganze Endung: " + ", ".join(broad))
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
    return _finish(op, entries, inc, exc, windows, new_inc, new_exc, allowlist,
                   open_before=is_open, open_after=is_open)


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
    is_open = scope_open(settings)
    new_open = is_open
    before, after = change.get("open_before"), change.get("open_after")
    if isinstance(before, bool) and isinstance(after, bool) and before != after:
        new_open = before  # E131: Öffnen bzw. Schliessen umkehren
    return _finish("revert", entries, inc, exc, windows, new_inc, new_exc, allowlist, revert_of,
                   open_before=is_open, open_after=new_open)


def render_toml(prev_toml: str, include: list[str], exclude: list[str],
                open_scope: bool | None = None) -> str:
    """Neuer Snapshot: der bisherige Text mit neuen Listen ``[scope] include`` und ``exclude`` (und
    ``open``, wenn angegeben); alles andere bleibt. Der Text wird danach wie jeder Snapshot geprüft."""
    doc = tomlkit.parse(prev_toml)
    scope = doc.get("scope")
    if scope is None:
        scope = tomlkit.table()
        doc.add("scope", scope)
    scope["include"] = list(include)
    scope["exclude"] = list(exclude)
    if open_scope is not None:
        scope["open"] = bool(open_scope)
    text = tomlkit.dumps(doc)
    try:
        parse_settings(text)
    except SettingsError as exc:  # pragma: no cover - der alte Text war gültig
        raise ScopeChangeError("invalid", "Einstellungen ungültig") from exc
    return text
