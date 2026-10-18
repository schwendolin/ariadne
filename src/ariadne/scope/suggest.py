"""Vorschläge zum Scope (E129, E130). Nur lesend, nie automatisch: aufgenommen wird erst nach einer
Bestätigung des Menschen (``ariadne scope add`` bzw. ``POST /p/{pid}/scope/changes``).

* :func:`proposals`: Was «in den Scope aufnehmen» zu einem Ziel der Scope-Warnung anbietet: exakter
  Name, IP, Domain mit Wildcard, Host einer URL. Zerlegt wird mit dem Parser des ScopeMatchers;
  jeder Vorschlag ist ein Eintrag, den auch ``ariadne start --target`` annähme.
* :func:`name_candidates`: E130. Ordnet nmap (Name im Scan-Bericht oder PTR) einen Namen einer IP im
  Scope zu und liegt der Name selbst ausserhalb, entsteht die Klärung «In den Scope aufnehmen?» mit
  der Wahl nur Name oder ``*.domain``. Verwerfen ist ``d.suggestion.dismiss`` mit
  :data:`KEY_PREFIX`-Schlüssel und bleibt verworfen, bis es rückgängig gemacht wird (``d.revoke``).

Keine DNS-Auflösung. Urteile allein über :class:`~ariadne.scope.matcher.ScopeMatcher`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ariadne.project.guardrails import InvalidTarget, LabAllowlist, is_public_name, parse_target
from ariadne.scope.api import ScopeChecker
from ariadne.scope.matcher import _parse_target

__all__ = [
    "KEY_PREFIX",
    "SOURCE_TYPES",
    "NameCandidate",
    "proposals",
    "wildcard_of",
    "name_candidates",
    "dismissed_keys",
    "candidate_key",
    "check_decision",
]

KEY_PREFIX = "scope-name:"
# Art des Namens aus nmap (attrs.type): Name im Scan-Bericht (Text: «report», XML: «user») oder PTR.
# Namen aus Bannern (service_info, smb) zählen nicht: E130 nennt nmap-Hostname und PTR.
SOURCE_TYPES = {"report": "nmap", "user": "nmap", "PTR": "ptr"}
SOURCE_LABEL = {"nmap": "nmap", "ptr": "PTR-Eintrag (nmap)"}
_PARSERS = ("nmap.text", "nmap.xml")
_MAX_ROWS = 20000
_MAX_ITEMS = 50


def wildcard_of(name: str) -> str | None:
    """``*.vantis.internal`` zu ``recovery.vantis.internal``; nur, wenn die Domain mindestens zwei
    Labels hat (nie ``*.lab`` oder ``*.com``)."""
    labels = name.split(".")
    if len(labels) < 3:
        return None
    return "*." + ".".join(labels[1:])


def _entry(value: str, kind: str, allowlist: LabAllowlist) -> dict[str, Any] | None:
    try:
        t = parse_target(value)
    except InvalidTarget:
        return None
    return {
        "entry": t.value,
        "kind": kind,
        "outside_lab": not allowlist.allows(t),
        "public": t.kind == "name" and is_public_name(t.value),
    }


def proposals(raw: str, allowlist: LabAllowlist | None = None) -> list[dict[str, Any]]:
    """Vorschläge für ein Ziel (roh, wie im Befehl): ``[{entry, kind, outside_lab, public}]``.

    ``kind``: ``name`` (exakter Name), ``url_host`` (Host einer URL), ``ip``, ``wildcard``."""
    allow = allowlist or LabAllowlist.default()
    t = _parse_target(raw) if isinstance(raw, str) else None
    if t is None:
        return []
    out: list[dict[str, Any]] = []
    if t.name is not None:
        first = _entry(t.name, "url_host" if t.url is not None else "name", allow)
        if first is not None:
            out.append(first)
            wc = wildcard_of(first["entry"])
            w = _entry(wc, "wildcard", allow) if wc else None
            if w is not None:
                out.append(w)
    else:
        addrs = [a for a in t.addrs if a is not None]
        if len(addrs) == 1 and len(t.addrs) == 1:  # mehrdeutige Schreibweise: kein Vorschlag
            e = _entry(str(addrs[0]), "ip", allow)
            if e is not None:
                out.append(e)
        for n in t.nets[:1]:
            e = _entry(str(n), "ip", allow)
            if e is not None:
                out.append(e)
    seen: set[str] = set()
    return [p for p in out if not (p["entry"] in seen or seen.add(p["entry"]))]  # type: ignore[func-returns-value]


@dataclass(frozen=True)
class NameCandidate:
    key: str  # suggestion_key und item_key
    name: str
    ip: str
    host_id: str
    source: str  # nmap | ptr
    claim_key: str
    unit_id: str | None
    ts: int | None
    choices: tuple[dict[str, Any], ...]
    public: bool


def candidate_key(name: str) -> str:
    return KEY_PREFIX + hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


def dismissed_keys(conn: Any) -> set[str]:
    """Verworfene E130-Schlüssel (``d.suggestion.dismiss`` ohne ``d.revoke``), aus der Projektion."""
    revoked: set[str] = set()
    dismiss: list[tuple[str, str]] = []
    for did, kind, payload in conn.execute(
        "SELECT id, kind, payload_json FROM decision WHERE kind IN ('d.suggestion.dismiss', 'd.revoke') "
        "ORDER BY seq LIMIT 100000"
    ):
        try:
            data = json.loads(payload)
        except (TypeError, ValueError):
            continue
        if not isinstance(data, Mapping):
            continue
        if kind == "d.revoke" and isinstance(data.get("decision_id"), str):
            revoked.add(data["decision_id"])
        elif kind == "d.suggestion.dismiss":
            key = data.get("suggestion_key")
            if isinstance(key, str) and key.startswith(KEY_PREFIX):
                dismiss.append((str(did), key))
    return {key for did, key in dismiss if did not in revoked}


def name_candidates(conn: Any, scope: ScopeChecker, *, allowlist: LabAllowlist | None = None,
                    with_dismissed: bool = False) -> list[NameCandidate]:
    """E130: Namen, die nmap einer IP im Scope zuordnet und die selbst ausserhalb liegen (``out``;
    ausgeschlossene Namen nie). Ein Eintrag pro Name, älteste Beobachtung zuerst."""
    allow = allowlist or LabAllowlist.default()
    dismissed = set() if with_dismissed else dismissed_keys(conn)
    best: dict[str, NameCandidate] = {}
    for ck, subject, value, attrs_json, parser_id, unit_id, ts in conn.execute(
        "SELECT c.claim_key, c.subject_identifier, c.value_text, o.attrs_json, o.parser_id, cs.unit_id, "
        "cs.ts_utc_ns FROM claim c JOIN claim_source cs ON cs.claim_key = c.claim_key "
        "JOIN observation o ON o.obs_id = cs.obs_id "
        "WHERE c.predicate = 'host.name' AND c.state != 'rejected' AND cs.distrusted = 0 "
        "AND c.subject_identifier LIKE 'ip:%' ORDER BY cs.ts_utc_ns LIMIT ?",
        (_MAX_ROWS,),
    ):
        if parser_id not in _PARSERS or not isinstance(value, str) or not isinstance(subject, str):
            continue
        try:
            attrs = json.loads(attrs_json) if attrs_json else {}
        except (TypeError, ValueError):
            continue
        source = SOURCE_TYPES.get(str(attrs.get("type"))) if isinstance(attrs, Mapping) else None
        if source is None:
            continue
        key = candidate_key(value)
        if key in dismissed or key in best:
            continue
        try:
            if scope.check(subject).verdict != "in" or scope.check("fqdn:" + value).verdict != "out":
                continue
        except Exception:  # noqa: BLE001, S112 - Scope-Prüfung darf die Ansicht nie stoppen
            continue
        first = _entry(value, "name", allow)
        if first is None:
            continue
        choices = [first]
        wc = wildcard_of(first["entry"])
        w = _entry(wc, "wildcard", allow) if wc else None
        if w is not None:
            choices.append(w)
        best[key] = NameCandidate(key, value, subject.split("/", 1)[-1], subject, source, str(ck),
                                  str(unit_id) if unit_id is not None else None,
                                  int(ts) if isinstance(ts, int) else None, tuple(choices),
                                  bool(first["public"]))
        if len(best) >= _MAX_ITEMS:
            break
    return list(best.values())


def check_decision(conn: Any, scope: ScopeChecker, kind: str, header: Mapping[str, Any]) -> bool:
    """``d.suggestion.*`` mit E130-Schlüssel prüfen. ``False``: kein E130-Schlüssel (andere prüfen
    weiter). Sonst ``True`` oder :class:`~ariadne.rules.api.RuleRefError` (``conflict``): «erledigt»
    gibt es hier nicht (aufnehmen geht über die Scope-Änderung), unbekannt oder schon verworfen."""
    from ariadne.rules.api import RuleRefError

    key = header.get("suggestion_key")
    if kind not in ("d.suggestion.done", "d.suggestion.dismiss") or not isinstance(key, str) \
            or not key.startswith(KEY_PREFIX):
        return False
    if kind == "d.suggestion.done":
        raise RuleRefError("conflict")
    if not any(c.key == key for c in name_candidates(conn, scope)):
        raise RuleRefError("conflict")
    return True
