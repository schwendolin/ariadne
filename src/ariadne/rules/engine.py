"""Regel-Engine: Kandidaten aus dem Katalog, Schlüssel, Zustand, Reihenfolge, Belege, JSON.

Ablauf pro Anfrage (im Thread der Auswertung, nur lesend):

1. :func:`ariadne.rules.facts.load` liest die Projektion.
2. Jede Regel des Katalogs liefert Kandidaten; daraus werden ``suggestion_key`` (``sg:`` + 24 Hex aus
   Regel und sortierten natürlichen Schlüsseln), Nebenschlüssel aus den anderen Kennungen des
   Subjekts (übersteht Merge) und ``basis`` (16 Hex aus den auslösenden Werten).
3. Der Zustand kommt aus den Entscheiden (:mod:`ariadne.rules.state`).
4. Sortiert wird nach Priorität der Regel, dann Host (Adressen numerisch), dann Port.
5. Erst für die ausgelieferten Einträge werden Belege (Einheit, Zeilen, Label) gelesen und Vorlagen
   gerendert (:mod:`ariadne.rules.templates`).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from ariadne.rules.catalog import CATALOG, Candidate
from ariadne.rules.commands import parse
from ariadne.rules.encoders import Scope
from ariadne.rules.facts import ClaimRef, Facts, load
from ariadne.rules.state import load_marks, state_of
from ariadne.rules.templates import TEMPLATES, render
from ariadne.rules.text import Parts, iso, mask_known, vis

__all__ = ["Built", "evaluate", "to_json", "suggestion_key", "basis_of", "clear_cache", "SUSPECT_REASONS"]

SUSPECT_REASONS = frozenset({"shell_meta", "control", "newline"})
_EVIDENCE_MAX = 5
_TEMPLATES_MAX = 4
_SHORT_OPT = re.compile(r"-{1,2}[A-Za-z]{1,3}")
_NOISE_OPT = re.compile(r"-o[A-Z]?|-v+|-d+|-n|--open|--reason")  # Ausgabe und Ausführlichkeit: nicht im Label


def _h(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "surrogatepass")).hexdigest()


def suggestion_key(rule_id: str, natural: Iterable[str]) -> str:
    return _key(rule_id, tuple(sorted(natural)))


@lru_cache(maxsize=131072)
def _key(rule_id: str, natural: tuple[str, ...]) -> str:
    return "sg:" + _h(rule_id, *natural)[:24]


def basis_of(rule_id: str, parts: Iterable[str]) -> str:
    return _h("basis", rule_id, *parts)[:16]


@dataclass(slots=True)
class Built:
    """Ein Denkanstoss mit Schlüssel und Zustand; ``basis`` und Nebenschlüssel nur bei Bedarf."""

    facts: Facts
    cand: Candidate
    key: str
    state: str = "open"
    decision_id: str | None = None
    _basis: str | None = None
    _aliases: tuple[str, ...] | None = None

    @property
    def basis(self) -> str:
        if self._basis is None:
            self._basis = basis_of(self.cand.rule.rule_id, self.cand.basis)
        return self._basis

    @property
    def aliases(self) -> tuple[str, ...]:
        if self._aliases is None:
            self._aliases = _aliases(self.facts, self.cand)
        return self._aliases

    def sort_key(self) -> tuple[Any, ...]:
        return _sort_key(self.cand, self.key)


def _sort_key(c: Candidate, key: str) -> tuple[Any, ...]:
    return (c.rule.priority, _host_sort(c.host.host_id), c.port, c.rule.rule_id, key)


@lru_cache(maxsize=65536)
def _host_sort(host_id: str) -> tuple[int, int, str]:
    addr = host_id.split("/", 1)[1] if host_id.startswith("ip:") and "/" in host_id else None
    if addr is not None:
        try:
            ip = ipaddress.ip_address(addr)
            return (ip.version, int(ip), host_id)
        except ValueError:
            pass
    return (9, 0, host_id)


def _aliases(f: Facts, c: Candidate) -> tuple[str, ...]:
    subject, extra = c.natural[0], c.natural[1:]
    idents: list[str] = []
    if subject in f.hosts:
        idents = f.hosts[subject].idents
    elif c.service is not None and subject == c.service.service_id:
        h = f.hosts.get(c.service.host_id)
        port = f"|{c.service.proto}/{c.service.port}"
        idents = [f"svc:{k}{port}" for k in (h.idents if h else []) if k.split(":", 1)[0] in ("ip", "fqdn")]
    keys = {suggestion_key(c.rule.rule_id, (k, *extra)) for k in idents if k != subject}
    return tuple(sorted(keys))


# Schnappschuss der Projektion: Fakten und sortierte Kandidaten hängen nur von ``derived.db`` ab, nicht
# von den Entscheiden über Denkanstösse (die liest jede Anfrage frisch). Neu berechnet wird, sobald sich
# die Projektion ändert: neue Generation (jede Neuauswertung, mit Zeitstempel, auch nach Reparse),
# Schreibzähler der Verbindung, neue Einheiten (auch ohne Neuauswertung) oder neue bekannte Secrets.
_SNAPSHOT: dict[str, Any] = {}
_LOCK = threading.Lock()


def _fingerprint(conn: Any) -> tuple[Any, ...]:
    gen = conn.execute(
        "SELECT generation, ts_utc_ns FROM generation ORDER BY generation DESC LIMIT 1"
    ).fetchone()
    table = (
        "unit"
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'unit'").fetchone()
        else "obs_unit"
    )
    units = conn.execute(f"SELECT MAX(rowid) FROM {table}").fetchone()[0]  # noqa: S608 - fester Name
    secrets = conn.execute("SELECT MAX(rowid), COUNT(*) FROM secret_value").fetchone()
    return (
        id(conn),
        getattr(conn, "total_changes", None),
        tuple(gen) if gen else None,
        units,
        tuple(secrets),
    )


def _snapshot(conn: Any) -> tuple[Facts, list[tuple[Candidate, str]]]:
    fp = _fingerprint(conn)
    with _LOCK:
        hit = _SNAPSHOT.get("v")
    if hit is not None and hit[0] == fp:
        return hit[1], hit[2]
    f = load(conn)
    cands: list[tuple[Candidate, str]] = []
    seen: set[str] = set()
    for rule in CATALOG:
        for c in rule.fn(f):
            key = suggestion_key(rule.rule_id, c.natural)
            if key not in seen:
                seen.add(key)
                cands.append((c, key))
    cands.sort(key=lambda ck: _sort_key(ck[0], ck[1]))
    with _LOCK:
        _SNAPSHOT["v"] = (fp, f, cands)
    return f, cands


def clear_cache() -> None:
    """Schnappschuss verwerfen (Tests, Projektwechsel)."""
    with _LOCK:
        _SNAPSHOT.clear()


def evaluate(conn: Any, *, profile: str) -> tuple[Facts, list[Built]]:
    """Alle Denkanstösse mit Zustand, sortiert (ohne Belege und Vorlagen).

    ``basis`` und Nebenschlüssel (Merge) werden nur berechnet, wenn es Entscheide gibt, die sie
    brauchen; sonst erst beim Ausliefern (Laufzeit mit vielen Hosts)."""
    f, cands = _snapshot(conn)
    marks = load_marks(conn)
    out = [Built(f, c, key) for c, key in cands]
    if marks:
        unmatched = set(marks) - {b.key for b in out}  # Entscheide, die nur über Nebenschlüssel passen
        for b in out:
            keys: tuple[str, ...] = (b.key,)
            if unmatched and set(b.aliases) & unmatched:
                keys = (b.key, *b.aliases)
            if any(k in marks for k in keys):
                b.state, b.decision_id = state_of(marks, keys, b.basis)
    return f, out


# --------------------------------------------------------------------------- Belege


def _source_rows(conn: Any, keys: list[str]) -> dict[str, list[tuple[str, Any, Any]]]:
    out: dict[str, list[tuple[str, Any, Any]]] = {}
    for i in range(0, len(keys), 500):
        part = keys[i : i + 500]
        q = ",".join("?" * len(part))
        for ck, unit_id, span_json, ts in conn.execute(
            f"SELECT claim_key, unit_id, span_json, ts_utc_ns FROM claim_source WHERE claim_key IN ({q}) "  # noqa: S608
            "AND distrusted = 0 AND unit_id IS NOT NULL LIMIT 20000",
            tuple(part),
        ):
            out.setdefault(str(ck), []).append((str(unit_id), span_json, ts))
    return out


def _lines(conn: Any, f: Facts, unit_id: str, span_json: Any) -> tuple[int, int] | None:
    try:
        span = json.loads(span_json) if isinstance(span_json, str) else None
    except ValueError:
        return None
    if not isinstance(span, dict):
        return None
    a, b = span.get("line_start"), span.get("line_end")
    if not isinstance(a, int) or not isinstance(b, int) or isinstance(a, bool) or a < 0 or b < a:
        return None
    if not f.has_unit_line:  # Projektion ohne Einheiten-Tabellen (Tests): Zählung des Parsers
        return (a, b)
    pos = dict(
        conn.execute("SELECT idx, pos FROM unit_line WHERE unit_id = ? AND idx IN (?, ?)", (unit_id, a, b))
    )
    if a not in pos or b not in pos:
        return None
    return (int(pos[a]), int(pos[b]))


def _unit_label(f: Facts, unit_id: str) -> str | None:
    u = f.units.get(unit_id)
    if u is None:
        return None
    if u.kind == "command" and u.title:
        cmds = parse(mask_known(u.title, f.known_secrets))
        if cmds:
            opts = [a for a in cmds[0].args[:8] if _SHORT_OPT.fullmatch(a) and not _NOISE_OPT.fullmatch(a)][
                :2
            ]
            return " ".join([cmds[0].tool, *opts])
        return None
    if u.path:
        return os.path.basename(mask_known(u.path, f.known_secrets))[:60] or None
    return None


def _evidence(
    conn: Any, f: Facts, refs: list[ClaimRef], sources: dict[str, list[tuple[str, Any, Any]]]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for ref in refs[:_EVIDENCE_MAX]:
        rows = sources.get(ref.claim_key) or []

        def rank(r: tuple[str, Any, Any]) -> tuple[int, int, str]:
            u = f.units.get(r[0])
            return (
                0 if u is not None and u.kind == "command" else 1,
                r[2] if isinstance(r[2], int) else 0,
                r[0],
            )

        best = min(rows, key=rank) if rows else None
        if best is None:
            out.append(
                {
                    "claim_key": ref.claim_key,
                    "unit_id": None,
                    "lines": None,
                    "label": vis(mask_known(ref.value, f.known_secrets))[0],
                    "ts": None,
                }
            )
            continue
        unit_id, span_json, ts = best
        lines = _lines(conn, f, unit_id, span_json)
        if (unit_id, lines) in seen:  # zwei Werte aus derselben Zeile: ein Beleg genügt
            continue
        seen.add((unit_id, lines))
        u = f.units.get(unit_id)
        # ohne Uhrzeit: die steht in ``ts``, die Oberfläche zeigt sie in der Lokalzeit des Browsers
        # (wie die Belege von Findings, web-api.md 18.12)
        bits = [b for b in (_unit_label(f, unit_id),) if b]
        if lines is not None:
            bits.append(
                f"Zeile {lines[0] + 1}"
                if lines[0] == lines[1]
                else f"Zeilen {lines[0] + 1} bis {lines[1] + 1}"
            )
        label = vis(" · ".join(bits))[0] if bits else "Beleg"
        out.append(
            {
                "claim_key": ref.claim_key,
                "unit_id": unit_id,
                "lines": list(lines) if lines else None,
                "label": label,
                "ts": iso(u.ts if u else ts),
            }
        )
    return out


# --------------------------------------------------------------------------- JSON


def _scope(f: Facts) -> Scope:
    return Scope(ip=f.ip_verdict.get, name=f.name_verdict.get, net=None)


def _masked(value: object, known: list[str]) -> object:
    return mask_known(value, known) if isinstance(value, str) else value


def _rendered(tid: str, raw: dict[str, object], known: list[str], scope: Scope) -> dict[str, Any]:
    slots = {k: _masked(v, known) for k, v in raw.items()}
    ip = slots.get("host.ip")
    return render(TEMPLATES[tid], slots, scope, ipv6=isinstance(ip, str) and ":" in ip)


def to_json(conn: Any, f: Facts, built: list[Built], *, profile: str) -> list[dict[str, Any]]:
    """``Suggestion`` (web-api.md 18.6) für die gegebenen Einträge, mit Belegen und Vorlagen."""
    keys = sorted({r.claim_key for b in built for r in b.cand.detail.evidence[:_EVIDENCE_MAX]})
    sources = _source_rows(conn, keys)
    scope = _scope(f)
    known = f.known_secrets
    out: list[dict[str, Any]] = []
    for b in built:
        c = b.cand
        d = c.detail
        title = Parts()
        for text, target in d.title:
            if target:
                title.target(mask_known(text, known))
            else:
                title.lit(text)
        reason = Parts()
        for text, target in d.reason:
            if target:
                reason.target(mask_known(text, known))
            else:
                reason.lit(text)
        flags = set(d.flags)
        templates: list[dict[str, Any]] = []
        items: list[dict[str, Any]] = []
        if not (c.rule.login_attempt and profile != "lab"):
            if d.items:
                # Liste mit je einer Vorlage (E119); ``templates`` trägt die ersten für ältere Ansichten
                for it in d.items:
                    t = _rendered(it.template, it.slots, known, scope)
                    if t["blocked_reason"] in SUSPECT_REASONS:
                        flags.add("injection_suspect")
                    label = Parts()
                    for text, target in it.label:
                        if target:
                            label.target(mask_known(text, known))
                        else:
                            label.lit(text)
                    items.append(
                        {
                            "service_id": it.service.service_id,
                            "port": it.service.port,
                            "proto": it.service.proto,
                            "label": label.text,
                            "ctrl": label.ctrl,
                            "label_parts": label.json(),
                            "template": t,
                        }
                    )
                templates = [i["template"] for i in items[:_TEMPLATES_MAX]]
            else:
                for tid in d.templates[:_TEMPLATES_MAX]:
                    t = _rendered(tid, d.slots, known, scope)
                    if t["blocked_reason"] in SUSPECT_REASONS:
                        flags.add("injection_suspect")
                    templates.append(t)
        host_label, _ = vis(mask_known(c.host.label, known))
        out.append(
            {
                "suggestion_key": b.key,
                "origin": "rule",
                "rule_id": c.rule.rule_id,
                "goal_id": c.rule.goal_id,
                "kind": c.rule.kind,
                "title": title.text,
                "ctrl": title.ctrl,
                "title_parts": title.json(),
                "host_id": c.host.host_id,
                "service_id": c.service.service_id if c.service is not None else None,
                "host_label": host_label,
                "reason": reason.text,
                "ctrl_reason": reason.ctrl,
                "evidence": _evidence(conn, f, d.evidence, sources),
                "stages": {"question": d.question, "direction": d.direction},
                "templates": templates,
                "items": items,
                "state": b.state,
                "decision_id": b.decision_id,
                "basis": b.basis,
                "flags": sorted(flags),
                "ts": iso(c.ts),
                "ai": None,
            }
        )
    return out
