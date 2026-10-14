"""Vollständige Neuberechnung der Projektion aus Beobachtungen und Entscheiden.

Reine Funktion :func:`build` ohne Datenbankzugriff: Eingaben sind die Zeilen
aus ``obs_unit``, ``observation``, ``mention`` und ``decision``, Ausgabe sind
die Zeilen der abgeleiteten Tabellen. So bleibt die Logik deterministisch und
einzeln testbar; :mod:`ariadne.ingest.projection` schreibt das Ergebnis.

Reihenfolge: Entscheide (mit ``d.revoke``) -> Kontext je Einheit -> Quellen
(Beobachtungen, IP-Mentions im Scope) -> Claims mit Konfidenz -> Zustände
(Entscheide, Automodus) -> Identitäten -> Konflikte -> Entitäten und Status ->
Faden -> Inbox.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ariadne.ingest.claims import (
    STATE_RANK,
    TRUST_ORDER,
    claim_key,
    combine,
    confidence_level,
    conflict_key,
    normalize_value,
    value_identifier,
)
from ariadne.ingest.identity import (
    HOST_TYPES,
    SCOPED_TYPES,
    STRONG_TYPES,
    WEAK_TYPES,
    IdentityGraph,
    host_identifier,
    host_part,
    id_type,
    normalize_identifier,
    strength,
)
from ariadne.ingest.schema_claims import MASK
from ariadne.ontology import PREDICATES
from ariadne.parsers.api import BASE_CONFIDENCE
from ariadne.scope.api import ScopeChecker

__all__ = ["UnitRow", "ObsRow", "MentionRow", "DecisionRow", "BuildResult", "build", "display",
           "MASS_THRESHOLD", "LOCAL_HOST"]

MASS_THRESHOLD = 256
LOCAL_HOST = "local:kali"
_LOCAL_KINDS = ("local", "su")
_ACCESS_RANK = {"none": 0, "user": 1, "admin": 2}
_STATUS_DECISIONS = ("d.status.work", "d.status.access", "d.note.set", "d.tag.add", "d.tag.remove")


# --------------------------------------------------------------------------- Eingaben
@dataclass(frozen=True)
class UnitRow:
    unit_id: str
    kind: str
    terminal_id: str | None
    cmd_id: str | None
    title: str | None
    path: str | None
    ts: int
    start_off: int | None
    end_off: int | None
    ctx_kind: str | None
    ctx_host: str | None
    ctx_user: str | None
    ctx_opened_at: int | None
    ctx_candidate: str | None
    from_target: bool
    journal_seq: int


@dataclass(frozen=True)
class ObsRow:
    obs_id: int
    unit_id: str
    parser_id: str
    parser_version: str
    trust: str
    auto_eligible: bool
    journal_seq: int
    subject: str
    predicate: str
    value: Any
    value_text: str
    span_json: str
    confidence: float
    attrs: Mapping[str, str]
    ts: int
    from_target: bool
    suspect: bool
    is_secret: bool


@dataclass(frozen=True)
class MentionRow:
    mention_id: int
    unit_id: str
    parser_id: str
    parser_version: str
    journal_seq: int
    value_type: str
    value: str | None
    span_json: str
    attrs: Mapping[str, str]
    ts: int
    from_target: bool
    suspect: bool


@dataclass(frozen=True)
class DecisionRow:
    seq: int
    id: str
    kind: str
    payload: Mapping[str, Any]
    ts: int


# --------------------------------------------------------------------------- intern
@dataclass
class _Src:
    subject: str
    predicate: str
    value: Any
    value_text: str
    is_secret: bool
    trust: str
    auto_eligible: bool
    confidence: float
    ts: int
    journal_seq: int
    unit_id: str | None = None
    parser_id: str | None = None
    parser_version: str | None = None
    span_json: str | None = None
    obs_id: int | None = None
    mention_id: int | None = None
    decision_id: str | None = None
    from_target: bool = False
    suspect: bool = False
    stage: tuple[str, int] | None = None

    def order(self) -> tuple:
        return (self.journal_seq, TRUST_ORDER.get(self.trust, 9), self.ts, self.obs_id or 0,
                self.mention_id or 0)


@dataclass
class _Claim:
    key: str
    subject: str
    predicate: str
    value: Any
    value_text: str
    is_secret: bool
    sources: list[_Src] = field(default_factory=list)
    state: str = "candidate"
    decision_id: str | None = None
    confidence: float = 0.0
    entity_id: str | None = None
    conflict_key: str | None = None
    scope: str | None = None

    @property
    def first(self) -> _Src:
        return min(self.sources, key=lambda s: s.order())

    @property
    def first_observation(self) -> _Src:
        """Erste echte Beobachtung (Mentions sind keine Beobachtungen); sonst die erste Quelle."""
        obs = [s for s in self.sources if s.obs_id is not None]
        return min(obs, key=lambda s: s.order()) if obs else self.first

    def strongest(self) -> _Src:
        return min(self.sources, key=lambda s: (TRUST_ORDER.get(s.trust, 9), s.order()))


@dataclass
class BuildResult:
    identifiers: list[tuple] = field(default_factory=list)
    entities: list[tuple] = field(default_factory=list)
    claims: list[tuple] = field(default_factory=list)
    claim_sources: list[tuple] = field(default_factory=list)
    conflicts: list[tuple] = field(default_factory=list)
    inbox: list[tuple] = field(default_factory=list)
    keysteps: list[tuple] = field(default_factory=list)
    mention_verdicts: dict[int, str | None] = field(default_factory=dict)
    secrets: dict[str, tuple[str, str]] = field(default_factory=dict)


def display(key: str) -> str:
    """Kurze Anzeige einer Kennung (Zieldaten, für die Senke zu kodieren)."""
    t = id_type(key)
    if t == "ip":
        return key.split("/", 1)[1]
    if t == "svc":
        host, _, pp = key[4:].rpartition("|")
        return f"{display(host)} {pp}"
    if t == "ctx":
        return "unbekannter Kontext"
    if key == LOCAL_HOST:
        return "Kali"
    if t == "secret":
        return f"Secret ({key[7:].split('|', 1)[0]})"
    return key.split(":", 1)[1] if ":" in key else key


def _dumps(obj: Any) -> str:
    """Stabiles JSON (sortiert, kompakt); anders als ``canonical_json`` mit Floats (Konfidenz)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _max_access(a: str, b: str) -> str:
    return a if _ACCESS_RANK.get(a, 0) >= _ACCESS_RANK.get(b, 0) else b


# --------------------------------------------------------------------------- Hauptfunktion
SpanRow = tuple[str, int, int | None, str | None, int | None]  # terminal, start, end, kind, opened_at


def build(units: Mapping[str, UnitRow], observations: Iterable[ObsRow], mentions: Iterable[MentionRow],
          decisions: Iterable[DecisionRow], scope: ScopeChecker, project_key: bytes,
          spans: Iterable[SpanRow] | None = None) -> BuildResult:
    """``spans`` sind die Kontextspannen des Segmenters (``ctx_span``). Ohne sie ordnet
    ``d.ctx.set`` nur über die schon geparsten Einheiten zu (Tests, alte Aufrufer)."""
    return _Builder(units, observations, mentions, decisions, scope, project_key, spans).run()


class _Builder:
    def __init__(self, units: Mapping[str, UnitRow], observations: Iterable[ObsRow],
                 mentions: Iterable[MentionRow], decisions: Iterable[DecisionRow], scope: ScopeChecker,
                 project_key: bytes, spans: Iterable[SpanRow] | None = None) -> None:
        self.spans: dict[str, list[SpanRow]] | None = None
        if spans is not None:
            self.spans = defaultdict(list)
            for sp in spans:
                self.spans[sp[0]].append(sp)
            for lst in self.spans.values():
                lst.sort(key=lambda x: x[1])
        self.units = dict(units)
        self.obs = list(observations)
        self.mentions = list(mentions)
        self.decisions = sorted(decisions, key=lambda d: d.seq)
        self.scope = scope
        self.pk = project_key
        self.res = BuildResult()
        self._verdicts: dict[str, tuple[str | None, str | None, int | None]] = {}
        self.orphans: list[tuple[DecisionRow, str, str | None]] = []

    # ------------------------------------------------------------------ Hilfen
    def secret_sink(self) -> Callable[[str, str, str], None]:
        def sink(ident: str, kind: str, value: str) -> None:
            self.res.secrets[ident] = (kind, value)
        return sink

    def verdict(self, key: str) -> str | None:
        return self._verdict_full(key)[0]

    def _verdict_full(self, key: str) -> tuple[str | None, str | None, int | None]:
        if key in self._verdicts:
            return self._verdicts[key]
        t = id_type(key)
        out: tuple[str | None, str | None, int | None]
        if t not in SCOPED_TYPES:
            out = (None, None, None)
        elif t == "svc" and id_type(host_part(key) or "") not in ("ip", "fqdn"):
            out = ("unknown", None, None)
        else:
            try:
                v = self.scope.check(key)
                out = (v.verdict, v.rule, v.scope_version)
            except Exception:  # Scope-Prüfung darf die Projektion nie stoppen: fail-closed
                out = ("unknown", None, None)
        self._verdicts[key] = out
        return out

    # ------------------------------------------------------------------ Ablauf
    def run(self) -> BuildResult:
        self._decisions()
        self._contexts()
        sources = self._sources()
        claims = self._aggregate(sources)
        self._claim_decisions(claims)
        self._automode(claims)
        keysteps = self._keystep_hosts()
        graph, entity_of = self._identity(claims, keysteps)
        self._conflicts(claims)
        self._entities(claims, keysteps, entity_of, graph)
        self._write_keysteps(keysteps, entity_of)
        self._inbox(claims, graph)
        self._write_claims(claims)
        return self.res

    # ------------------------------------------------------------------ Entscheide
    def _decisions(self) -> None:
        revoked: set[str] = set()
        for d in reversed(self.decisions):
            if d.kind == "d.revoke" and d.id not in revoked:
                target = d.payload.get("decision_id")
                if isinstance(target, str):
                    revoked.add(target)
        self.active = [d for d in self.decisions if d.id not in revoked and d.kind != "d.revoke"]

    def _contexts(self) -> None:
        """Kontext-Host je Einheit; ``d.ctx.set`` setzt den Host der Stufe, die den Offset enthält."""
        overrides: dict[tuple[str, int], str] = {}
        stages: dict[str, list[int]] = defaultdict(list)
        for u in self.units.values():
            if u.terminal_id and u.ctx_opened_at is not None and u.ctx_kind not in _LOCAL_KINDS:
                stages[u.terminal_id].append(u.ctx_opened_at)
        for d in self.active:
            if d.kind != "d.ctx.set" or not d.payload.get("host"):
                continue
            term = d.payload.get("terminal_id")
            off = d.payload.get("from_off")
            if not isinstance(term, str) or not isinstance(off, int):
                continue
            host = host_identifier(str(d.payload["host"]))
            if not host:
                continue
            spans = self.spans.get(term) if self.spans is not None else None
            if spans:
                # Die Stufe, die bei from_off tatsächlich lief (aus dem Segmenter), nicht
                # die jüngste schon geparste: deren Einheiten können noch offen sein.
                hit = next((sp for sp in spans if sp[1] <= off < (sp[2] if sp[2] is not None else 1 << 62)),
                           spans[0] if off < spans[0][1] else None)
                if hit is not None and hit[3] not in _LOCAL_KINDS and hit[4] is not None:
                    overrides[(term, int(hit[4]))] = host
                continue
            cands = [o for o in stages.get(term, []) if o <= off]
            if cands:
                overrides[(term, max(cands))] = host
        self.ctx_host: dict[str, str] = {}
        for u in self.units.values():
            self.ctx_host[u.unit_id] = self._resolve_ctx(u, overrides)

    def _resolve_ctx(self, u: UnitRow, overrides: Mapping[tuple[str, int], str]) -> str:
        if u.ctx_kind in _LOCAL_KINDS or u.ctx_host == "local":
            return LOCAL_HOST
        if u.terminal_id and u.ctx_opened_at is not None:
            o = overrides.get((u.terminal_id, u.ctx_opened_at))
            if o:
                return o
        if u.ctx_host:
            ident = host_identifier(u.ctx_host)
            if ident and ident != "ctx:host":
                return ident
        if u.terminal_id and u.ctx_opened_at is not None:
            return f"ctx:{u.terminal_id}@{u.ctx_opened_at}"
        return f"ctx:unit:{u.unit_id}"

    def _ctx_unknown(self, u: UnitRow) -> bool:
        return id_type(self.ctx_host.get(u.unit_id, "")) == "ctx" and u.ctx_kind not in (None, *_LOCAL_KINDS)

    @staticmethod
    def _subst(key: str, host: str) -> str:
        if key == "ctx:host":
            return host
        if key.startswith("svc:ctx:host|"):
            return "svc:" + host + key[len("svc:ctx:host") :]
        return key

    # ------------------------------------------------------------------ Quellen
    def _sources(self) -> list[_Src]:
        out: list[_Src] = []
        callbacks: dict[tuple[str, int], _Src] = {}
        for o in self.obs:
            u = self.units.get(o.unit_id)
            if u is None:
                continue
            host = self.ctx_host[u.unit_id]
            subject = self._subst(o.subject, host)
            value = o.value
            text = o.value_text
            if isinstance(value, Mapping) and isinstance(value.get("ref"), str):
                ref = self._subst(value["ref"], host)
                value = {"ref": ref}
                text = ref
            stage = None
            if u.terminal_id and u.ctx_opened_at is not None:
                stage = (u.terminal_id, u.ctx_opened_at)
            src = _Src(subject=subject, predicate=o.predicate, value=value, value_text=text,
                       is_secret=o.is_secret, trust=o.trust, auto_eligible=o.auto_eligible,
                       confidence=o.confidence, ts=o.ts, journal_seq=o.journal_seq, unit_id=o.unit_id,
                       parser_id=o.parser_id, parser_version=o.parser_version, span_json=o.span_json,
                       obs_id=o.obs_id, from_target=o.from_target, suspect=o.suspect,
                       stage=stage)  # type: ignore[arg-type]
            if o.predicate == "access.callback" and stage is not None:
                # nur der erste Callback einer Listener-Stufe zählt (ein Ziel kann Zeilen fälschen)
                prev = callbacks.get(stage)  # type: ignore[arg-type]
                if prev is None or src.order() < prev.order():
                    callbacks[stage] = src  # type: ignore[index]
                continue
            out.append(src)
        out.extend(callbacks.values())
        for m in self.mentions:
            u = self.units.get(m.unit_id)
            if u is None or m.value is None:
                continue
            if m.value_type == "ip":
                ident = f"ip:default/{m.value}"
                v = self.verdict(ident)
                self.res.mention_verdicts[m.mention_id] = v
                if v != "in" or m.attrs.get("state") == "down":
                    continue
                out.append(_Src(subject=ident, predicate="host.address", value=m.value, value_text=m.value,
                                is_secret=False, trust="heuristic", auto_eligible=False,
                                confidence=BASE_CONFIDENCE["heuristic"], ts=m.ts, journal_seq=m.journal_seq,
                                unit_id=m.unit_id, parser_id=m.parser_id, parser_version=m.parser_version,
                                span_json=m.span_json, mention_id=m.mention_id,
                                from_target=m.from_target, suspect=m.suspect))
            elif m.value_type == "url":
                self.res.mention_verdicts[m.mention_id] = self.verdict(f"url:{m.value}")
        return out

    # ------------------------------------------------------------------ Claims
    def _aggregate(self, sources: list[_Src]) -> dict[str, _Claim]:
        claims: dict[str, _Claim] = {}
        for s in sources:
            secret = s.is_secret or id_type(s.subject) == "secret"
            key = claim_key(s.subject, s.predicate, s.value, secret=secret, project_key=self.pk)
            c = claims.get(key)
            if c is None:
                c = claims[key] = _Claim(key, s.subject, s.predicate, s.value, s.value_text, secret)
            c.sources.append(s)
        return claims

    def _add_user_claim(self, claims: dict[str, _Claim], base: _Claim, value: Any, text: str, secret: bool,
                        d: DecisionRow) -> str:
        key = claim_key(base.subject, base.predicate, value, secret=secret or base.is_secret,
                        project_key=self.pk)
        c = claims.get(key)
        if c is None:
            c = claims[key] = _Claim(key, base.subject, base.predicate, value, text, secret or base.is_secret)
        c.sources.append(_Src(subject=base.subject, predicate=base.predicate, value=value, value_text=text,
                              is_secret=c.is_secret, trust="user", auto_eligible=False, confidence=1.0,
                              ts=d.ts, journal_seq=d.seq, decision_id=d.id))
        return key

    def _claim_decisions(self, claims: dict[str, _Claim]) -> None:
        for d in self.active:
            if d.kind not in ("d.claim.confirm", "d.claim.reject", "d.claim.edit"):
                continue
            key = d.payload.get("claim_key")
            if not isinstance(key, str) or key not in claims:
                self.orphans.append((d, "Claim existiert nicht mehr", key if isinstance(key, str) else None))
                continue
            c = claims[key]
            if d.kind == "d.claim.confirm":
                c.state, c.decision_id = "confirmed", d.id
            elif d.kind == "d.claim.reject":
                c.state, c.decision_id = "rejected", d.id
            else:
                pred = PREDICATES.get(c.predicate)
                try:
                    if pred is None:
                        raise ValueError("Prädikat")
                    value, text, secret = normalize_value(pred, d.payload.get("value"), self.pk,
                                                          self.secret_sink())
                except ValueError:
                    self.orphans.append((d, "ungültiger Wert", key))
                    continue
                new_key = self._add_user_claim(claims, c, value, text, secret, d)
                if new_key != key:
                    c.state, c.decision_id = "rejected", d.id
                claims[new_key].state = "confirmed"
                claims[new_key].decision_id = d.id
        for c in claims.values():
            if c.state == "confirmed":
                c.confidence = 1.0
                continue
            per_unit: dict[str, float] = {}
            for s in c.sources:
                uk = s.unit_id or f"decision:{s.decision_id}"
                per_unit[uk] = max(per_unit.get(uk, 0.0), s.confidence)
            c.confidence = combine(per_unit.values())

    def _automode(self, claims: dict[str, _Claim]) -> None:
        phases = [(d.seq, bool(d.payload.get("enabled")), tuple(d.payload.get("parsers") or ()))
                  for d in self.active if d.kind == "d.automode.set"]
        for c in claims.values():
            c.scope = self.verdict(c.subject)
            if c.decision_id is not None:
                continue
            first = c.first_observation
            enabled, parsers = False, ()
            for seq, en, ps in phases:
                if seq < first.journal_seq:
                    enabled, parsers = en, ps
                else:
                    break
            if not enabled or not first.auto_eligible or first.trust in ("ai", "ocr", "user", "heuristic"):
                continue
            if parsers and first.parser_id not in parsers:
                continue
            if c.scope != "in":
                continue
            vi = value_identifier(c.predicate, c.subject, c.value)
            if vi is not None and id_type(vi) in ("ip", "url") and self.verdict(vi) != "in":
                continue  # ein Wert ausserhalb des Scopes würde zum Ziel
            c.state = "auto"

    # ------------------------------------------------------------------ Faden (Hosts)
    def _keystep_hosts(self) -> list[tuple[DecisionRow, str | None]]:
        out: list[tuple[DecisionRow, str | None]] = []
        for d in self.active:
            if d.kind != "d.keystep.mark":
                continue
            host: str | None = None
            raw = d.payload.get("host")
            if isinstance(raw, str) and raw:
                host = host_identifier(raw)
            if host is None:
                host = self._host_at(d.payload.get("terminal_id"), d.payload.get("stream_off"))
            out.append((d, host))
        return out

    def _host_at(self, term: Any, off: Any) -> str | None:
        if not isinstance(term, str) or not isinstance(off, int):
            return None
        best: UnitRow | None = None
        containing: UnitRow | None = None
        for u in sorted(self.units.values(), key=lambda x: x.unit_id):
            if u.terminal_id != term:
                continue
            if u.start_off is not None and u.end_off is not None and u.start_off <= off <= u.end_off:
                if containing is None or (containing.start_off or 0) < u.start_off:
                    containing = u  # die innerste (zuletzt begonnene) Einheit
            elif u.ctx_opened_at is not None and u.ctx_opened_at <= off and (
                    best is None or (best.ctx_opened_at or 0) < u.ctx_opened_at):
                best = u
        hit = containing or best
        return self.ctx_host[hit.unit_id] if hit is not None else None

    # ------------------------------------------------------------------ Identitäten
    def _identity(self, claims: dict[str, _Claim], keysteps: list[tuple[DecisionRow, str | None]]
                  ) -> tuple[IdentityGraph, dict[str, str | None]]:
        live = [c for c in claims.values() if c.state != "rejected"]
        nodes: set[str] = set()
        anchors: set[str] = set()
        for c in live:
            hp = host_part(c.subject)
            if hp is not None and id_type(hp) in HOST_TYPES:
                nodes.add(hp)
                anchors.add(hp)
            vi = value_identifier(c.predicate, c.subject, c.value)
            if vi is not None and id_type(vi) in HOST_TYPES:
                nodes.add(vi)
        for _, host in keysteps:
            if host:
                nodes.add(host)
                anchors.add(host)
        verdicts = {k: self.verdict(k) for k in nodes}
        g = IdentityGraph(verdicts)
        for k in sorted(nodes):
            g.add(k)
        # Nutzerentscheide: jeweils die letzte Aussage pro Paar zählt
        relation: dict[frozenset[str], str] = {}
        merges: list[tuple[DecisionRow, list[str]]] = []
        for d in self.active:
            if d.kind not in ("d.entity.merge", "d.entity.split"):
                continue
            ids = [normalize_identifier(str(x)) for x in d.payload.get("identifiers", ())]
            known = sorted({i for i in ids if i is not None and i in nodes})
            if len(known) < 2:
                self.orphans.append((d, "Kennungen unbekannt", None))
                continue
            for a in known:
                for b in known:
                    if a < b:
                        relation[frozenset((a, b))] = "must" if d.kind == "d.entity.merge" else "cannot"
            if d.kind == "d.entity.merge":
                merges.append((d, known))
        g.cannot = {p for p, r in relation.items() if r == "cannot"}
        for _, ids in merges:
            g.must(ids)
        self.suggestion_ts: dict[str, int] = {}
        strong = []
        weak_holders: dict[str, set[str]] = defaultdict(set)
        for c in live:
            vi = value_identifier(c.predicate, c.subject, c.value)
            hp = host_part(c.subject)
            if vi is None or hp is None or id_type(hp) not in HOST_TYPES:
                continue
            if id_type(vi) in STRONG_TYPES:
                strong.append((min(s.ts for s in c.sources), c.key, hp, vi))
            elif id_type(vi) in WEAK_TYPES:
                weak_holders[vi].add(hp)
        for ts, _, hp, vi in sorted(strong):
            before = set(g.suggestions)
            g.link_strong(hp, vi, vi)
            for k in set(g.suggestions) - before:
                self.suggestion_ts[k] = ts
        for vi in sorted(weak_holders):
            g.attach_weak(vi, weak_holders[vi])
        entity_of: dict[str, str | None] = {}
        anchored_roots = {g.find(a) for a in anchors}
        for k in sorted(nodes):
            root = g.find(k)
            entity_of[k] = g.main(k) if root in anchored_roots else None
        return g, entity_of

    def _entity_for(self, key: str, entity_of: Mapping[str, str | None]) -> str | None:
        t = id_type(key)
        if t == "svc":
            host, _, pp = key[4:].rpartition("|")
            he = entity_of.get(host)
            return f"svc:{he}|{pp}" if he else None
        if t in HOST_TYPES:
            return entity_of.get(key)
        return key

    # ------------------------------------------------------------------ Konflikte
    def _conflicts(self, claims: dict[str, _Claim]) -> None:
        groups: dict[tuple[str, str], list[_Claim]] = defaultdict(list)
        for c in claims.values():
            p = PREDICATES.get(c.predicate)
            if p is not None and p.cardinality == "one" and c.state != "rejected":
                groups[(c.subject, c.predicate)].append(c)
        resolution: dict[str, DecisionRow] = {}
        for d in self.active:
            if d.kind == "d.conflict.resolve" and isinstance(d.payload.get("conflict_key"), str):
                resolution[d.payload["conflict_key"]] = d
        self.conflicts: dict[str, tuple[str, str, list[_Claim], str, str | None, str | None]] = {}
        for (subject, pred), cs in sorted(groups.items()):
            if len(cs) < 2:
                continue
            ck = conflict_key(subject, pred)
            state, choice, did = "open", None, None
            d = resolution.get(ck)
            if d is not None:
                did = d.id
                if d.payload.get("keep_open"):
                    state = "kept_open"
                elif d.payload.get("choice") is not None:
                    state, choice = "resolved", str(d.payload.get("choice"))
            cs.sort(key=lambda c: c.key)
            for c in cs:
                c.conflict_key = ck
            self.conflicts[ck] = (subject, pred, cs, state, choice, did)

    # ------------------------------------------------------------------ Entitäten
    def _entities(self, claims: dict[str, _Claim], keysteps: list[tuple[DecisionRow, str | None]],
                  entity_of: dict[str, str | None], g: IdentityGraph) -> None:
        for c in claims.values():
            c.entity_id = self._entity_for(c.subject, entity_of)
        live = [c for c in claims.values() if c.state != "rejected"]
        ents: dict[str, dict[str, Any]] = {}

        def ent(eid: str, etype: str) -> dict[str, Any]:
            e = ents.get(eid)
            if e is None:
                e = ents[eid] = {"type": etype, "claims": [], "keysteps": [], "members": set()}
            return e

        for c in live:
            if c.entity_id is None:
                continue
            t = id_type(c.subject)
            etype = "service" if t == "svc" else "host" if t in HOST_TYPES else {
                "url": "url", "id": "identity", "secret": "secret"}.get(t, "other")
            e = ent(c.entity_id, etype)
            e["claims"].append(c)
            if etype == "service":
                he = c.entity_id[4:].rpartition("|")[0]
                ent(he, "host")
        for d, host in keysteps:
            eid = entity_of.get(host) if host else None
            if eid:
                ent(eid, "host")["keysteps"].append(d)
        for k, eid in entity_of.items():
            if eid is not None and eid in ents:
                ents[eid]["members"].add(k)
        self.entity_ids = set(ents)
        # Identifier-Zeilen
        ident_keys: set[str] = set(entity_of)
        for c in claims.values():
            ident_keys.add(c.subject)
            vi = value_identifier(c.predicate, c.subject, c.value)
            if vi is not None:
                ident_keys.add(vi)
        for k in sorted(ident_keys):
            v, rule, ver = self._verdict_full(k)
            eid = self._entity_for(k, entity_of)
            if eid is not None and eid not in ents:
                eid = None
            self.res.identifiers.append((k, id_type(k), eid, strength(k), v, rule, ver))
        status = self._status_decisions(entity_of, ents)
        # Service-Zählungen und Konflikte pro Host
        svc_by_host: dict[str, list[str]] = defaultdict(list)
        for eid, e in ents.items():
            if e["type"] == "service":
                svc_by_host[eid[4:].rpartition("|")[0]].append(eid)
        open_conf: dict[str, int] = defaultdict(int)
        for _, _, cs, state, _, _ in self.conflicts.values():
            if state != "open" or not cs or cs[0].entity_id is None:
                continue
            eid = cs[0].entity_id
            open_conf[eid] += 1
            if eid.startswith("svc:"):
                open_conf[eid[4:].rpartition("|")[0]] += 1
        self.entity_first_unit: dict[str, str | None] = {}
        self.entity_meta: dict[str, dict[str, Any]] = {}
        for eid in sorted(ents):
            e = ents[eid]
            cs: list[_Claim] = e["claims"]
            srcs = [s for c in cs for s in c.sources if s.unit_id]
            first_src = min(srcs, key=lambda s: (s.ts, s.journal_seq)) if srcs else None
            first_unit = first_src.unit_id if first_src else None
            self.entity_first_unit[eid] = first_unit
            ts_all = [s.ts for c in cs for s in c.sources] + [d.ts for d in e["keysteps"]]
            first_seen = min(ts_all) if ts_all else None
            last_seen = max(ts_all) if ts_all else None
            st = status.get(eid, {})
            best_state = min((c.state for c in cs), key=lambda s: STATE_RANK[s], default=None)
            if best_state is None and e["keysteps"]:
                best_state = "confirmed"
            members = sorted(e["members"])
            scope = self._entity_scope(eid, members)
            label = self._label(eid)
            knowledge = access = None
            progress = None
            attrs: dict[str, Any]
            if e["type"] == "host":
                svc_claims = [c for sid in svc_by_host.get(eid, []) for c in ents[sid]["claims"]]
                knowledge = self._knowledge(cs, svc_claims, bool(e["keysteps"]))
                access = self._access(cs, e["keysteps"], st.get("access"))
                progress = _progress(knowledge, access)
                attrs = self._host_attrs(eid, cs, members, len(svc_by_host.get(eid, [])), open_conf[eid])
            elif e["type"] == "service":
                knowledge = "versions" if any(c.predicate in ("service.product", "service.version")
                                              for c in cs) else "scanned"
                attrs = self._service_attrs(eid, cs, open_conf[eid])
            else:
                attrs = {}
            work, reason = st.get("work", ("open", None))
            self.entity_meta[eid] = {"type": e["type"], "scope": scope}
            self.res.entities.append((
                eid, e["type"], label, knowledge, access, work, reason, progress, first_seen, last_seen,
                json.dumps(sorted(st.get("tags", set())), ensure_ascii=False), st.get("note"), scope,
                best_state, first_unit, _dumps(attrs),
            ))

    def _entity_scope(self, eid: str, members: list[str]) -> str | None:
        if any(self.verdict(m) == "excluded" for m in members):
            return "excluded"  # Ausschluss wirkt konservativ auf die ganze Entität
        v = self.verdict(eid)
        return v if v is not None else "unknown"

    def _label(self, eid: str) -> str:
        return display(eid)

    def _status_decisions(self, entity_of: Mapping[str, str | None], ents: Mapping[str, Any]
                          ) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = defaultdict(dict)
        for d in self.active:
            if d.kind not in _STATUS_DECISIONS:
                continue
            subj = d.payload.get("subject")
            eid = None
            if isinstance(subj, str):
                if subj in ents:
                    eid = subj
                else:
                    ident = normalize_identifier(subj) or host_identifier(subj)
                    eid = self._entity_for(ident, entity_of) if ident else None
            if eid is None or eid not in ents:
                self.orphans.append((d, "Subjekt unbekannt", subj if isinstance(subj, str) else None))
                continue
            st = out[eid]
            if d.kind == "d.status.work":
                st["work"] = (str(d.payload.get("value")), d.payload.get("reason"))
            elif d.kind == "d.status.access":
                st["access"] = str(d.payload.get("value"))
            elif d.kind == "d.note.set":
                st["note"] = d.payload.get("text")
            elif d.kind == "d.tag.add":
                st.setdefault("tags", set()).add(str(d.payload.get("tag")))
            elif d.kind == "d.tag.remove":
                st.setdefault("tags", set()).discard(str(d.payload.get("tag")))
        return out

    @staticmethod
    def _knowledge(host_claims: list[_Claim], svc_claims: list[_Claim], keystep: bool) -> str:
        if any(c.predicate in ("service.product", "service.version") for c in svc_claims):
            return "versions"
        if any(c.predicate == "service.state" for c in svc_claims):
            return "scanned"
        if keystep or any(s.trust in ("structured", "tool_text", "user")
                          for c in host_claims + svc_claims for s in c.sources):
            return "discovered"
        return "mentioned"

    @staticmethod
    def _access(cs: list[_Claim], keysteps: list[DecisionRow], override: str | None) -> str:
        if override in _ACCESS_RANK:
            return override  # type: ignore[return-value]
        level = "none"
        for c in cs:
            if c.state not in ("auto", "confirmed"):
                continue
            if c.predicate == "access.shell" and isinstance(c.value, str):
                level = _max_access(level, c.value)
            elif c.predicate == "access.callback":
                level = _max_access(level, "user")
        for d in keysteps:
            level = _max_access(level, "admin" if d.payload.get("step") == "privesc" else "user")
        return level

    @staticmethod
    def _best(cs: list[_Claim], pred: str) -> _Claim | None:
        cands = [c for c in cs if c.predicate == pred]
        if not cands:
            return None
        return min(cands, key=lambda c: (STATE_RANK[c.state], -c.confidence, c.value_text))

    def _host_attrs(self, eid: str, cs: list[_Claim], members: list[str], services: int, conflicts: int
                    ) -> dict[str, Any]:
        addrs = {m.split("/", 1)[1] for m in members if id_type(m) == "ip"}
        addrs |= {c.value for c in cs if c.predicate == "host.address" and isinstance(c.value, str)}
        names = sorted({c.value for c in cs if c.predicate == "host.name" and isinstance(c.value, str)})
        macs = sorted({c.value for c in cs if c.predicate == "host.mac" and isinstance(c.value, str)})
        os_claim = self._best(cs, "host.os")
        return {
            "addresses": sorted(addrs),
            "names": names,
            "macs": macs,
            "os": os_claim.value_text if os_claim else None,
            "services_total": services,
            "conflicts": conflicts,
            "placeholder": id_type(eid) == "ctx",
        }

    def _service_attrs(self, eid: str, cs: list[_Claim], conflicts: int) -> dict[str, Any]:
        host, _, pp = eid[4:].rpartition("|")
        proto, _, port = pp.partition("/")
        out: dict[str, Any] = {"host_id": host, "proto": proto, "port": int(port), "conflicts": conflicts}
        for pred in ("name", "product", "version", "state"):
            c = self._best(cs, f"service.{pred}")
            out[pred] = c.value_text if c else None
        out["cves"] = sorted({c.value_text for c in cs if c.predicate == "hint.cve"})
        return out

    # ------------------------------------------------------------------ Faden
    def _write_keysteps(self, keysteps: list[tuple[DecisionRow, str | None]],
                        entity_of: Mapping[str, str | None]) -> None:
        for d, host in keysteps:
            eid = entity_of.get(host) if host else None
            so = d.payload.get("stream_off")
            self.res.keysteps.append((d.seq, d.id, str(d.payload.get("step")), host, eid,
                                      d.payload.get("terminal_id"), so if isinstance(so, int) else None,
                                      d.payload.get("note"), d.ts))

    # ------------------------------------------------------------------ Inbox
    def _payload_value(self, c: _Claim) -> Any:
        if c.is_secret:
            return MASK
        return c.value if not isinstance(c.value, Mapping) else c.value_text

    def _inbox(self, claims: dict[str, _Claim], g: IdentityGraph) -> None:
        items = self.res.inbox
        # Kandidaten pro Einheit
        by_unit: dict[str, list[_Claim]] = defaultdict(list)
        for c in claims.values():
            p = PREDICATES.get(c.predicate)
            if c.state != "candidate" or p is None or not p.inbox:
                continue
            first = c.first
            if first.unit_id is None:
                continue
            by_unit[first.unit_id].append(c)
        new_hosts: dict[str, int] = defaultdict(int)
        for eid, fu in self.entity_first_unit.items():
            if fu is not None and self.entity_meta[eid]["type"] == "host":
                new_hosts[fu] += 1
        for unit_id in sorted(by_unit):
            u = self.units[unit_id]
            cs = sorted(by_unit[unit_id], key=lambda c: (c.subject, c.predicate, c.value_text))
            title = u.title or u.path or ("Segment" if u.kind == "segment" else u.kind)
            unit_info = {"unit_id": unit_id, "cmd_id": u.cmd_id, "terminal_id": u.terminal_id,
                         "kind": u.kind, "title": title}
            if new_hosts.get(unit_id, 0) >= MASS_THRESHOLD:
                items.append((f"mass:{unit_id}", "mass_find", f"mass:{unit_id}", title, _dumps({
                    "unit": unit_info, "hosts": new_hosts[unit_id], "candidates": len(cs),
                    "hint": "möglicher Honeypot oder Tarpit",
                }), "open", u.ts))
                continue
            summary = _summary(cs)
            for c in cs:
                first = c.first
                items.append((f"claim:{c.key}", "candidate_group", f"unit:{unit_id}", title, _dumps({
                    "claim_key": c.key, "subject": c.subject, "subject_label": display(c.subject),
                    "entity_id": c.entity_id, "predicate": c.predicate, "value": self._payload_value(c),
                    "confidence": c.confidence, "confidence_level": confidence_level(c.confidence),
                    "scope": c.scope or "unknown", "trust": c.strongest().trust, "parser": first.parser_id,
                    "ai": any(s.trust == "ai" for s in c.sources),
                    "from_target": any(s.from_target for s in c.sources),
                    "suspect": any(s.suspect for s in c.sources), "state": c.state, "unit": unit_info,
                    "summary": summary,
                }), "open", u.ts))
        # Konflikte
        for ck, (subject, pred, cs, state, _choice, _did) in sorted(self.conflicts.items()):
            if state != "open":
                continue
            values = [{"claim_key": c.key, "value": self._payload_value(c), "sources": len(c.sources),
                       "trust": c.strongest().trust, "state": c.state} for c in cs]
            items.append((f"conflict:{ck}", "conflict", "conflict", f"{display(subject)} {pred}", _dumps({
                "conflict_key": ck, "subject": subject, "subject_label": display(subject),
                "entity_id": cs[0].entity_id, "predicate": pred, "values": values,
            }), "open", max(s.ts for c in cs for s in c.sources)))
        # Merge-Vorschläge
        for key, sug in sorted(g.suggestions.items()):
            roots = {g.find(i) for i in sug.identifiers if i != sug.shared}
            if len(roots) < 2:
                continue
            items.append((key, "merge_suggestion", "merge", "Zusammenführen?", _dumps({
                "identifiers": list(sug.identifiers), "shared": sug.shared, "reason": sug.reason,
            }), "open", self.suggestion_ts.get(key, 0)))
        # Kontext klären
        self._ctx_items(claims)
        # Verwaiste Entscheide
        for d, reason, ref in self.orphans:
            items.append((f"orphan:{d.id}", "orphan_decision", "orphan", "Verwaister Entscheid", _dumps({
                "decision_id": d.id, "kind": d.kind, "reason": reason, "ref": ref, "seq": d.seq,
            }), "open", d.ts))

    def _ctx_items(self, claims: dict[str, _Claim]) -> None:
        stages: dict[tuple[str, int], list[UnitRow]] = defaultdict(list)
        for u in self.units.values():
            if u.terminal_id and u.ctx_opened_at is not None and self._ctx_unknown(u):
                stages[(u.terminal_id, u.ctx_opened_at)].append(u)
        callbacks: dict[tuple[str, int], _Claim] = {}
        for c in claims.values():
            if c.predicate != "access.callback" or c.state == "rejected":
                continue
            for s in c.sources:
                if s.stage is not None and s.stage in stages:
                    prev = callbacks.get(s.stage)
                    if prev is None or s.order() < prev.first.order():
                        callbacks[s.stage] = c
        for (term, off), us in sorted(stages.items()):
            us.sort(key=lambda u: (u.ts, u.unit_id))
            placeholder = f"ctx:{term}@{off}"
            payload: dict[str, Any] = {
                "terminal_id": term, "from_off": off, "kind": us[0].ctx_kind,
                "candidate": us[0].ctx_candidate, "units": len(us), "placeholder": placeholder,
                "placeholder_entity": placeholder if placeholder in self.entity_ids else None,
            }
            cb = callbacks.get((term, off))
            kind = "ctx_unknown"
            if cb is not None:
                kind = "ctx_suggestion"
                payload["suggested_host"] = cb.subject
                payload["reason"] = f"Callback von {display(cb.subject)} ({cb.value_text})"
                payload["claim_key"] = cb.key
            self.res.inbox.append((f"ctx:{term}@{off}", kind, f"ctx:{term}@{off}", "Kontext klären",
                                   _dumps(payload), "open", us[0].ts))

    # ------------------------------------------------------------------ Claims schreiben
    def _write_claims(self, claims: dict[str, _Claim]) -> None:
        for key in sorted(claims):
            c = claims[key]
            srcs = sorted(c.sources, key=lambda s: s.order())
            with_unit = [s for s in srcs if s.unit_id]
            first = min(with_unit, key=lambda s: (s.ts, s.journal_seq)) if with_unit else None
            last = max(with_unit, key=lambda s: (s.ts, s.journal_seq)) if with_unit else None
            strongest = c.strongest()
            text = MASK if c.is_secret else c.value_text
            self.res.claims.append((
                c.key, c.subject, c.entity_id, c.predicate, _dumps(c.value), text, c.confidence, c.state,
                first.unit_id if first else None, last.unit_id if last else None,
                min(s.ts for s in srcs), max(s.ts for s in srcs), c.conflict_key,
                int(any(s.from_target for s in srcs)), strongest.trust,
                strongest.parser_id or ("user" if strongest.trust == "user" else None), len(srcs),
                int(c.is_secret), int(any(s.suspect for s in srcs)), c.scope, c.decision_id,
            ))
            for s in srcs:
                self.res.claim_sources.append((c.key, s.obs_id, s.mention_id, s.decision_id, s.unit_id,
                                               s.parser_id, s.parser_version, s.trust, s.confidence,
                                               s.span_json, s.journal_seq, s.ts))
        for ck, (subject, pred, cs, state, choice, did) in sorted(self.conflicts.items()):
            self.res.conflicts.append((ck, subject, cs[0].entity_id, pred, _dumps([c.key for c in cs]), state,
                                       choice, did))


def _progress(knowledge: str | None, access: str | None) -> int:
    if access == "admin":
        return 5
    if access == "user":
        return 4
    return {"versions": 3, "scanned": 2, "discovered": 1}.get(knowledge or "", 0)


def _summary(cs: list[_Claim]) -> dict[str, int]:
    hosts: set[str] = set()
    services: set[str] = set()
    creds: set[str] = set()
    other = out = low = 0
    for c in cs:
        t = id_type(c.subject)
        eid = c.entity_id or c.subject
        if t == "svc":
            services.add(eid)
        elif t in HOST_TYPES:
            hosts.add(eid)
        elif t in ("id", "secret"):
            creds.add(eid)
        else:
            other += 1
        if c.scope != "in":
            out += 1
        if c.confidence < 0.5:
            low += 1
    return {"hosts": len(hosts), "services": len(services), "credentials": len(creds), "other": other,
            "out_of_scope": out, "low_confidence": low}
