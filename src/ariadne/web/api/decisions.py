"""``POST /p/{pid}/decisions`` und ``POST /p/{pid}/decisions/confirm-group`` (``docs/web-api.md`` 12).

Der einzige allgemeine Schreibweg (Architektur 7.1). Ablauf «alle oder keiner»:

1. Jede Nutzlast mit :func:`ariadne.events.validate_header` prüfen, Arten nach Stand einteilen
   (``d.ctx.*`` 422, kritische 403 ``policy``, spätere 501).
2. Jeden Bezug (Claim, Widerspruch, Kennungen, Subjekt, Terminal, Entscheid) gegen den Stand der
   Auswertung und des Journals prüfen (``ingest.query_journal``).
3. Ohne ``await`` dazwischen: dasselbe Projekt noch offen? Dann alle Entscheide mit Herkunft
   ``webui`` einreihen (``daemon.submit``) und in einem Commit schreiben (``daemon.flush``).

``d.unit.distrust`` geht allein über die ctl-Operation ``unit.distrust`` (Herkunft ``webui``), die
``cmd_id`` bzw. ``cmd_ref`` auflöst. ``client_ref`` macht Wiederholungen 10 Minuten lang idempotent.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict
from typing import Any

from fastapi import APIRouter
from pydantic import ValidationError
from starlette.responses import Response

from ariadne import events
from ariadne.ai import store as ai_store
from ariadne.daemon.terminal import normalize_host
from ariadne.ingest.identity import host_identifier, normalize_identifier
from ariadne.ingest.proj_findings import FINDING_KINDS, evidence_id, fold
from ariadne.ingest.queries import entity_of_subject
from ariadne.rules import api as rules_api
from ariadne.scope import suggest as scope_suggest
from ariadne.scope.matcher import ScopeMatcher
from ariadne.store.api import AppendItem
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError, validation_detail
from ariadne.web.api.models import INT64_MAX, ConfirmGroupRequest, DecisionRequest
from ariadne.web.api.views import loads

__all__ = ["add_routes", "WRITABLE", "CRITICAL", "LATER", "IdempotencyCache"]

WRITABLE = frozenset(
    {
        "d.claim.confirm",
        "d.claim.reject",
        "d.claim.edit",
        "d.conflict.resolve",
        "d.entity.merge",
        "d.entity.split",
        "d.status.work",
        "d.status.access",
        "d.note.set",
        "d.tag.add",
        "d.tag.remove",
        "d.terminal.label",
        "d.keystep.mark",
        "d.revoke",
        "d.unit.distrust",
        # Bau v0.1-Oberfläche (web-api.md 18.5, 18.6)
        "d.suggestion.done",
        "d.suggestion.dismiss",
        *FINDING_KINDS,
    }
)
CRITICAL = frozenset({"d.scope.update", "d.lab.not_customer"})  # v0.1 nur im Terminal (Briefing 9.10)
LATER = frozenset({"d.artifact", "d.hypothesis", "d.goal.status"})
OLD_FINDING = "d.finding"  # altes Modell ohne Felder: ersetzt durch d.finding.* (422)
_ATTACK_RE = events.ATTACK_ID_RE  # fullmatch, nur ASCII-Ziffern (Korrektur SEC-FIND-1)
_CVE_RE = events.CVE_ID_RE
_CTX = frozenset({"d.ctx.set", "d.ctx.push", "d.ctx.pop", "d.ctx.accept"})
_SUBJECT = frozenset({"d.status.work", "d.status.access", "d.note.set", "d.tag.add", "d.tag.remove"})
_CACHE_S = 600.0
_CACHE_MAX = 5000


class IdempotencyCache:
    """Ergebnisse pro (Projekt, ``client_ref``) für 10 Minuten, höchstens 5000 Einträge."""

    def __init__(self, ttl: float = _CACHE_S, size: int = _CACHE_MAX) -> None:
        self.ttl = ttl
        self.size = size
        self._data: OrderedDict[tuple[str, str], tuple[float, dict[str, Any]]] = OrderedDict()

    def get(self, pid: str, ref: str | None) -> dict[str, Any] | None:
        if ref is None:
            return None
        now = time.monotonic()
        hit = self._data.get((pid, ref))
        if hit is None or hit[0] < now:
            self._data.pop((pid, ref), None)
            return None
        return dict(hit[1])

    def put(self, pid: str, ref: str | None, result: dict[str, Any]) -> None:
        if ref is None:
            return
        self._data[(pid, ref)] = (time.monotonic() + self.ttl, dict(result))
        self._data.move_to_end((pid, ref))
        while len(self._data) > self.size:
            self._data.popitem(last=False)


def _bad(i: int, field: str, typ: str) -> ApiError:
    return ApiError("validation", [{"loc": ["body", "decisions", i, field], "type": typ}])


def _ints_fit(obj: Any, depth: int = 0) -> bool:
    """Jede Ganzzahl der Nutzlast passt in 64 Bit (sonst 422 statt eines Fehlers in SQLite)."""
    if depth > 32:
        return False
    if isinstance(obj, bool):
        return True
    if isinstance(obj, int):
        return -INT64_MAX - 1 <= obj <= INT64_MAX
    if isinstance(obj, dict):
        return all(_ints_fit(v, depth + 1) for v in obj.values())
    if isinstance(obj, list | tuple):
        return all(_ints_fit(v, depth + 1) for v in obj)
    return True


def _bad_at(i: int, loc: list[Any], typ: str) -> ApiError:
    return ApiError("validation", [{"loc": ["body", "decisions", i, "payload", *loc], "type": typ}])


def _finding_shape(i: int, kind: str, payload: dict[str, Any]) -> None:
    """Prüfungen der Findings mit eigenen 422-Typen (18.10: ``attack``, ``cve``, ``subject``,
    ``severity_required``), bevor das Modell die Nutzlast sieht. Nie mit Werten in der Antwort."""
    for key, rx, typ in (("attack", _ATTACK_RE, "attack"), ("cves", _CVE_RE, "cve")):
        refs = payload.get(key)
        if refs is None:
            continue
        if not isinstance(refs, list):
            raise _bad_at(i, [key], typ)
        for j, r in enumerate(refs):
            rid = r.get("id") if isinstance(r, dict) else None
            if not isinstance(rid, str) or not rx.fullmatch(rid):
                raise _bad_at(i, [key, j, "id"], typ)
            if "supported" in r and not isinstance(r["supported"], bool):  # kein 'yes' als true
                raise _bad_at(i, [key, j, "supported"], typ)
    title = payload.get("title")
    if isinstance(title, str) and not events.title_ok(title):
        raise _bad_at(i, ["title"], "title")
    affected = payload.get("affected")
    if affected is not None:
        if not isinstance(affected, list):
            raise _bad_at(i, ["affected"], "subject")
        for j, a in enumerate(affected):
            if not isinstance(a, str) or not a or len(a) > 600:
                raise _bad_at(i, ["affected", j], "subject")
    if kind == "d.finding.create" and payload.get("status") == "final" and payload.get("severity") is None:
        raise _bad_at(i, ["severity"], "severity_required")


def _validate(i: int, kind: str, payload: dict[str, Any], profile: str, alone: bool) -> dict[str, Any]:
    """Nutzlast prüfen und normalisieren. Reihenfolge der Fehler: 422, 403, 501."""
    if kind == OLD_FINDING:
        raise _bad(i, "kind", "kind")  # web-api.md 18.5: nur noch d.finding.*
    if not kind.startswith("d.") or kind not in events.KINDS or kind in _CTX:
        raise _bad(i, "kind", "kind")
    if kind in CRITICAL:
        raise ApiError("policy")
    if kind == "d.automode.set":
        raise ApiError("policy" if profile != "customer" else "not_implemented")
    if kind in LATER:
        raise ApiError("not_implemented")
    if kind not in WRITABLE:
        raise _bad(i, "kind", "kind")
    if kind == "d.unit.distrust" and not alone:
        raise _bad(i, "kind", "distrust_alone")
    if not _ints_fit(payload):
        raise _bad(i, "payload", "int_range")
    if kind in FINDING_KINDS:
        _finding_shape(i, kind, payload)
    if kind == "d.suggestion.done" and not payload.get("basis"):
        raise _bad_at(i, ["basis"], "basis_required")
    if kind == "d.keystep.mark":
        if "terminal_id" in payload or "stream_off" in payload:
            raise _bad(i, "payload", "extra_forbidden")
        host = payload.get("host")
        if isinstance(host, str):
            try:
                payload = {**payload, "host": normalize_host(host)}
            except ValueError:
                raise _bad(i, "payload", "host") from None
    try:
        header = events.validate_header(kind, payload)
    except ValidationError as exc:
        detail = validation_detail(exc.errors())
        for d in detail:
            d["loc"] = ["body", "decisions", i, "payload", *d["loc"]]
        raise ApiError("validation", detail) from None
    except (ValueError, TypeError):
        raise _bad(i, "payload", "value_error") from None
    if kind == "d.conflict.resolve" and header.get("choice") is None and not header.get("keep_open"):
        raise _bad(i, "payload", "nothing_to_decide")
    if kind in ("d.note.set",) and len(str(header.get("text") or "")) > 100_000:
        raise _bad(i, "payload", "too_long")
    return header


def _entity(conn: Any, subject: Any) -> str | None:
    if not isinstance(subject, str) or not subject or len(subject) > 600:
        return None
    if conn.execute("SELECT 1 FROM entity WHERE entity_id = ?", (subject,)).fetchone() is not None:
        return subject
    ident = normalize_identifier(subject) or host_identifier(subject)
    if ident is None:
        return None
    row = conn.execute("SELECT entity_id FROM identifier WHERE key = ?", (ident,)).fetchone()
    if row is None or row[0] is None:
        return None
    ok = conn.execute("SELECT 1 FROM entity WHERE entity_id = ?", (row[0],)).fetchone()
    return str(row[0]) if ok else None


class _Rec:
    """Journal-Record in der Form, die :func:`ariadne.ingest.proj_findings.fold` erwartet."""

    __slots__ = ("seq", "id", "kind", "payload", "ts")

    def __init__(self, rec: Any) -> None:
        self.seq, self.id, self.kind = rec.seq, rec.id, rec.kind
        self.payload, self.ts = dict(rec.header), rec.ts_utc_ns


class _Findings:
    """Stand der Findings für die Prüfung einer Anfrage (alle oder keiner): aus den Entscheiden im
    Journal (nicht aus der Projektion, die erst nach der nächsten Auswertung nachzieht), danach jeder
    Entscheid der Anfrage der Reihe nach angewandt."""

    def __init__(self, conn: Any, journal: Any) -> None:
        self.conn = conn
        recs = [_Rec(r) for r in journal.iter_events(kinds=[*FINDING_KINDS, "d.revoke"])]
        self.state: dict[str, dict[str, Any]] = {
            fid: {
                "deleted": f.deleted or not f.exists,
                "severity": f.severity,
                "status": f.status,
                "ev": set(f.evidence),
            }
            for fid, f in fold(recs).items()
        }
        self.creates_here = False

    def ref_ok(self, ev: Any) -> bool:
        if not isinstance(ev, dict):
            return False
        ck, uid = ev.get("claim_key"), ev.get("unit_id")
        if ck is not None:
            row = self.conn.execute("SELECT 1 FROM claim WHERE claim_key = ?", (ck,)).fetchone()
            if row is None:
                return False
        if uid is not None and not _unit_known(self.conn, uid):
            return False
        return ck is not None or uid is not None

    def live(self, i: int, fid: Any) -> dict[str, Any]:
        f = self.state.get(str(fid))
        if f is None:
            if self.creates_here:
                raise _bad_at(i, ["finding_id"], "same_request")
            raise ApiError("conflict")
        if f["deleted"]:
            raise ApiError("conflict")
        return f

    def check(self, i: int, kind: str, h: dict[str, Any]) -> None:
        for a in h.get("affected") or ():
            if entity_of_subject(self.conn, a) is None:
                raise ApiError("conflict")
        if kind == "d.finding.create":
            for ev in h.get("evidence") or ():
                if not self.ref_ok(ev):
                    raise ApiError("conflict")
            if h.get("created_from") is not None and not self.ref_ok(h["created_from"]):
                raise ApiError("conflict")
            self.creates_here = True
            return
        f = self.live(i, h.get("finding_id"))
        if kind == "d.finding.update":
            severity = h.get("severity", f["severity"])
            status = h.get("status", f["status"])
            if status == "final" and severity is None:
                raise _bad_at(i, ["severity"], "severity_required")
            f["severity"], f["status"] = severity, status
        elif kind == "d.finding.evidence.add":
            if not self.ref_ok(h):
                raise ApiError("conflict")
            eid = evidence_id(h.get("claim_key"), h.get("unit_id"), h.get("lines"))
            if eid in f["ev"]:
                raise ApiError("conflict")  # dieser Beleg hängt schon am Finding
            f["ev"].add(eid)
        elif kind == "d.finding.evidence.remove":
            eid = str(h.get("evidence_id"))
            if eid not in f["ev"]:
                raise ApiError("conflict")
            f["ev"].discard(eid)
        elif kind == "d.finding.delete":
            f["deleted"] = True


def _unit_known(conn: Any, unit_id: Any) -> bool:
    if not isinstance(unit_id, str):
        return False
    for table in ("unit", "obs_unit"):
        try:
            if conn.execute(f"SELECT 1 FROM {table} WHERE unit_id = ?", (unit_id,)).fetchone():  # noqa: S608
                return True
        except Exception as exc:  # noqa: BLE001 - Tabelle fehlt (nur Projektion)
            if "no such table" not in str(exc):
                raise
    return False


def _dup_key(kind: str, h: dict[str, Any]) -> tuple[str, ...] | None:
    """Bezug eines Entscheids, der in einer Anfrage nur einmal vorkommen darf (Korrektur K5)."""
    if kind in ("d.suggestion.done", "d.suggestion.dismiss"):
        return ("suggestion", str(h.get("suggestion_key")))
    if kind == "d.finding.evidence.remove":
        return ("evidence", str(h.get("finding_id")), str(h.get("evidence_id")))
    if kind == "d.finding.delete":
        return ("delete", str(h.get("finding_id")))
    if kind == "d.revoke":
        return ("revoke", str(h.get("decision_id")))
    return None


def _check_refs(
    conn: Any,
    journal: Any,
    items: list[tuple[str, dict[str, Any]]],
    profile: str = "lab",
    positions: list[int] | None = None,
    scope: Any = None,
) -> None:
    """Bezüge gegen den Stand prüfen; Fehler: 409 ``conflict`` (oder 403 bei kritischen Zielen,
    422 bei ``severity_required``, ``same_request`` und ``basis_required``). ``positions`` nennt die
    Stelle jedes Eintrags in der Anfrage (für ``loc``)."""
    revoked: set[str] | None = None
    findings: _Findings | None = None
    seen: set[tuple[str, ...]] = set()
    for kind, h in items:  # Korrektur K5: derselbe Bezug zweimal in einer Anfrage ist ein Konflikt
        ref = _dup_key(kind, h)
        if ref is not None:
            if ref in seen:
                raise ApiError("conflict")
            seen.add(ref)
    for n, (kind, h) in enumerate(items):
        i = positions[n] if positions is not None and n < len(positions) else n
        if kind in FINDING_KINDS:
            if findings is None:
                findings = _Findings(conn, journal)
            findings.check(i, kind, h)
            continue
        if kind in ("d.suggestion.done", "d.suggestion.dismiss"):
            try:
                # Zuerst E130 (Name zu IP im Scope) und die KI-Denkanstösse (eigene Schlüssel),
                # sonst die Regel-Engine
                if scope is not None and scope_suggest.check_decision(conn, scope, kind, h):
                    continue
                if not ai_store.check_decision(conn, kind, h):
                    rules_api.check_decision(conn, kind, h, profile=profile)
            except rules_api.RuleRefError as exc:
                if exc.code == "basis_required":
                    raise _bad_at(i, ["basis"], "basis_required") from None
                raise ApiError("conflict") from None
            continue
        if kind in ("d.claim.confirm", "d.claim.reject", "d.claim.edit"):
            row = conn.execute(
                "SELECT lane_reason FROM claim WHERE claim_key = ?", (h["claim_key"],)
            ).fetchone()
            if row is None or (kind != "d.claim.reject" and row[0] == "own_address"):
                raise ApiError("conflict")
        elif kind == "d.conflict.resolve":
            row = conn.execute(
                "SELECT claim_keys_json FROM conflict WHERE conflict_key = ?", (h["conflict_key"],)
            ).fetchone()
            if row is None:
                raise ApiError("conflict")
            choice = h.get("choice")
            if choice is not None:
                keys = [k for k in loads(row[0], []) or [] if isinstance(k, str)]
                texts = (
                    [
                        str(r[0])
                        for r in conn.execute(
                            "SELECT value_text FROM v_claim WHERE claim_key IN "  # noqa: S608
                            f"({','.join('?' * len(keys))})",
                            keys,
                        )
                    ]
                    if keys
                    else []
                )
                if choice not in keys and texts.count(choice) != 1:
                    raise ApiError("conflict")
        elif kind in ("d.entity.merge", "d.entity.split"):
            known = set()
            for x in h.get("identifiers") or ():
                ident = normalize_identifier(str(x)) or host_identifier(str(x))
                if ident and conn.execute("SELECT 1 FROM identifier WHERE key = ?", (ident,)).fetchone():
                    known.add(ident)
            if len(known) < 2:
                raise ApiError("conflict")
        elif kind in _SUBJECT:
            if _entity(conn, h.get("subject")) is None:
                raise ApiError("conflict")
        elif kind == "d.terminal.label":
            tid = h.get("terminal_id")
            if (
                conn.execute("SELECT 1 FROM seg_term WHERE terminal_id = ?", (tid,)).fetchone() is None
                and conn.execute("SELECT 1 FROM unit WHERE terminal_id = ? LIMIT 1", (tid,)).fetchone()
                is None
            ):
                raise ApiError("conflict")
        elif kind == "d.revoke":
            target = journal.get_by_id(str(h["decision_id"]))
            if target is None or target.layer != "decision":
                raise ApiError("conflict")
            if target.kind in CRITICAL:
                raise ApiError("policy")
            if revoked is None:
                revoked = {str(r.header.get("decision_id")) for r in journal.iter_events(kinds=["d.revoke"])}
            if h["decision_id"] in revoked:
                raise ApiError("conflict")  # schon rückgängig gemacht


def _canon(header: dict[str, Any]) -> str:
    return json.dumps(header, sort_keys=True, ensure_ascii=False, default=str)


def _match(records: list[Any], items: list[tuple[str, dict[str, Any]]]) -> list[Any] | None:
    """Die eigenen Records im Commit (die letzten passenden, in Reihenfolge)."""
    out: list[Any] = []
    j = len(records) - 1
    for kind, header in reversed(items):
        want = _canon(header)
        while j >= 0 and not (
            records[j].kind == kind
            and records[j].origin == "webui"
            and _canon(dict(records[j].header)) == want
        ):
            j -= 1
        if j < 0:
            return None
        out.append(records[j])
        j -= 1
    out.reverse()
    return out


def add_routes(router: APIRouter, api: Api) -> None:
    cache = IdempotencyCache()
    # Korrektur K5: Prüfen und Schreiben eines Projekts nacheinander. Ohne Sperre bestanden zwei
    # gleichzeitige Anfragen (zwei Tabs, Doppelklick) beide die Prüfung, bevor eine schrieb.
    locks: dict[str, asyncio.Lock] = {}

    @router.post("/p/{pid}/decisions", name="decisions", status_code=201)
    async def post_decisions(pid: str, body: DecisionRequest) -> Response:
        p = api.project(pid)
        profile = p.info.profile
        alone = len(body.decisions) == 1
        validated = [
            _validate(i, d.kind, dict(d.payload), profile, alone) for i, d in enumerate(body.decisions)
        ]
        lock = locks.setdefault(p.info.id, asyncio.Lock())
        async with lock:
            api.same(p)
            return await _post_locked(p, pid, profile, body, validated)

    async def _post_locked(
        p: Any, pid: str, profile: str, body: DecisionRequest, validated: list[dict[str, Any]]
    ) -> Response:
        results: list[dict[str, Any] | None] = [cache.get(p.info.id, d.client_ref) for d in body.decisions]
        todo = [i for i, r in enumerate(results) if r is None]
        if not todo:
            return await api.respond({"results": results}, 201)
        first = body.decisions[todo[0]]
        if first.kind == "d.unit.distrust":
            h = validated[todo[0]]
            args: dict[str, Any] = {"ref": h["cmd_id"], "origin": "webui"}
            if h.get("reason"):
                args["reason"] = h["reason"]
            res = await api.call("unit.distrust", args)
            api.same(p)
            out = {
                "decision_id": res.get("decision_id"),
                "seq": None,
                "client_ref": first.client_ref,
                "effect": {
                    "rejected": int(res.get("rejected") or 0),
                    "weakened": int(res.get("weakened") or 0),
                },
            }
            cache.put(p.info.id, first.client_ref, out)
            return await api.respond({"results": [out]}, 201)
        items = [(body.decisions[i].kind, validated[i]) for i in todo]
        if any(k in ("d.suggestion.done", "d.suggestion.dismiss") for k, _h in items):
            await api.sync(p)  # die Regel-Engine liest frühere Entscheide aus der Projektion
        matcher = ScopeMatcher.from_settings(p.settings, p.settings_version)
        await api.query_journal(p, lambda c, j: _check_refs(c, j, items, profile, todo, matcher))
        # Ab hier kein await: Projekt prüfen, einreihen, ein Commit (E70)
        d = api.daemon
        if d.project is not p or p.info.id != pid:
            raise ApiError("project_mismatch")
        try:
            for kind, header in items:
                d.submit(AppendItem(kind, header, origin="webui"))
        except Exception:
            raise ApiError("project_mismatch") from None
        records = d.flush()
        mine = _match(records, items)
        if mine is None:
            raise ApiError("internal")  # Commit fehlgeschlagen; der Writer schreibt später nach
        for i, rec in zip(todo, mine, strict=True):
            out = {
                "decision_id": rec.id,
                "seq": rec.seq,
                "client_ref": body.decisions[i].client_ref,
                "effect": None,
            }
            cache.put(p.info.id, body.decisions[i].client_ref, out)
            results[i] = out
        return await api.respond({"results": results}, 201)

    @router.post("/p/{pid}/decisions/confirm-group", name="confirm_group")
    async def confirm_group(pid: str, body: ConfirmGroupRequest) -> Response:
        p = api.project(pid)
        res = await api.call("claim.confirm", {"ref": body.group_ref, "origin": "webui"})
        api.same(p)
        excluded = res.get("excluded") if isinstance(res.get("excluded"), dict) else {}
        keys = (
            "own_address",
            "context",
            "out_of_scope",
            "conflict",
            "merge",
            "ai",
            "suspect",
            "low_confidence",
        )
        return await api.respond(
            {
                "confirmed": int(res.get("confirmed") or 0),
                "excluded": {k: int(excluded.get(k) or 0) for k in keys},
            }
        )
