"""KI-Denkanstösse lesen und Entscheide dazu prüfen (``docs/web-api.md`` 18.6, Herkunft ``ai``).

Speicher ist das Journal: Jeder Auftrag schreibt einen Entscheid ``d.ai.denkanstoss`` mit den geprüften
Einträgen. Die Projektion kopiert ihn in die Tabelle ``decision`` (übersteht Reparse); ``d.revoke`` auf
den Entscheid blendet alle seine Einträge aus. Der Zustand jedes Eintrags folgt wie bei den Regeln aus
``d.suggestion.done`` und ``d.suggestion.dismiss`` (:mod:`ariadne.rules.state`); ``basis`` ist pro Eintrag
fest, «erledigt» bleibt also erledigt.

Für die Integration (``/next``, ``/suggestions``, ``POST /decisions``):

* :func:`suggestions` liefert ``Suggestion``-Objekte mit ``origin: 'ai'`` (nur lesend, im Thread der
  Auswertung, mit Grenzen);
* :func:`check_decision` prüft ``d.suggestion.*`` auf einen KI-Schlüssel und gibt ``False`` zurück, wenn
  der Schlüssel keiner KI gehört (dann prüft die Regel-Engine).

Vorlagen rendert der Server bei jedem Lesen mit den aktuellen Werten der Projektion und den Encodern der
Regeln (E68); bekannte Secret-Werte vom Ziel sind maskiert.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ariadne.rules.api import RuleRefError
from ariadne.rules.engine import _evidence, _scope, _source_rows, evaluate
from ariadne.rules.facts import ClaimRef, Facts
from ariadne.rules.state import load_marks, state_of
from ariadne.rules.templates import TEMPLATES, render
from ariadne.rules.text import iso, mask_known, vis

__all__ = [
    "suggestions",
    "check_decision",
    "key_of",
    "basis_of",
    "records",
    "done_titles",
    "RULE_ID",
    "LIMIT",
]

RULE_ID = "KI"
LIMIT = 200
_ROWS = 500
_PREDICATES = ("service.product", "service.version", "service.name")
_SUSPECT = frozenset({"shell_meta", "control", "newline", "non_ascii"})


def _h(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "surrogatepass")).hexdigest()


def key_of(call_id: str, idx: int) -> str:
    return "sg:" + _h("ai", call_id, str(idx))[:24]


def basis_of(call_id: str, idx: int) -> str:
    return _h("basis", "ai", call_id, str(idx))[:16]


def records(conn: Any) -> list[tuple[int, str, int | None, dict[str, Any]]]:
    """Aktive ``d.ai.denkanstoss`` (ohne widerrufene): ``(seq, decision_id, ts_ns, payload)``,
    jüngste zuletzt."""
    rows = conn.execute(
        "SELECT seq, id, kind, payload_json, ts FROM decision WHERE kind IN ('d.ai.denkanstoss', 'd.revoke') "
        "ORDER BY seq DESC LIMIT ?",
        (_ROWS * 4,),
    ).fetchall()
    revoked: set[str] = set()
    out: list[tuple[int, str, int | None, dict[str, Any]]] = []
    for seq, did, kind, payload, ts in rows:  # jüngste zuerst: ein späteres d.revoke gilt
        try:
            data = json.loads(payload) if isinstance(payload, str) else {}
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            continue
        if kind == "d.revoke":
            if str(did) not in revoked and isinstance(data.get("decision_id"), str):
                revoked.add(data["decision_id"])
            continue
        if str(did) in revoked:
            continue
        out.append((int(seq), str(did), ts if isinstance(ts, int) else None, data))
        if len(out) >= _ROWS:
            break
    out.reverse()
    return out


class _Entry:
    __slots__ = ("key", "basis", "item", "rec", "idx", "state", "decision_id")

    def __init__(
        self,
        key: str,
        basis: str,
        item: dict[str, Any],
        rec: tuple[int, str, int | None, dict[str, Any]],
        idx: int,
    ) -> None:
        self.key, self.basis, self.item, self.rec, self.idx = key, basis, item, rec, idx
        self.state = "open"
        self.decision_id: str | None = None


def _entries(conn: Any) -> list[_Entry]:
    marks = load_marks(conn)
    out: list[_Entry] = []
    for rec in records(conn):
        payload = rec[3]
        call_id = payload.get("call_id")
        items = payload.get("items")
        if not isinstance(call_id, str) or not isinstance(items, list):
            continue
        for idx, item in enumerate(items[:4]):
            if not isinstance(item, dict):
                continue
            e = _Entry(key_of(call_id, idx), basis_of(call_id, idx), item, rec, idx)
            e.state, e.decision_id = state_of(marks, [e.key], e.basis)
            out.append(e)
    return out


def done_titles(conn: Any) -> list[tuple[str, str]]:
    """(Zustand, Titel) erledigter und verworfener KI-Denkanstösse (für das Lagebild)."""
    return [
        (e.state, str(e.item.get("title") or "")) for e in _entries(conn) if e.state in ("done", "dismissed")
    ]


def _refs_for(f: Facts, item: dict[str, Any]) -> list[ClaimRef]:
    keys = item.get("claim_keys") if isinstance(item.get("claim_keys"), list) else []
    sid, hid = item.get("service_id"), item.get("host_id")
    owner = f.services.get(sid) if isinstance(sid, str) else None
    if owner is None and isinstance(hid, str):
        owner = f.hosts.get(hid)  # type: ignore[assignment]
    if owner is None:
        return []
    out: list[ClaimRef] = []
    for claims in owner.claims.values():
        for c in claims:
            if c.claim_key in keys and c not in out:
                out.append(c)
    return out[:5]


def _slots(f: Facts, hid: Any, sid: Any) -> dict[str, object]:
    h = f.hosts.get(hid) if isinstance(hid, str) else None
    s = f.services.get(sid) if isinstance(sid, str) else None
    if h is None and s is not None:
        h = f.hosts.get(s.host_id)
    slots: dict[str, object] = {}
    if h is not None and h.ip:
        slots["host.ip"] = h.ip
    if s is not None:
        slots["service.port"] = s.port
        prod, ver = s.value("service.product"), s.value("service.version")
        if prod:
            slots["service.product"] = " ".join(prod.split()[:3])
        if ver:
            slots["service.version"] = ver.split()[0] if ver.split() else ver
        if h is not None and h.ip:
            name = (s.name or "").lower()
            sch = "https" if ("https" in name or "ssl" in name or s.port in (443, 8443)) else "http"
            host_part = f"[{h.ip}]" if ":" in h.ip else h.ip
            slots["service.url"] = f"{sch}://{host_part}:{s.port}/"
    return {k: (mask_known(v, f.known_secrets) if isinstance(v, str) else v) for k, v in slots.items()}


def _text(v: Any, known: list[str]) -> tuple[str, bool]:
    return vis(mask_known(str(v or ""), known))


def _json(conn: Any, f: Facts, e: _Entry, sources: dict[str, Any], profile: str) -> dict[str, Any]:
    it = e.item
    known = f.known_secrets
    title, ctrl = _text(it.get("title"), known)
    reason, ctrl_r = _text(it.get("reason"), known)
    flags = {"ai"} | {x for x in (it.get("flags") or []) if x == "injection_suspect"}
    templates: list[dict[str, Any]] = []
    scope = _scope(f)
    if profile == "lab":
        for t in (it.get("templates") or [])[:3]:
            if not isinstance(t, dict) or t.get("template_id") not in TEMPLATES:
                continue
            slots = _slots(f, t.get("host_id"), t.get("service_id"))
            ip = slots.get("host.ip")
            r = render(TEMPLATES[t["template_id"]], slots, scope, ipv6=isinstance(ip, str) and ":" in ip)
            if r["blocked_reason"] in _SUSPECT:
                flags.add("injection_suspect")
            templates.append(r)
    hid, sid = it.get("host_id"), it.get("service_id")
    h = f.hosts.get(hid) if isinstance(hid, str) else None
    host_label = vis(mask_known(h.label, known))[0] if h is not None else None
    payload = e.rec[3]
    model = payload.get("model") if isinstance(payload.get("model"), str) else ""
    title_parts = [{"text": title, "target": False}]
    return {
        "suggestion_key": e.key,
        "origin": "ai",
        "rule_id": RULE_ID,
        "goal_id": it.get("goal_id") if isinstance(it.get("goal_id"), str) else None,
        "kind": it.get("kind") if it.get("kind") in ("hypothesis", "question", "goal") else "hypothesis",
        "title": title,
        "ctrl": ctrl,
        "title_parts": title_parts,
        "host_id": hid if isinstance(hid, str) else None,
        "service_id": sid if isinstance(sid, str) else None,
        "host_label": host_label,
        "reason": reason,
        "ctrl_reason": ctrl_r,
        "evidence": _evidence(conn, f, _refs_for(f, it), sources),
        "stages": {
            "question": _text(it.get("question"), known)[0],
            "direction": _text(it.get("direction"), known)[0],
        },
        "templates": templates,
        "items": [],  # einheitliche Form mit den Regeln (E119); KI-Denkanstösse haben keine Dienstliste
        "state": e.state,
        "decision_id": e.decision_id,
        "basis": e.basis,
        "flags": sorted(flags),
        "ts": iso(e.rec[2]),
        "ai": {
            "model": vis(model)[0],
            "confirmed_if": _text(it.get("confirmed_if"), known)[0],
            "refuted_if": _text(it.get("refuted_if"), known)[0],
            "job_id": str(payload.get("job_id") or ""),
            "created_at": iso(e.rec[2]),
        },
    }


def suggestions(
    conn: Any, *, profile: str, state: str = "open", limit: int = 50
) -> tuple[list[dict[str, Any]], bool]:
    """KI-Denkanstösse mit Zustand ``state`` (``open``, ``done``, ``dismissed``, ``all``), jüngste zuerst."""
    if state not in ("open", "done", "dismissed", "all"):
        raise ValueError("state")
    chosen = [e for e in reversed(_entries(conn)) if state == "all" or e.state == state]
    n = max(0, int(limit))
    if not chosen:
        return [], False
    f, _built = evaluate(conn, profile=profile)
    picked = chosen[:n]
    keys = sorted({r.claim_key for e in picked for r in _refs_for(f, e.item)})
    sources = _source_rows(conn, keys)
    return [_json(conn, f, e, sources, profile) for e in picked], len(chosen) > n


def check_decision(conn: Any, kind: str, header: dict[str, Any]) -> bool:
    """Prüft ``d.suggestion.done``/``dismiss`` auf einen KI-Schlüssel wie
    :func:`ariadne.rules.api.check_decision`.

    ``False``: Schlüssel gehört keinem KI-Denkanstoss (die Regel-Engine prüft weiter). Sonst ``True`` oder
    :class:`~ariadne.rules.api.RuleRefError` (``conflict``, ``basis_required``)."""
    if kind not in ("d.suggestion.done", "d.suggestion.dismiss"):
        return False
    key = header.get("suggestion_key")
    match = next((e for e in _entries(conn) if e.key == key), None)
    if match is None:
        return False
    if kind == "d.suggestion.dismiss":
        if match.state == "dismissed":
            raise RuleRefError("conflict")
        return True
    if not header.get("basis"):
        raise RuleRefError("basis_required")
    if header.get("basis") != match.basis or match.state != "open":
        raise RuleRefError("conflict")
    return True
