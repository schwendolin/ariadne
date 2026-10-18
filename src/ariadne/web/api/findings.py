"""``GET /p/{pid}/findings`` und ``GET /p/{pid}/findings/{finding_id}`` (``docs/web-api.md`` 18.5, E113).

Die Findings liest die Route aus der Projektion (Tabellen ``finding`` und ``finding_evidence``, gebaut
von :mod:`ariadne.ingest.proj_findings` aus den Entscheiden ``d.finding.*``). Gelöschte Findings
erscheinen nicht (404), behalten aber ihre Nummer. Texte (Titel, Beschreibung, Massnahme) sind
Markdown ohne HTML; sie können Zieldaten enthalten und gehen wie jeder Zielwert durch die Tasche
(sichtbare Steuerzeichen, ``ctrl``) und den Redaktor. Labels von Belegen enthalten Befehlstexte und
sind darum wie diese maskiert (SEC-W1); eine Uhrzeit steht nie im Label, sondern in ``ts``.

Schreiben geht nur über ``POST /decisions`` (:mod:`.decisions`). Besitzer: Teil «backend-ui».
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter
from starlette.responses import Response

from ariadne.ingest.proj_build import display
from ariadne.ingest.queries import entity_of_subject, term_refs
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.text import Bag, iso
from ariadne.web.api.views import commands_for, loads, term_ref, with_secrets

__all__ = ["add_routes", "findings_list", "finding_detail", "FINDINGS_MAX"]

FINDINGS_MAX = 500
_LABEL_TITLE_MAX = 80
_COLS = (
    "finding_id, ordinal, title, severity, status, affected_json, description, remediation, attack_json, "
    "cves_json, created_from_json, deleted, created_ts, updated_ts, history_json"
)
_NAMES = [c.strip() for c in _COLS.split(",")]
_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _rows(conn: Any, where: str, params: tuple[Any, ...], limit: int) -> list[dict[str, Any]]:
    sql = f"SELECT {_COLS} FROM finding WHERE deleted = 0 AND {where} ORDER BY ordinal LIMIT ?"  # noqa: S608
    return [dict(zip(_NAMES, r, strict=True)) for r in conn.execute(sql, (*params, int(limit)))]


def _evidence_rows(conn: Any, ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for fid in ids:
        out[fid] = [
            {
                "evidence_id": r[0],
                "claim_key": r[1],
                "unit_id": r[2],
                "lines": [int(r[3]), int(r[4])] if r[3] is not None and r[4] is not None else None,
                "state": r[5],
                "added_ts": r[6],
                "decision_id": r[7],
            }
            for r in conn.execute(
                "SELECT evidence_id, claim_key, unit_id, line_start, line_end, state, added_ts, decision_id "
                "FROM finding_evidence WHERE finding_id = ? ORDER BY pos LIMIT 200",
                (fid,),
            )
        ]
    return out


def _affected(conn: Any, subjects: Any, bag: Bag) -> list[dict[str, Any]]:
    """«192.168.56.101:21 ftp» für einen Service, das Label des Hosts für einen Host."""
    out: list[dict[str, Any]] = []
    for subj in subjects if isinstance(subjects, list) else []:
        if not isinstance(subj, str):
            continue
        b = bag.new()
        eid = entity_of_subject(conn, subj) or subj
        label: str | None = None
        svc = conn.execute(
            "SELECT host_id, proto, port, name FROM v_service WHERE service_id = ?", (eid,)
        ).fetchone()
        if svc is not None:
            host = conn.execute("SELECT label FROM v_host WHERE host_id = ?", (svc[0],)).fetchone()
            host_label = host[0] if host and host[0] else display(str(svc[0]))
            label = f"{host_label}:{svc[2]}" + (f" {svc[3]}" if svc[3] else "")
            if svc[1] and svc[1] != "tcp":
                label += f" ({svc[1]})"
        else:
            host = conn.execute("SELECT label FROM v_host WHERE host_id = ?", (eid,)).fetchone()
            label = host[0] if host and host[0] else display(eid)
        out.append({"subject": b(eid) or "", "label": b(label) or "", "ctrl": b.ctrl})
    return out


def _warnings(f: Mapping[str, Any], evidence: list[dict[str, Any]]) -> list[str]:
    out = []
    states = {e["state"] for e in evidence}
    if "distrusted" in states:
        out.append("evidence_distrusted")
    if "missing" in states:
        out.append("evidence_missing")
    if not evidence:
        out.append("no_evidence")
    if f.get("severity") not in _SEVERITIES:
        out.append("no_severity")
    return out


def _summary(conn: Any, f: Mapping[str, Any], evidence: list[dict[str, Any]], bag: Bag) -> dict[str, Any]:
    b = bag.new()
    severity = f.get("severity") if f.get("severity") in _SEVERITIES else None
    out = {
        "finding_id": f["finding_id"],
        "ordinal": int(f["ordinal"]),
        "title": b(f.get("title")) or "",
        "severity": severity,
        "status": "final" if f.get("status") == "final" else "draft",
        "affected": _affected(conn, loads(f.get("affected_json"), []), bag),
        "evidence_count": len(evidence),
        "warnings": _warnings(f, evidence),
        "created_at": iso(f.get("created_ts")),
        "updated_at": iso(f.get("updated_ts")),
    }
    out["ctrl"] = b.ctrl
    return out


def findings_list(conn: Any, bag: Bag) -> dict[str, Any]:
    rows = _rows(conn, "1 = 1", (), FINDINGS_MAX)
    ev = _evidence_rows(conn, [str(r["finding_id"]) for r in rows])
    return {"findings": [_summary(conn, r, ev.get(str(r["finding_id"]), []), bag) for r in rows]}


def _short(text: str | None) -> str:
    t = (text or "").strip()
    return t if len(t) <= _LABEL_TITLE_MAX else t[: _LABEL_TITLE_MAX - 1] + "…"


def _lines_label(lines: Any) -> str | None:
    if not isinstance(lines, list | tuple) or len(lines) != 2:
        return None
    a, b = int(lines[0]) + 1, int(lines[1]) + 1  # für Menschen ab 1 gezählt
    return f"Zeile {a}" if a == b else f"Zeilen {a} bis {b}"


def _ref_view(
    conn: Any,
    claim_key: Any,
    unit_id: Any,
    lines: Any,
    bag: Bag,
    refs: Mapping[str, Mapping[str, Any]],
    units: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None, str | None, bool]:
    """EvidenceRef mit Label, dazu TermRef, Zeit der Quelle und ``ctrl``."""
    b = bag.new()
    value: str | None = None
    unit: Mapping[str, Any] | None = units.get(unit_id) if isinstance(unit_id, str) else None
    ts: Any = None
    if isinstance(claim_key, str):
        row = conn.execute(
            "SELECT value_text, first_unit, first_ts, predicate FROM v_claim WHERE claim_key = ?",
            (claim_key,),
        ).fetchone()
        if row is not None:
            value = row[0]
            ts = row[2]
            if unit is None and isinstance(row[1], str):
                unit = units.get(row[1]) or (commands_for(conn, [row[1]]).get(row[1]))
    if unit is not None:
        ts = unit.get("ts_utc_ns") or ts
    tid = unit.get("terminal_id") if unit is not None else None
    tref = term_ref(tid, refs, bag) if isinstance(tid, str) else None
    parts: list[str] = []
    if tref is not None and tref.get("ordinal") is not None:
        parts.append(f"T{tref['ordinal']}" + (f" {tref['label']}" if tref.get("label") else ""))
    if unit is not None:
        raw = unit.get("cmd_text") or unit.get("path") or ("Segment" if unit.get("kind") == "segment" else "")
        title = _short(b.cmd(raw))
        if title:
            parts.append(title)
    ll = _lines_label(lines)
    if ll:
        parts.append(ll)
    if value:
        parts.append(_short(b(value)))
    if not parts:
        parts.append("Beleg nicht mehr vorhanden")
    ref = {
        "claim_key": claim_key if isinstance(claim_key, str) else None,
        "unit_id": b(unit_id) if isinstance(unit_id, str) else None,
        "lines": list(lines) if isinstance(lines, list | tuple) and len(lines) == 2 else None,
        "label": " · ".join(parts),
    }
    return ref, tref, iso(ts), b.ctrl


def finding_detail(conn: Any, finding_id: str, bag: Bag) -> dict[str, Any] | None:
    rows = _rows(conn, "finding_id = ?", (finding_id,), 1)
    if not rows:
        return None
    f = rows[0]
    bag = with_secrets(bag, conn)  # Labels enthalten Befehlstexte (SEC-W1)
    evidence = _evidence_rows(conn, [finding_id]).get(finding_id, [])
    out = _summary(conn, f, evidence, bag)
    refs = term_refs(conn)
    units = commands_for(conn, [str(e["unit_id"]) for e in evidence if isinstance(e.get("unit_id"), str)])
    ev_out = []
    for e in evidence:
        ref, tref, ts, ctrl = _ref_view(conn, e["claim_key"], e["unit_id"], e["lines"], bag, refs, units)
        ev_out.append(
            {
                "evidence_id": e["evidence_id"],
                "ref": ref,
                "label": ref["label"],
                "ctrl": ctrl,
                "terminal": tref,
                "ts": ts,
                "state": e["state"] if e["state"] in ("ok", "distrusted", "missing") else "missing",
                "added_at": iso(e["added_ts"]),
                "decision_id": e["decision_id"],
            }
        )
    created_from = None
    cf = loads(f.get("created_from_json"), None)
    if isinstance(cf, dict):
        cunits = commands_for(conn, [cf["unit_id"]]) if isinstance(cf.get("unit_id"), str) else {}
        created_from, _t, _ts, _c = _ref_view(
            conn, cf.get("claim_key"), cf.get("unit_id"), cf.get("lines"), bag, refs, cunits
        )
    b = bag.new()

    def refs_of(key: str) -> list[dict[str, Any]]:
        items = loads(f.get(key), []) or []
        return [
            {
                "id": b(r.get("id")) or "",
                "supported": bool(r.get("supported")),
                "hypothesis": bool(r.get("hypothesis", True)),
            }
            for r in items
            if isinstance(r, dict) and isinstance(r.get("id"), str)
        ]

    out.update(
        {
            "description": b(f.get("description")) or "",
            "remediation": b(f.get("remediation")) or "",
            "attack": refs_of("attack_json"),
            "cves": refs_of("cves_json"),
            "evidence": ev_out,
            "created_from": created_from,
            "history": [
                {"decision_id": h.get("decision_id"), "kind": h.get("kind"), "ts": iso(h.get("ts"))}
                for h in loads(f.get("history_json"), []) or []
                if isinstance(h, dict)
            ],
        }
    )
    out["ctrl"] = bool(out["ctrl"] or b.ctrl)
    return out


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/findings", name="findings")
    async def get_findings(pid: str) -> Response:
        p = api.project(pid)
        bag = api.bag()
        return await api.respond(await api.query(p, lambda c: findings_list(c, bag)))

    @router.get("/p/{pid}/findings/{finding_id}", name="finding")
    async def get_finding(pid: str, finding_id: str) -> Response:
        p = api.project(pid)
        if not (8 <= len(finding_id) <= 64) or not all(ch in "0123456789abcdefABCDEF-" for ch in finding_id):
            raise ApiError("not_found")
        bag = api.bag()
        res = await api.query(p, lambda c: finding_detail(c, finding_id, bag))
        if res is None:
            raise ApiError("not_found")
        return await api.respond(res)
