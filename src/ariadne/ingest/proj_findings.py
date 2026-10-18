"""Findings aus Entscheiden (E113, ``docs/web-api.md`` 18.5).

Ein Finding ist ein Urteil des Menschen über Belege. Es entsteht nur aus den Entscheiden
``d.finding.create``, ``d.finding.update``, ``d.finding.evidence.add``, ``d.finding.evidence.remove``
und ``d.finding.delete``; :func:`rebuild_findings` baut daraus bei jeder Neuberechnung der Projektion
die Tabellen ``finding`` und ``finding_evidence`` (aktive Entscheide in Journal-Reihenfolge, ohne
widerrufene). Weil die Entscheide im Journal stehen, übersteht ein Finding jeden Reparse.

* ``finding_id`` ist die ``decision_id`` des ``d.finding.create``; die Nummer (F1, F2 …) folgt der
  Reihenfolge aller Anlagen, auch gelöschter und widerrufener (gelöschte behalten ihre Nummer).
* Ein gelöschtes Finding bleibt als Zeile mit ``deleted = 1`` stehen (Nummer, Wiederherstellen per
  ``d.revoke`` auf den Löschentscheid); die Web-API zeigt es nicht.
* Belege: ``evidence_id`` = ``ev:`` + 16 Hex aus ``claim_key | unit_id | lines`` (stabil über
  Reparse). Zustand nach dem Reparse: ``missing`` (Claim oder Einheit nicht mehr da, Zeilen
  ausserhalb), ``distrusted`` (Claim verworfen oder nur aus misstrauten Befehlen, Einheit aus einem
  Befehl mit ``d.unit.distrust``), sonst ``ok``.
* ATT&CK und CVE sind Text. ``hypothesis`` ist wahr, ausser der Mensch hat den Eintrag als belegt
  markiert (``supported``) **und** das Finding hat mindestens einen Beleg im Zustand ``ok``.

Die Funktion liest nur ``claim``, ``claim_source``, ``unit``/``obs_unit`` und ``unit_distrust`` (alle
schon neu berechnet) und schreibt nur ihre zwei Tabellen. Schwere setzt nur der Mensch; hier wird
nichts geschätzt.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "FINDING_KINDS",
    "evidence_id",
    "FindingState",
    "fold",
    "rebuild_findings",
    "snapshot_rows",
    "evidence_state",
]

FINDING_KINDS = (
    "d.finding.create",
    "d.finding.update",
    "d.finding.evidence.add",
    "d.finding.evidence.remove",
    "d.finding.delete",
)
_FIELDS = ("title", "severity", "status", "affected", "description", "remediation", "attack", "cves")


def evidence_id(claim_key: Any, unit_id: Any, lines: Any) -> str:
    """Stabile Kennung eines Belegs (``ev:`` + 16 Hex)."""
    if isinstance(lines, list | tuple) and len(lines) == 2:
        ls = f"{int(lines[0])}-{int(lines[1])}"
    else:
        ls = ""
    raw = f"{claim_key or ''}|{unit_id or ''}|{ls}".encode()
    return "ev:" + hashlib.sha256(raw).hexdigest()[:16]


def _lines(v: Any) -> tuple[int, int] | None:
    if (
        isinstance(v, list | tuple)
        and len(v) == 2
        and all(isinstance(x, int) and not isinstance(x, bool) for x in v)
    ):
        a, b = int(v[0]), int(v[1])
        if 0 <= a <= b:
            return a, b
    return None


@dataclass
class Evidence:
    evidence_id: str
    claim_key: str | None
    unit_id: str | None
    lines: tuple[int, int] | None
    added_ts: int
    decision_id: str


@dataclass
class FindingState:
    """Zustand eines Findings nach den Entscheiden (ohne Belegzustand)."""

    finding_id: str
    ordinal: int
    title: str = ""
    severity: str | None = None
    status: str = "draft"
    affected: list[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    attack: list[dict[str, Any]] = field(default_factory=list)
    cves: list[dict[str, Any]] = field(default_factory=list)
    created_from: dict[str, Any] | None = None
    deleted: bool = False
    exists: bool = True  # False: Anlage widerrufen (nur die Nummer bleibt)
    created_ts: int = 0
    updated_ts: int = 0
    evidence: dict[str, Evidence] = field(default_factory=dict)  # Reihenfolge = Anlage
    history: list[dict[str, Any]] = field(default_factory=list)

    def apply_fields(self, payload: Mapping[str, Any]) -> None:
        for key in _FIELDS:
            if key not in payload or payload[key] is None:
                continue
            v = payload[key]
            if key in ("attack", "cves"):
                refs = [x for x in v if isinstance(x, Mapping) and isinstance(x.get("id"), str)]
                setattr(self, key, [_ref(x) for x in refs])
            elif key == "affected":
                self.affected = [str(x) for x in v if isinstance(x, str)][:50]
            else:
                setattr(self, key, str(v))


def _ref(x: Mapping[str, Any]) -> dict[str, Any]:
    return {"id": str(x["id"]), "supported": bool(x.get("supported"))}


def _evidence_from(payload: Mapping[str, Any], ts: int, decision_id: str) -> Evidence | None:
    ck = payload.get("claim_key") if isinstance(payload.get("claim_key"), str) else None
    uid = payload.get("unit_id") if isinstance(payload.get("unit_id"), str) else None
    if ck is None and uid is None:
        return None
    lines = _lines(payload.get("lines"))
    return Evidence(evidence_id(ck, uid, lines), ck, uid, lines, ts, decision_id)


def _revoked(decisions: Sequence[Any]) -> set[str]:
    revoked: set[str] = set()
    for d in reversed(decisions):
        if d.kind == "d.revoke" and d.id not in revoked:
            target = d.payload.get("decision_id")
            if isinstance(target, str):
                revoked.add(target)
    return revoked


def fold(decisions: Iterable[Any]) -> dict[str, FindingState]:
    """Findings aus den Entscheiden (``DecisionRow`` oder gleichwertig, in Journal-Reihenfolge).

    Entscheide, die nicht passen (unbekanntes oder gelöschtes Finding, unbekannter Beleg), haben
    keine Wirkung; die Web-API lehnt sie vorher mit 409 ab."""
    ds = sorted(decisions, key=lambda d: int(d.seq))
    revoked = _revoked(ds)
    out: dict[str, FindingState] = {}
    ordinal = 0
    for d in ds:
        if d.kind == "d.finding.create":
            ordinal += 1
            f = FindingState(str(d.id), ordinal, created_ts=int(d.ts), updated_ts=int(d.ts))
            out[f.finding_id] = f
            if d.id in revoked:
                f.exists = False
                continue
            f.apply_fields(d.payload)
            f.status = str(d.payload.get("status") or "draft")
            for e in d.payload.get("evidence") or ():
                if isinstance(e, Mapping):
                    ev = _evidence_from(e, int(d.ts), str(d.id))
                    if ev is not None and ev.evidence_id not in f.evidence:
                        f.evidence[ev.evidence_id] = ev
            cf = d.payload.get("created_from")
            if isinstance(cf, Mapping):
                ck = cf.get("claim_key") if isinstance(cf.get("claim_key"), str) else None
                uid = cf.get("unit_id") if isinstance(cf.get("unit_id"), str) else None
                if ck or uid:
                    f.created_from = {"claim_key": ck, "unit_id": uid, "lines": _lines(cf.get("lines"))}
            f.history.append({"decision_id": str(d.id), "kind": d.kind, "ts": int(d.ts)})
            continue
        if d.kind not in FINDING_KINDS or d.id in revoked:
            continue
        f = out.get(str(d.payload.get("finding_id")))
        if f is None or not f.exists or f.deleted:
            continue
        if d.kind == "d.finding.update":
            f.apply_fields(d.payload)
        elif d.kind == "d.finding.evidence.add":
            ev = _evidence_from(d.payload, int(d.ts), str(d.id))
            if ev is None or ev.evidence_id in f.evidence:
                continue
            f.evidence[ev.evidence_id] = ev
        elif d.kind == "d.finding.evidence.remove":
            if f.evidence.pop(str(d.payload.get("evidence_id")), None) is None:
                continue
        elif d.kind == "d.finding.delete":
            f.deleted = True
        f.updated_ts = int(d.ts)
        f.history.append({"decision_id": str(d.id), "kind": d.kind, "ts": int(d.ts)})
    return out


# --------------------------------------------------------------------------- Belegzustand


def evidence_state(
    conn: Any,
    claim_key: str | None,
    unit_id: str | None,
    lines: tuple[int, int] | None,
    distrusted_cmds: set[str],
) -> str:
    """``ok``, ``distrusted`` oder ``missing`` nach dem aktuellen Stand der Projektion."""
    state = "ok"
    if claim_key is not None:
        row = conn.execute("SELECT state FROM claim WHERE claim_key = ?", (claim_key,)).fetchone()
        if row is None:
            return "missing"
        if row[0] == "rejected":
            state = "distrusted"
        else:
            n, bad = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(distrusted), 0) FROM claim_source WHERE claim_key = ?",
                (claim_key,),
            ).fetchone()
            if int(n or 0) > 0 and int(bad or 0) >= int(n):
                state = "distrusted"
    if unit_id is not None:
        row = _unit(conn, unit_id)
        if row is None:
            return "missing"
        cmd_id, line_count = row
        if lines is not None and line_count is not None and lines[1] >= int(line_count):  # Zeilen nach pos
            return "missing"
        if isinstance(cmd_id, str) and cmd_id in distrusted_cmds:
            state = "distrusted"
    return state


def _unit(conn: Any, unit_id: str) -> tuple[Any, Any] | None:
    try:
        row = conn.execute(
            "SELECT u.cmd_id, (SELECT COUNT(*) FROM unit_line l WHERE l.unit_id = u.unit_id) FROM unit u "
            "WHERE u.unit_id = ?",
            (unit_id,),
        ).fetchone()
    except Exception as exc:  # noqa: BLE001 - Projektion ohne Pipeline-Tabellen (Tests)
        if "no such table" not in str(exc):
            raise
        row = None
    if row is not None:
        return row[0], row[1]
    row = conn.execute("SELECT cmd_id FROM obs_unit WHERE unit_id = ?", (unit_id,)).fetchone()
    return (row[0], None) if row is not None else None


def _hypothesis(refs: list[dict[str, Any]], any_ok: bool) -> list[dict[str, Any]]:
    return [{**r, "hypothesis": not (bool(r.get("supported")) and any_ok)} for r in refs]


# --------------------------------------------------------------------------- Schreiben


def rebuild_findings(conn: Any, decisions: Iterable[Any]) -> int:
    """Baut ``finding`` und ``finding_evidence`` neu. Gibt die Zahl der sichtbaren Findings zurück."""
    found = fold(decisions)
    distrusted = {str(r[0]) for r in conn.execute("SELECT cmd_id FROM unit_distrust")}
    conn.execute("DELETE FROM finding")
    conn.execute("DELETE FROM finding_evidence")
    visible = 0
    for f in found.values():
        states = []
        for ev in f.evidence.values():
            st = (
                evidence_state(conn, ev.claim_key, ev.unit_id, ev.lines, distrusted)
                if f.exists
                else "missing"
            )
            states.append(st)
            conn.execute(
                "INSERT INTO finding_evidence (finding_id, evidence_id, claim_key, unit_id, line_start, "
                "line_end, state, added_ts, decision_id, pos) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    f.finding_id,
                    ev.evidence_id,
                    ev.claim_key,
                    ev.unit_id,
                    ev.lines[0] if ev.lines else None,
                    ev.lines[1] if ev.lines else None,
                    st,
                    ev.added_ts,
                    ev.decision_id,
                    len(states),
                ),
            )
        any_ok = "ok" in states
        conn.execute(
            "INSERT INTO finding (finding_id, ordinal, title, severity, status, affected_json, description, "
            "remediation, attack_json, cves_json, created_from_json, deleted, created_ts, updated_ts, "
            "history_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                f.finding_id,
                f.ordinal,
                f.title,
                f.severity,
                f.status,
                json.dumps(f.affected),
                f.description,
                f.remediation,
                json.dumps(_hypothesis(f.attack, any_ok)),
                json.dumps(_hypothesis(f.cves, any_ok)),
                json.dumps(f.created_from) if f.created_from else None,
                int(f.deleted or not f.exists),
                f.created_ts,
                f.updated_ts,
                json.dumps(f.history),
            ),
        )
        if f.exists and not f.deleted:
            visible += 1
    return visible


def snapshot_rows(conn: Any) -> dict[tuple[str, str], tuple[Any, ...]]:
    """Schnappschuss für ``projection_delta`` (Entität ``finding``): Finding samt Belegzuständen."""
    ev: dict[str, list[tuple[Any, ...]]] = {}
    for r in conn.execute(
        "SELECT finding_id, evidence_id, state FROM finding_evidence ORDER BY finding_id, pos"
    ):
        ev.setdefault(str(r[0]), []).append((r[1], r[2]))
    out: dict[tuple[str, str], tuple[Any, ...]] = {}
    for r in conn.execute("SELECT * FROM finding"):
        if r[11]:  # gelöscht oder widerrufen: für die Oberfläche nicht da
            continue
        out[("finding", str(r[0]))] = (*tuple(r), tuple(ev.get(str(r[0]), ())))
    return out
