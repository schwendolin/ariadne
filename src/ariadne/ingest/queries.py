"""Lesende Abfragen auf ``derived.db`` für CLI und (später) Web-API.

Ersatz für die noch fehlende Web-Oberfläche: Hosts, Services, Inbox,
Zeitachse, Schlüsselschritte, Volltextsuche und der Diff nach einem Reparse.
Alle Funktionen geben JSON-taugliche Werte zurück. Sie lesen nur Sichten und
Tabellen ohne Secret-Klartext (``secret_value`` dient nur zum Maskieren in der
Suche). Werte stammen aus Zieldaten: Die Senke kodiert sie (CLI: ``term_safe``).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any

from ariadne.ingest.claims import confidence_level
from ariadne.ingest.proj_build import display
from ariadne.ingest.schema_claims import MASK

__all__ = [
    "RefError",
    "group_ref",
    "hosts",
    "services",
    "inbox",
    "timeline",
    "keysteps",
    "search",
    "resolve_confirm",
    "resolve_claim",
    "claim_snapshot",
    "reparse_diff",
    "context_label",
]

_HEX = re.compile(r"[0-9a-f]{8,64}")
_GROUP = re.compile(r"g[0-9a-f]{8}")


class RefError(LookupError):
    """Verweis auf Claim oder Gruppe ist unbekannt oder nicht eindeutig."""


def group_ref(group_key: str) -> str:
    """Kurzer, stabiler Verweis auf eine Inbox-Gruppe (``g`` + 8 Hex-Zeichen)."""
    return "g" + hashlib.sha256(group_key.encode()).hexdigest()[:8]


def _json(text: Any, default: Any) -> Any:
    if not isinstance(text, str):
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def context_label(ctx: dict[str, Any] | None) -> str:
    """Kurzbezeichnung einer Kontextstufe: ``Kali``, ``10.10.10.3 (root)``, ``? [revshell]``."""
    ctx = ctx or {}
    kind = ctx.get("kind")
    host = ctx.get("host")
    user = ctx.get("user")
    if kind in (None, "local", "su") and host in (None, "local"):
        base = "Kali"
    elif isinstance(host, str) and host and host != "local":
        base = display(host) if ":" in host else host
        if host.startswith("name:"):
            base = host[5:]
    else:
        base = "?"
    if user and (kind not in (None, "local") or base != "Kali"):
        base += f" ({user})"
    if kind not in (None, "local", "su"):
        base += f" [{kind}]"
    return base


# --------------------------------------------------------------------------- Hosts, Services


def services(conn: Any, host_id: str | None = None) -> list[dict[str, Any]]:
    sql = ("SELECT s.service_id, s.host_id, s.proto, s.port, s.name, s.product, s.version, s.state, "
           "s.scope, s.claim_state, s.cves_json, h.label FROM v_service s "
           "LEFT JOIN entity h ON h.entity_id = s.host_id")
    params: tuple[Any, ...] = ()
    if host_id is not None:
        sql += " WHERE s.host_id = ?"
        params = (host_id,)
    rows = conn.execute(sql + " ORDER BY h.label, s.proto, s.port", params).fetchall()
    return [{"service_id": r[0], "host_id": r[1], "proto": r[2], "port": r[3], "name": r[4],
             "product": r[5], "version": r[6], "state": r[7], "scope": r[8], "claim_state": r[9],
             "cves": _json(r[10], []) or [], "host": r[11] or (display(r[1]) if r[1] else None)}
            for r in rows]


def hosts(conn: Any) -> list[dict[str, Any]]:
    by_host: dict[str, list[dict[str, Any]]] = {}
    for s in services(conn):
        by_host.setdefault(str(s["host_id"]), []).append(s)
    out: list[dict[str, Any]] = []
    for r in conn.execute(
            "SELECT host_id, label, scope, claim_state, knowledge, access, work, progress, os, "
            "addresses_json, names_json, services_total, placeholder, conflicts FROM v_host "
            "ORDER BY placeholder, label"):
        out.append({
            "host_id": r[0], "label": r[1], "scope": r[2], "claim_state": r[3], "knowledge": r[4],
            "access": r[5], "work": r[6], "progress": r[7], "os": r[8], "addresses": _json(r[9], []) or [],
            "names": _json(r[10], []) or [], "services_total": r[11], "placeholder": bool(r[12]),
            "conflicts": r[13] or 0, "services": by_host.get(str(r[0]), []),
        })
    return out


# --------------------------------------------------------------------------- Inbox


def inbox(conn: Any) -> list[dict[str, Any]]:
    """Offene Inbox-Einträge, gruppiert (Reihenfolge: Zeit der ersten Meldung)."""
    groups: dict[str, dict[str, Any]] = {}
    for key, kind, group_key, title, payload_json, ts in conn.execute(
            "SELECT item_key, kind, group_key, title, payload_json, created_ts FROM v_inbox "
            "ORDER BY created_ts, group_key, item_key"):
        payload = _json(payload_json, {}) or {}
        g = groups.get(group_key)
        if g is None:
            g = groups[group_key] = {"ref": group_ref(group_key), "group_key": group_key, "kind": kind,
                                     "title": title, "ts": ts, "items": []}
            if kind == "candidate_group":
                g["summary"] = payload.get("summary") or {}
                g["unit"] = payload.get("unit") or {}
        item: dict[str, Any] = {"key": key, "kind": kind}
        if kind == "candidate_group":
            ck = str(payload.get("claim_key", ""))
            conf = payload.get("confidence")
            item.update({
                "ref": ck[:12], "claim_key": ck, "subject": payload.get("subject_label"),
                "predicate": payload.get("predicate"), "value": _value_text(payload.get("value")),
                "confidence": payload.get("confidence_level") or (
                    confidence_level(float(conf)) if isinstance(conf, int | float) else None),
                "scope": payload.get("scope"), "trust": payload.get("trust"),
                "from_target": bool(payload.get("from_target")), "suspect": bool(payload.get("suspect")),
            })
        else:
            item["payload"] = {k: v for k, v in payload.items() if k not in ("claim_key",)}
            if "claim_key" in payload:
                item["claim_key"] = payload["claim_key"]
        g["items"].append(item)
    return list(groups.values())


def _value_text(v: Any) -> str:
    if isinstance(v, dict) and isinstance(v.get("ref"), str):
        return display(v["ref"])
    if isinstance(v, bool):
        return "ja" if v else "nein"
    return "" if v is None else str(v)


def resolve_confirm(conn: Any, ref: str) -> list[str]:
    """Claim-Schlüssel zu einem Verweis: Gruppe (``g1a2b3c4d``, ``unit:...``) oder Claim (Präfix)."""
    ref = ref.strip()
    groups = [g for g in inbox(conn) if g["kind"] == "candidate_group"]
    for g in groups:
        if ref.lower() == g["ref"] or ref == g["group_key"]:
            keys = [i["claim_key"] for i in g["items"] if i.get("claim_key")]
            if not keys:
                raise RefError("Gruppe ohne offene Kandidaten")
            return keys
    if _GROUP.fullmatch(ref.lower()) or ref.startswith("unit:"):
        raise RefError("Gruppe nicht gefunden (ariadne show inbox)")
    return [resolve_claim(conn, ref)]


def resolve_claim(conn: Any, ref: str) -> str:
    """Vollständiger Claim-Schlüssel zu einem eindeutigen Präfix (mindestens 8 Hex-Zeichen)."""
    ref = ref.strip().lower()
    if not _HEX.fullmatch(ref):
        raise RefError("ungültiger Verweis (Claim-Schlüssel oder Gruppe wie g1a2b3c4d)")
    rows = conn.execute("SELECT claim_key FROM claim WHERE substr(claim_key, 1, ?) = ? LIMIT 2",
                        (len(ref), ref)).fetchall()
    if not rows:
        raise RefError("Claim nicht gefunden")
    if len(rows) > 1:
        raise RefError("Verweis nicht eindeutig, mehr Zeichen angeben")
    return str(rows[0][0])


def claim_snapshot(conn: Any, keys: Iterable[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for k in keys:
        r = conn.execute("SELECT claim_key, subject_identifier, predicate, value_text, state FROM v_claim "
                         "WHERE claim_key = ?", (k,)).fetchone()
        if r is not None:
            out.append({"claim_key": r[0], "subject": display(r[1]), "predicate": r[2], "value": r[3],
                        "state": r[4]})
    return out


# --------------------------------------------------------------------------- Zeitachse


def keysteps(conn: Any) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT k.ordinal, k.step, k.host_ident, k.entity_id, k.note, k.ts_utc_ns, k.terminal_id, e.label "
        "FROM v_keystep k LEFT JOIN entity e ON e.entity_id = k.entity_id ORDER BY k.ordinal").fetchall()
    return [{"ordinal": r[0], "step": r[1], "host": r[7] or (display(r[2]) if r[2] else None),
             "note": r[4], "ts": r[5], "terminal_id": r[6]} for r in rows]


def timeline(conn: Any, limit: int = 200) -> list[dict[str, Any]]:
    """Einheiten (Befehle, Segmente, Dateien) und Schlüsselschritte nach Zeit, die neuesten ``limit``."""
    entries: list[dict[str, Any]] = []
    for r in conn.execute(
            "SELECT u.unit_id, u.kind, u.terminal_id, u.cmd_id, u.cmd_text, u.path, u.context, u.exit_code, "
            "u.ts_utc_ns, u.state, u.flags, u.vis_count, a.src_ip, a.target_scope FROM unit u "
            "LEFT JOIN activity a ON a.cmd_id = u.cmd_id AND u.kind = 'command' "
            "ORDER BY u.ts_utc_ns DESC, u.unit_id DESC LIMIT ?", (int(limit),)):
        ctx = _json(r[6], {}) or {}
        if r[1] == "segment" and not r[11]:
            continue  # leere Segmente (nur Prompt) zeigen nichts
        title = r[4] if r[1] == "command" else (r[5] if r[1] == "file" else "Segment")
        entries.append({
            "type": r[1], "unit_id": r[0], "terminal_id": r[2], "cmd_id": r[3], "title": title,
            "context": context_label(ctx), "host": ctx.get("host"), "exit": r[7], "ts": r[8],
            "state": r[9], "flags": _json(r[10], []) or [], "lines": r[11], "src_ip": r[12],
            "scope": [t.get("verdict") for t in (_json(r[13], []) or []) if isinstance(t, dict)],
        })
    for k in keysteps(conn):
        entries.append({"type": "keystep", "title": k["step"], "context": k["host"] or "-", "ts": k["ts"],
                        "note": k["note"], "terminal_id": k["terminal_id"]})
    entries.sort(key=lambda e: (e["ts"] or 0, e["type"]))
    return entries[-limit:]


# --------------------------------------------------------------------------- Suche


def _secret_values(conn: Any) -> list[str]:
    vals = [str(r[0]) for r in conn.execute("SELECT value FROM secret_value") if isinstance(r[0], str)]
    return sorted((v for v in vals if len(v) >= 4), key=len, reverse=True)


def search(conn: Any, text: str, limit: int = 50) -> list[dict[str, Any]]:
    """Volltextsuche über die Ausgabe (ohne Prompt-Echo), als Phrase. Bekannte Secrets maskiert."""
    words = text.strip()
    if not words:
        return []
    query = '"' + words.replace('"', '""') + '"'
    secrets = _secret_values(conn)
    out: list[dict[str, Any]] = []
    for r in conn.execute(
            "SELECT l.unit_id, l.n, l.text, u.kind, u.context, u.cmd_text, u.ts_utc_ns, l.idx "
            "FROM unit_fts f JOIN unit_line l ON l.id = f.rowid JOIN unit u ON u.unit_id = l.unit_id "
            "WHERE unit_fts MATCH ? AND (l.flags & 1) = 0 ORDER BY u.ts_utc_ns, l.pos LIMIT ?",
            (query, int(limit))):
        line = str(r[2])
        for s in secrets:
            line = line.replace(s, MASK)
        ctx = _json(r[4], {}) or {}
        out.append({"unit_id": r[0], "n": r[1], "text": line, "kind": r[3], "context": context_label(ctx),
                    "host": ctx.get("host"), "cmd": r[5], "ts": r[6], "idx": r[7]})
    return out


# --------------------------------------------------------------------------- Reparse


def _claims(conn: Any) -> dict[str, tuple[Any, ...]]:
    return {str(r[0]): tuple(r[1:]) for r in conn.execute(
        "SELECT claim_key, state, value_text, round(confidence, 3), subject_identifier, predicate "
        "FROM v_claim")}


def reparse_diff(old: Any, new: Any, sample: int = 10) -> dict[str, Any]:
    """Unterschiede der Claims zwischen alter und neuer ``derived.db`` plus verwaiste Entscheide."""
    a, b = _claims(old), _claims(new)

    def show(key: str, row: tuple[Any, ...]) -> dict[str, Any]:
        return {"claim": key[:12], "subject": display(str(row[3])), "predicate": row[4], "value": row[1],
                "state": row[0]}

    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    orphans = []
    for (payload_json,) in new.execute(
            "SELECT payload_json FROM inbox_item WHERE kind = 'orphan_decision' ORDER BY created_ts"):
        p = _json(payload_json, {}) or {}
        orphans.append({"kind": p.get("kind"), "reason": p.get("reason"), "seq": p.get("seq"),
                        "ref": (str(p["ref"])[:12] if p.get("ref") else None)})
    units = new.execute("SELECT count(*) FROM unit").fetchone()[0]
    failures = new.execute("SELECT count(*) FROM parse_failure").fetchone()[0]
    return {
        "claims_before": len(a), "claims_after": len(b), "added": len(added), "removed": len(removed),
        "changed": len(changed), "units": units, "parse_failures": failures, "orphans": orphans,
        "added_sample": [show(k, b[k]) for k in added[:sample]],
        "removed_sample": [show(k, a[k]) for k in removed[:sample]],
        "changed_sample": [{**show(k, b[k]), "before": a[k][0]} for k in changed[:sample]],
    }
