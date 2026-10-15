"""Lesende Abfragen auf ``derived.db`` für CLI und (später) Web-API.

Ersatz für die noch fehlende Web-Oberfläche: Hosts, Services, Inbox,
Zeitachse, Schlüsselschritte, Volltextsuche und der Diff nach einem Reparse.
Alle Funktionen geben JSON-taugliche Werte zurück. Sie lesen nur Sichten und
Tabellen ohne Secret-Klartext (``secret_value`` dient nur zum Maskieren in der
Suche). Werte stammen aus Zieldaten: Die Senke kodiert sie (CLI: ``term_safe``).

Drei-Spuren-Regel (E42): ``hosts``/``services`` zeigen ``auto`` und pro Host die
stillen Werte als Zähler; ``inbox`` zeigt nur die Spur «entscheiden» und
:func:`quiet_summary` die Summe der stillen Werte. :func:`resolve_confirm` nimmt
bei einer Sammelbestätigung nur, was sicher ist (E88), und zählt den Rest pro Grund.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any

from ariadne.ingest.claims import confidence_level, value_identifier
from ariadne.ingest.identity import id_type
from ariadne.ingest.proj_build import display
from ariadne.ingest.schema_claims import MASK

__all__ = [
    "RefError",
    "group_ref",
    "cmd_ref",
    "hosts",
    "services",
    "inbox",
    "quiet_summary",
    "timeline",
    "keysteps",
    "search",
    "resolve_confirm",
    "resolve_claim",
    "resolve_cmd",
    "resolve_distrust",
    "claim_snapshot",
    "distrust_result",
    "auto_contexts",
    "reparse_diff",
    "context_label",
    "EXCLUDE_REASONS",
    "QUIET_KEYS",
]

_HEX = re.compile(r"[0-9a-f]{8,64}")
_GROUP = re.compile(r"g[0-9a-f]{8}")
_VALUE_KINDS = ("candidate_group", "decide_value")
# Gründe, aus denen eine Sammelbestätigung einen Wert auslässt (Reihenfolge = Vorrang).
EXCLUDE_REASONS = ("own_address", "context", "out_of_scope", "conflict", "merge", "ai", "suspect",
                   "low_confidence")
# Zähler der stillen Spur (lane_reason -> Schlüssel)
QUIET_KEYS = {"heuristic": "heuristic", "out_of_scope": "out_of_scope", "mention": "mentions",
              "system_account": "system_accounts", "own_address": "own_address"}
MIN_CONFIRM_CONFIDENCE = 0.5


class RefError(LookupError):
    """Verweis auf Claim, Gruppe oder Befehl ist unbekannt oder nicht eindeutig."""


def group_ref(group_key: str) -> str:
    """Kurzer, stabiler Verweis auf eine Inbox-Gruppe (``g`` + 8 Hex-Zeichen)."""
    return "g" + hashlib.sha256(group_key.encode()).hexdigest()[:8]


def cmd_ref(cmd_id: str | None) -> str | None:
    """Kurzform einer ``cmd_id``: ``<letzte 8 Zeichen der terminal_id>@<Offset>``.

    Das Ende der terminal_id (UUIDv7) ist zufällig; der Anfang ist die Startzeit und
    bei Terminals, die in derselben Minute starten, gleich. ``ariadne status`` zeigt
    dieselbe Kurz-ID.
    """
    if not isinstance(cmd_id, str) or "@" not in cmd_id:
        return None
    term, _, off = cmd_id.rpartition("@")
    return f"{term[-8:]}@{off}"


def _json(text: Any, default: Any) -> Any:
    if not isinstance(text, str):
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def context_label(ctx: dict[str, Any] | None) -> str:
    """Kurzbezeichnung einer Kontextstufe: ``Kali``, ``10.10.10.3 (root)``, ``? [revshell]``.

    Die Art ``unknown`` sagt nichts Zusätzliches und wird weggelassen. Ein Host aus
    dem ersten Callback (``host_source = auto``) bekommt ``(auto)``.
    """
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
    if kind not in (None, "local", "su", "unknown"):
        base += f" [{kind}]"
    if ctx.get("host_source") == "auto" and base != "Kali":
        base += " (auto)"
    return base


def _auto_map(conn: Any) -> dict[tuple[str, int], str]:
    try:
        return {(str(r[0]), int(r[1])): str(r[2])
                for r in conn.execute("SELECT terminal_id, opened_at, host FROM ctx_auto")}
    except Exception:  # noqa: BLE001 - ohne Projektion (Tests der Pipeline)
        return {}


def _with_auto(ctx: dict[str, Any], auto: dict[tuple[str, int], str]) -> dict[str, Any]:
    """Kontext einer Einheit um den Auto-Host ergänzen (nur, wenn kein Host bekannt ist)."""
    if ctx.get("host") or not auto:
        return ctx
    term, opened = ctx.get("terminal_id"), ctx.get("opened_at")
    host = auto.get((term, opened)) if isinstance(term, str) and isinstance(opened, int) else None
    return {**ctx, "host": host, "host_source": "auto"} if host else ctx


def auto_contexts(conn: Any) -> list[tuple[str, int, str]]:
    """Auto-Kontexte (terminal_id, opened_at, Host-Kennung) für den Daemon (E23)."""
    return [(str(r[0]), int(r[1]), str(r[2])) for r in conn.execute(
        "SELECT terminal_id, opened_at, host FROM ctx_auto ORDER BY terminal_id, opened_at")]


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


def _quiet_by_host(conn: Any) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = defaultdict(lambda: dict.fromkeys(
        ("heuristic", "out_of_scope", "mentions", "system_accounts"), 0))
    for eid, reason, n in conn.execute(
            "SELECT entity_id, lane_reason, COUNT(*) FROM claim WHERE lane = 'quiet' "
            "AND entity_id IS NOT NULL GROUP BY entity_id, lane_reason"):
        key = QUIET_KEYS.get(str(reason))
        if key is None or key == "own_address":
            continue
        host = str(eid)[4:].rpartition("|")[0] if str(eid).startswith("svc:") else str(eid)
        out[host][key] += int(n)
    return out


def hosts(conn: Any) -> list[dict[str, Any]]:
    by_host: dict[str, list[dict[str, Any]]] = {}
    for s in services(conn):
        by_host.setdefault(str(s["host_id"]), []).append(s)
    quiet = _quiet_by_host(conn)
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
            "quiet": dict(quiet.get(str(r[0])) or dict.fromkeys(
                ("heuristic", "out_of_scope", "mentions", "system_accounts"), 0)),
        })
    return out


# --------------------------------------------------------------------------- Inbox


def quiet_summary(conn: Any) -> dict[str, int]:
    """Summe der stillen Werte (nie zum Klären): «+27 Systemkonten», «3 Werte ausserhalb des Scopes»."""
    out = dict.fromkeys(("heuristic", "out_of_scope", "mentions", "system_accounts", "own_address"), 0)
    for reason, n in conn.execute("SELECT lane_reason, COUNT(*) FROM claim WHERE lane = 'quiet' "
                                  "GROUP BY lane_reason"):
        key = QUIET_KEYS.get(str(reason))
        if key is not None:
            out[key] += int(n)
    return out


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
            if kind in _VALUE_KINDS:
                g["summary"] = payload.get("summary") or {}
                g["unit"] = payload.get("unit") or {}
                g["cmd_ref"] = cmd_ref((payload.get("unit") or {}).get("cmd_id"))
        item: dict[str, Any] = {"key": key, "kind": kind}
        if kind in _VALUE_KINDS:
            ck = str(payload.get("claim_key", ""))
            conf = payload.get("confidence")
            item.update({
                "ref": ck[:12], "claim_key": ck, "subject": payload.get("subject_label"),
                "predicate": payload.get("predicate"), "value": _value_text(payload.get("value")),
                "confidence": payload.get("confidence_level") or (
                    confidence_level(float(conf)) if isinstance(conf, int | float) else None),
                "scope": payload.get("scope"), "trust": payload.get("trust"),
                "from_target": bool(payload.get("from_target")), "suspect": bool(payload.get("suspect")),
                "reason": payload.get("reason"),
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


def _own_addrs(conn: Any) -> set[str]:
    return {str(r[0]) for r in conn.execute("SELECT addr FROM own_addr")}


def _merge_idents(conn: Any) -> set[str]:
    out: set[str] = set()
    for (payload,) in conn.execute("SELECT payload_json FROM v_inbox WHERE kind = 'merge_suggestion'"):
        out.update(str(i) for i in (_json(payload, {}) or {}).get("identifiers") or [])
    return out


def _exclusion(conn: Any, key: str, own: set[str], merges: set[str]) -> tuple[str | None, dict[str, Any]]:
    """Grund, aus dem eine Sammelbestätigung den Claim auslässt (oder ``None``), und eine Kurzform."""
    r = conn.execute(
        "SELECT c.subject_identifier, c.predicate, c.value_json, c.confidence, "
        "COALESCE(c.host_scope, c.scope), c.lane_reason, "
        "c.conflict_key, c.suspect, k.state, v.value_text FROM claim c "
        "LEFT JOIN conflict k ON k.conflict_key = c.conflict_key "
        "JOIN v_claim v ON v.claim_key = c.claim_key WHERE c.claim_key = ?", (key,)).fetchone()
    if r is None:
        return "context", {"claim_key": key}
    subject, pred, value_json, conf, scope, reason, _ck, suspect, conflict_state, text = r
    short = {"claim_key": key, "subject": display(subject), "predicate": pred, "value": text}
    value = _json(value_json, None)
    vi = value_identifier(str(pred), str(subject), value)
    host = str(subject)[4:].rpartition("|")[0] if id_type(str(subject)) == "svc" else str(subject)
    idents = {i for i in (host, vi) if isinstance(i, str)}
    if reason == "own_address" or any(id_type(i) == "ip" and i.split("/", 1)[1] in own for i in idents):
        return "own_address", short
    if id_type(host) == "ctx" or reason == "context":
        return "context", short
    if scope != "in":
        return "out_of_scope", short
    if conflict_state == "open":
        return "conflict", short
    if idents & merges:
        return "merge", short
    ai = conn.execute("SELECT 1 FROM claim_source WHERE claim_key = ? AND trust IN ('ai', 'ocr') LIMIT 1",
                      (key,)).fetchone()
    if ai is not None:
        return "ai", short
    if suspect:
        return "suspect", short
    if float(conf) < MIN_CONFIRM_CONFIDENCE:
        return "low_confidence", short
    return None, short


def resolve_confirm(conn: Any, ref: str) -> dict[str, Any]:
    """Was ``ariadne confirm REF`` bestätigt (E88).

    Gruppe (``g1a2b3c4d``, ``unit:...``): nur Werte im Scope, ohne KI- oder OCR-Quelle,
    Konfidenz mindestens 0.5, keine eigene Adresse, nicht Teil eines offenen Konflikts,
    kein Kontext-Platzhalter, kein Merge, keine verdächtige Quelle. Eigene Adressen, die
    in der Ausgabe der Einheit stehen, zählen mit. Einzelner Claim (Präfix): alles
    ausser eigenen Adressen. Ergebnis: ``keys``, ``excluded`` (Zahl pro Grund),
    ``excluded_sample`` und ``group`` (bool).
    """
    ref = ref.strip()
    own = _own_addrs(conn)
    merges = _merge_idents(conn)
    excluded = dict.fromkeys(EXCLUDE_REASONS, 0)
    sample: list[dict[str, Any]] = []
    for g in inbox(conn):
        if g["kind"] not in _VALUE_KINDS or (ref.lower() != g["ref"] and ref != g["group_key"]):
            continue
        keys: list[str] = []
        for item in g["items"]:
            ck = item.get("claim_key")
            if not ck:
                continue
            reason, short = _exclusion(conn, ck, own, merges)
            if reason is None:
                keys.append(ck)
                continue
            excluded[reason] += 1
            if len(sample) < 10:
                sample.append({**short, "reason": reason})
        unit_id = (g.get("unit") or {}).get("unit_id")
        if unit_id and own:
            mentioned = sorted({str(r[0]) for r in conn.execute(
                "SELECT DISTINCT value FROM mention WHERE unit_id = ? AND value_type = 'ip'", (unit_id,))}
                & own)
            for addr in mentioned:
                excluded["own_address"] += 1
                if len(sample) < 10:
                    sample.append({"subject": addr, "predicate": "host.address", "value": addr,
                                   "reason": "own_address"})
        return {"keys": keys, "excluded": excluded, "excluded_sample": sample, "group": True}
    if _GROUP.fullmatch(ref.lower()) or ref.startswith("unit:"):
        raise RefError("Gruppe nicht gefunden (ariadne show inbox)")
    key = resolve_claim(conn, ref)
    reason, short = _exclusion(conn, key, own, merges)
    if reason == "own_address":
        excluded["own_address"] = 1
        return {"keys": [], "excluded": excluded, "excluded_sample": [{**short, "reason": reason}],
                "group": False}
    return {"keys": [key], "excluded": excluded, "excluded_sample": [], "group": False}


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


def resolve_cmd(conn: Any, ref: str) -> str:
    """Volle ``cmd_id`` zu einer ``cmd_id`` oder ihrer Kurzform ``<8 Zeichen>@<Offset>``.

    Die Kurzform nimmt das Ende der terminal_id (:func:`cmd_ref`) oder ihren Anfang.
    """
    ref = ref.strip()
    term, sep, off = ref.rpartition("@")
    if not sep or not off.isdigit() or len(term) < 8 or len(ref) > 200:
        raise RefError("ungültiger Verweis (Befehl wie 9f3c1a7e@1234, siehe ariadne show timeline)")
    known: set[str] = set()
    for table in ("obs_unit", "unit", "cmd_block"):
        try:
            known |= {str(r[0]) for r in conn.execute(
                f"SELECT DISTINCT cmd_id FROM {table} WHERE cmd_id IS NOT NULL")}  # noqa: S608
        except Exception:  # noqa: BLE001, S112 - Tabelle fehlt (nur Projektion)
            continue
    if ref in known:
        return ref
    hits = sorted(c for c in known if c.rpartition("@")[2] == off
                  and (c.startswith(term) or c.rpartition("@")[0].endswith(term)))
    if not hits:
        raise RefError("Befehl nicht gefunden (ariadne show timeline)")
    if len(hits) > 1:
        raise RefError("Verweis nicht eindeutig, volle cmd_id angeben")
    return hits[0]


def resolve_distrust(conn: Any, ref: str) -> str:
    """``cmd_id`` für ``ariadne undo``: nur Befehle, aus denen Werte stammen."""
    cmd_id = resolve_cmd(conn, ref)
    if conn.execute("SELECT 1 FROM claim_source WHERE group_key = ? LIMIT 1", (cmd_id,)).fetchone() is None:
        raise RefError("aus diesem Befehl stammen keine Werte, nichts rückgängig zu machen")
    return cmd_id


def claim_snapshot(conn: Any, keys: Iterable[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for k in keys:
        r = conn.execute("SELECT claim_key, subject_identifier, predicate, value_text, state, lane "
                         "FROM v_claim WHERE claim_key = ?", (k,)).fetchone()
        if r is not None:
            out.append({"claim_key": r[0], "subject": display(r[1]), "predicate": r[2], "value": r[3],
                        "state": r[4], "lane": r[5]})
    return out


def distrust_result(conn: Any, cmd_id: str) -> dict[str, Any]:
    """Wirkung von ``d.unit.distrust`` (aus der letzten Projektion)."""
    r = conn.execute("SELECT rejected, weakened FROM unit_distrust WHERE cmd_id = ?", (cmd_id,)).fetchone()
    return {"cmd_id": cmd_id, "cmd_ref": cmd_ref(cmd_id), "rejected": int(r[0]) if r else 0,
            "weakened": int(r[1]) if r else 0}


# --------------------------------------------------------------------------- Zeitachse


def keysteps(conn: Any) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT k.ordinal, k.step, k.host_ident, k.entity_id, k.note, k.ts_utc_ns, k.terminal_id, e.label, "
        "k.mono_ns, k.boot_id, k.stream_off, k.seq "
        "FROM v_keystep k LEFT JOIN entity e ON e.entity_id = k.entity_id ORDER BY k.ordinal").fetchall()
    return [{"ordinal": r[0], "step": r[1], "host": r[7] or (display(r[2]) if r[2] else None),
             "note": r[4], "ts": r[5], "terminal_id": r[6], "mono_ns": r[8], "boot_id": r[9],
             "stream_off": r[10], "seq": r[11]} for r in rows]


def _boot_ranks(conn: Any) -> dict[str, int]:
    try:
        rows = conn.execute("SELECT boot_id FROM boot ORDER BY first_seq").fetchall()
        return {str(b): i for i, (b,) in enumerate(rows)}
    except Exception:  # noqa: BLE001 - alte Datei ohne Tabelle
        return {}


def _sort_time(entries: list[dict[str, Any]], ranks: dict[str, int]) -> None:
    """Sortiert nach (Rang des Systemstarts, monotone Uhr, Terminal, Offset, seq) (E96).

    Ohne ``mono_ns`` wird die Wanduhr über den mittleren Abstand Wanduhr - monotone Uhr
    desselben Systemstarts umgerechnet, ganz ohne Bezug gilt die Wanduhr."""
    deltas: dict[Any, list[int]] = defaultdict(list)
    for e in entries:
        if isinstance(e.get("mono_ns"), int) and isinstance(e.get("ts"), int):
            deltas[e.get("boot_id")].append(e["ts"] - e["mono_ns"])
    med = {b: sorted(v)[len(v) // 2] for b, v in deltas.items()}

    def key(e: dict[str, Any]) -> tuple:
        boot = e.get("boot_id")
        rank = ranks.get(boot, len(ranks)) if boot is not None else -1
        ts = e.get("ts") if isinstance(e.get("ts"), int) else 0
        mono = e.get("mono_ns")
        if not isinstance(mono, int):
            mono = ts - med[boot] if boot in med else ts
        return (rank, mono, e.get("terminal_id") or "", e.get("start_off") or 0, e.get("seq") or 0,
                e.get("type") or "")

    entries.sort(key=key)


def _adopted(conn: Any) -> dict[str, int]:
    try:
        return {str(g): int(n) for g, n in conn.execute(
            "SELECT cs.group_key, COUNT(DISTINCT cs.claim_key) FROM claim_source cs "
            "JOIN claim c ON c.claim_key = cs.claim_key WHERE c.state = 'auto' AND cs.distrusted = 0 "
            "AND cs.group_key IS NOT NULL GROUP BY cs.group_key")}
    except Exception:  # noqa: BLE001 - ohne Projektion (Tests der Pipeline)
        return {}


def _distrusted(conn: Any) -> set[str]:
    try:
        return {str(r[0]) for r in conn.execute("SELECT cmd_id FROM unit_distrust")}
    except Exception:  # noqa: BLE001
        return set()


def timeline(conn: Any, limit: int = 200) -> list[dict[str, Any]]:
    """Einheiten (Befehle, Segmente, Dateien) und Schlüsselschritte nach Shim-Zeit, die neuesten ``limit``.

    Befehle tragen ``cmd_id``, ``cmd_ref`` (für ``ariadne undo``), ``adopted`` (Werte in
    der Spur ``auto`` aus dieser Evidenzgruppe) und ``distrusted``.
    """
    auto = _auto_map(conn)
    adopted = _adopted(conn)
    distrusted = _distrusted(conn)
    entries: list[dict[str, Any]] = []
    for r in conn.execute(
            "SELECT u.unit_id, u.kind, u.terminal_id, u.cmd_id, u.cmd_text, u.path, u.context, u.exit_code, "
            "u.ts_utc_ns, u.state, u.flags, u.vis_count, a.src_ip, a.target_scope, u.mono_ns, u.boot_id, "
            "u.start_off, u.event_seq FROM unit u "
            "LEFT JOIN activity a ON a.cmd_id = u.cmd_id AND u.kind = 'command' "
            "ORDER BY u.event_seq DESC, u.unit_id DESC LIMIT ?", (int(limit) * 4 + 50,)):
        ctx = _with_auto(_json(r[6], {}) or {}, auto)
        if r[1] == "segment" and not r[11]:
            continue  # leere Segmente (nur Prompt) zeigen nichts
        title = r[4] if r[1] == "command" else (r[5] if r[1] == "file" else "Segment")
        e: dict[str, Any] = {
            "type": r[1], "unit_id": r[0], "terminal_id": r[2], "cmd_id": r[3], "title": title,
            "context": context_label(ctx), "host": ctx.get("host"), "exit": r[7], "ts": r[8],
            "state": r[9], "flags": _json(r[10], []) or [], "lines": r[11], "src_ip": r[12],
            "scope": [t.get("verdict") for t in (_json(r[13], []) or []) if isinstance(t, dict)],
            "mono_ns": r[14], "boot_id": r[15], "start_off": r[16], "seq": r[17],
        }
        if r[1] == "command" and r[3]:
            e.update(cmd_ref=cmd_ref(r[3]), adopted=adopted.get(r[3], 0), distrusted=r[3] in distrusted)
        entries.append(e)
    for k in keysteps(conn):
        entries.append({"type": "keystep", "title": k["step"], "context": k["host"] or "-", "ts": k["ts"],
                        "note": k["note"], "terminal_id": k["terminal_id"], "mono_ns": k["mono_ns"],
                        "boot_id": k["boot_id"], "start_off": k["stream_off"], "seq": k["seq"]})
    _sort_time(entries, _boot_ranks(conn))
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
    auto = _auto_map(conn)
    out: list[dict[str, Any]] = []
    for r in conn.execute(
            "SELECT l.unit_id, l.n, l.text, u.kind, u.context, u.cmd_text, u.ts_utc_ns, l.idx "
            "FROM unit_fts f JOIN unit_line l ON l.id = f.rowid JOIN unit u ON u.unit_id = l.unit_id "
            "WHERE unit_fts MATCH ? AND (l.flags & 1) = 0 ORDER BY u.ts_utc_ns, l.pos LIMIT ?",
            (query, int(limit))):
        line = str(r[2])
        for s in secrets:
            line = line.replace(s, MASK)
        ctx = _with_auto(_json(r[4], {}) or {}, auto)
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
    states = Counter(str(r[0]) for r in new.execute("SELECT state FROM claim"))
    return {
        "claims_before": len(a), "claims_after": len(b), "added": len(added), "removed": len(removed),
        "changed": len(changed), "units": units, "parse_failures": failures, "orphans": orphans,
        "auto": states.get("auto", 0),
        "added_sample": [show(k, b[k]) for k in added[:sample]],
        "removed_sample": [show(k, a[k]) for k in removed[:sample]],
        "changed_sample": [{**show(k, b[k]), "before": a[k][0]} for k in changed[:sample]],
    }
