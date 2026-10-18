"""Gemeinsame Lesemodelle (``docs/web-api.md`` 2): Stufe, Befehl, Einheit, Wert, Widerspruch.

Die Funktionen laufen im Thread der Auswertung (``ingest.query``) und bekommen eine offene
Verbindung auf ``derived.db``. Sie lesen nur Sichten und Tabellen ohne Secret-Klartext
(``v_claim`` maskiert Secret-Werte, ``secret_value`` liest nur das Aufdecken und die Maskierung
von Logzeilen und Befehlstexten). Jeder Text aus Zieldaten geht durch eine
:class:`~ariadne.web.api.text.Bag`; Befehlstexte und daraus abgeleitete Titel zusätzlich durch
:meth:`~ariadne.web.api.text.Bag.cmd` mit den bekannten Secrets (:func:`with_secrets`, SEC-W1).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ariadne.ingest.claims import confidence_level
from ariadne.ingest.proj_build import display
from ariadne.ingest.queries import cmd_ref, context_label
from ariadne.web.api.text import Bag, iso

__all__ = [
    "loads",
    "secret_values",
    "prompt_secret_texts",
    "with_secrets",
    "stage_view",
    "stack_views",
    "breadcrumb",
    "command_ref",
    "unit_brief",
    "fact_view",
    "conflict_view",
    "claim_rows",
    "conflict_rows",
    "unit_rows",
    "commands_for",
    "level",
    "CLAIM_COLS",
    "UNIT_COLS",
    "chunks",
]

CLAIM_COLS = (
    "claim_key, subject_identifier, entity_id, predicate, value_text, confidence, state, trust, "
    "parser_id, sources, from_target, suspect, scope, conflict_key, first_ts, last_ts, is_secret, "
    "lane, lane_reason, history, group_key, first_unit"
)
_CLAIM_NAMES = [c.strip() for c in CLAIM_COLS.split(",")]

UNIT_COLS = (
    "unit_id, kind, terminal_id, cmd_id, cmd_text, path, context, exit_code, ts_utc_ns, ts_end_ns, "
    "state, flags, line_count, vis_count, span_id, start_off, end_off, sha256"
)
_UNIT_NAMES = [c.strip() for c in UNIT_COLS.split(",")]
_IN_MAX = 500  # Platzhalter pro IN (...)


def loads(text: Any, default: Any) -> Any:
    if not isinstance(text, str):
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def chunks(seq: Sequence[Any], size: int = _IN_MAX) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def level(conf: Any) -> str | None:
    if isinstance(conf, int | float) and not isinstance(conf, bool):
        return confidence_level(float(conf))
    return None


# --------------------------------------------------------------------------- bekannte Secrets


def secret_values(conn: Any) -> list[str]:
    """Bekannte Secret-Werte (``secret_value``), längste zuerst, nur zum Maskieren."""
    vals = [
        str(r[0]) for r in conn.execute("SELECT value FROM secret_value LIMIT 10000") if isinstance(r[0], str)
    ]
    return sorted((v for v in vals if len(v) >= 4), key=len, reverse=True)


def prompt_secret_texts(conn: Any, limit: int = 20000) -> list[str]:
    """Texte aller Secret-Bereiche, die Parser auf Prompt-Zeilen (Befehlsecho) gemeldet haben.

    Für den Präsentationsmodus (Architektur 7.8): Was dort als Secret markiert ist, steht auch im
    Befehlstext der Einheit und wird dort ebenfalls verdeckt."""
    out: set[str] = set()
    rows = conn.execute(
        "SELECT unit_id, span_json FROM observation WHERE is_secret = 1 "
        "UNION ALL SELECT unit_id, span_json FROM mention WHERE is_secret = 1 LIMIT ?",
        (int(limit),),
    ).fetchall()
    for unit_id, span_json in rows:
        span = loads(span_json, None)
        if not isinstance(span, Mapping) or not isinstance(unit_id, str):
            continue
        a, b = span.get("line_start"), span.get("line_end")
        if not isinstance(a, int) or not isinstance(b, int) or b < a or b - a > 10000:
            continue
        cs, ce = span.get("col_start"), span.get("col_end")
        for idx, text in conn.execute(
            "SELECT idx, text FROM unit_line WHERE unit_id = ? AND idx BETWEEN ? AND ? AND (flags & 1) = 1 "
            "LIMIT 10001",
            (unit_id, a, b),
        ):
            text = str(text)
            start = cs if idx == a and isinstance(cs, int) else 0
            end = ce if idx == b and isinstance(ce, int) and ce >= 0 else len(text)
            piece = text[max(0, start) : max(0, end)].strip()
            if len(piece) >= 4:
                out.add(piece)
    return sorted(out, key=len, reverse=True)


def with_secrets(bag: Bag, conn: Any) -> Bag:
    """Tasche mit den bekannten Secrets für Befehlstexte; im Präsentationsmodus dazu die
    Secret-Bereiche aus Prompt-Zeilen."""
    known = secret_values(conn)
    if bag.presentation:
        known += prompt_secret_texts(conn)
    return bag.with_known(known)


# --------------------------------------------------------------------------- Kontext


def stage_view(depth: int, st: Mapping[str, Any], bag: Bag) -> dict[str, Any]:
    """Eine Stufe des Kontext-Stapels (StageView)."""
    kind = str(st.get("kind") or "unknown")
    host = st.get("host")
    host_id = host if isinstance(host, str) and host and host != "local" else None
    if depth == 0 and kind in ("local", "su") and host_id is None:
        label: str | None = "Kali"
    else:
        label = bag(display(host_id)) if host_id else None
    opened = st.get("opened_at")
    return {
        "depth": depth,
        "kind": kind,
        "host_id": bag(host_id),
        "host_label": label,
        "user": bag(st.get("user")),
        "state": "suspended" if st.get("state") == "suspended" else "active",
        "source": str(st.get("source") or "auto"),
        "auto": st.get("host_source") == "auto",
        "candidate": bag(st.get("candidate")),
        "opened_at": opened if isinstance(opened, int) and not isinstance(opened, bool) else 0,
    }


def stack_views(stack: Any, bag: Bag) -> list[dict[str, Any]]:
    if not isinstance(stack, list):
        return []
    return [stage_view(i, st, bag) for i, st in enumerate(stack) if isinstance(st, Mapping)]


def breadcrumb(stack: Any, bag: Bag) -> str | None:
    """Brotkrumen «Kali › 10.10.10.3 [revshell] (auto)» aus den aktiven Stufen."""
    if not isinstance(stack, list) or not stack:
        return None
    parts = [
        context_label(dict(st))
        for st in stack
        if isinstance(st, Mapping) and st.get("state", "active") == "active"
    ]
    return bag(" › ".join(parts)) if parts else None


# --------------------------------------------------------------------------- Befehle, Einheiten


def unit_rows(conn: Any, where: str, params: Sequence[Any], limit: int = 1000) -> list[dict[str, Any]]:
    """Einheiten nach einer festen Bedingung (nur Konstanten und Platzhalter im SQL)."""
    sql = f"SELECT {UNIT_COLS} FROM unit WHERE {where} LIMIT ?"  # noqa: S608 - feste Spalten und Bedingung
    return [dict(zip(_UNIT_NAMES, r, strict=True)) for r in conn.execute(sql, (*params, int(limit)))]


def command_ref(u: Mapping[str, Any], bag: Bag, src_ip: Any = None) -> dict[str, Any]:
    """CommandRef zu einer Einheit der Art ``command`` (``ended_at`` erst, wenn der Befehl endete)."""
    cid = u.get("cmd_id")
    running = u.get("state") == "open" and u.get("exit_code") is None
    return {
        "cmd_id": cid,
        "cmd_ref": cmd_ref(cid),
        "text": bag.cmd(u.get("cmd_text")),
        "started_at": iso(u.get("ts_utc_ns")),
        "ended_at": None if running else iso(u.get("ts_end_ns")),
        "exit": u.get("exit_code") if isinstance(u.get("exit_code"), int) else None,
        "src_ip": bag(src_ip),
        "origin": "local",
    }


def _unit_kind(kind: Any) -> str:
    return "command" if kind == "command" else "segment" if kind == "segment" else "file"


def unit_brief(u: Mapping[str, Any] | None, bag: Bag, *, parser: Any = None) -> dict[str, Any] | None:
    """UnitBrief aus einer Zeile von ``unit`` oder einer ``unit``-Angabe der Auswertung."""
    if not u or not u.get("unit_id"):
        return None
    kind = _unit_kind(u.get("kind"))
    title = u.get("cmd_text") or u.get("title") or u.get("path") or ("Segment" if kind == "segment" else None)
    sub = bag.new()
    out = {
        "unit_id": u.get("unit_id"),
        "kind": kind,
        "cmd_id": u.get("cmd_id"),
        "cmd_ref": cmd_ref(u.get("cmd_id")),
        "title": sub.cmd(title) or "",
        "terminal_id": u.get("terminal_id"),
        "parser": parser,
        "ts": iso(u.get("ts_utc_ns") or u.get("ts")),
    }
    out["ctrl"] = sub.ctrl
    return out


def commands_for(conn: Any, unit_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    """Einheiten nach ``unit_id`` (für Belege und Arbeitsliste)."""
    out: dict[str, dict[str, Any]] = {}
    ids = sorted({u for u in unit_ids if isinstance(u, str)})
    for part in chunks(ids):
        marks = ",".join("?" * len(part))
        for row in unit_rows(conn, f"unit_id IN ({marks})", part, limit=len(part)):
            out[str(row["unit_id"])] = row
    return out


# --------------------------------------------------------------------------- Werte


def claim_rows(conn: Any, where: str, params: Sequence[Any], limit: int) -> list[dict[str, Any]]:
    """Zeilen aus ``v_claim`` (Secret-Werte dort schon maskiert)."""
    sql = (
        f"SELECT {CLAIM_COLS} FROM v_claim WHERE {where} "  # noqa: S608 - feste Spalten und Bedingung
        "ORDER BY subject_identifier, predicate, claim_key LIMIT ?"
    )
    return [dict(zip(_CLAIM_NAMES, r, strict=True)) for r in conn.execute(sql, (*params, int(limit)))]


def fact_view(c: Mapping[str, Any], bag: Bag) -> dict[str, Any]:
    """Fact aus einer Zeile von :func:`claim_rows`."""
    b = bag.new()
    subject = str(c.get("subject_identifier") or "")
    out = {
        "claim_key": c.get("claim_key"),
        "subject": b(subject),
        "subject_label": b(display(subject)),
        "predicate": c.get("predicate"),
        "value": b(c.get("value_text")) or "",
        "is_secret": bool(c.get("is_secret")),
        "state": c.get("state"),
        "lane": c.get("lane"),
        "lane_reason": c.get("lane_reason"),
        "confidence": level(c.get("confidence")) or "low",
        "trust": c.get("trust"),
        "parser": c.get("parser_id"),
        "from_target": bool(c.get("from_target")),
        "suspect": bool(c.get("suspect")),
        "verdict": c.get("scope"),
        "sources": int(c.get("sources") or 0),
        "first_seen": iso(c.get("first_ts")),
        "last_seen": iso(c.get("last_ts")),
        "conflict_key": c.get("conflict_key"),
        "history": bool(c.get("history")),
    }
    out["ctrl"] = b.ctrl
    return out


def conflict_rows(conn: Any, where: str, params: Sequence[Any], limit: int = 500) -> list[dict[str, Any]]:
    sql = (
        "SELECT conflict_key, subject_identifier, entity_id, predicate, claim_keys_json, state, choice "  # noqa: S608
        f"FROM conflict WHERE {where} ORDER BY conflict_key LIMIT ?"
    )
    return [
        {
            "conflict_key": r[0],
            "subject": r[1],
            "entity_id": r[2],
            "predicate": r[3],
            "claim_keys": loads(r[4], []) or [],
            "state": r[5],
            "choice": r[6],
        }
        for r in conn.execute(sql, (*params, int(limit)))
    ]


def conflict_view(conn: Any, k: Mapping[str, Any], bag: Bag) -> dict[str, Any]:
    """Conflict mit seinen Werten (aus ``v_claim``, Secrets maskiert)."""
    keys = [x for x in k.get("claim_keys") or [] if isinstance(x, str)][:50]
    rows = (
        {
            r["claim_key"]: r
            for r in claim_rows(conn, f"claim_key IN ({','.join('?' * len(keys))})", keys, len(keys))
        }
        if keys
        else {}
    )
    values = []
    for key in keys:
        r = rows.get(key)
        if r is None:
            continue
        vb = bag.new()
        values.append(
            {
                "claim_key": key,
                "value": vb(r.get("value_text")) or "",
                "ctrl": vb.ctrl,
                "sources": int(r.get("sources") or 0),
                "trust": r.get("trust"),
                "state": r.get("state"),
            }
        )
    b = bag.new()
    subject = str(k.get("subject") or "")
    choice = k.get("choice")
    if isinstance(choice, str) and choice not in rows:  # Wahl als Wert: nur über den Claim anzeigen
        picked = [r for r in rows.values() if r.get("value_text") == choice]
        choice = picked[0]["claim_key"] if len(picked) == 1 else None
    state = k.get("state")
    return {
        "conflict_key": k.get("conflict_key"),
        "subject": b(subject),
        "subject_label": b(display(subject)),
        "predicate": k.get("predicate"),
        "state": state if state in ("open", "resolved", "kept_open") else "open",
        "values": values,
        "choice": choice,
        "ctrl": b.ctrl,
    }
