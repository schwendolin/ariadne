"""``GET /p/{pid}/timeline`` und ``GET /p/{pid}/inputs`` (``docs/web-api.md`` 10).

Die Zeitachse mischt Einheiten und Schlüsselschritte (:func:`ariadne.ingest.queries.timeline`,
mit «N Werte übernommen», ``cmd_ref`` und Rückgängig), Kontextwechsel, Entscheide, Lücken und
Pausen, Projektbeginn und -ende, übernommenen Vorlauf und auf Wunsch Eingaben (E104 verdeckt).
Sortiert wird nach Shim-Zeit (E96) wie in der CLI, neueste zuerst, mit undurchsichtigem Cursor.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Query
from starlette.responses import Response

from ariadne.daemon.terminal import STAGE_KINDS
from ariadne.ingest import inputs, pending, queries
from ariadne.ingest.pipeline import SILENCE_NS
from ariadne.ingest.proj_build import display
from ariadne.ingest.seg_stream import record_time
from ariadne.rules import api as rules_api
from ariadne.web.api.common import Api, valid_tid
from ariadne.web.api.errors import ApiError
from ariadne.web.api.text import MASK, Bag, decode_cursor, encode_cursor, iso, ns_str
from ariadne.web.api.views import chunks, command_ref, loads, secret_values, term_ref, with_secrets

__all__ = [
    "add_routes",
    "TYPES",
    "DEFAULT_TYPES",
    "timeline_page",
    "input_view",
    "secret_values",
    "UNITS_MAX",
]

TYPES = (
    "command",
    "segment",
    "file",
    "keystep",
    "context",
    "decision",
    "gap",
    "project",
    "input",
    "callback",
)
_STAGE_KINDS = STAGE_KINDS
DEFAULT_TYPES = frozenset(TYPES) - {"input"}
UNITS_MAX = 5000  # so viele jüngste Einträge aus Einheiten und Schritten trägt die Zeitachse
INPUTS_MAX = 1000
_CTX_KINDS = ("d.ctx.set", "d.ctx.push", "d.ctx.pop", "d.ctx.accept")
_CTX_CHANGE = {"d.ctx.set": "set", "d.ctx.push": "push", "d.ctx.pop": "pop", "d.ctx.accept": "set"}
_SOURCE = {"shim": "hotkey", "webui": "webui", "cli": "cli"}
_FLAGS = ("partial", "truncated", "gap", "altscreen", "marker_forged")
_SUMMARY = {
    "d.claim.confirm": "Wert bestätigt",
    "d.claim.reject": "Wert verworfen",
    "d.claim.edit": "Wert geändert",
    "d.entity.merge": "Kennungen zusammengeführt",
    "d.entity.split": "Kennungen getrennt",
    "d.note.set": "Notiz gesetzt",
    "d.tag.add": "Tag hinzugefügt",
    "d.tag.remove": "Tag entfernt",
    "d.terminal.label": "Terminal benannt",
    "d.revoke": "Rückgängig gemacht",
    "d.unit.distrust": "Rückgängig pro Befehl",
    "d.lab.not_customer": "Bestätigt: kein Kundenauftrag",
    "d.automode.set": "Automodus geändert",
    # Korrektur K3: Findings und Denkanstösse (web-api.md 18.5, 18.6) mit festen Texten
    "d.finding.create": "Finding angelegt",
    "d.finding.update": "Finding geändert",
    "d.finding.evidence.add": "Beleg zum Finding hinzugefügt",
    "d.finding.evidence.remove": "Beleg aus dem Finding entfernt",
    "d.finding.delete": "Finding gelöscht",
    "d.suggestion.done": "Denkanstoss erledigt",
    "d.suggestion.dismiss": "Denkanstoss verworfen",
}
_WORK = {
    "open": "offen",
    "in_progress": "in Arbeit",
    "dead_end": "Sackgasse",
    "done": "erledigt",
    "out_of_scope": "ausserhalb des Scopes",
}
_ACCESS = {"none": "kein Zugriff", "user": "Benutzer", "admin": "Administrator"}
_SCOPE_OP = {  # E129: Änderungen über ariadne scope bzw. POST /scope/changes
    "add": "Scope erweitert",
    "remove": "Aus dem Scope entfernt",
    "exclude": "Aus dem Scope ausgeschlossen",
    "revert": "Scope-Änderung rückgängig",
    "open": "Scope geöffnet",  # E131
    "close": "Scope geschlossen",
}


def _summary(kind: str, payload: Mapping[str, Any]) -> str:
    """Fester Text pro Entscheid; nie Werte aus Zieldaten (nur feste Wörter und Zahlen)."""
    if kind == "d.conflict.resolve":
        return "Widerspruch bewusst offen gelassen" if payload.get("keep_open") else "Widerspruch gelöst"
    if kind == "d.status.work":
        return "Arbeitsstand: " + _WORK.get(str(payload.get("value")), "geändert")
    if kind == "d.status.access":
        return "Zugriff: " + _ACCESS.get(str(payload.get("value")), "geändert")
    if kind == "d.scope.update":
        v = payload.get("version")
        ch = payload.get("change")
        word = "Scope gesetzt"
        if isinstance(ch, Mapping):
            word = _SCOPE_OP.get(str(ch.get("op")), word)
        return f"{word} (Version {int(v)})" if isinstance(v, int) else word
    return _SUMMARY.get(kind, "Entscheid")


def input_view(v: Mapping[str, Any], bag: Bag, secrets: list[str]) -> dict[str, Any]:
    """InputView aus :func:`ariadne.ingest.inputs.input_view` (Text schon verdeckt bzw. sichtbar)."""
    b = bag.new()
    text = str(v.get("text") or "")
    if not v.get("hidden"):
        for s in secrets:
            text = text.replace(s, MASK)
    out = {
        "seq": v.get("seq"),
        "terminal_id": v.get("terminal_id"),
        "stream_off": v.get("stream_off"),
        "out_end": v.get("out_end"),
        "ts": iso(v.get("t_shim_ns")),
        "ts_ns": ns_str(v.get("t_shim_ns")),
        # verdeckt und nicht aufgedeckt: keine Länge (SEC-W3, E104)
        "length": None if v.get("hidden") and not v.get("revealed") else int(v.get("length") or 0),
        "paste": bool(v.get("paste")),
        "redacted": bool(v.get("redacted")),
        "hidden": bool(v.get("hidden")),
        "reason": v.get("reason"),
        "revealed": bool(v.get("revealed")),
        "text": b(text) or "",
    }
    out["ctrl"] = (
        b.ctrl
        or "<" in text
        and text != MASK
        and any(
            tag in text for tag in ("<ESC>", "<BEL>", "<BS>", "<DEL>", "<CR>", "<LF>", "<TAB>", "<0x", "<U+")
        )
    )
    return out


def _entities(conn: Any) -> dict[str, str]:
    return {
        str(k): str(e)
        for k, e in conn.execute(
            "SELECT key, entity_id FROM identifier WHERE entity_id IS NOT NULL LIMIT 200000"
        )
    }


def _entry(
    id_: str, type_: str, ts: Any, mono: Any, boot: Any, tid: Any, off: Any, seq: Any, **extra: Any
) -> dict[str, Any]:
    return {
        "id": id_,
        "type": type_,
        "ts": ts if isinstance(ts, int) else 0,
        "mono_ns": mono,
        "boot_id": boot,
        "terminal_id": tid,
        "start_off": off if isinstance(off, int) else 0,
        "seq": seq if isinstance(seq, int) else 0,
        **extra,
    }


def _callbacks(conn: Any) -> list[dict[str, Any]]:
    """Callbacks eines Listeners als eigene Zeile «Callback von 192.168.56.101:49158» (Korrektur D15,
    SCREENS 6): jede Beobachtung ``access.callback``, die den Kontext nicht automatisch gesetzt hat
    (die erscheint als Zeile ``context`` «Callback, Kontext automatisch: …»)."""
    from ariadne.web.api.evidence import _lines_of

    rows = conn.execute("SELECT terminal_id, opened_at, claim_key FROM ctx_auto LIMIT 10000").fetchall()
    auto = {(str(tid), int(opened), str(ck)) for tid, opened, ck in rows if ck is not None}
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for ck, entity, scope, unit_id, ts, span_json, attrs_json, value, tid, opened, mono, boot in conn.execute(
        "SELECT c.claim_key, c.entity_id, c.scope, cs.unit_id, cs.ts_utc_ns, cs.span_json, o.attrs_json, "
        "c.value_text, u.terminal_id, u.ctx_opened_at, un.mono_ns, un.boot_id FROM claim c "
        "JOIN claim_source cs ON cs.claim_key = c.claim_key "
        "JOIN observation o ON o.obs_id = cs.obs_id "
        "JOIN obs_unit u ON u.unit_id = cs.unit_id "
        "LEFT JOIN unit un ON un.unit_id = cs.unit_id "
        "WHERE c.predicate = 'access.callback' AND c.state != 'rejected' AND cs.distrusted = 0 "
        "ORDER BY cs.ts_utc_ns LIMIT 2000"
    ):
        if tid is not None and opened is not None and (str(tid), int(opened), str(ck)) in auto:
            continue
        if (str(unit_id), str(ck)) in seen:
            continue
        seen.add((str(unit_id), str(ck)))
        attrs = loads(attrs_json, {}) or {}
        attrs = attrs if isinstance(attrs, Mapping) else {}
        lines = _lines_of(conn, str(unit_id), loads(span_json, None))
        session = attrs.get("session")
        session = session if isinstance(session, str) and session.isdigit() and len(session) <= 9 else None
        out.append(
            _entry(
                f"cb:{unit_id}:{str(ck)[:16]}",
                "callback",
                ts,
                mono,
                boot,
                tid,
                None,
                0,
                host_id=entity,
                unit_id=str(unit_id),
                remote=attrs.get("remote") if isinstance(attrs.get("remote"), str) else None,
                listener=value,
                scope=scope if scope in ("in", "out", "excluded", "outside_window") else None,
                session=session,
                lines=lines,
            )
        )
    return out


def _collect(conn: Any, journal: Any, types: frozenset[str], terminal: str | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if types & {"command", "segment", "file", "keystep"}:
        k_ent = {
            int(r[0]): (r[1], r[2]) for r in conn.execute("SELECT seq, entity_id, decision_id FROM keystep")
        }
        k_ord = {int(k["seq"]): k["ordinal"] for k in queries.keysteps(conn) if isinstance(k.get("seq"), int)}

        # offene Segmente, deren Zeilen erst vorläufig vorliegen (laufendes msf, Listener), mit zeigen
        def keep(uid: str) -> bool:
            return pending.visible_extra(conn, uid) > 0

        for e in queries.timeline(conn, UNITS_MAX, keep_segment=keep):
            t = e.get("type")
            if t == "keystep":
                ent, did = k_ent.get(int(e.get("seq") or 0), (None, None))
                out.append(
                    {
                        **e,
                        "id": f"k:{e.get('seq')}",
                        "host_id": ent,
                        "decision_id": did,
                        "ordinal": k_ord.get(int(e.get("seq") or 0)),
                    }
                )
            else:
                host = e.get("host")
                out.append({**e, "id": str(e.get("unit_id")), "host_id": host if host != "local" else None})
    if "decision" in types:
        for seq, did, kind, payload, ts, mono, boot in conn.execute(
            "SELECT seq, id, kind, payload_json, ts, mono_ns, boot_id FROM decision "
            "ORDER BY seq DESC LIMIT 20000"
        ):
            if kind in _CTX_KINDS or kind == "d.keystep.mark":
                continue
            data = loads(payload, {}) or {}
            subj = data.get("subject")
            out.append(
                _entry(
                    str(did),
                    "decision",
                    ts,
                    mono,
                    boot,
                    data.get("terminal_id"),
                    None,
                    seq,
                    kind=kind,
                    summary=_summary(str(kind), data),
                    host_id=subj if isinstance(subj, str) else None,
                    payload=data,
                )
            )
    if "context" in types:
        for rec in journal.iter_events(kinds=list(_CTX_KINDS)):
            h = rec.header
            wall, mono, boot = record_time(rec)
            stage = {
                "kind": h.get("kind") or ("unknown" if rec.kind == "d.ctx.push" else None),
                "host": h.get("host"),
                "user": h.get("user"),
            }
            off = h.get("from_off", h.get("stream_off"))
            out.append(
                _entry(
                    f"c:{rec.seq}",
                    "context",
                    wall,
                    mono,
                    boot,
                    h.get("terminal_id"),
                    off,
                    rec.seq,
                    change=_CTX_CHANGE.get(rec.kind, "set"),
                    stack_label=(
                        queries.context_label(stage) if rec.kind != "d.ctx.pop" else "Stufe beendet"
                    ),
                    source=_SOURCE.get(str(rec.origin), "auto"),
                    host_id=h.get("host"),
                    stage_kind=stage["kind"] if rec.kind != "d.ctx.pop" else None,
                    user=h.get("user") if rec.kind != "d.ctx.pop" else None,
                )
            )
        for tid, opened, host, claim_key in conn.execute(
            "SELECT terminal_id, opened_at, host, claim_key FROM ctx_auto LIMIT 10000"
        ):
            row = conn.execute(
                "SELECT ts_utc_ns, mono_ns, boot_id FROM unit WHERE terminal_id = ? AND start_off >= ? "
                "ORDER BY start_off LIMIT 1",
                (tid, int(opened)),
            ).fetchone()
            if row is None:
                continue
            kind_row = conn.execute(
                "SELECT ctx_kind FROM obs_unit WHERE terminal_id = ? AND ctx_opened_at = ? LIMIT 1",
                (tid, int(opened)),
            ).fetchone()
            # Der Callback, der den Kontext setzte: Zeit und Sitzung («msf session 1», 18.12)
            cb = conn.execute(
                "SELECT cs.ts_utc_ns, o.attrs_json FROM claim_source cs "
                "JOIN observation o ON o.obs_id = cs.obs_id "
                "JOIN obs_unit u ON u.unit_id = cs.unit_id WHERE cs.claim_key = ? AND u.terminal_id = ? "
                "AND u.ctx_opened_at = ? ORDER BY cs.ts_utc_ns LIMIT 1",
                (claim_key, tid, int(opened)),
            ).fetchone()
            attrs = loads(cb[1], {}) if cb else {}
            session = attrs.get("session") if isinstance(attrs, Mapping) else None
            if not (isinstance(session, str) and session.isdigit() and len(session) <= 9):
                session = None
            if cb and isinstance(cb[0], int):
                row = (cb[0], None, row[2])  # Zeit des Callbacks; Ordnung über denselben Systemstart
            out.append(
                _entry(
                    f"a:{tid}@{opened}",
                    "context",
                    row[0],
                    row[1],
                    row[2],
                    tid,
                    opened,
                    0,
                    change="auto",
                    stack_label=queries.context_label(
                        {"kind": "remote", "host": host, "host_source": "auto"}
                    ),
                    source="auto",
                    host_id=host,
                    stage_kind=str(kind_row[0]) if kind_row and isinstance(kind_row[0], str) else None,
                    user=None,
                    session=session,
                )
            )
    if "callback" in types:
        out.extend(_callbacks(conn))
    if "gap" in types:
        pauses: dict[str, Any] = {}
        for rec in journal.iter_events(kinds=["term.pause", "term.gap"]):
            h = rec.header
            tid = h.get("terminal_id") or rec.terminal_id
            wall, mono, boot = record_time(rec)
            if rec.kind == "term.pause":
                pauses[str(tid)] = (rec, wall, mono, boot)
                continue
            start = pauses.pop(str(tid), None) if h.get("reason") == "pause" else None
            if start is not None:
                prec, pwall, pmono, pboot = start
                out.append(
                    _entry(
                        f"g:{rec.seq}",
                        "gap",
                        pwall,
                        pmono,
                        pboot,
                        tid,
                        prec.header.get("stream_off"),
                        prec.seq,
                        reason="pause",
                        until=wall,
                        bytes_lost=int(h.get("bytes_lost") or 0),
                    )
                )
            else:
                out.append(
                    _entry(
                        f"g:{rec.seq}",
                        "gap",
                        wall,
                        mono,
                        boot,
                        tid,
                        h.get("stream_off"),
                        rec.seq,
                        reason=h.get("reason"),
                        until=None,
                        bytes_lost=int(h.get("bytes_lost") or 0),
                    )
                )
        for tid, (prec, pwall, pmono, pboot) in pauses.items():  # Pause läuft noch
            until = prec.header.get("until_ns")
            out.append(
                _entry(
                    f"g:{prec.seq}",
                    "gap",
                    pwall,
                    pmono,
                    pboot,
                    tid,
                    prec.header.get("stream_off"),
                    prec.seq,
                    reason="pause",
                    until=until if isinstance(until, int) else None,
                    bytes_lost=0,
                )
            )
    if "project" in types:
        for rec in journal.iter_events(
            kinds=["system.project_created", "system.project_end", "term.preroll"]
        ):
            h = rec.header
            wall, mono, boot = record_time(rec)
            if rec.kind == "system.project_created":
                out.append(
                    _entry(
                        f"p:{rec.seq}",
                        "project",
                        wall,
                        mono,
                        boot,
                        None,
                        None,
                        rec.seq,
                        change="start",
                        reason=None,
                        detail=None,
                    )
                )
            elif rec.kind == "system.project_end":
                idle = h.get("idle_s")
                detail = f"nach {int(idle) // 60} min ohne Ausgabe" if isinstance(idle, int) else None
                out.append(
                    _entry(
                        f"p:{rec.seq}",
                        "project",
                        wall,
                        mono,
                        boot,
                        None,
                        None,
                        rec.seq,
                        change="end",
                        reason=h.get("reason"),
                        detail=detail,
                    )
                )
            else:
                frames = h.get("frames")
                out.append(
                    _entry(
                        f"p:{rec.seq}",
                        "project",
                        wall,
                        mono,
                        boot,
                        h.get("terminal_id"),
                        h.get("from_off"),
                        rec.seq,
                        change="preroll",
                        reason=None,
                        detail=f"{int(frames)} Rahmen aus dem Vorlauf übernommen"
                        if isinstance(frames, int)
                        else None,
                    )
                )
    if "input" in types:
        for v in inputs.collect_inputs(journal, terminal_id=terminal, limit=INPUTS_MAX):
            out.append(
                _entry(
                    f"i:{v.get('seq')}",
                    "input",
                    v.get("t_shim_ns"),
                    v.get("mono_ns"),
                    v.get("boot_id"),
                    v.get("terminal_id"),
                    v.get("stream_off"),
                    v.get("seq"),
                    view=v,
                )
            )
    return out


def _shape(e: Mapping[str, Any], ctx: Mapping[str, Any], bag: Bag) -> dict[str, Any]:
    b = bag.new()
    t = e["type"]
    item: dict[str, Any] = {
        "id": b(e["id"]),
        "type": t,
        "ts": iso(e.get("ts")),
        "ts_ns": ns_str(e.get("ts")),
        "terminal_id": e.get("terminal_id"),
        "context_label": None,
        "host_id": b(e.get("host_id")) if isinstance(e.get("host_id"), str) else None,
        "terminal": term_ref(e.get("terminal_id"), ctx["refs"], b),
    }
    if t in ("command", "segment", "file"):
        item["context_label"] = b(e.get("context"))
    if t == "command":
        cid = e.get("cmd_id")
        unit = {
            "state": e.get("state"),
            "cmd_id": cid,
            "cmd_text": e.get("title"),
            "ts_utc_ns": e.get("ts"),
            "ts_end_ns": ctx["ends"].get(str(e.get("unit_id"))),
            "exit_code": e.get("exit"),
        }
        dist = ctx["distrust"].get(str(cid)) if e.get("distrusted") else None
        targets = ctx["scope"].get(str(cid))
        item.update(
            {
                "cmd": command_ref(unit, b, e.get("src_ip")),
                "unit_id": e.get("unit_id"),
                "adopted": int(e.get("adopted") or 0),
                "distrusted": (
                    {"decision_id": dist[0], "rejected": int(dist[1]), "weakened": int(dist[2])}
                    if dist
                    else None
                ),
                "scope_warning": (
                    {
                        "targets": [
                            {"value": b(x.get("raw") or x.get("id")) or "", "verdict": x.get("verdict")}
                            for x in targets
                        ]
                    }
                    if targets
                    else None
                ),
                "flags": [f for f in (e.get("flags") or []) if f in _FLAGS],
                "files": [{"unit_id": f[0], "path": b(f[1]) or ""} for f in ctx["files"].get(str(cid), [])],
                "lines": int(e.get("lines") or 0),
                "result": ctx["results"].get(
                    str(cid), {"hosts_new": 0, "services": 0, "values": 0, "out_of_scope": 0, "conflicts": 0}
                ),
            }
        )
    elif t == "segment":
        extra = int((ctx.get("pending") or {}).get(str(e.get("unit_id")), 0))
        item.update(
            {
                "unit_id": e.get("unit_id"),
                "lines": int(e.get("lines") or 0) + extra,
                "state": e.get("state") if e.get("state") in ("open", "provisional", "final") else "open",
                "evaluate_after": (
                    iso(ctx["last_out"].get(str(e.get("terminal_id"))) + SILENCE_NS)
                    if e.get("state") != "final"
                    and isinstance(ctx["last_out"].get(str(e.get("terminal_id"))), int)
                    else None
                ),
            }
        )
    elif t == "file":
        item.update({"unit_id": e.get("unit_id"), "path": b(e.get("title")) or "", "cmd_id": e.get("cmd_id")})
    elif t == "keystep":
        item.update(
            {
                "step": e.get("title"),
                "host_label": b(e.get("context") if e.get("context") != "-" else None),
                "note": b(e.get("note")),
                "ordinal": int(e.get("ordinal") or 0),
                "decision_id": e.get("decision_id"),
            }
        )
    elif t == "context":
        host = e.get("host_id")
        host = host if isinstance(host, str) and host and host != "local" else None
        kind = e.get("stage_kind")
        item.update(
            {
                "change": e.get("change"),
                "stack_label": b(e.get("stack_label")) or "",
                "source": e.get("source"),
                # 18.12: einzeln für die Zeile «Kontext automatisch: 192.168.56.101 (auto)»
                "host_label": b(display(host)) if host else None,
                "stage_kind": kind if isinstance(kind, str) and kind in _STAGE_KINDS else None,
                "user": b(e.get("user")) if isinstance(e.get("user"), str) else None,
                "session": e.get("session") if isinstance(e.get("session"), str) else None,
            }
        )
        item["context_label"] = item["stack_label"]
    elif t == "decision":
        item.update({"decision_id": e.get("id"), "kind": e.get("kind"), "summary": e.get("summary")})
        item.update(_decision_extra(e, ctx, b))
    elif t == "callback":
        item.update(
            {
                "unit_id": e.get("unit_id"),
                "remote": b(e.get("remote")),
                "listener": b(e.get("listener")),
                "scope": e.get("scope"),
                "session": e.get("session"),
                "lines": e.get("lines"),
            }
        )
    elif t == "gap":
        item.update(
            {
                "reason": e.get("reason"),
                "until": iso(e.get("until")),
                "bytes_lost": int(e.get("bytes_lost") or 0),
            }
        )
    elif t == "project":
        item.update({"change": e.get("change"), "reason": e.get("reason"), "detail": e.get("detail")})
    elif t == "input":
        item["input"] = input_view(e["view"], bag, ctx["secrets"])
        item["ctrl"] = bool(item["input"]["ctrl"])
    item["ctrl"] = bool(item.get("ctrl")) or b.ctrl
    return item


def _page_context(
    conn: Any, page: list[dict[str, Any]], all_entries: list[dict[str, Any]], profile: str = "lab"
) -> dict[str, Any]:
    cmd_ids = sorted({str(e["cmd_id"]) for e in page if e["type"] == "command" and e.get("cmd_id")})
    unit_ids = sorted({str(e["unit_id"]) for e in page if e["type"] == "command" and e.get("unit_id")})
    ends: dict[str, Any] = {}
    scope: dict[str, list[dict[str, Any]]] = {}
    distrust: dict[str, tuple[Any, Any, Any]] = {}
    for part in chunks(unit_ids):
        marks = ",".join("?" * len(part))
        for uid, end in conn.execute(
            f"SELECT unit_id, ts_end_ns FROM unit WHERE unit_id IN ({marks})",  # noqa: S608
            tuple(part),
        ):
            ends[str(uid)] = end
    for part in chunks(cmd_ids):
        marks = ",".join("?" * len(part))
        for cid, ts_json in conn.execute(
            f"SELECT cmd_id, target_scope FROM activity WHERE cmd_id IN ({marks})",  # noqa: S608
            tuple(part),
        ):
            bad = [t for t in (loads(ts_json, []) or []) if isinstance(t, dict) and t.get("verdict") != "in"]
            if bad:
                scope[str(cid)] = bad[:50]
        for cid, did, rej, weak in conn.execute(
            f"SELECT cmd_id, decision_id, rejected, weakened FROM unit_distrust WHERE cmd_id IN ({marks})",  # noqa: S608
            tuple(part),
        ):
            distrust[str(cid)] = (did, rej, weak)
    files: dict[str, list[tuple[str, str]]] = {}
    wanted = set(cmd_ids)
    for e in all_entries:
        if e["type"] == "file" and e.get("cmd_id") in wanted:
            files.setdefault(str(e["cmd_id"]), []).append((str(e.get("unit_id")), str(e.get("title") or "")))
    secrets = secret_values(conn) if any(e["type"] == "input" for e in page) else []
    last_out = {
        str(tid): int(ts)
        for tid, ts in conn.execute(
            "SELECT terminal_id, last_out_ns FROM seg_term WHERE last_out_ns IS NOT NULL"
        )
    }
    return {
        "ends": ends,
        "scope": scope,
        "distrust": distrust,
        "files": files,
        "secrets": secrets,
        "refs": queries.term_refs(conn),
        "results": _results(conn, cmd_ids),
        "last_out": last_out,
        "decisions": _decision_refs(conn, page, profile),
        # offene Segmente: Zeilen, die erst vorläufig gelesen sind (ingest.pending)
        "pending": {
            str(e["unit_id"]): pending.visible_extra(conn, str(e["unit_id"]))
            for e in page
            if e["type"] == "segment" and e.get("unit_id") and e.get("state") != "final"
        },
    }


def _results(conn: Any, cmd_ids: list[str]) -> dict[str, dict[str, int]]:
    """Ergebnis pro Befehl (18.8): «1 Host, 23 Services · 141 Werte übernommen», «+17 ausserhalb»,
    «1 Widerspruch». Grundlage ist die Evidenzgruppe des Befehls (``claim_source.group_key``)."""
    out: dict[str, dict[str, int]] = {}
    for part in chunks(cmd_ids):
        marks = ",".join("?" * len(part))
        where = f"WHERE cs.group_key IN ({marks}) AND cs.distrusted = 0"
        sql = (
            "SELECT cs.group_key, c.claim_key, c.entity_id, c.state, c.lane, c.lane_reason, c.scope, "  # noqa: S608
            "c.conflict_key FROM claim_source cs JOIN claim c ON c.claim_key = cs.claim_key " + where
        )
        rows = conn.execute(sql, tuple(part)).fetchall()
        seen: set[tuple[str, str]] = set()
        services: dict[str, set[str]] = {}
        open_conf = {
            str(r[0]) for r in conn.execute("SELECT conflict_key FROM conflict WHERE state = 'open'")
        }
        for gk, ck, eid, state, lane, reason, scope, conflict in rows:
            g = str(gk)
            if (g, ck) in seen:
                continue
            seen.add((g, ck))
            r = out.setdefault(
                g, {"hosts_new": 0, "services": 0, "values": 0, "out_of_scope": 0, "conflicts": 0}
            )
            if lane == "auto" and state == "auto":
                r["values"] += 1
            if reason == "out_of_scope" or (scope not in (None, "in") and lane == "quiet"):
                r["out_of_scope"] += 1
            if conflict is not None and str(conflict) in open_conf:
                r["conflicts"] += 1
            if isinstance(eid, str) and eid.startswith("svc:") and scope == "in":
                services.setdefault(g, set()).add(eid)
        for g, svcs in services.items():
            out[g]["services"] = len(svcs)
    # neue Hosts: Hosts im Scope, deren früheste Quelle (eines Werts des Hosts selbst) aus diesem
    # Befehl stammt. SQLite liefert zu MIN() die Spalten derselben Zeile.
    wanted = set(cmd_ids)
    if wanted:
        for _eid, gk, _ts in conn.execute(
            "SELECT c.entity_id, cs.group_key, MIN(cs.ts_utc_ns) FROM claim c "
            "JOIN claim_source cs ON cs.claim_key = c.claim_key "
            "JOIN v_host h ON h.host_id = c.entity_id WHERE h.scope = 'in' AND cs.ts_utc_ns IS NOT NULL "
            "GROUP BY c.entity_id"
        ):
            if gk in wanted:
                r = out.setdefault(
                    str(gk), {"hosts_new": 0, "services": 0, "values": 0, "out_of_scope": 0, "conflicts": 0}
                )
                r["hosts_new"] += 1
    return out


def _finding_refs(conn: Any, page: list[dict[str, Any]]) -> dict[str, tuple[int, str]]:
    """Nummer und Titel der Findings, auf die Entscheide der Seite zeigen (Korrektur K3)."""
    ids: set[str] = set()
    for e in page:
        kind = str(e.get("kind") or "")
        if e["type"] != "decision" or not kind.startswith("d.finding."):
            continue
        fid = (e.get("payload") or {}).get("finding_id") if kind != "d.finding.create" else e.get("id")
        if isinstance(fid, str):
            ids.add(fid)
    out: dict[str, tuple[int, str]] = {}
    for part in chunks(sorted(ids)):
        marks = ",".join("?" * len(part))
        try:
            rows = conn.execute(
                f"SELECT finding_id, ordinal, title FROM finding WHERE finding_id IN ({marks})",  # noqa: S608
                tuple(part),
            ).fetchall()
        except sqlite3.Error:
            return {}
        for fid, ordinal, title in rows:
            out[str(fid)] = (int(ordinal), str(title))
    return out


def _suggestion_refs(conn: Any, page: list[dict[str, Any]], profile: str) -> dict[str, tuple[str, str]]:
    """Regel und Titel der Denkanstösse, auf die Entscheide der Seite zeigen (Korrektur K3)."""
    keys = {
        str((e.get("payload") or {}).get("suggestion_key"))
        for e in page
        if e["type"] == "decision" and str(e.get("kind") or "").startswith("d.suggestion.")
    }
    if not keys:
        return {}
    try:
        items, _more = rules_api.suggestions(conn, profile=profile, state="all", limit=2000)
    except Exception:  # noqa: BLE001 - die Zeitachse zeigt den Entscheid auch ohne Titel
        return {}
    return {
        str(s["suggestion_key"]): (str(s.get("rule_id") or ""), str(s.get("title") or ""))
        for s in items
        if isinstance(s, dict) and s.get("suggestion_key") in keys
    }


def _decision_refs(conn: Any, page: list[dict[str, Any]], profile: str = "lab") -> dict[str, Any]:
    """Wirkung von ``d.unit.distrust`` und Befehle der Entscheide auf der Seite."""
    ids = [str(e["id"]) for e in page if e["type"] == "decision"]
    effects: dict[str, tuple[int, int, str]] = {}
    for part in chunks(ids):
        marks = ",".join("?" * len(part))
        sql = "SELECT decision_id, rejected, weakened, cmd_id FROM unit_distrust WHERE decision_id IN "
        sql += f"({marks})"
        for did, rej, weak, cid in conn.execute(sql, tuple(part)):
            effects[str(did)] = (int(rej), int(weak), str(cid))
    claims: dict[str, tuple[str, str]] = {}
    keys = sorted(
        {
            str((e.get("payload") or {}).get("claim_key"))
            for e in page
            if e["type"] == "decision" and isinstance((e.get("payload") or {}).get("claim_key"), str)
        }
    )
    for part in chunks(keys):
        marks = ",".join("?" * len(part))
        for ck, subj, pred in conn.execute(
            f"SELECT claim_key, subject_identifier, predicate FROM claim WHERE claim_key IN ({marks})",  # noqa: S608
            tuple(part),
        ):
            claims[str(ck)] = (str(subj), str(pred))
    return {
        "effects": effects,
        "claims": claims,
        "findings": _finding_refs(conn, page),
        "suggestions": _suggestion_refs(conn, page, profile),
        "scope_reverted": _scope_reverted(conn, page),
        "profile": profile,
    }


def _scope_reverted(conn: Any, page: list[dict[str, Any]]) -> dict[str, str]:
    """Scope-Änderungen (E129), die schon rückgängig gemacht sind: ``decision_id`` -> Entscheid, der
    sie rückgängig machte."""
    if not any(e["type"] == "decision" and e.get("kind") == "d.scope.update" for e in page):
        return {}
    out: dict[str, str] = {}
    for did, payload in conn.execute(
        "SELECT id, payload_json FROM decision WHERE kind = 'd.scope.update' ORDER BY seq LIMIT 100000"
    ):
        ch = (loads(payload, {}) or {}).get("change")
        if isinstance(ch, Mapping) and isinstance(ch.get("revert_of"), str):
            out[ch["revert_of"]] = str(did)
    return out


_ACCESS_DETAIL = {"none": "kein Zugriff", "user": "Benutzer", "admin": "root"}


def _decision_extra(e: Mapping[str, Any], ctx: Mapping[str, Any], b: Bag) -> dict[str, Any]:
    """``detail`` (Zielbezug als Text), ``reason``, ``ref`` und ``effect`` eines Entscheids (18.8)."""
    kind = str(e.get("kind") or "")
    data = e.get("payload") or {}
    refs = ctx["decisions"]
    detail: str | None = None
    subj = data.get("subject")
    if kind == "d.status.access" and isinstance(subj, str):
        detail = f"Zugriff {_ACCESS_DETAIL.get(str(data.get('value')), 'geändert')} auf {display(subj)}"
    elif kind in ("d.status.work", "d.note.set", "d.tag.add", "d.tag.remove") and isinstance(subj, str):
        detail = display(subj)
        if kind in ("d.tag.add", "d.tag.remove") and isinstance(data.get("tag"), str):
            detail += f" · {data['tag']}"
    elif kind.startswith("d.claim.") and isinstance(data.get("claim_key"), str):
        c = refs["claims"].get(data["claim_key"])
        if c is not None:
            detail = f"{display(c[0])} · {c[1]}"
    elif kind in ("d.entity.merge", "d.entity.split"):
        idents = [display(str(x)) for x in data.get("identifiers") or [] if isinstance(x, str)]
        detail = " + ".join(idents[:4]) or None
    elif kind.startswith("d.finding."):
        fid = e.get("id") if kind == "d.finding.create" else data.get("finding_id")
        f = refs.get("findings", {}).get(fid) if isinstance(fid, str) else None
        title = data.get("title") if isinstance(data.get("title"), str) else (f[1] if f else None)
        if f is not None:
            detail = f"F{f[0]} · {title}" if title else f"F{f[0]}"
        elif title:
            detail = title
    elif kind.startswith("d.suggestion."):
        sg = refs.get("suggestions", {}).get(data.get("suggestion_key"))
        if sg is not None:
            detail = sg[1] or sg[0] or None
    effect = refs["effects"].get(str(e.get("id")))
    ref = None
    if kind == "d.unit.distrust":
        cid = data.get("cmd_id")
        ref = queries.cmd_ref(cid) if isinstance(cid, str) else (effect[2] if effect else None)
    reason = data.get("reason") if isinstance(data.get("reason"), str) else None
    scope_change = None
    ch = data.get("change") if kind == "d.scope.update" else None
    if isinstance(ch, Mapping):
        entries = [str(x) for x in ch.get("entries") or [] if isinstance(x, str)]
        detail = ", ".join(entries[:6]) or None
        reason = ch.get("reason") if isinstance(ch.get("reason"), str) else None
        by = refs.get("scope_reverted", {}).get(str(e.get("id")))
        scope_change = {
            "op": ch.get("op") if ch.get("op") in _SCOPE_OP else None,
            "entries": [b(x) or "" for x in entries],
            # E131: Listen der Änderung, damit der Text bei Rückgängig stimmt
            **{k: [b(x) or "" for x in (ch.get(k) or []) if isinstance(x, str)][:50]
               for k in ("include_added", "include_removed", "exclude_added", "exclude_removed")},
            "open_before": ch.get("open_before") if isinstance(ch.get("open_before"), bool) else None,
            "open_after": ch.get("open_after") if isinstance(ch.get("open_after"), bool) else None,
            "version": data.get("version") if isinstance(data.get("version"), int) else None,
            "revert_of": ch.get("revert_of") if isinstance(ch.get("revert_of"), str) else None,
            "reverted_by": by,
            # Rückgängig über POST /p/{pid}/scope/changes {op: 'revert', decision_id} (web-api.md 20)
            "revertible": by is None and refs.get("profile") != "customer",
        }
    return {
        "detail": b(detail),
        "reason": b(reason),
        "ref": b(ref),
        "effect": {"rejected": effect[0], "weakened": effect[1]} if effect else None,
        "scope_change": scope_change,
    }


def timeline_page(
    conn: Any,
    journal: Any,
    *,
    types: frozenset[str],
    terminal: str | None,
    host: str | None,
    cursor: dict[str, Any] | None,
    limit: int,
    bag: Bag,
    profile: str = "lab",
) -> dict[str, Any]:
    bag = with_secrets(bag, conn)  # Befehlstexte maskiert (SEC-W1)
    entries = _collect(conn, journal, types, terminal)
    queries.sort_time(entries, queries.boot_ranks(conn))  # dieselbe Ordnung wie ariadne show timeline (E96)
    entries.reverse()  # neueste zuerst
    if host is not None:
        ents = _entities(conn)

        def of(x: Any) -> str | None:
            return ents.get(x, x) if isinstance(x, str) else None

        target = of(host)
        entries_f = [e for e in entries if of(e.get("host_id")) in (host, target)]
    else:
        entries_f = entries
    picked = [
        e for e in entries_f if e["type"] in types and (terminal is None or e.get("terminal_id") == terminal)
    ]
    start = 0
    if cursor is not None:
        cid = cursor.get("id")
        idx = next((i for i, e in enumerate(picked) if e["id"] == cid), None)
        if idx is not None:
            start = idx + 1
        else:
            cts = cursor.get("ts")
            cts = cts if isinstance(cts, int) else 0
            start = next((i for i, e in enumerate(picked) if int(e.get("ts") or 0) < cts), len(picked))
    page = picked[start : start + limit]
    more = start + limit < len(picked)
    ctx = _page_context(conn, page, entries, profile)
    items = [_shape(e, ctx, bag) for e in page]
    nxt = encode_cursor({"id": page[-1]["id"], "ts": int(page[-1].get("ts") or 0)}) if more and page else None
    return {"items": items, "next_cursor": nxt}


def _parse_types(raw: str | None) -> frozenset[str]:
    if raw is None or not raw.strip():
        return DEFAULT_TYPES
    parts = frozenset(x.strip() for x in raw.split(",") if x.strip())
    if not parts or not parts <= set(TYPES):
        raise ApiError("validation", [{"loc": ["query", "types"], "type": "enum"}])
    return parts


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/timeline", name="timeline")
    async def get_timeline(
        pid: str,
        types: str | None = Query(default=None, max_length=200),  # noqa: B008
        terminal: str | None = Query(default=None, max_length=64),  # noqa: B008
        host: str | None = Query(default=None, max_length=600),  # noqa: B008
        cursor: str | None = Query(default=None, max_length=512),  # noqa: B008
        limit: int = Query(default=200, ge=1, le=1000),
    ) -> Response:  # noqa: B008
        p = api.project(pid)
        wanted = _parse_types(types)
        if terminal is not None and not valid_tid(terminal):
            raise ApiError("validation", [{"loc": ["query", "terminal"], "type": "value_error"}])
        try:
            cur = decode_cursor(cursor)
        except ValueError:
            raise ApiError("validation", [{"loc": ["query", "cursor"], "type": "value_error"}]) from None
        bag = api.bag()
        profile = p.info.profile
        res = await api.query_journal(
            p,
            lambda c, j: timeline_page(
                c,
                j,
                types=wanted,
                terminal=terminal,
                host=host,
                cursor=cur,
                limit=limit,
                bag=bag,
                profile=profile,
            ),
        )
        return await api.respond(res)

    @router.get("/p/{pid}/inputs", name="inputs")
    async def get_inputs(
        pid: str,
        terminal: str | None = Query(default=None, max_length=64),  # noqa: B008
        limit: int = Query(default=200, ge=1, le=1000),
    ) -> Response:  # noqa: B008
        p = api.project(pid)
        if terminal is not None and not valid_tid(terminal):
            raise ApiError("validation", [{"loc": ["query", "terminal"], "type": "value_error"}])
        bag = api.bag()

        def run(conn: Any, journal: Any) -> list[dict[str, Any]]:
            secrets = secret_values(conn)
            return [
                input_view(v, bag, secrets)
                for v in inputs.collect_inputs(journal, terminal_id=terminal, limit=limit)
            ]

        return await api.respond({"items": await api.query_journal(p, run)})
