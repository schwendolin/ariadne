"""Daten für den Export sammeln (läuft im Thread der Auswertung, nur lesend).

:func:`collect` liest ``derived.db`` (Projektion) und das Journal (Kettenköpfe, Terminalgerät) und
gibt eine reine Datenstruktur zurück. Alle Texte darin sind schon für den Ausgang vorbereitet:

* eigene Secrets ersetzt (``redact_for_exit``, E72), immer, auch mit Klartext;
* Ziel-Credentials maskiert (bekannte Secret-Werte, Secret-Bereiche der Parser, verdeckte Eingaben
  und SGR-verdeckter Text), ausser mit Klartext (nur Profil lab, Bestätigung im Terminal);
* noch **nicht** für Markdown kodiert: das macht allein :mod:`ariadne.export.render` mit
  :mod:`ariadne.export.mdsafe` (ein Encoder pro Senke, E13).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ariadne.ingest import pending, proj_phases, queries

__all__ = ["Masker", "collect", "iso_ms", "MASK", "UNIT_MAX", "LINES_MAX"]

MASK = "••••••••"
UNIT_MAX = 1000  # höchstens so viele Belege
LINES_MAX = 400  # höchstens so viele Zeilen pro Beleg
CONTEXT_LINES = 3  # Zeilen vor und nach einem Belegbereich
_PNG = b"\x89PNG\r\n\x1a\n"
_IMG_MAX = 15 << 20


def iso_ms(ns: Any) -> str | None:
    """UTC mit Millisekunden: ``2026-10-18T10:15:00.123Z``."""
    if not isinstance(ns, int) or isinstance(ns, bool):
        return None
    dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{(ns // 1_000_000) % 1000:03d}Z"


def _json(text: Any, default: Any) -> Any:
    if not isinstance(text, str):
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


class Masker:
    """Ausgangsfilter für Texte aus dem Projekt (ein Objekt pro Export)."""

    def __init__(self, redactor: Any, known: Iterable[str], *, klartext: bool) -> None:
        self._red = redactor
        self.klartext = bool(klartext)
        self.known = sorted({k for k in known if isinstance(k, str) and len(k) >= 4}, key=len, reverse=True)
        self.masked = 0  # wie oft ein Ziel-Credential maskiert wurde

    def own(self, text: Any) -> str:
        s = text if isinstance(text, str) else ("" if text is None else str(text))
        if self._red is not None and s:
            out, _labels = self._red.redact_for_exit(s)
            s = str(out)
        return s

    def target(self, text: Any) -> str:
        """Eigene Secrets ersetzen, dann (ohne Klartext) bekannte Ziel-Credentials maskieren."""
        s = self.own(text)
        if not self.klartext:
            for k in self.known:
                if k in s:
                    self.masked += s.count(k)
                    s = s.replace(k, MASK)
        return s

    def line(self, text: str, spans: list[tuple[int, int]]) -> str:
        """Eine Logzeile: Secret-Bereiche (Spalten) zuerst, dann wie :meth:`target`."""
        s = self.own(text)
        if not self.klartext and spans:
            chars = list(s)
            hit = False
            for a, b in spans:
                end = len(chars) if b < 0 else min(b, len(chars))
                for i in range(max(0, a), end):
                    chars[i] = "\x00"
                    hit = True
            if hit:
                self.masked += 1
                out: list[str] = []
                prev = False
                for ch in chars:
                    if ch == "\x00":
                        if not prev:
                            out.append(MASK)
                        prev = True
                    else:
                        out.append(ch)
                        prev = False
                s = "".join(out)
        return self.target(s)


@dataclass
class Beleg:
    unit_id: str
    kind: str
    cmd_id: str | None
    command: str | None
    started: str | None
    ended: str | None
    exit_code: int | None
    terminal: str | None
    tty: str | None
    context: str
    chain_seq: int | None
    chain_hash: str | None
    total_lines: int
    lines: list[tuple[int, str]] = field(default_factory=list)
    ranges: list[tuple[int, int]] = field(default_factory=list)
    truncated: bool = False
    path: str | None = None
    sha256: str | None = None


def _secret_spans(conn: Any, unit_id: str) -> dict[int, list[tuple[int, int]]]:
    out: dict[int, list[tuple[int, int]]] = {}
    for (span_json,) in conn.execute(
        "SELECT span_json FROM observation WHERE unit_id = ? AND is_secret = 1 "
        "UNION ALL SELECT span_json FROM mention WHERE unit_id = ? AND is_secret = 1 LIMIT 100000",
        (unit_id, unit_id),
    ):
        span = _json(span_json, None)
        if not isinstance(span, Mapping):
            continue
        a, b = span.get("line_start"), span.get("line_end")
        if not isinstance(a, int) or not isinstance(b, int) or b < a or b - a > 10000:
            continue
        cs, ce = span.get("col_start"), span.get("col_end")
        for i in range(a, b + 1):
            start = cs if i == a and isinstance(cs, int) else 0
            end = ce if i == b and isinstance(ce, int) else -1
            out.setdefault(i, []).append((start, end))
    return out


def _concealed(sgr_json: Any) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for sp in _json(sgr_json, []) or []:
        if (
            isinstance(sp, Mapping)
            and sp.get("c")
            and isinstance(sp.get("s"), int)
            and isinstance(sp.get("e"), int)
        ):
            out.append((int(sp["s"]), int(sp["e"])))
    return out


def _tty(jconn: Any, tid: Any) -> str | None:
    import re

    if jconn is None or not isinstance(tid, str):
        return None
    row = jconn.execute(
        "SELECT header FROM event WHERE kind = 'term.open' AND terminal_id = ? ORDER BY seq LIMIT 1", (tid,)
    ).fetchone()
    header = _json(row[0], {}) if row else {}
    tty = header.get("tty") if isinstance(header, Mapping) else None
    return tty if isinstance(tty, str) and re.fullmatch(r"/dev/[A-Za-z0-9/._-]{1,40}", tty) else None


def _chain_at(jconn: Any, seq: Any) -> tuple[int | None, str | None]:
    """Kettenkopf am Event ``seq`` (Hash dieses Events; alles davor ist darin verankert)."""
    if jconn is None or not isinstance(seq, int):
        return None, None
    row = jconn.execute("SELECT seq, hash FROM event WHERE seq = ?", (seq,)).fetchone()
    if row is None:
        return None, None
    return int(row[0]), bytes(row[1]).hex()


def _term_label(refs: Mapping[str, Mapping[str, Any]], tid: Any, m: Masker) -> str | None:
    if not isinstance(tid, str):
        return None
    r = refs.get(tid)
    if not r:
        return "Terminal"
    label = r.get("label")
    return f"T{r.get('ordinal')}" + (f" {m.target(label)}" if isinstance(label, str) and label else "")


def _ranges_merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for a, b in sorted(ranges):
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _beleg(
    conn: Any,
    jconn: Any,
    unit_id: str,
    focus: list[tuple[int, int]],
    m: Masker,
    refs: Mapping[str, Mapping[str, Any]],
) -> Beleg | None:
    row = conn.execute(
        "SELECT unit_id, kind, terminal_id, cmd_id, cmd_text, exit_code, context, ts_utc_ns, ts_end_ns, "
        "event_seq, path, sha256 FROM unit WHERE unit_id = ?",
        (unit_id,),
    ).fetchone()
    if row is None:
        return None
    kind, tid, cmd_id, cmd_text = row[1], row[2], row[3], row[4]
    if kind == "segment" and not cmd_text and cmd_id:
        opener = conn.execute(
            "SELECT cmd_text FROM unit WHERE cmd_id = ? AND kind = 'command' LIMIT 1", (cmd_id,)
        ).fetchone()
        if opener is not None and opener[0]:
            cmd_text = opener[0]
    total = pending.line_count(conn, unit_id)
    spans = _secret_spans(conn, unit_id)
    # Ausschnitt: Belegbereiche mit Kontext, sonst der Anfang
    if focus:
        want = _ranges_merge([(max(0, a - CONTEXT_LINES), b + CONTEXT_LINES) for a, b in focus])
    else:
        want = [(0, LINES_MAX - 1)]
    lines: list[tuple[int, str]] = []
    for a, b in want:
        if len(lines) >= LINES_MAX:
            break
        count = min(b - a + 1, LINES_MAX - len(lines))
        for pos, idx, text, flags, sgr in pending.line_rows(conn, unit_id, a, count):
            if pos > b:
                break
            sp = list(spans.get(idx, [])) if isinstance(idx, int) else []
            sp += _concealed(sgr)
            if int(flags or 0) & 2:  # verdeckte Zeile (Eingabe ohne Echo)
                sp.append((0, -1))
            lines.append((int(pos), m.line(str(text), sp)))
    shown = len(lines)
    seq, chash = _chain_at(jconn, row[9])
    ctx = _json(row[6], {}) or {}
    return Beleg(
        unit_id=str(unit_id),
        kind=str(kind),
        cmd_id=cmd_id,
        command=m.target(cmd_text) if cmd_text else None,
        started=iso_ms(row[7]),
        ended=iso_ms(row[8]),
        exit_code=row[5] if isinstance(row[5], int) else None,
        terminal=_term_label(refs, tid, m),
        tty=_tty(jconn, tid),
        context=m.target(queries.context_label(ctx)),
        chain_seq=seq,
        chain_hash=chash,
        total_lines=int(total),
        lines=lines,
        ranges=[(a, b) for a, b in focus],
        truncated=shown < total,
        path=m.target(row[10]) if row[10] else None,
        sha256=row[11] if isinstance(row[11], str) else None,
    )


def _claim_focus(conn: Any, claim_key: str) -> list[tuple[str, tuple[int, int] | None]]:
    """Quellen eines Claims: (unit_id, Zeilenbereich als pos) aus ``claim_source``."""
    out: list[tuple[str, tuple[int, int] | None]] = []
    for unit_id, span_json in conn.execute(
        "SELECT unit_id, span_json FROM claim_source WHERE claim_key = ? AND unit_id IS NOT NULL "
        "AND distrusted = 0 ORDER BY ts_utc_ns LIMIT 5",
        (claim_key,),
    ):
        span = _json(span_json, None)
        rng: tuple[int, int] | None = None
        if (
            isinstance(span, Mapping)
            and isinstance(span.get("line_start"), int)
            and isinstance(span.get("line_end"), int)
        ):
            r = conn.execute(
                "SELECT MIN(pos), MAX(pos) FROM unit_line WHERE unit_id = ? AND idx BETWEEN ? AND ?",
                (unit_id, span["line_start"], span["line_end"]),
            ).fetchone()
            if r and r[0] is not None:
                rng = (int(r[0]), int(r[1]))
        out.append((str(unit_id), rng))
    return out


def _findings(conn: Any, m: Masker) -> tuple[list[dict[str, Any]], dict[str, list[tuple[int, int]]]]:
    focus: dict[str, list[tuple[int, int]]] = {}
    out: list[dict[str, Any]] = []
    rows = conn.execute(
        "SELECT finding_id, ordinal, title, severity, status, affected_json, description, remediation, "
        "attack_json, cves_json, created_from_json, created_ts, updated_ts FROM finding WHERE deleted = 0 "
        "ORDER BY ordinal LIMIT 500"
    ).fetchall()
    for r in rows:
        evid: list[dict[str, Any]] = []
        for claim_key, unit_id, ls, le, state in conn.execute(
            "SELECT claim_key, unit_id, line_start, line_end, state FROM finding_evidence "
            "WHERE finding_id = ? ORDER BY pos LIMIT 200",
            (r[0],),
        ):
            sources: list[tuple[str, tuple[int, int] | None]] = []
            if isinstance(unit_id, str):
                sources.append((unit_id, (int(ls), int(le)) if ls is not None and le is not None else None))
            elif isinstance(claim_key, str):
                sources.extend(_claim_focus(conn, claim_key))
            label = None
            if isinstance(claim_key, str):
                c = conn.execute(
                    "SELECT predicate, value_text FROM claim WHERE claim_key = ?", (claim_key,)
                ).fetchone()
                if c is not None:
                    label = f"{c[0]}: {m.target(c[1])}"
            for uid, rng in sources:
                focus.setdefault(uid, [])
                if rng is not None:
                    focus[uid].append(rng)
            evid.append(
                {
                    "state": state,
                    "label": label,
                    "units": [u for u, _ in sources],
                    "lines": [list(rng) if rng else None for _, rng in sources],
                }
            )
        created = _json(r[10], {}) or {}
        cf = created.get("unit_id") if isinstance(created, Mapping) else None
        if isinstance(cf, str):
            focus.setdefault(cf, [])
        affected = []
        for subj in _json(r[5], []) or []:
            if isinstance(subj, str):
                affected.append(m.target(_subject_label(conn, subj)))
        out.append(
            {
                "finding_id": r[0],
                "ordinal": r[1],
                "title": m.target(r[2]),
                "severity": r[3],
                "status": r[4],
                "affected": affected,
                "description": m.target(r[6] or ""),
                "remediation": m.target(r[7] or ""),
                "attack": [_ref_item(x, m) for x in _json(r[8], []) or [] if isinstance(x, Mapping)],
                "cves": [_ref_item(x, m) for x in _json(r[9], []) or [] if isinstance(x, Mapping)],
                "evidence": evid,
                "created_from": cf if isinstance(cf, str) else None,
                "created": iso_ms(r[11]),
                "updated": iso_ms(r[12]),
            }
        )
    return out, focus


def _ref_item(x: Mapping[str, Any], m: Masker) -> dict[str, Any]:
    return {"id": m.target(x.get("id") or "?"), "hypothesis": x.get("hypothesis") is not False}


def _subject_label(conn: Any, subj: str) -> str:
    eid = queries.entity_of_subject(conn, subj) or subj
    svc = conn.execute(
        "SELECT host_id, proto, port, name FROM v_service WHERE service_id = ?", (eid,)
    ).fetchone()
    if svc is not None:
        host = conn.execute("SELECT label FROM entity WHERE entity_id = ?", (svc[0],)).fetchone()
        hl = host[0] if host and host[0] else queries.display(str(svc[0]))
        return f"{hl}:{svc[2]} {svc[3] or ''}".strip() + (
            f" ({svc[1]})" if svc[1] and svc[1] != "tcp" else ""
        )
    host = conn.execute("SELECT label FROM entity WHERE entity_id = ?", (eid,)).fetchone()
    if host is not None and host[0]:
        return str(host[0])
    return queries.display(subj) if ":" in subj else subj


def _keystep_unit(conn: Any, k: Mapping[str, Any]) -> str | None:
    tid, off = k.get("terminal_id"), k.get("stream_off")
    if not isinstance(tid, str) or not isinstance(off, int):
        return None
    row = conn.execute(
        "SELECT unit_id FROM unit WHERE terminal_id = ? AND kind IN ('command', 'segment') "
        "AND start_off <= ? ORDER BY start_off DESC LIMIT 1",
        (tid, off),
    ).fetchone()
    return str(row[0]) if row else None


def _shots(
    journal: Any, jconn: Any, read_blob: Callable[[str], bytes] | None, m: Any
) -> list[dict[str, Any]]:
    """Screenshots aus ``shot.captured`` (Teil «screenshots»): nur Blobs, die Ariadne selbst als Screenshot
    abgelegt hat (``blob.kind = 'screenshot'``), nur kanonisches PNG (``check_png``). Die Pixel sind nicht
    redigiert; Fenstertitel und Notiz gehen wie Zieldaten durch den Maskierer."""
    from ariadne.sources.screenshot import check_png
    from ariadne.sources.screenshot_service import BLOB_KIND

    if journal is None or not hasattr(journal, "iter_events"):
        return []
    out: list[dict[str, Any]] = []
    for r in journal.iter_events(kinds=["shot.captured"]):
        if len(out) >= 500:
            break
        h = r.header if isinstance(r.header, dict) else {}
        blob_id, sha = h.get("blob_id"), h.get("sha256")
        data: bytes | None = None
        if read_blob is not None and jconn is not None and isinstance(blob_id, str):
            try:
                row = jconn.execute("SELECT kind FROM blob WHERE blob_id = ?", (blob_id,)).fetchone()
                if row is not None and row[0] == BLOB_KIND:
                    data = read_blob(blob_id)
                    check_png(data)
            except Exception:  # noqa: BLE001 - fehlt oder kein kanonisches PNG: nur vermerken
                data = None
        title, note, host = h.get("window_title"), h.get("note"), h.get("host")
        tid, off = h.get("terminal_id"), h.get("stream_off")
        out.append(
            {
                "unit_id": None,
                "sha256": sha if isinstance(sha, str) else None,
                "ts": iso_ms(r.ts_utc_ns),
                "data": data if isinstance(data, bytes) and len(data) <= _IMG_MAX else None,
                "title": m.target(title) if isinstance(title, str) and title else None,
                "note": m.target(note) if isinstance(note, str) and note else None,
                "host": m.target(host) if isinstance(host, str) and host else None,
                "terminal_id": tid if isinstance(tid, str) and tid else None,
                "stream_off": off if isinstance(off, int) and not isinstance(off, bool) else None,
            }
        )
    return out


def collect(
    conn: Any,
    journal: Any,
    *,
    redactor: Any,
    template: str,
    klartext: bool,
    project: Mapping[str, Any],
    read_blob: Callable[[str], bytes] | None = None,
    now_ns: int,
) -> dict[str, Any]:
    """Alle Daten für einen Export (siehe Moduldokumentation)."""
    jconn = getattr(journal, "conn", None)
    known = [
        str(r[0]) for r in conn.execute("SELECT value FROM secret_value LIMIT 10000") if isinstance(r[0], str)
    ]
    m = Masker(redactor, known, klartext=klartext)
    revoked = queries.revoked_ids(conn)
    refs = queries.term_refs(conn)

    # Befehle mit Phase
    cmds = proj_phases.assign(conn, template, revoked)
    commands = [
        {
            "unit_id": c["unit_id"],
            "cmd_id": c["cmd_id"],
            "command": m.target(c["cmd_text"] or ""),
            "ts": iso_ms(c["ts"]),
            "phase": c["phase"],
            "source": c["source"],
            "program": m.target(c["program"]) if c["program"] else None,
            "context": m.target(queries.context_label(c["context"])),
        }
        for c in cmds
    ]

    findings, focus = _findings(conn, m)

    # Faden
    keysteps = []
    for k in queries.keysteps(conn):
        uid = _keystep_unit(conn, k)
        if uid:
            focus.setdefault(uid, [])
        keysteps.append(
            {
                "ordinal": k["ordinal"],
                "step": k["step"],
                "host": m.target(k["host"]) if k["host"] else None,
                "note": m.target(k["note"]) if k.get("note") else None,
                "ts": iso_ms(k["ts"]),
                "unit_id": uid,
            }
        )

    # Belege: Findings und Faden zuerst, dann alle Befehle im Writeup
    order: list[str] = list(focus)
    for c in commands:
        if c["phase"] != proj_phases.OMIT and c["unit_id"] not in focus:
            order.append(c["unit_id"])
            focus[c["unit_id"]] = []
    belege: dict[str, Beleg] = {}
    for uid in order[:UNIT_MAX]:
        b = _beleg(conn, jconn, uid, focus.get(uid, []), m, refs)
        if b is not None:
            belege[uid] = b

    # Hosts und Dienste
    hosts = []
    for h in queries.hosts(conn):
        if h.get("placeholder"):
            continue
        hosts.append(
            {
                "host_id": h["host_id"],
                "label": m.target(h["label"] or ""),
                "scope": h["scope"],
                "access": h["access"],
                "knowledge": h["knowledge"],
                "work": h["work"],
                "os": m.target(h["os"]) if h.get("os") else None,
                "addresses": [m.target(a) for a in h.get("addresses") or []],
                "names": [m.target(a) for a in h.get("names") or []],
                "services": [
                    {
                        "proto": s["proto"],
                        "port": s["port"],
                        "name": m.target(s["name"]) if s.get("name") else None,
                        "product": m.target(s["product"]) if s.get("product") else None,
                        "version": m.target(s["version"]) if s.get("version") else None,
                        "state": s.get("state"),
                        "cves": [
                            m.target(c) if isinstance(c, str) else m.target((c or {}).get("id", "?"))
                            for c in s.get("cves") or []
                        ],
                    }
                    for s in h.get("services") or []
                ],
            }
        )

    # Zeitachse
    timeline = []
    for e in queries.timeline(conn, limit=5000):
        timeline.append(
            {
                "type": e.get("type"),
                "ts": iso_ms(e.get("ts")),
                "title": m.target(e.get("title") or ""),
                "context": m.target(e.get("context") or ""),
                "unit_id": e.get("unit_id"),
                "terminal": _term_label(refs, e.get("terminal_id"), m),
                "exit": e.get("exit"),
            }
        )

    # Credentials (nur bekannte Secret-Werte; maskiert ausser Klartext)
    creds = []
    for ident, kind, value in conn.execute(
        "SELECT secret_ident, kind, value FROM secret_value ORDER BY kind, secret_ident LIMIT 500"
    ):
        shown = m.own(value) if klartext else MASK
        creds.append({"kind": m.target(kind), "value": shown, "ref": str(ident)})

    # Screenshots
    images = []
    for unit_id, blob_id, sha, ts, path in conn.execute(
        "SELECT unit_id, blob_id, sha256, ts_utc_ns, path FROM unit WHERE kind = 'image' "
        "ORDER BY ts_utc_ns LIMIT 500"
    ):
        data: bytes | None = None
        if read_blob is not None and isinstance(blob_id, str):
            try:
                data = read_blob(blob_id)
            except Exception:  # noqa: BLE001 - Blob fehlt: nur vermerken
                data = None
        ok = isinstance(data, bytes) and data.startswith(_PNG) and len(data) <= _IMG_MAX
        images.append(
            {
                "unit_id": unit_id,
                "sha256": sha if isinstance(sha, str) else None,
                "ts": iso_ms(ts),
                "data": data if ok else None,
                "title": m.target(path) if path else None,
            }
        )

    images.extend(_shots(journal, jconn, read_blob, m))

    head = journal.read_head() if journal is not None and hasattr(journal, "read_head") else (0, b"")
    times = [
        t
        for (t,) in conn.execute(
            "SELECT ts_utc_ns FROM unit WHERE ts_utc_ns IS NOT NULL ORDER BY ts_utc_ns LIMIT 1"
        )
    ]
    times += [
        t
        for (t,) in conn.execute(
            "SELECT ts_utc_ns FROM unit WHERE ts_utc_ns IS NOT NULL ORDER BY ts_utc_ns DESC LIMIT 1"
        )
    ]
    settings = project.get("settings") if isinstance(project.get("settings"), Mapping) else {}
    scope = settings.get("scope") if isinstance(settings.get("scope"), Mapping) else {}
    return {
        "meta": {
            "project_id": project.get("id"),
            "slug": m.target(project.get("slug") or ""),
            "name": m.target((settings.get("project") or {}).get("name") or project.get("slug") or ""),
            "profile": project.get("profile"),
            "template": template,
            "klartext": bool(klartext),
            "created_at": iso_ms(now_ns),
            "chain_seq": int(head[0]),
            "chain_hash": bytes(head[1]).hex(),
            "period": [iso_ms(times[0]) if times else None, iso_ms(times[-1]) if times else None],
            "scope_include": [m.target(x) for x in scope.get("include") or [] if isinstance(x, str)],
            "scope_exclude": [m.target(x) for x in scope.get("exclude") or [] if isinstance(x, str)],
            "scope_open": scope.get("open") is True,  # E131: offener Scope
        },
        "commands": commands,
        "findings": findings,
        "keysteps": keysteps,
        "belege": belege,
        "hosts": hosts,
        "timeline": timeline,
        "credentials": creds,
        "images": images,
        "masked": m.masked,
    }
