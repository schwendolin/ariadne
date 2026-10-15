"""Projektion: Beobachtungen und Entscheide zu Claims, Entitäten, Inbox und Status.

Architektur 5.7 bis 5.10. Schnittstelle für die Pipeline:

* :meth:`Projector.apply_unit` speichert die Ergebnisse eines Parsers für eine
  Einheit und ersetzt frühere Ergebnisse desselben Paares (Einheit, Parser).
  Eingaben sind ``Obs``/``Mention`` oder deren ``to_dict()`` (aus dem Worker).
  Alles wird geprüft und normalisiert; Ungültiges wird verworfen, nie geraten.
* :meth:`Projector.apply_decision` speichert Entscheide (alle ``d.*``-Arten).
* :func:`record_own_addrs` merkt eigene Adressen von Kali (``own_addr``, A5);
  die Pipeline ruft sie für ``net.local_addrs`` und ``net.route.src_ip``.
* :meth:`Projector.rebuild` berechnet alles Abgeleitete vollständig neu
  (:func:`ariadne.ingest.proj_build.build`), erhöht die Generation und schreibt
  ``projection_delta``. v0.1 rechnet immer komplett; bis etwa 50 Hosts genügt das.

Das Profil (``lab`` oder ``customer``) bestimmt die Spuren (Drei-Spuren-Regel, E42).

Die Projektion parst keine Zieldaten selbst und sendet nichts. Secrets stehen
im Klartext nur in ``secret_value``; Kennungen und Schlüssel sind HMACs.
Funktioniert mit ``sqlite3`` und ``sqlcipher3``; Schreibvorgänge laufen in
Savepoints, damit eine Transaktion des Aufrufers erhalten bleibt.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from ariadne.events import canonical_json
from ariadne.ingest.claims import effective_confidence, normalize_value
from ariadne.ingest.identity import canon_ip, id_type, normalize_identifier
from ariadne.ingest.proj_build import PROFILES, DecisionRow, MentionRow, ObsRow, UnitRow, build
from ariadne.ingest.schema_claims import MASK, SCHEMA_SQL, VIEWS_SQL, statements
from ariadne.ontology import PREDICATES
from ariadne.parsers.api import BASE_CONFIDENCE, Mention, Obs, UnitView
from ariadne.parsers.regex_net import SECRET_TYPES
from ariadne.scope.api import ScopeChecker, Verdict
from ariadne.store.api import EventRecord
from ariadne.store.chain import secret_key

__all__ = ["Projector", "ensure_schema", "record_own_addrs", "DELTA_KEEP"]

DELTA_KEEP = 1000  # so viele Generationen bleiben in projection_delta
MAX_ATTRS = 32
MAX_ATTR_LEN = 4096
MAX_MENTION = 64 * 1024
_ENTITY_FEED = {"host": "host", "service": "service", "identity": "credential", "secret": "credential",
                "url": "url"}


class _NoScope:
    """Ohne Scope ist alles ``unknown`` (fail-closed: nichts wird auto, nichts verbindet über Scope)."""

    version = 0

    def check(self, identifier: str, at_utc_ns: int | None = None) -> Verdict:
        return Verdict("unknown", None, 0)


def ensure_schema(conn: Any) -> None:
    """Legt Tabellen und Sichten an (idempotent, ohne ``executescript``)."""
    for stmt in statements(SCHEMA_SQL) + statements(VIEWS_SQL):
        conn.execute(stmt)


def record_own_addrs(conn: Any, addrs: Iterable[Any], source: str, seq: int) -> bool:
    """Eigene Adressen von Kali speichern (nie verfallend). ``True``, wenn eine neu war.

    Nur gültige IP-Adressen (kanonisch über ``ipaddress``), alles andere wird verworfen.
    """
    new = False
    for a in addrs:
        ip = canon_ip(a) if isinstance(a, str) else None
        if ip is None:
            continue
        cur = conn.execute("INSERT OR IGNORE INTO own_addr(addr, source, first_seq) VALUES (?,?,?)",
                           (ip, source, int(seq)))
        new = new or cur.rowcount > 0
    return new


@contextmanager
def _savepoint(conn: Any, name: str = "ariadne_proj") -> Iterator[None]:
    conn.execute(f"SAVEPOINT {name}")
    try:
        yield
    except BaseException:
        conn.execute(f"ROLLBACK TO {name}")
        conn.execute(f"RELEASE {name}")
        raise
    conn.execute(f"RELEASE {name}")


def _span_json(span: Any) -> str | None:
    if hasattr(span, "to_dict"):
        span = span.to_dict()
    if not isinstance(span, Mapping):
        return None
    out: dict[str, Any] = {}
    for k in ("line_start", "line_end", "col_start", "col_end"):
        v = span.get(k)
        if v is None:
            continue
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return None
        out[k] = v
    if "line_start" not in out or "line_end" not in out or out["line_end"] < out["line_start"]:
        return None
    path = span.get("path")
    if path is not None:
        if not isinstance(path, str) or len(path) > 512:
            return None
        out["path"] = path
    return canonical_json(out).decode()


def _attrs(raw: Any) -> dict[str, str] | None:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping) or len(raw) > MAX_ATTRS:
        return None
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, str) or len(k) > 64:
            return None
        out[k] = v if len(v) <= MAX_ATTR_LEN else v[: MAX_ATTR_LEN - 1] + "…"
    return out


class Projector:
    """Projektion auf einer ``derived.db``-Verbindung (sqlite3 oder sqlcipher3)."""

    def __init__(self, conn: Any, *, project_key: bytes, scope: ScopeChecker | None,
                 profile: str = "lab") -> None:
        if not isinstance(project_key, bytes | bytearray) or len(project_key) < 16:
            raise ValueError("Projektschlüssel fehlt oder ist zu kurz")
        if profile not in PROFILES:
            raise ValueError(f"unbekanntes Profil {profile!r}")
        self.profile = profile
        self.conn = conn
        self.project_key = bytes(project_key)
        self.scope: ScopeChecker = scope if scope is not None else _NoScope()
        ensure_schema(conn)

    # ------------------------------------------------------------------ Scope
    def set_scope(self, scope: ScopeChecker | None) -> None:
        """Neuer Scope (nach ``d.scope.update``); wirkt beim nächsten :meth:`rebuild`."""
        self.scope = scope if scope is not None else _NoScope()

    # ------------------------------------------------------------------ Einheiten
    def apply_unit(self, unit: UnitView, *, parser_id: str, parser_version: str, trust: str,
                   auto_eligible: bool, journal_seq: int, items: Iterable[Any]) -> int:
        """Speichert die Ergebnisse von (Einheit, Parser) und ersetzt frühere.

        Gibt die Zahl der gespeicherten Beobachtungen und Mentions zurück.
        """
        if trust not in BASE_CONFIDENCE:
            raise ValueError(f"unbekannte Vertrauensklasse {trust!r}")
        if not isinstance(parser_id, str) or not parser_id or len(parser_id) > 64:
            raise ValueError("ungültige Parser-ID")
        stored = 0
        with _savepoint(self.conn):
            self._upsert_unit(unit, journal_seq)
            self.conn.execute("DELETE FROM observation WHERE unit_id = ? AND parser_id = ?",
                              (unit.unit_id, parser_id))
            self.conn.execute("DELETE FROM mention WHERE unit_id = ? AND parser_id = ?",
                              (unit.unit_id, parser_id))
            from_target = self._unit_from_target(unit)
            for item in items:
                d = item.to_dict() if isinstance(item, Obs | Mention) else item
                if not isinstance(d, Mapping):
                    continue
                if "predicate" in d:
                    stored += self._store_obs(d, unit, parser_id, parser_version, trust, auto_eligible,
                                              journal_seq)
                elif "value_type" in d:
                    stored += self._store_mention(d, unit, parser_id, parser_version, journal_seq,
                                                  from_target)
        return stored

    def clear_unit(self, unit_id: str) -> None:
        with _savepoint(self.conn):
            for table in ("observation", "mention", "obs_unit"):
                self.conn.execute(f"DELETE FROM {table} WHERE unit_id = ?", (unit_id,))  # noqa: S608

    def set_unit_context(self, unit_id: str, context: Mapping[str, Any]) -> bool:
        """Kontext einer Einheit nachführen (z. B. nach ``d.ctx.set`` in der Pipeline)."""
        c = dict(context or {})
        with _savepoint(self.conn):
            cur = self.conn.execute(
                "UPDATE obs_unit SET ctx_kind = ?, ctx_host = ?, ctx_user = ?, ctx_opened_at = ?, "
                "ctx_candidate = ? WHERE unit_id = ?",
                (_s(c.get("kind")), _s(c.get("host")), _s(c.get("user")), _i(c.get("opened_at")),
                 _s(c.get("candidate")), unit_id))
        return cur.rowcount > 0

    @staticmethod
    def _unit_from_target(unit: UnitView) -> bool:
        kind = (unit.context or {}).get("kind")
        return unit.kind in ("segment", "file") or (kind is not None and kind not in ("local", "su"))

    def _upsert_unit(self, unit: UnitView, journal_seq: int) -> None:
        ctx = dict(unit.context or {})
        terminal_id = getattr(unit, "terminal_id", None) or ctx.get("terminal_id")
        lines = list(unit.lines)
        start_off = getattr(unit, "start_off", None)
        end_off = getattr(unit, "end_off", None)
        if start_off is None and lines:
            start_off = lines[0].raw_start
        if end_off is None and lines:
            end_off = lines[-1].raw_end
        title = unit.cmd_text or unit.path
        flags = sorted({f for f in getattr(unit, "flags", ()) or () if isinstance(f, str) and len(f) <= 32})
        row = (unit.unit_id, unit.kind, _s(terminal_id), _s(getattr(unit, "cmd_id", None)),
               title[:512] if isinstance(title, str) else None, _s(unit.path), int(unit.ts_utc_ns),
               _i(start_off), _i(end_off), _s(ctx.get("kind")), _s(ctx.get("host")), _s(ctx.get("user")),
               _i(ctx.get("opened_at")), _s(ctx.get("candidate")), int(self._unit_from_target(unit)),
               int(journal_seq), json.dumps(flags[:16]), _i(getattr(unit, "mono_ns", None)))
        self.conn.execute(
            "INSERT INTO obs_unit (unit_id, kind, terminal_id, cmd_id, title, path, ts_utc_ns, start_off, "
            "end_off, ctx_kind, ctx_host, ctx_user, ctx_opened_at, ctx_candidate, from_target, journal_seq, "
            "flags, mono_ns) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(unit_id) DO UPDATE SET "
            "kind=excluded.kind, terminal_id=excluded.terminal_id, cmd_id=excluded.cmd_id, "
            "title=excluded.title, path=excluded.path, ts_utc_ns=excluded.ts_utc_ns, "
            "start_off=excluded.start_off, end_off=excluded.end_off, ctx_kind=excluded.ctx_kind, "
            "ctx_host=excluded.ctx_host, ctx_user=excluded.ctx_user, ctx_opened_at=excluded.ctx_opened_at, "
            "ctx_candidate=excluded.ctx_candidate, from_target=excluded.from_target, "
            "journal_seq=MAX(obs_unit.journal_seq, excluded.journal_seq), flags=excluded.flags, "
            "mono_ns=excluded.mono_ns", row)

    def _sink(self, ident: str, kind: str, value: str) -> None:
        self.conn.execute("INSERT OR IGNORE INTO secret_value (secret_ident, kind, value) VALUES (?,?,?)",
                          (ident, kind, value))

    def _store_obs(self, d: Mapping[str, Any], unit: UnitView, parser_id: str, parser_version: str,
                   trust: str, auto_eligible: bool, journal_seq: int) -> int:
        subject = d.get("subject")
        pred = PREDICATES.get(str(d.get("predicate")))
        if not isinstance(subject, str) or pred is None:
            return 0
        subj = normalize_identifier(subject, self.project_key, secret_sink=self._sink)
        span = _span_json(d.get("span"))
        attrs = _attrs(d.get("attrs"))
        if subj is None or span is None or attrs is None:
            return 0
        try:
            value, text, secret = normalize_value(pred, d.get("value"), self.project_key, self._sink)
        except ValueError:
            return 0
        conf = d.get("confidence")
        if conf is not None and (isinstance(conf, bool) or not isinstance(conf, int | float)):
            return 0
        is_secret = secret or id_type(subj) == "secret"
        suspect = attrs.get("suspect") in ("concealed", "overwritten")
        self.conn.execute(
            "INSERT INTO observation (unit_id, parser_id, parser_version, trust, auto_eligible, journal_seq, "
            "subject, predicate, value_json, value_text, span_json, confidence, attrs_json, ts_utc_ns, "
            "from_target, suspect, is_secret) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (unit.unit_id, parser_id, str(parser_version), trust, int(bool(auto_eligible)), int(journal_seq),
             subj, pred.name, canonical_json(value).decode(), MASK if is_secret else text, span,
             effective_confidence(trust, conf), canonical_json(attrs).decode(), int(unit.ts_utc_ns),
             int(attrs.get("from_target") == "1"), int(suspect), int(is_secret)))
        return 1

    def _store_mention(self, d: Mapping[str, Any], unit: UnitView, parser_id: str, parser_version: str,
                       journal_seq: int, from_target: bool) -> int:
        vtype = d.get("value_type")
        value = d.get("value")
        span = _span_json(d.get("span"))
        attrs = _attrs(d.get("attrs"))
        if (not isinstance(vtype, str) or not vtype or len(vtype) > 32 or not isinstance(value, str)
                or not value or len(value) > MAX_MENTION or span is None or attrs is None):
            return 0
        if not all(c.isalnum() or c in "_-." for c in vtype):
            return 0
        is_secret = vtype in SECRET_TYPES
        stored: str | None
        if is_secret:
            h = secret_key(self.project_key, vtype, value)
            self._sink(f"secret:{vtype}|h:{h}", vtype, value)
            stored, key = None, f"{vtype}:h:{h}"
        else:
            if vtype == "ip":
                ip = canon_ip(value)
                if ip is None:
                    return 0
                value = ip
            stored, key = value, f"{vtype}:{value}"
        suspect = attrs.get("suspect") in ("concealed", "overwritten")
        self.conn.execute(
            "INSERT INTO mention (unit_id, parser_id, parser_version, journal_seq, value_type, value, "
            "value_key, span_json, attrs_json, ts_utc_ns, from_target, suspect, is_secret) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (unit.unit_id, parser_id, str(parser_version), int(journal_seq), vtype, stored, key, span,
             canonical_json(attrs).decode(), int(unit.ts_utc_ns), int(from_target), int(suspect),
             int(is_secret)))
        return 1

    # ------------------------------------------------------------------ Entscheide
    def apply_decision(self, rec: EventRecord) -> bool:
        """Speichert einen Entscheid (``d.*``). Andere Events werden ignoriert."""
        if not rec.kind.startswith("d."):
            return False
        with _savepoint(self.conn):
            self.conn.execute(
                "INSERT OR IGNORE INTO decision (seq, id, kind, payload_json, ts, mono_ns, boot_id) "
                "VALUES (?,?,?,?,?,?,?)",
                (int(rec.seq), rec.id, rec.kind, canonical_json(dict(rec.header)).decode(),
                 int(rec.ts_utc_ns), _i(rec.mono_ns), _s(rec.boot_id)))
        return True

    # ------------------------------------------------------------------ Neuberechnung
    @property
    def generation(self) -> int:
        row = self.conn.execute("SELECT MAX(generation) FROM generation").fetchone()
        return int(row[0] or 0)

    def rebuild(self) -> int:
        """Berechnet die Projektion neu und gibt die neue Generation zurück."""
        with _savepoint(self.conn):
            before = self._snapshot()
            res = build(self._units(), self._observations(), self._mentions(), self._decisions(),
                        self.scope, self.project_key, spans=self._spans(), profile=self.profile,
                        own_addrs=self._own_addrs())
            for table in ("identifier", "entity", "claim", "claim_source", "conflict", "inbox_item",
                          "keystep", "ctx_auto", "unit_distrust"):
                self.conn.execute(f"DELETE FROM {table}")  # noqa: S608
            ex = self.conn.executemany
            ex("INSERT INTO identifier VALUES (?,?,?,?,?,?,?)", res.identifiers)
            ex("INSERT INTO entity VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", res.entities)
            ex("INSERT INTO claim VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", res.claims)
            ex("INSERT INTO claim_source VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", res.claim_sources)
            ex("INSERT INTO conflict VALUES (?,?,?,?,?,?,?,?)", res.conflicts)
            ex("INSERT INTO inbox_item VALUES (?,?,?,?,?,?,?)", res.inbox)
            ex("INSERT INTO keystep VALUES (?,?,?,?,?,?,?,?,?,?,?)", res.keysteps)
            ex("INSERT INTO ctx_auto VALUES (?,?,?,?)", res.ctx_auto)
            ex("INSERT INTO unit_distrust VALUES (?,?,?,?)", res.distrust)
            ex("UPDATE mention SET scope_verdict = ? WHERE mention_id = ?",
               [(v, k) for k, v in sorted(res.mention_verdicts.items())])
            ex("INSERT OR IGNORE INTO secret_value VALUES (?,?,?)",
               [(k, kind, val) for k, (kind, val) in sorted(res.secrets.items())])
            after = self._snapshot()
            changes = _diff(before, after)
            gen = self.generation + 1
            self.conn.execute("INSERT INTO generation VALUES (?,?,?)", (gen, time.time_ns(), len(changes)))
            ex("INSERT INTO projection_delta VALUES (?,?,?,?)", [(gen, e, k, c) for e, k, c in changes])
            self.conn.execute("DELETE FROM projection_delta WHERE generation <= ?", (gen - DELTA_KEEP,))
        return gen

    def changes_since(self, generation: int) -> list[tuple[int, str, str, str]]:
        """Änderungen nach ``generation`` (aufsteigend): (generation, entity, key, change)."""
        return [tuple(r) for r in self.conn.execute(  # type: ignore[misc]
            "SELECT generation, entity, entity_key, change FROM projection_delta WHERE generation > ? "
            "ORDER BY generation, entity, entity_key", (int(generation),))]

    # ------------------------------------------------------------------ Laden
    def _spans(self) -> list[tuple[str, int, int | None, str | None, int | None]] | None:
        try:
            rows = self.conn.execute(
                "SELECT terminal_id, start_off, end_off, kind, opened_at FROM ctx_span").fetchall()
        except Exception:  # noqa: BLE001 - ohne Segmenter-Tabellen (Tests): alte Zuordnung
            return None
        return [(r[0], int(r[1]), r[2], r[3], r[4]) for r in rows]

    def _units(self) -> dict[str, UnitRow]:
        out: dict[str, UnitRow] = {}
        for r in self.conn.execute(
                "SELECT unit_id, kind, terminal_id, cmd_id, title, path, ts_utc_ns, start_off, end_off, "
                "ctx_kind, ctx_host, ctx_user, ctx_opened_at, ctx_candidate, from_target, journal_seq, "
                "flags, mono_ns FROM obs_unit"):
            flags = json.loads(r[16] or "[]")
            out[r[0]] = UnitRow(r[0], r[1], r[2], r[3], r[4], r[5], int(r[6]), r[7], r[8], r[9], r[10], r[11],
                                r[12], r[13], bool(r[14]), int(r[15]),
                                tuple(f for f in flags if isinstance(f, str)), r[17])
        return out

    def _own_addrs(self) -> list[str]:
        return [str(r[0]) for r in self.conn.execute("SELECT addr FROM own_addr ORDER BY addr")]

    def _observations(self) -> list[ObsRow]:
        return [
            ObsRow(r[0], r[1], r[2], r[3], r[4], bool(r[5]), int(r[6]), r[7], r[8], json.loads(r[9]), r[10],
                   r[11], float(r[12]), json.loads(r[13]), int(r[14]), bool(r[15]), bool(r[16]), bool(r[17]))
            for r in self.conn.execute(
                "SELECT obs_id, unit_id, parser_id, parser_version, trust, auto_eligible, journal_seq, "
                "subject, predicate, value_json, value_text, span_json, confidence, attrs_json, ts_utc_ns, "
                "from_target, suspect, is_secret FROM observation ORDER BY obs_id")
        ]

    def _mentions(self) -> list[MentionRow]:
        return [
            MentionRow(r[0], r[1], r[2], r[3], int(r[4]), r[5], r[6], r[7], json.loads(r[8]), int(r[9]),
                       bool(r[10]), bool(r[11]))
            for r in self.conn.execute(
                "SELECT mention_id, unit_id, parser_id, parser_version, journal_seq, value_type, value, "
                "span_json, attrs_json, ts_utc_ns, from_target, suspect FROM mention "
                "WHERE value_type IN ('ip', 'url', 'callback') ORDER BY mention_id")
        ]

    def _decisions(self) -> list[DecisionRow]:
        rows = self.conn.execute("SELECT seq, id, kind, payload_json, ts, mono_ns, boot_id FROM decision "
                                 "ORDER BY seq")
        return [DecisionRow(int(r[0]), r[1], r[2], json.loads(r[3]), int(r[4]), r[5], r[6]) for r in rows]

    def _snapshot(self) -> dict[tuple[str, str], tuple]:
        snap: dict[tuple[str, str], tuple] = {}
        for r in self.conn.execute("SELECT * FROM entity"):
            snap[(_ENTITY_FEED.get(r[1], "other"), r[0])] = tuple(r)
        for r in self.conn.execute(
                "SELECT claim_key, state, confidence, value_text, conflict_key, entity_id, sources, scope, "
                "lane, history FROM claim"):
            snap[("claim", r[0])] = tuple(r)
        for r in self.conn.execute("SELECT item_key, kind, payload_json, state FROM inbox_item"):
            snap[("inbox", r[0])] = tuple(r)
        for r in self.conn.execute("SELECT * FROM keystep"):
            snap[("thread", r[1])] = tuple(r)
        return snap


def _diff(before: Mapping[tuple[str, str], tuple], after: Mapping[tuple[str, str], tuple]
          ) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for k in sorted(set(before) | set(after)):
        if k not in before:
            out.append((k[0], k[1], "added"))
        elif k not in after:
            out.append((k[0], k[1], "removed"))
        elif before[k] != after[k]:
            out.append((k[0], k[1], "updated"))
    return out


def _s(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def _i(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None
