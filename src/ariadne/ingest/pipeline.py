"""Auswertungs-Pipeline: Journal -> Einheiten -> Parser -> Projektion (Architektur 5.4, 5.10).

:meth:`Pipeline.process_new` verarbeitet alle Journal-Events nach dem
Wasserstand ``ingest`` (inkrementell und idempotent; eine Transaktion pro
Durchgang, grosse Rückstände in Abschnitten):

1. ``term.*`` und ``d.ctx.*`` gehen an den Segmenter des Terminals
   (:mod:`ariadne.ingest.seg_stream`), ``file.observed`` wird eine Datei-Einheit,
   ``net.route`` trägt die Quell-IP im Aktivitätsprotokoll nach.
2. Pro geändertem Terminal: Layout neu rechnen und abgleichen
   (``cmd_block``, ``ctx_span``, ``unit``, ``unit_line``, ``activity``).
3. Fertige Einheiten parsen (alle passenden Parser, höchste Priorität zuerst)
   und an ``Projector.apply_unit`` geben; hat sich eine schon geparste Einheit
   geändert, vorher ``clear_unit``. Offene Einheiten nach 10 Minuten Stille
   vorläufig parsen.
4. Entscheide (``d.*``) an ``Projector.apply_decision``, am Ende
   ``Projector.rebuild()``.

Ohne Projector oder ohne Parser (Import fehlt) läuft alles andere trotzdem;
geparst wird dann nicht. Der Projector teilt sich die Verbindung und damit die
Transaktion. Fehler eines Parsers oder der Projektion einer Einheit werden zu
``parse_failure`` und blockieren die übrigen Einheiten nicht.
:meth:`Pipeline.reparse` baut alles in einer neuen Verbindung neu auf; den
Dateitausch macht der Aufrufer.

Einbindung in den Daemon (noch offen): ``process_new`` blockiert (Worker bis
60 s pro Einheit) und gehört deshalb in einen eigenen Thread mit eigener
Verbindung; Aufruf nach jedem Commit und zusätzlich periodisch (Stille).
"""

from __future__ import annotations

import importlib
import json
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ariadne.ingest.db import apply_schema, get_meta, get_watermark, set_meta, set_watermark
from ariadne.ingest.runner import Runner, RunResult
from ariadne.ingest.seg_activity import activity_row, add_route
from ariadne.ingest.seg_stream import TermStream, seg_event_from_record
from ariadne.ingest.segmenter import SEG_KINDS, CmdBlock, compute_layout
from ariadne.ingest.unit_store import load_unit, save_unit, store_file_lines, sync_layout
from ariadne.ingest.units import MAX_FILE_LINES_BYTES, Unit, file_lines, is_binary
from ariadne.scope.api import ScopeChecker
from ariadne.store.api import EventRecord

__all__ = ["Pipeline", "Stats", "SILENCE_NS", "WATERMARK"]

log = logging.getLogger("ariadne.ingest")

SILENCE_NS = 10 * 60 * 1_000_000_000
WATERMARK = "ingest"
BATCH_VOLUME = 50_000  # Events plus Ausgabe/64 Bytes pro Transaktion (begrenzt gepufferte Zeilen)


@dataclass
class Stats:
    events: int = 0
    units_parsed: int = 0
    units_provisional: int = 0
    units_removed: int = 0
    decisions: int = 0
    failures: int = 0
    generation: int | None = None
    terminals: set[str] = field(default_factory=set)


def _auto_registry() -> list[Any]:
    try:
        mod = importlib.import_module("ariadne.parsers.registry")
    except ImportError:
        return []
    try:
        return list(mod.default_registry())
    except Exception:  # noqa: BLE001 - defekte Registry darf die Aufnahme nicht stoppen
        log.warning("Parser-Registry nicht ladbar")
        return []


def _auto_projector(conn: Any, project_key: bytes, scope: ScopeChecker | None) -> Any:
    try:
        mod = importlib.import_module("ariadne.ingest.projection")
    except ImportError:
        return None
    cls = getattr(mod, "Projector", None)
    if cls is None:
        return None
    return cls(conn, project_key=project_key, scope=scope)


class Pipeline:
    def __init__(self, journal: Any, blobs: Any, conn: Any, *, project_key: bytes,
                 scope: ScopeChecker | None, runner: Runner, projector: Any = None,
                 registry: Sequence[Any] | None = None,
                 projector_factory: Callable[[Any], Any] | None = None,
                 clock: Callable[[], int] = time.time_ns, silence_ns: int = SILENCE_NS) -> None:
        """``runner`` ist im Daemon ein :class:`~ariadne.ingest.runner.SubprocessRunner`
        (wer Schlüssel hält, parst nicht); ``InProcessRunner`` nur für Tests.
        ``projector=None`` sucht ``ariadne.ingest.projection.Projector``, ``False`` schaltet ab.
        ``registry=None`` lädt ``ariadne.parsers.registry.default_registry()``."""
        self.journal = journal
        self.blobs = blobs
        self.conn = conn
        self.project_key = project_key
        self.scope = scope
        self.runner: Runner = runner
        self.clock = clock
        self.silence_ns = silence_ns
        self.projector_factory = projector_factory
        apply_schema(conn)
        self.registry: list[Any] = list(_auto_registry() if registry is None else registry)
        self._by_id = {str(p.id): p for p in self.registry}
        if projector is False:
            self.projector = None
        elif projector is None:
            self.projector = (projector_factory(conn) if projector_factory is not None
                              else _auto_projector(conn, project_key, scope))
        else:
            self.projector = projector
        set_meta(conn, "parsers", json.dumps({str(p.id): str(p.version) for p in self.registry},
                                             sort_keys=True))
        conn.commit()
        self.terms: dict[str, TermStream] = {}
        self._loaded = False
        self.needs_reparse = False

    # ------------------------------------------------------------------ öffentlich
    @property
    def can_parse(self) -> bool:
        return self.projector is not None and bool(self.registry)

    @property
    def watermark(self) -> int:
        return get_watermark(self.conn, WATERMARK)

    def process_new(self) -> Stats:
        """Verarbeitet alle neuen Journal-Events.

        Grosse Rückstände (Reparse) laufen in Abschnitten mit je einer
        Transaktion, damit der Speicher begrenzt bleibt. ``rebuild()`` des
        Projectors läuft einmal am Ende.
        """
        stats = Stats()
        conn = self.conn
        try:
            while True:
                more = self._batch(stats)
                if not more:
                    break
            if self.projector is not None and (
                    stats.units_parsed or stats.units_removed or stats.decisions or stats.units_provisional
                    or get_meta(conn, "rebuild_pending") == "1"):
                gen = self.projector.rebuild()
                if isinstance(gen, int):
                    stats.generation = gen
                    set_meta(conn, "generation", str(gen))
                set_meta(conn, "rebuild_pending", "0")
            conn.commit()
        except BaseException:
            conn.rollback()
            self.terms.clear()
            self._loaded = False
            raise
        return stats

    def _batch(self, stats: Stats) -> bool:
        """Ein Abschnitt in einer Transaktion. ``True``, wenn noch Events warten."""
        conn = self.conn
        wm = get_watermark(conn, WATERMARK)
        if not self._loaded:
            for (tid,) in conn.execute("SELECT terminal_id FROM seg_term WHERE closed = 0").fetchall():
                self._term(tid, wm)
            self._loaded = True
        decisions: list[EventRecord] = []
        files: list[EventRecord] = []
        last = wm
        volume = 0
        more = False
        for rec in self.journal.iter_events(wm):
            if volume >= BATCH_VOLUME:
                more = True
                break
            last = rec.seq
            stats.events += 1
            volume += 1 + (len(rec.body) // 64 if rec.kind == "term.out" and rec.body else 0)
            self._route(rec, wm, decisions, files, stats)
        self._finish_terms(stats)
        for rec in files:
            self._file_unit(rec, stats)
        if self.projector is not None:
            for rec in decisions:
                stats.decisions += 1
                try:
                    self.projector.apply_decision(rec)
                except Exception as exc:  # noqa: BLE001 - Analyse darf nie dauerhaft hängen bleiben
                    stats.failures += 1
                    log.warning("Projektion: Entscheid %s nicht angewendet (%s)", rec.seq, type(exc).__name__)
        for ts in self.terms.values():
            ts.save()
        set_watermark(conn, WATERMARK, last)
        if more:
            set_meta(conn, "rebuild_pending", "1")
            conn.commit()
        return more

    def reparse(self, new_conn: Any) -> Pipeline:
        """Baut alles in ``new_conn`` neu auf und gibt die neue Pipeline zurück."""
        projector: Any = False
        if self.projector_factory is not None:
            projector = self.projector_factory(new_conn)
        elif self.projector is not None:
            projector = type(self.projector)(new_conn, project_key=self.project_key, scope=self.scope)
        new = Pipeline(self.journal, self.blobs, new_conn, project_key=self.project_key, scope=self.scope,
                       runner=self.runner, projector=projector, registry=self.registry,
                       projector_factory=self.projector_factory, clock=self.clock, silence_ns=self.silence_ns)
        new.process_new()
        return new

    # ------------------------------------------------------------------ Verteilung
    def _term(self, tid: str, wm: int) -> TermStream:
        ts = self.terms.get(tid)
        if ts is None:
            ts = TermStream.load(self.conn, tid, self.journal, wm)
            self.terms[tid] = ts
        return ts

    def _route(self, rec: EventRecord, wm: int, decisions: list[EventRecord], files: list[EventRecord],
               stats: Stats) -> None:
        kind = rec.kind
        if kind == "term.out":
            if rec.terminal_id is None or rec.stream_off is None:
                return
            ts = self._term(rec.terminal_id, wm)
            length = rec.header.get("length")
            length = length if isinstance(length, int) else len(rec.body or b"")
            ts.add_chunk(rec.seq, int(rec.stream_off), rec.body, length, rec.ts_utc_ns)
            stats.terminals.add(rec.terminal_id)
            return
        if kind in SEG_KINDS:
            tid = rec.header.get("terminal_id") or rec.terminal_id
            if isinstance(tid, str) and tid:
                self._term(tid, wm).add_event(seg_event_from_record(rec))
                stats.terminals.add(tid)
        if kind.startswith("d."):
            decisions.append(rec)
        elif kind == "file.observed":
            files.append(rec)
        elif kind == "net.route":
            add_route(self.conn, rec.seq, rec.header)
        elif kind == "system.redaction":
            self.needs_reparse = True  # FTS enthält den Klartext noch: derived.db neu bauen

    # ------------------------------------------------------------------ Terminals
    def _finish_terms(self, stats: Stats) -> None:
        now = self.clock()
        for tid, ts in self.terms.items():
            silent = (not ts.closed and ts.last_out_ns is not None
                      and now - ts.last_out_ns >= self.silence_ns)
            if silent:
                ts.force_feed()
            if ts.dirty:
                layout = compute_layout(tid, ts.events, ts.stream_end, closed=ts.closed,
                                        alt_offsets=ts.alt_offsets)
                for b in layout.blocks:
                    b.companions = self._companions(ts, b)
                res = sync_layout(self.conn, ts, layout,
                                  activity=lambda b, lay: activity_row(b, lay, self.scope))
                ts.dirty = False
                for uid in res.removed:
                    stats.units_removed += 1
                    if self.projector is not None:
                        self.projector.clear_unit(uid)
            if not self.can_parse:
                continue
            for uid, sig, parsed in self.conn.execute(
                    "SELECT unit_id, sig, parsed_sig FROM unit WHERE terminal_id = ? AND state = 'final' "
                    "AND (parsed_sig IS NULL OR parsed_sig != sig) ORDER BY start_off", (tid,)).fetchall():
                unit = load_unit(self.conn, uid)
                if unit is not None:
                    self._parse(unit, sig, parsed, stats)
            if silent:
                self._provisional(ts, stats)

    def _companions(self, ts: TermStream, block: CmdBlock) -> tuple[str, ...]:
        """Dateien, die ein lokaler Befehl laut den Parsern schreibt (Architektur 4.2)."""
        if not block.argv or not block.local:
            return ()
        key = (block.cmd_id, block.text, block.cwd)
        hit = ts.companions.get(key)
        if hit is not None:
            return hit
        out: list[str] = []
        for p in self.registry:
            try:
                paths = p.companions(list(block.argv), block.cwd or "")
            except Exception:  # noqa: BLE001 - ein defekter Parser verhindert keine Verknüpfung
                log.warning("companions() von %s fehlgeschlagen", getattr(p, "id", "?"))
                paths = []
            out += [x for x in paths if isinstance(x, str) and x and x not in out]
        ts.companions[key] = tuple(out[:64])
        return ts.companions[key]

    def _provisional(self, ts: TermStream, stats: Stats) -> None:
        pending = ts.pending_lines()
        rows = self.conn.execute(
            "SELECT unit_id, sig, parsed_sig, start_off, end_off, line_count FROM unit WHERE terminal_id = ? "
            "AND state != 'final' ORDER BY start_off", (ts.tid,)).fetchall()
        for uid, sig, parsed, start, end, count in rows:
            hi = end if end is not None else 1 << 62
            extra = [ln for ln in pending if start <= ln.raw_start < hi]
            if not count and not extra:
                continue
            psig = f"{sig}~{count}+{len(extra)}"
            if parsed == psig:
                continue
            unit = load_unit(self.conn, uid, extra_lines=extra)
            if unit is None or not unit.lines:
                continue
            self._parse(unit, psig, parsed, stats, provisional=True)

    # ------------------------------------------------------------------ Dateien
    def _file_unit(self, rec: EventRecord, stats: Stats) -> None:
        h = rec.header
        uid = f"f:{rec.id}"
        if self.conn.execute("SELECT 1 FROM unit WHERE unit_id = ? AND parsed_sig IS NOT NULL",
                             (uid,)).fetchone():
            return
        blob_id = h.get("blob_id")
        data: bytes | None = None
        flags: list[str] = []
        if isinstance(blob_id, str):
            try:
                data = self.blobs.open_bytes(blob_id)
            except Exception:  # noqa: BLE001 - fehlender oder beschädigter Blob ist kein Absturz
                flags.append("blob_missing")
        else:
            flags.append("not_stored")
        lines = file_lines(data) if data is not None else None
        if data is not None and lines is None:
            big = len(data) > MAX_FILE_LINES_BYTES and not is_binary(data)
            flags.append("too_large" if big else "binary")
        path = h.get("path") if isinstance(h.get("path"), str) else None
        context = self._file_context(h, path)
        sig = f"file:{rec.id}"
        row = {
            "unit_id": uid, "kind": "file", "terminal_id": None, "cmd_id": h.get("produced_by_cmd"),
            "span_id": None, "start_off": None, "end_off": None, "argv": "[]", "cmd_text": None,
            "exit_code": None, "cwd": None,
            "context": json.dumps(context, ensure_ascii=False, sort_keys=True),
            "path": path, "mime": h.get("mime"), "sniff": h.get("sniff"), "blob_id": blob_id,
            "sha256": h.get("sha256"), "size": h.get("size"), "ts_utc_ns": rec.ts_utc_ns, "ts_end_ns": None,
            "state": "final", "flags": json.dumps(sorted(flags)), "sig": sig, "line_count": 0, "vis_count": 0,
            "event_seq": rec.seq,
        }
        save_unit(self.conn, row)
        if lines:
            count, vis = store_file_lines(self.conn, uid, lines)
            self.conn.execute("UPDATE unit SET line_count = ?, vis_count = ? WHERE unit_id = ?",
                              (count, vis, uid))
        unit = load_unit(self.conn, uid, data=data)
        if unit is not None:
            self._parse(unit, sig, None, stats)

    def _file_context(self, h: Any, path: str | None) -> dict[str, Any]:
        hint = h.get("host_hint")
        if isinstance(hint, str) and hint:
            return {"kind": "unknown", "host": hint, "source": "import"}
        if path is not None and (path == "loot" or path.startswith("loot/")):
            return {"kind": "unknown"}
        cmd = h.get("produced_by_cmd")
        if isinstance(cmd, str):
            row = self.conn.execute("SELECT ctx FROM cmd_block WHERE cmd_id = ?", (cmd,)).fetchone()
            if row and row[0]:
                stack = [s for s in json.loads(row[0]) if s.get("state", "active") == "active"]
                if stack:
                    return dict(stack[-1])
        return {"kind": "local", "host": "local"}

    # ------------------------------------------------------------------ Parsen
    def _parse(self, unit: Unit, sig: str, previous: str | None, stats: Stats, *,
               provisional: bool = False) -> None:
        if not self.can_parse:
            return
        conn = self.conn
        seq_row = conn.execute("SELECT event_seq FROM unit WHERE unit_id = ?", (unit.unit_id,)).fetchone()
        journal_seq = int(seq_row[0]) if seq_row and seq_row[0] is not None else 0
        results: list[RunResult] = self.runner.run(unit, self.registry)
        if previous is not None:
            self.projector.clear_unit(unit.unit_id)
        conn.execute("DELETE FROM parse_failure WHERE unit_id = ?", (unit.unit_id,))
        for r in results:
            p = self._by_id.get(r.parser_id)
            if p is None:
                continue
            if r.error is not None:
                stats.failures += 1
                conn.execute("INSERT OR REPLACE INTO parse_failure(unit_id, parser_id, parser_version, "
                             "reason, ts_utc_ns) VALUES (?, ?, ?, ?, ?)",
                             (unit.unit_id, r.parser_id, r.parser_version, r.error[:200], self.clock()))
                log.warning("Parser %s fehlgeschlagen (%s)", r.parser_id, r.error.split(":", 1)[0])
                continue
            try:
                self.projector.apply_unit(unit, parser_id=r.parser_id, parser_version=r.parser_version,
                                          trust=p.trust, auto_eligible=bool(p.auto_eligible),
                                          journal_seq=journal_seq, items=r.items)
            except Exception as exc:  # noqa: BLE001 - ein Fehler der Projektion blockiert nicht alles
                stats.failures += 1
                conn.execute("INSERT OR REPLACE INTO parse_failure(unit_id, parser_id, parser_version, "
                             "reason, ts_utc_ns) VALUES (?, ?, ?, ?, ?)",
                             (unit.unit_id, r.parser_id, r.parser_version, f"projection:{type(exc).__name__}",
                              self.clock()))
                log.warning("Projektion von %s fehlgeschlagen (%s)", r.parser_id, type(exc).__name__)
        if provisional:
            conn.execute("UPDATE unit SET parsed_sig = ?, state = 'provisional' WHERE unit_id = ?",
                         (sig, unit.unit_id))
            stats.units_provisional += 1
        else:
            conn.execute("UPDATE unit SET parsed_sig = ? WHERE unit_id = ?", (sig, unit.unit_id))
            stats.units_parsed += 1

