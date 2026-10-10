"""Schema der Auswertung, Teil Einheiten (``derived.db``, Architektur 5.1, 5.4, 5.13).

Alles hier ist Schicht 2 und jederzeit neu berechenbar. Natürliche Schlüssel
(``cmd_id``, ``unit_id``) sind deterministisch, damit Entscheide einen Reparse
überstehen.

``unit_line``
    ``pos`` ist die Position in der Einheit (Anzeige-Reihenfolge, ab 0).
    ``idx`` ist der Index in ``UnitView.lines`` (ab 0), also die Zählung in
    ``Span.line_start``; NULL bei Zeilen, die kein Parser sieht (Prompt-Echo,
    Alternate Screen). ``n`` ist die Zeilennummer im Terminal-Strom.
    ``flags`` sind die Bits aus ``ariadne.ingest.normalizer`` (1 prompt_echo,
    2 concealed, 4 overwritten, 8 altscreen, 16 wrapped).
``unit_fts``
    FTS5 über ``unit_line.text`` (External Content, über Trigger gepflegt).
    Prompt-Echo-Zeilen werden nie indexiert.
``activity``
    Eine Zeile pro lokalem Befehl (Herkunftsstufe ``local``).
"""

from __future__ import annotations

__all__ = ["SCHEMA_VERSION", "UNITS_SQL", "UNIT_TABLES"]

SCHEMA_VERSION = 1

UNIT_TABLES = (
    "meta", "watermark", "unit", "unit_line", "unit_fts", "cmd_block", "ctx_span", "activity",
    "net_route", "parse_failure", "seg_term", "seg_event", "seg_chunk",
)

UNITS_SQL = """
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watermark (
  name TEXT PRIMARY KEY,
  seq  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS unit (
  unit_id     TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('command', 'segment', 'file', 'image')),
  terminal_id TEXT,
  cmd_id      TEXT,
  span_id     TEXT,
  start_off   INTEGER,
  end_off     INTEGER,
  argv        TEXT,              -- JSON-Liste
  cmd_text    TEXT,
  exit_code   INTEGER,
  cwd         TEXT,
  context     TEXT NOT NULL,     -- JSON Stage-Dict
  path        TEXT,
  mime        TEXT,
  sniff       TEXT,
  blob_id     TEXT,
  sha256      TEXT,
  size        INTEGER,
  ts_utc_ns   INTEGER NOT NULL,
  ts_end_ns   INTEGER,
  state       TEXT NOT NULL CHECK (state IN ('open', 'provisional', 'final')),
  flags       TEXT NOT NULL DEFAULT '[]',
  sig         TEXT NOT NULL,
  parsed_sig  TEXT,
  line_count  INTEGER NOT NULL DEFAULT 0,
  event_seq   INTEGER
);
CREATE INDEX IF NOT EXISTS unit_term_idx ON unit(terminal_id, start_off);
CREATE INDEX IF NOT EXISTS unit_cmd_idx ON unit(cmd_id);

CREATE TABLE IF NOT EXISTS unit_line (
  id          INTEGER PRIMARY KEY,
  unit_id     TEXT NOT NULL,
  pos         INTEGER NOT NULL,
  idx         INTEGER,
  terminal_id TEXT,
  n           INTEGER,
  text        TEXT NOT NULL,
  raw_start   INTEGER NOT NULL,
  raw_end     INTEGER NOT NULL,
  flags       INTEGER NOT NULL DEFAULT 0,
  sgr         TEXT,
  colmap      TEXT
);
CREATE INDEX IF NOT EXISTS unit_line_unit_idx ON unit_line(unit_id, pos);
CREATE UNIQUE INDEX IF NOT EXISTS unit_line_stream_idx ON unit_line(terminal_id, n);
CREATE INDEX IF NOT EXISTS unit_line_raw_idx ON unit_line(terminal_id, raw_start);

CREATE VIRTUAL TABLE IF NOT EXISTS unit_fts USING fts5(
  text, content='unit_line', content_rowid='id', tokenize='unicode61'
);
CREATE TRIGGER IF NOT EXISTS unit_line_fts_ai AFTER INSERT ON unit_line
WHEN (new.flags & 1) = 0 BEGIN
  INSERT INTO unit_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS unit_line_fts_ad AFTER DELETE ON unit_line
WHEN (old.flags & 1) = 0 BEGIN
  INSERT INTO unit_fts(unit_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TRIGGER IF NOT EXISTS unit_line_fts_au_old AFTER UPDATE OF text, flags ON unit_line
WHEN (old.flags & 1) = 0 BEGIN
  INSERT INTO unit_fts(unit_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TRIGGER IF NOT EXISTS unit_line_fts_au_new AFTER UPDATE OF text, flags ON unit_line
WHEN (new.flags & 1) = 0 BEGIN
  INSERT INTO unit_fts(rowid, text) VALUES (new.id, new.text);
END;

CREATE TABLE IF NOT EXISTS cmd_block (
  cmd_id      TEXT PRIMARY KEY,
  terminal_id TEXT NOT NULL,
  c_off       INTEGER NOT NULL,
  d_off       INTEGER,
  prompt_off  INTEGER,
  cmd_text    TEXT,
  cmd_typed   TEXT,
  argv        TEXT NOT NULL,     -- JSON-Liste
  cwd         TEXT,
  user        TEXT,
  exit_code   INTEGER,
  pipestatus  TEXT,              -- JSON-Liste
  ts_start_ns INTEGER,
  ts_end_ns   INTEGER,
  flags       TEXT NOT NULL DEFAULT '[]',
  ctx         TEXT               -- JSON: Stapel beim C-Marker
);
CREATE INDEX IF NOT EXISTS cmd_block_term_idx ON cmd_block(terminal_id, c_off);

CREATE TABLE IF NOT EXISTS ctx_span (
  span_id     TEXT PRIMARY KEY,
  terminal_id TEXT NOT NULL,
  start_off   INTEGER NOT NULL,
  end_off     INTEGER,
  kind        TEXT NOT NULL,
  host        TEXT,
  user        TEXT,
  candidate   TEXT,
  opened_at   INTEGER,
  source      TEXT,
  stage_key   TEXT NOT NULL,
  stack       TEXT NOT NULL      -- JSON-Liste von Stage-Dicts
);
CREATE INDEX IF NOT EXISTS ctx_span_term_idx ON ctx_span(terminal_id, start_off);

CREATE TABLE IF NOT EXISTS activity (
  cmd_id       TEXT PRIMARY KEY,
  terminal_id  TEXT NOT NULL,
  ts_utc_ns    INTEGER NOT NULL,
  ts_end_ns    INTEGER,
  operator_id  TEXT,
  ctx_kind     TEXT,
  ctx_host     TEXT,
  ctx_user     TEXT,
  tool         TEXT,
  cmd_text     TEXT,
  targets      TEXT NOT NULL DEFAULT '[]',   -- JSON: rohe Ziele aus extract_targets
  target_files TEXT NOT NULL DEFAULT '[]',   -- JSON: Ziel-Listen (nmap -iL), nicht gelesen
  target_scope TEXT NOT NULL DEFAULT '[]',   -- JSON: [{raw, id, verdict, rule}]
  scope_version INTEGER,
  src_ip       TEXT,
  exit_code    INTEGER,
  evidence     TEXT,             -- JSON Provenienz {"t": "stream", ...}
  unit_id      TEXT,
  origin       TEXT NOT NULL DEFAULT 'local' CHECK (origin IN ('local', 'remote_confirmed',
                                                             'remote_reconstructed'))
);
CREATE INDEX IF NOT EXISTS activity_ts_idx ON activity(ts_utc_ns);

CREATE TABLE IF NOT EXISTS net_route (
  seq     INTEGER PRIMARY KEY,
  cmd_id  TEXT NOT NULL,
  target  TEXT NOT NULL,
  src_ip  TEXT,
  dev     TEXT,
  via     TEXT
);
CREATE INDEX IF NOT EXISTS net_route_cmd_idx ON net_route(cmd_id);

CREATE TABLE IF NOT EXISTS parse_failure (
  unit_id        TEXT NOT NULL,
  parser_id      TEXT NOT NULL,
  parser_version TEXT,
  reason         TEXT NOT NULL,
  ts_utc_ns      INTEGER NOT NULL,
  PRIMARY KEY (unit_id, parser_id)
);

-- Zustand des Segmenters (neu berechenbar, erlaubt Wiederaufnahme nach Neustart)
CREATE TABLE IF NOT EXISTS seg_term (
  terminal_id  TEXT PRIMARY KEY,
  operator_id  TEXT,
  cols         INTEGER NOT NULL DEFAULT 0,
  rows         INTEGER NOT NULL DEFAULT 24,
  stream_end   INTEGER NOT NULL DEFAULT 0,
  last_out_ns  INTEGER,
  closed       INTEGER NOT NULL DEFAULT 0,
  norm_off     INTEGER,          -- letzte Grenze, an der der Normalizer zurückgesetzt wurde
  norm_n       INTEGER NOT NULL DEFAULT 0,
  norm_prompt  INTEGER NOT NULL DEFAULT 0,
  next_n       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS seg_event (
  terminal_id TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  kind        TEXT NOT NULL,
  off         INTEGER,
  ts_utc_ns   INTEGER NOT NULL,
  operator_id TEXT,
  header      TEXT NOT NULL,
  PRIMARY KEY (terminal_id, seq)
);

CREATE TABLE IF NOT EXISTS seg_chunk (
  terminal_id TEXT NOT NULL,
  off         INTEGER NOT NULL,
  len         INTEGER NOT NULL,
  seq         INTEGER NOT NULL,
  ts_utc_ns   INTEGER NOT NULL,
  PRIMARY KEY (terminal_id, off)
);
"""
