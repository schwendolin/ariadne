"""Schema der Projektion in ``derived.db`` (Architektur 5.7 bis 5.10).

Eigene Tabellen dieses Teilsystems; ``unit``, ``unit_line``, ``cmd_block`` usw.
legt die Pipeline an. Alle Anweisungen sind idempotent (``IF NOT EXISTS``) und
laufen mit ``sqlite3`` wie mit ``sqlcipher3``.

* Schicht-2-Eingaben: ``obs_unit`` (Kontext der Einheit zum Zeitpunkt des
  Parsens), ``observation``, ``mention``, ``decision`` (Kopie der Entscheide).
* Abgeleitet bei jedem ``rebuild``: ``identifier``, ``entity``, ``claim``,
  ``claim_source``, ``conflict``, ``inbox_item``, ``keystep``.
* ``secret_value`` hält Klartext von Secrets nur hier (die Datei ist
  verschlüsselt). Keine Sicht liest daraus; überall sonst stehen HMAC-Kennungen.
* ``generation`` und ``projection_delta`` sind der Änderungsfeed.
* ``own_addr`` (eigene Adressen von Kali aus ``net.local_addrs`` und
  ``net.route``, A5) schreibt die Pipeline; ``ctx_auto`` (Auto-Kontext aus dem
  ersten Callback, E23) und ``unit_distrust`` (Rückgängig pro Befehl, A2) sind
  abgeleitet.
* Spuren (E42): ``claim.lane`` ist ``auto``, ``quiet``, ``decide`` oder ``user``,
  ``lane_reason`` der Grund; ``history = 1`` heisst durch einen neueren Zustand
  oder eine genauere Version abgelöst (E45). ``group_key`` ist die Evidenzgruppe.
  ``host_scope`` ist das Scope-Urteil, nach dem Spur und Sammelbestätigung gehen
  (bei Konto, Secret und Hinweis das des Hosts, auf dem beobachtet wurde, A1).

:data:`CLAIMS_VERSION` steht als ``schema_claims_version`` in ``meta``. Weicht sie
ab, baut die Auswertung ``derived.db`` neu (``CREATE ... IF NOT EXISTS`` ergänzt
keine Spalten).

Sichten zeigen Secret-Werte nur maskiert (:data:`MASK`, wörtlich im SQL).
"""

from __future__ import annotations

__all__ = ["SCHEMA_SQL", "VIEWS_SQL", "MASK", "statements", "CLAIMS_VERSION"]

MASK = "••••••••"
CLAIMS_VERSION = 3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS obs_unit (
  unit_id        TEXT PRIMARY KEY,
  kind           TEXT NOT NULL,
  terminal_id    TEXT,
  cmd_id         TEXT,
  title          TEXT,
  path           TEXT,
  ts_utc_ns      INTEGER NOT NULL,
  start_off      INTEGER,
  end_off        INTEGER,
  ctx_kind       TEXT,
  ctx_host       TEXT,
  ctx_user       TEXT,
  ctx_opened_at  INTEGER,
  ctx_candidate  TEXT,
  from_target    INTEGER NOT NULL DEFAULT 0,
  journal_seq    INTEGER NOT NULL DEFAULT 0,
  flags          TEXT NOT NULL DEFAULT '[]',
  mono_ns        INTEGER
);
CREATE INDEX IF NOT EXISTS obs_unit_cmd ON obs_unit(cmd_id);

CREATE TABLE IF NOT EXISTS observation (
  obs_id          INTEGER PRIMARY KEY,
  unit_id         TEXT NOT NULL,
  parser_id       TEXT NOT NULL,
  parser_version  TEXT NOT NULL,
  trust           TEXT NOT NULL,
  auto_eligible   INTEGER NOT NULL,
  journal_seq     INTEGER NOT NULL,
  subject         TEXT NOT NULL,
  predicate       TEXT NOT NULL,
  value_json      TEXT NOT NULL,
  value_text      TEXT NOT NULL,
  span_json       TEXT NOT NULL,
  confidence      REAL NOT NULL,
  attrs_json      TEXT NOT NULL,
  ts_utc_ns       INTEGER NOT NULL,
  from_target     INTEGER NOT NULL DEFAULT 0,
  suspect         INTEGER NOT NULL DEFAULT 0,
  is_secret       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS observation_unit ON observation(unit_id, parser_id);

CREATE TABLE IF NOT EXISTS mention (
  mention_id      INTEGER PRIMARY KEY,
  unit_id         TEXT NOT NULL,
  parser_id       TEXT NOT NULL,
  parser_version  TEXT NOT NULL,
  journal_seq     INTEGER NOT NULL,
  value_type      TEXT NOT NULL,
  value           TEXT,
  value_key       TEXT NOT NULL,
  span_json       TEXT NOT NULL,
  attrs_json      TEXT NOT NULL,
  ts_utc_ns       INTEGER NOT NULL,
  from_target     INTEGER NOT NULL DEFAULT 0,
  suspect         INTEGER NOT NULL DEFAULT 0,
  is_secret       INTEGER NOT NULL DEFAULT 0,
  scope_verdict   TEXT
);
CREATE INDEX IF NOT EXISTS mention_unit ON mention(unit_id, parser_id);
CREATE INDEX IF NOT EXISTS mention_key ON mention(value_key);

CREATE TABLE IF NOT EXISTS decision (
  seq           INTEGER PRIMARY KEY,
  id            TEXT NOT NULL UNIQUE,
  kind          TEXT NOT NULL,
  payload_json  TEXT NOT NULL,
  ts            INTEGER NOT NULL,
  mono_ns       INTEGER,
  boot_id       TEXT
);

CREATE TABLE IF NOT EXISTS secret_value (
  secret_ident  TEXT PRIMARY KEY,
  kind          TEXT NOT NULL,
  value         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identifier (
  key            TEXT PRIMARY KEY,
  type           TEXT NOT NULL,
  entity_id      TEXT,
  strength       TEXT NOT NULL,
  scope_verdict  TEXT,
  scope_rule     TEXT,
  scope_version  INTEGER
);
CREATE INDEX IF NOT EXISTS identifier_entity ON identifier(entity_id);

CREATE TABLE IF NOT EXISTS entity (
  entity_id    TEXT PRIMARY KEY,
  type         TEXT NOT NULL,
  label        TEXT NOT NULL,
  knowledge    TEXT,
  access       TEXT,
  work         TEXT,
  work_reason  TEXT,
  progress     INTEGER,
  first_seen   INTEGER,
  last_seen    INTEGER,
  tags_json    TEXT NOT NULL DEFAULT '[]',
  note         TEXT,
  scope        TEXT,
  claim_state  TEXT,
  first_unit   TEXT,
  attrs_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS claim (
  claim_key           TEXT PRIMARY KEY,
  subject_identifier  TEXT NOT NULL,
  entity_id           TEXT,
  predicate           TEXT NOT NULL,
  value_json          TEXT NOT NULL,
  value_text          TEXT NOT NULL,
  confidence          REAL NOT NULL,
  state               TEXT NOT NULL CHECK (state IN ('candidate','auto','confirmed','rejected')),
  first_unit          TEXT,
  last_unit           TEXT,
  first_ts            INTEGER,
  last_ts             INTEGER,
  conflict_key        TEXT,
  from_target         INTEGER NOT NULL DEFAULT 0,
  trust               TEXT NOT NULL,
  parser_id           TEXT,
  sources             INTEGER NOT NULL,
  is_secret           INTEGER NOT NULL DEFAULT 0,
  suspect             INTEGER NOT NULL DEFAULT 0,
  scope               TEXT,
  decision_id         TEXT,
  lane                TEXT NOT NULL DEFAULT 'quiet' CHECK (lane IN ('auto','quiet','decide','user')),
  lane_reason         TEXT,
  group_key           TEXT,
  history             INTEGER NOT NULL DEFAULT 0,
  host_scope          TEXT
);
CREATE INDEX IF NOT EXISTS claim_entity ON claim(entity_id);
CREATE INDEX IF NOT EXISTS claim_lane ON claim(lane, lane_reason);
CREATE INDEX IF NOT EXISTS claim_subject ON claim(subject_identifier, predicate);

CREATE TABLE IF NOT EXISTS claim_source (
  claim_key       TEXT NOT NULL,
  obs_id          INTEGER,
  mention_id      INTEGER,
  decision_id     TEXT,
  unit_id         TEXT,
  parser_id       TEXT,
  parser_version  TEXT,
  trust           TEXT NOT NULL,
  confidence      REAL NOT NULL,
  span_json       TEXT,
  journal_seq     INTEGER,
  ts_utc_ns       INTEGER,
  group_key       TEXT,
  side            INTEGER NOT NULL DEFAULT 0,
  distrusted      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS claim_source_key ON claim_source(claim_key);
CREATE INDEX IF NOT EXISTS claim_source_group ON claim_source(group_key);

CREATE TABLE IF NOT EXISTS conflict (
  conflict_key        TEXT PRIMARY KEY,
  subject_identifier  TEXT NOT NULL,
  entity_id           TEXT,
  predicate           TEXT NOT NULL,
  claim_keys_json     TEXT NOT NULL,
  state               TEXT NOT NULL CHECK (state IN ('open','resolved','kept_open')),
  choice              TEXT,
  decision_id         TEXT
);

CREATE TABLE IF NOT EXISTS inbox_item (
  item_key      TEXT PRIMARY KEY,
  kind          TEXT NOT NULL CHECK (kind IN ('candidate_group','decide_value','conflict',
                  'merge_suggestion','ctx_suggestion','ctx_unknown','orphan_decision','mass_find')),
  group_key     TEXT NOT NULL,
  title         TEXT NOT NULL,
  payload_json  TEXT NOT NULL,
  state         TEXT NOT NULL DEFAULT 'open',
  created_ts    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS inbox_group ON inbox_item(group_key);

CREATE TABLE IF NOT EXISTS keystep (
  seq          INTEGER PRIMARY KEY,
  decision_id  TEXT NOT NULL,
  step         TEXT NOT NULL,
  host_ident   TEXT,
  entity_id    TEXT,
  terminal_id  TEXT,
  stream_off   INTEGER,
  note         TEXT,
  ts_utc_ns    INTEGER NOT NULL,
  mono_ns      INTEGER,
  boot_id      TEXT
);

CREATE TABLE IF NOT EXISTS own_addr (
  addr       TEXT PRIMARY KEY,
  source     TEXT NOT NULL,
  first_seq  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ctx_auto (
  terminal_id  TEXT NOT NULL,
  opened_at    INTEGER NOT NULL,
  host         TEXT NOT NULL,
  claim_key    TEXT,
  PRIMARY KEY (terminal_id, opened_at)
);

CREATE TABLE IF NOT EXISTS unit_distrust (
  cmd_id       TEXT PRIMARY KEY,
  decision_id  TEXT NOT NULL,
  rejected     INTEGER NOT NULL,
  weakened     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS generation (
  generation  INTEGER PRIMARY KEY,
  ts_utc_ns   INTEGER NOT NULL,
  changes     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projection_delta (
  generation  INTEGER NOT NULL,
  entity      TEXT NOT NULL,
  entity_key  TEXT NOT NULL,
  change      TEXT NOT NULL CHECK (change IN ('added','updated','removed'))
);
CREATE INDEX IF NOT EXISTS projection_delta_gen ON projection_delta(generation);
"""

VIEWS_SQL = """
CREATE VIEW IF NOT EXISTS v_host AS
SELECT e.entity_id AS host_id, e.label, e.scope, e.claim_state, e.knowledge, e.access, e.work,
       e.work_reason, e.progress, json_extract(e.attrs_json, '$.os') AS os,
       json_extract(e.attrs_json, '$.addresses') AS addresses_json,
       json_extract(e.attrs_json, '$.names') AS names_json,
       json_extract(e.attrs_json, '$.macs') AS macs_json,
       json_extract(e.attrs_json, '$.services_total') AS services_total,
       json_extract(e.attrs_json, '$.conflicts') AS conflicts,
       json_extract(e.attrs_json, '$.placeholder') AS placeholder,
       e.first_seen, e.last_seen, e.first_unit, e.tags_json, e.note
FROM entity e WHERE e.type = 'host'
  AND NOT EXISTS (SELECT 1 FROM own_addr o WHERE e.entity_id = 'ip:default/' || o.addr);

CREATE VIEW IF NOT EXISTS v_service AS
SELECT e.entity_id AS service_id, json_extract(e.attrs_json, '$.host_id') AS host_id,
       json_extract(e.attrs_json, '$.proto') AS proto, json_extract(e.attrs_json, '$.port') AS port,
       json_extract(e.attrs_json, '$.name') AS name, json_extract(e.attrs_json, '$.product') AS product,
       json_extract(e.attrs_json, '$.version') AS version, json_extract(e.attrs_json, '$.state') AS state,
       json_extract(e.attrs_json, '$.cves') AS cves_json,
       json_extract(e.attrs_json, '$.conflicts') AS conflicts,
       e.scope, e.claim_state, e.knowledge, e.work, e.work_reason, e.first_seen, e.last_seen, e.tags_json,
       e.note
FROM entity e WHERE e.type = 'service'
  AND NOT EXISTS (SELECT 1 FROM own_addr o
                  WHERE json_extract(e.attrs_json, '$.host_id') = 'ip:default/' || o.addr);

CREATE VIEW IF NOT EXISTS v_claim AS
SELECT c.claim_key, c.subject_identifier, c.entity_id, c.predicate,
       CASE WHEN c.is_secret THEN NULL ELSE c.value_json END AS value_json,
       CASE WHEN c.is_secret THEN '••••••••' ELSE c.value_text END AS value_text,
       c.confidence, c.state, c.trust, c.parser_id, c.sources, c.from_target, c.suspect, c.scope,
       c.conflict_key, c.first_unit, c.last_unit, c.first_ts, c.last_ts, c.is_secret, c.lane,
       c.lane_reason, c.group_key, c.history
FROM claim c;

CREATE VIEW IF NOT EXISTS v_mention AS
SELECT m.mention_id, m.unit_id, m.parser_id, m.value_type,
       CASE WHEN m.is_secret THEN '••••••••' ELSE m.value END AS value,
       m.span_json, m.attrs_json, m.ts_utc_ns, m.from_target, m.suspect, m.is_secret, m.scope_verdict,
       u.terminal_id, u.title, u.kind AS unit_kind
FROM mention m LEFT JOIN obs_unit u ON u.unit_id = m.unit_id;

CREATE VIEW IF NOT EXISTS v_inbox AS
SELECT i.item_key, i.kind, i.group_key, i.title, i.payload_json, i.state, i.created_ts
FROM inbox_item i WHERE i.state = 'open';

CREATE VIEW IF NOT EXISTS v_keystep AS
SELECT ROW_NUMBER() OVER (ORDER BY k.seq) AS ordinal, k.seq, k.decision_id, k.step, k.host_ident,
       k.entity_id, k.terminal_id, k.stream_off, k.note, k.ts_utc_ns, k.mono_ns, k.boot_id
FROM keystep k;
"""


def statements(sql: str) -> list[str]:
    """Teilt ein Skript in einzelne Anweisungen (ohne Trigger, daher genügt ``;``).

    ``executescript`` würde eine offene Transaktion des Aufrufers committen.
    """
    return [s.strip() for s in sql.split(";") if s.strip()]
