/**
 * Typen der HTTP-API /api/v1 (Entwurf, siehe docs/web-api.md).
 *
 * Später erzeugt `openapi-typescript` diese Typen aus dem OpenAPI-Schema des
 * Daemons (Architektur 7.1). Bis dahin ist diese Datei der Vertrag auf der
 * UI-Seite. Namen und Literale folgen src/ariadne/events.py, ontology.py,
 * parsers/api.py und scope/api.py.
 *
 * Konventionen:
 * - Zeitpunkte sind ISO-8601-Strings in UTC (`2026-10-08T12:02:11.123456Z`).
 *   Nanosekunden aus dem Journal gehen nie als JSON-Zahl über die Leitung
 *   (über 2^53), sondern höchstens als Dezimalstring (`ts_ns`).
 * - Alle Strings, die aus Zieldaten stammen können, sind feindlich und werden
 *   in der UI nur über displaySafe() angezeigt.
 */

// ---------------------------------------------------------------- Literale aus events.py
export type StageKind =
  | 'local' | 'su' | 'ssh' | 'winrm' | 'remote' | 'revshell' | 'msf' | 'meterpreter' | 'db' | 'unknown';
export type StageState = 'active' | 'suspended';
export type StageSource = 'auto' | 'hotkey' | 'webui' | 'cli' | 'suggestion';
export type Keystep = 'foothold' | 'privesc' | 'pivot' | 'loot';
export type WorkStatus = 'open' | 'in_progress' | 'dead_end' | 'done' | 'out_of_scope';
export type AccessLevel = 'none' | 'user' | 'admin';
export type GapReason =
  | 'rec_off' | 'buffer_overflow' | 'daemon_down' | 'project_switch'
  | 'sensitive_output' | 'locked' | 'disk_low' | 'shim_error';
export type RecSource = 'webui' | 'cli' | 'hotkey' | 'system';
export type Profile = 'lab' | 'customer';

// ---------------------------------------------------------------- parsers/api.py, scope/api.py
export type Trust = 'user' | 'structured' | 'tool_text' | 'heuristic' | 'ai' | 'ocr';
export type VerdictKind = 'in' | 'out' | 'excluded' | 'outside_window' | 'unknown';
export type ClaimState = 'candidate' | 'auto' | 'confirmed' | 'rejected';
/** Drei Konfidenz-Stufen in der UI (Architektur 5.7). */
export type ConfidenceLevel = 'high' | 'medium' | 'low';
/** Architektur 5.9: entdeckt, gescannt, Versionen bekannt. */
export type Knowledge = 'discovered' | 'scanned' | 'versions';
/** 0 bis 5, reine Funktion aus knowledge und access (siehe progressOf). */
export type Progress = 0 | 1 | 2 | 3 | 4 | 5;
/** Kartenebenen aus ontology.py, plus UI-Ebenen. */
export type MapLayer = 'topology' | 'services' | 'creds' | 'attack' | 'web' | 'ad';
export type GraphLayer = MapLayer | 'oos' | 'fog';
export type Lens = 'karte' | 'faden';

// ---------------------------------------------------------------- Fehler und Sitzung
export type ApiErrorCode =
  | 'unauthorized' // 401: Token fehlt, abgelaufen oder widerrufen
  | 'forbidden' // 403: Host/Origin/Sec-Fetch-Site falsch
  | 'policy' // 403: Profil oder Policy verbietet die Aktion (z. B. Cloud-KI im Profil customer)
  | 'budget' // 403: KI-Budget erschöpft
  | 'not_found' // 404
  | 'no_project' // 409: kein aktives Projekt
  | 'project_mismatch' // 409: pid ist nicht das aktive Projekt
  | 'conflict' // 409: Entscheid passt nicht mehr (verwaist, veraltet)
  | 'locked' // 423: Projekt gesperrt, `ariadne unlock` nötig
  | 'validation' // 422: Eingabe ungültig
  | 'rate_limited' // 429: zu viele Codeversuche
  | 'llm_unavailable' // 503: Provider nicht erreichbar
  | 'internal'; // 500

export interface ApiErrorBody {
  error: {
    code: ApiErrorCode;
    /** Deutscher Klartext ohne Zieldaten. Die UI übersetzt über `code`. */
    message: string;
    /** z. B. Pydantic-Fehlerliste bei 422 (nur Feldpfade, keine Werte). */
    detail?: { loc: (string | number)[]; type: string }[];
    request_id?: string;
  };
}

export interface SessionRequest {
  code: string;
}
export interface SessionResponse {
  token: string;
  expires_at: string;
}

// ---------------------------------------------------------------- Status und REC
export interface ProjectInfo {
  id: string;
  slug: string;
  name: string;
  profile: Profile;
  created_at: string;
  scope_version: number;
  /** Leitplanken lab (Architektur 8.1). */
  lab_guard: { public_targets: boolean; confirmed_not_customer: boolean } | null;
}

export type RecMode = 'off' | 'on' | 'waiting' | 'offline';
export interface RecState {
  on: boolean;
  /** waiting = REC an, Projekt gesperrt (Shim puffert im RAM). */
  mode: RecMode;
  since: string | null;
  source: RecSource | null;
  terminals_recording: number;
}

export type LlmMode = 'off' | 'local' | 'cloud';
export interface LlmState {
  mode: LlmMode;
  model: string | null;
  available: boolean;
  budget: { month_limit_usd: number; month_used_usd: number } | null;
}

export interface AutomodeState {
  enabled: boolean;
  parsers: string[];
  auto_ctx: boolean;
}

export interface Status {
  version: string;
  api: 1;
  operator_id: string;
  server_time: string;
  project: ProjectInfo | null;
  locked: boolean;
  rec: RecState;
  llm: LlmState;
  presentation: boolean;
  automode: AutomodeState | null;
  /** Lernmodus für Denkanstösse (im Profil lab Standard). */
  learning_mode: boolean;
  generation: number | null;
}

export interface RecRequest {
  on: boolean;
}
export interface PresentationRequest {
  on: boolean;
}
export interface Accepted {
  accepted: true;
}

// ---------------------------------------------------------------- Terminals und Kontext
export interface StageView {
  depth: number;
  kind: StageKind;
  /** eingegebene Kennung (`ip:default/10.10.10.5`, `name:web01`) oder null */
  host: string | null;
  /** aufgelöstes Host-Label (Zieldaten!) */
  host_label: string | null;
  host_id: string | null;
  user: string | null;
  state: StageState;
  source: StageSource;
  candidate: string | null;
  opened_at: number;
  scope: VerdictKind | null;
}

export interface CommandRef {
  cmd_id: string;
  text: string | null;
  started_at: string;
  ended_at: string | null;
  exit: number | null;
  src_ip: string | null;
  /** lokal | remote_confirmed | remote_reconstructed (Architektur 5.13) */
  origin: 'local' | 'remote_confirmed' | 'remote_reconstructed';
}

export interface Terminal {
  terminal_id: string;
  label: string | null;
  tty: string | null;
  shell: string;
  alive: boolean;
  project_id: string | null;
  recording: boolean;
  paused_reason: GapReason | null;
  opened_at: string;
  last_activity: string | null;
  last_command: CommandRef | null;
  stack: StageView[];
  /** Kontext-Vorschlag (ab v0.2) */
  suggestion: { suggestion_key: string; host: string; user: string | null; reason: string } | null;
}

export type ContextOp =
  | { op: 'set'; depth?: number; host?: string | null; user?: string | null; kind?: StageKind; from_off?: number }
  | { op: 'push'; kind?: StageKind; host?: string | null; user?: string | null }
  | { op: 'pop' }
  | { op: 'accept'; suggestion_key: string };

export interface ContextResult {
  decision_id: string;
  /** z. B. Scope-Warnung, wenn der Host nicht `in` ist */
  warnings: { code: 'scope_out' | 'scope_excluded' | 'scope_unknown' | 'host_unknown'; identifier: string }[];
}

// ---------------------------------------------------------------- Karte
export interface ServiceCounts {
  web: number;
  smb: number;
  db: number;
  remote: number;
  file: number;
  mail: number;
  other: number;
}
export type ServiceClass = keyof ServiceCounts;

export interface IdentifierView {
  key: string;
  scope: VerdictKind;
  /** Regel, die gegriffen hat, z. B. `include:10.10.10.0/24` */
  rule: string | null;
}

export interface KaliNode {
  kind: 'kali';
  id: 'kali';
  label: string;
  addresses: string[];
}

export interface SegmentNode {
  kind: 'segment';
  id: string;
  label: string;
  cidr: string;
  scope: VerdictKind;
  /** scope = aus dem Scope gezeichnet, observed = aus Funden */
  origin: 'scope' | 'observed';
  via_pivot: string | null;
}

export interface HostNode {
  kind: 'host';
  /** stabiler Schlüssel: stärkste Kennung, z. B. `ip:default/10.10.10.3` */
  id: string;
  segment: string | null;
  label: string;
  addresses: string[];
  names: string[];
  identifiers: IdentifierView[];
  /** Urteil der Hauptkennung, für die Darstellung */
  scope: VerdictKind;
  claim_state: ClaimState;
  confidence: ConfidenceLevel;
  knowledge: Knowledge;
  access: AccessLevel;
  work: WorkStatus;
  work_reason: string | null;
  progress: Progress;
  os: string | null;
  service_counts: ServiceCounts;
  services_total: number;
  conflicts: number;
  findings: number;
  hints: { total: number; high: number };
  ai: boolean;
  on_thread: boolean;
  tags: string[];
}

export interface ServiceNode {
  kind: 'service';
  id: string;
  host: string;
  proto: 'tcp' | 'udp';
  port: number;
  name: string | null;
  product: string | null;
  version: string | null;
  class: ServiceClass;
  state: 'open' | 'filtered' | 'closed';
  claim_state: ClaimState;
  confidence: ConfidenceLevel;
  work: WorkStatus;
  conflicts: number;
  ai: boolean;
  cves: string[];
}

export type GraphNode = KaliNode | SegmentNode | HostNode | ServiceNode;

export interface ThreadEdge {
  kind: 'thread';
  id: string;
  /** Nummer des Schlüsselschritts, ab 1 */
  seq: number;
  step: Keystep;
  source: string;
  target: string;
  ts: string;
  decision_id: string;
  note: string | null;
  evidence: EvidenceRef | null;
}

export interface ReachEdge {
  kind: 'reach';
  id: string;
  source: string;
  target: string;
  /** direct | pivot | tunnel (ab v0.2) */
  via: 'direct' | 'pivot' | 'tunnel';
}

export type GraphEdge = ThreadEdge | ReachEdge;

export interface OosItem {
  identifier: string;
  label: string;
  verdict: Exclude<VerdictKind, 'in'>;
  rule: string | null;
  mentions: number;
}

export interface GraphView {
  project_id: string;
  generation: number;
  lens: Lens;
  layers: GraphLayer[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Out-of-Scope, am Rand zu einer Zahl zusammengefasst */
  oos: { out: number; excluded: number; unknown: number; items: OosItem[] };
}

export interface GraphQuery {
  layers: GraphLayer[];
  lens: Lens;
}

export interface Positions {
  lens: Lens;
  positions: Record<string, { x: number; y: number }>;
  updated_at: string | null;
}

// ---------------------------------------------------------------- Änderungsfeed
export type ChangeEntity =
  | 'host' | 'service' | 'claim' | 'credential' | 'suggestion' | 'finding'
  | 'terminal' | 'timeline' | 'inbox' | 'thread' | 'note';
export interface Change {
  generation: number;
  entity: ChangeEntity;
  entity_key: string;
  change: 'added' | 'updated' | 'removed';
}
export interface ChangeSet {
  project_id: string;
  from: number;
  to: number;
  /** true: `since` liegt ausserhalb des Ringpuffers, Client lädt alles neu */
  reset: boolean;
  changes: Change[];
}

// ---------------------------------------------------------------- Fakten und Belege
export interface Fact {
  /** = claim_key (natürlicher Schlüssel, übersteht Reparse) */
  fact_id: string;
  claim_key: string;
  subject: string;
  subject_label: string;
  predicate: string;
  value: string | number | boolean;
  state: ClaimState;
  confidence: number;
  confidence_level: ConfidenceLevel;
  trust: Trust;
  parser: string | null;
  ai: boolean;
  /** Credential-Kandidat aus Banner, HTML-Kommentar oder KI (Architektur 6.4.8) */
  offered_by_target: boolean;
  scope: VerdictKind;
  sources_count: number;
  first_seen: string;
  last_seen: string;
  conflict_key: string | null;
  injection_suspect: boolean;
}

export interface EvidenceRef {
  fact_id: string | null;
  label: string;
}

export type SourceView =
  | {
      t: 'stream';
      terminal_id: string;
      terminal_label: string | null;
      unit_id: string;
      cmd: CommandRef | null;
      context: StageView[];
      off: [number, number];
      /** Zeilen in der Einheit, 0-basiert, Ende inklusiv (parsers/api.py Span) */
      lines: [number, number];
      parser: string;
      trust: Trust;
      truncated: boolean;
      partial: boolean;
    }
  | {
      t: 'file';
      blob_id: string | null;
      path: string;
      sha256: string;
      lines: [number, number] | null;
      xpath: string | null;
      parser: string;
      trust: Trust;
    }
  | {
      t: 'image';
      blob_id: string;
      bbox: [number, number, number, number];
      width: number;
      height: number;
      taken_at: string;
      window_title: string | null;
    }
  | { t: 'ai'; call_id: string; model: string; quote_in: SourceView | null }
  | { t: 'user'; decision_id: string; ts: string; operator_id: string };

export interface FactSources {
  fact: Fact;
  sources: SourceView[];
}

export interface SgrSpan {
  col_start: number;
  col_end: number;
  fg: string | null;
  bg: string | null;
  bold: boolean;
  concealed: boolean;
}

export interface LogLine {
  /** Zeilennummer in der Einheit bzw. im Strom, 0-basiert */
  n: number;
  text: string;
  sgr: SgrSpan[];
  prompt_echo: boolean;
  concealed: boolean;
  overwritten: boolean;
  /** Bereiche, die der Server maskiert hat (Präsentationsmodus, eigene Secrets) */
  masked: { col_start: number; col_end: number; kind: string }[];
}

export interface LinesQuery {
  unit?: string;
  from: number;
  count: number;
  /** verdeckte und überschriebene Teile mitliefern */
  reveal_hidden?: boolean;
}

export interface LinesPage {
  terminal_id: string;
  unit_id: string | null;
  total: number;
  from: number;
  lines: LogLine[];
}

// ---------------------------------------------------------------- Listen
export interface ServiceView {
  service_id: string;
  host_id: string;
  host_label: string;
  proto: 'tcp' | 'udp';
  port: number;
  name: string | null;
  product: string | null;
  version: string | null;
  class: ServiceClass;
  state: 'open' | 'filtered' | 'closed';
  claim_state: ClaimState;
  confidence_level: ConfidenceLevel;
  scope: VerdictKind;
  work: WorkStatus;
  auth_capable: boolean;
  conflicts: number;
  ai: boolean;
  cves: string[];
  fact_id: string | null;
}

export type SecretKind = 'password' | 'ntlm' | 'crypt' | 'hash' | 'key' | 'ticket' | 'token' | 'empty';
export interface CredentialView {
  credential_id: string;
  identity: { realm: string; name: string };
  secret_kind: SecretKind;
  /** immer maskiert; Klartext nur über /reveal (Profil lab, nicht im Präsentationsmodus) */
  secret_masked: string;
  origin: 'target_offered' | 'cracked' | 'dumped' | 'observed' | 'user';
  claim_state: ClaimState;
  ai: boolean;
  valid_on: { service_id: string; label: string; result: 'ok' | 'admin' }[];
  untested: number;
  fact_id: string | null;
}

export interface HostSummary extends Omit<HostNode, 'kind' | 'segment'> {
  segment: string | null;
  first_seen: string;
  last_seen: string;
}

export interface Conflict {
  conflict_key: string;
  subject: string;
  predicate: string;
  values: { value: string; claim_key: string; fact_id: string; sources_count: number; trust: Trust }[];
  resolved: { choice: string | null; keep_open: boolean } | null;
}

export interface Shot {
  blob_id: string;
  taken_at: string;
  mode: 'window' | 'monitor' | 'region';
  window_title: string | null;
  terminal_id: string | null;
  note: string | null;
}

export interface HostDetail extends HostSummary {
  services: ServiceView[];
  credentials: CredentialView[];
  facts: Fact[];
  conflicts_detail: Conflict[];
  note: { text: string; updated_at: string } | null;
  shots: Shot[];
  commands: (CommandRef & { terminal_id: string; unit_id: string })[];
}

// ---------------------------------------------------------------- Inbox
export type InboxGroupKind = 'unit' | 'context' | 'conflict' | 'merge' | 'orphan' | 'mass';

export interface InboxItem {
  item_id: string;
  type: 'claim' | 'conflict' | 'context' | 'merge' | 'orphan';
  claim_key: string | null;
  fact_id: string | null;
  subject: string;
  subject_label: string;
  predicate: string;
  value: string | number | boolean | null;
  confidence_level: ConfidenceLevel;
  scope: VerdictKind;
  trust: Trust;
  parser: string | null;
  ai: boolean;
  offered_by_target: boolean;
  state: ClaimState;
  conflict: Conflict | null;
  context: { terminal_id: string; terminal_label: string | null; from_off: number; candidate: string | null; kind: StageKind } | null;
  merge: { identifiers: string[]; reason: string } | null;
  orphan: { decision_id: string; kind: string; reason: string } | null;
}

export interface InboxGroup {
  group_id: string;
  kind: InboxGroupKind;
  title: string;
  ts: string;
  unit: { unit_id: string; cmd_id: string | null; text: string | null; terminal_id: string | null; parser: string | null } | null;
  items: InboxItem[];
  summary: {
    hosts: number;
    services: number;
    credentials: number;
    other: number;
    out_of_scope: number;
    low_confidence: number;
  };
}

export interface InboxView {
  open: number;
  groups: InboxGroup[];
  automode: AutomodeState;
}

// ---------------------------------------------------------------- Denkanstösse
export type SuggestionKind = 'question' | 'hypothesis' | 'goal' | 'hint';
export type SuggestionOrigin =
  | { type: 'rule'; rule_id: string }
  | { type: 'ai'; model: string; call_id: string; prompt_version: string };

export interface CommandTemplateView {
  template_id: string;
  title: string;
  /** false: ein Wert enthält Sonderzeichen, der Befehl wird nicht gerendert */
  renderable: boolean;
  reason: string | null;
  /** Befehl in Teilen, Anteile aus Zieldaten markiert (Architektur 6.1.6) */
  parts: { text: string; from_target: boolean }[];
  /** exakt der Text für die Zwischenablage, ohne Zeilenumbruch am Ende */
  copy_text: string | null;
  /** Werte, die sich nicht sicher rendern liessen, einzeln kopierbar */
  values: { name: string; value: string }[];
}

export interface SuggestionStage {
  level: 1 | 2 | 3;
  kind: 'question' | 'direction' | 'commands';
  text: string | null;
  commands: CommandTemplateView[];
}

export interface Suggestion {
  suggestion_key: string;
  origin: SuggestionOrigin;
  kind: SuggestionKind;
  goal_id: string | null;
  title: string;
  reasoning: string;
  subjects: { id: string; label: string; kind: 'host' | 'service' | 'credential' }[];
  evidence: EvidenceRef[];
  criteria: { confirmed: string; refuted: string } | null;
  stages: SuggestionStage[];
  status: 'open' | 'done' | 'dismissed';
  created_at: string;
  injection_suspect: boolean;
}

export interface DenkanstossRequest {
  /** optionaler Fokus, sonst ganzes Lagebild */
  host_ids?: string[];
}

export interface Job {
  job_id: string;
  kind: 'ai.denkanstoss' | 'ai.frage' | 'export' | 'screenshot' | 'reparse';
  status: 'queued' | 'running' | 'done' | 'failed' | 'refused';
}

// ---------------------------------------------------------------- Findings und Zeitachse
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface Finding {
  finding_id: string;
  title: string;
  severity: Severity;
  assets: { id: string; label: string; kind: 'host' | 'service' }[];
  description: string;
  evidence: EvidenceRef[];
  mitigation: string;
  attack_ids: string[];
  cves: string[];
  status: 'draft' | 'final';
  created_at: string;
  updated_at: string;
}

export type TimelineType =
  | 'command' | 'segment' | 'rec' | 'context' | 'screenshot' | 'decision' | 'keystep' | 'file' | 'gap' | 'ai';
export interface TimelineItem {
  id: string;
  ts: string;
  type: TimelineType;
  terminal_id: string | null;
  host_id: string | null;
  host_label: string | null;
  title: string;
  detail: string | null;
  exit: number | null;
  facts: number;
  evidence: EvidenceRef | null;
}
export interface TimelineQuery {
  types?: TimelineType[];
  terminal?: string;
  host?: string;
  cursor?: string;
  limit?: number;
}
export interface TimelinePage {
  items: TimelineItem[];
  next_cursor: string | null;
}

// ---------------------------------------------------------------- Entscheide (events.py, Präfix d.)
export interface DClaim { claim_key: string; reason?: string | null }
export interface DClaimEdit { claim_key: string; value: string }
export interface DEntityIds { identifiers: string[]; reason?: string | null }
export interface DKeystepMark { terminal_id?: string | null; stream_off?: number | null; step: Keystep; host?: string | null; note?: string | null }
export interface DStatusWork { subject: string; value: WorkStatus; reason?: string | null }
export interface DStatusAccess { subject: string; value: AccessLevel }
export interface DNoteSet { subject: string; text: string }
export interface DTag { subject: string; tag: string }
export interface DScopeUpdate { version: number; toml: string }
export interface DAutomodeSet { enabled: boolean; parsers?: string[]; auto_ctx?: boolean }
export interface DConflictResolve { conflict_key: string; choice?: string | null; keep_open?: boolean }
export interface DTerminalLabel { terminal_id: string; label: string }
export interface DRevoke { decision_id: string; reason?: string | null }
export interface DSuggestion { suggestion_key: string; reason?: string | null }
export interface DLabNotCustomer { scope_version: number }
/** Vorschlag für d.finding (in events.py noch DGeneric) */
export interface DFinding {
  finding_id: string;
  action: 'create' | 'update' | 'delete';
  title?: string;
  severity?: Severity;
  assets?: string[];
  description?: string;
  mitigation?: string;
  attack_ids?: string[];
  evidence?: string[];
}

/** Abbildung Entscheid-Art -> Nutzlast. Entscheide zu Terminals laufen über /terminals/{tid}/context. */
export interface DecisionPayloads {
  'd.claim.confirm': DClaim;
  'd.claim.reject': DClaim;
  'd.claim.edit': DClaimEdit;
  'd.entity.merge': DEntityIds;
  'd.entity.split': DEntityIds;
  'd.keystep.mark': DKeystepMark;
  'd.status.work': DStatusWork;
  'd.status.access': DStatusAccess;
  'd.note.set': DNoteSet;
  'd.tag.add': DTag;
  'd.tag.remove': DTag;
  'd.scope.update': DScopeUpdate;
  'd.automode.set': DAutomodeSet;
  'd.conflict.resolve': DConflictResolve;
  'd.terminal.label': DTerminalLabel;
  'd.revoke': DRevoke;
  'd.suggestion.done': DSuggestion;
  'd.suggestion.dismiss': DSuggestion;
  'd.lab.not_customer': DLabNotCustomer;
  'd.finding': DFinding;
}
export type DecisionKind = keyof DecisionPayloads;
export type DecisionInput = { [K in DecisionKind]: { kind: K; payload: DecisionPayloads[K]; client_ref?: string } }[DecisionKind];

export interface DecisionRequest {
  decisions: DecisionInput[];
}
export interface DecisionResult {
  decision_id: string;
  seq: number;
  ts: string;
  client_ref: string | null;
}
export interface DecisionResponse {
  results: DecisionResult[];
}

// ---------------------------------------------------------------- Abfrage-DSL (Architektur 5.12)
export type QueryFrom = 'hosts' | 'services' | 'endpoints' | 'identities' | 'credentials' | 'cred_tests' | 'hints' | 'activity' | 'mentions' | 'findings' | 'goals';
export type QueryOp = 'eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte' | 'in' | 'contains' | 'prefix' | 'is_null';
export type QueryCond =
  | { field: string; op: QueryOp; value?: string | number | boolean | (string | number)[] }
  | { all: QueryCond[] }
  | { any: QueryCond[] }
  | { not: QueryCond };
export interface QueryDsl {
  from: QueryFrom;
  where?: QueryCond;
  select?: string[];
  order?: { field: string; dir: 'asc' | 'desc' }[];
  limit?: number;
}
export interface QueryResult {
  columns: string[];
  rows: (string | number | boolean | null)[][];
  truncated: boolean;
  /** rein informativ, nie ausführbar */
  sql_preview: string;
}

// ---------------------------------------------------------------- SSE
export type StreamEventName =
  | 'changes' | 'rec' | 'terminal' | 'inbox' | 'suggestion' | 'progress' | 'presentation' | 'project' | 'reset';

export interface StreamPayloads {
  changes: { generation: number; entities: Partial<Record<ChangeEntity, number>> };
  rec: RecState;
  terminal: { terminal_id: string; change: 'opened' | 'closed' | 'context' | 'command' | 'label' | 'bind' | 'gap' };
  inbox: { open: number };
  suggestion: { suggestion_key: string; change: 'added' | 'updated' | 'removed'; open: number };
  progress: { job_id: string; kind: Job['kind']; status: Job['status']; pct: number | null; message: string | null };
  presentation: { on: boolean };
  project: { project_id: string | null; locked: boolean };
  reset: { reason: 'reparse' | 'buffer' | 'restart'; generation: number | null };
}

export type StreamEvent = { [K in StreamEventName]: { name: K; id: string | null; data: StreamPayloads[K] } }[StreamEventName];

// ---------------------------------------------------------------- Hilfsfunktionen
/** Architektur 5.9: progress ist eine reine Funktion aus knowledge und access. */
export function progressOf(knowledge: Knowledge | null, access: AccessLevel): Progress {
  if (access === 'admin') return 5;
  if (access === 'user') return 4;
  switch (knowledge) {
    case 'versions':
      return 3;
    case 'scanned':
      return 2;
    case 'discovered':
      return 1;
    default:
      return 0;
  }
}

/** Grenzen der drei Konfidenz-Stufen (Server liefert die Stufe mit). */
export function confidenceLevel(c: number): ConfidenceLevel {
  if (c >= 0.9) return 'high';
  if (c >= 0.6) return 'medium';
  return 'low';
}
