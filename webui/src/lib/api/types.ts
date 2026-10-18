/**
 * Typen der HTTP-API /api/v1 (API v2, docs/web-api.md, mit Abschnitt 18 «Ergänzungen für die
 * Oberfläche v0.1»). Diese Datei ist der Vertrag auf der UI-Seite (Vertrag v0.1-Oberfläche,
 * Abschnitt 3). Besitzer: ui-fundament. Andere Teile melden Änderungen als contract_request.
 *
 * Konventionen (web-api.md 1.2, 1.3):
 * - Zeitpunkte sind ISO-8601 in UTC mit Mikrosekunden. Wo die Ordnung zählt, kommt `ts_ns` als
 *   Dezimalstring (Nanosekunden liegen über 2^53).
 * - Felder, die es nicht gibt, sind `null`, nie weggelassen.
 * - Jeder String aus Zieldaten ist feindlich. Der Server macht Steuerzeichen sichtbar und setzt
 *   `ctrl`; die UI zeigt ihn trotzdem nur über `Txt`/`displaySafe` (zweite Schicht).
 * - Secrets stehen als '••••••••' da. Klartext nur über `secrets/reveal` (einzeln, nie im
 *   Präsentationsmodus); «in die Kali» über `secrets/copy`, nie über den Browser.
 */

// ------------------------------------------------------------------ Literale (2)
export type TermState = 'paused' | 'held' | 'on' | 'locked' | 'preroll' | 'off';
export type StageKind = 'local' | 'su' | 'ssh' | 'winrm' | 'remote' | 'revshell' | 'msf' | 'meterpreter' | 'db' | 'unknown';
export type StageSource = 'auto' | 'hotkey' | 'webui' | 'cli' | 'suggestion';
export type GapReason =
  | 'pause' | 'no_project' | 'daemon_down' | 'project_switch' | 'sensitive_output' | 'locked'
  | 'disk_low' | 'shim_error' | 'multiplexer' | 'buffer_overflow' | 'rec_off';
export type Keystep = 'foothold' | 'privesc' | 'pivot' | 'loot';
export type WorkStatus = 'open' | 'in_progress' | 'dead_end' | 'done' | 'out_of_scope';
export type AccessLevel = 'none' | 'user' | 'admin';
export type Profile = 'lab' | 'customer';
export type Trust = 'user' | 'structured' | 'tool_text' | 'heuristic' | 'ai' | 'ocr';
export type Verdict = 'in' | 'out' | 'excluded' | 'outside_window' | 'unknown';
export type ClaimState = 'candidate' | 'auto' | 'confirmed' | 'rejected';
export type Lane = 'auto' | 'quiet' | 'decide' | 'user';
export type ConfidenceLevel = 'high' | 'medium' | 'low';
export type Knowledge = 'mentioned' | 'discovered' | 'scanned' | 'versions';
export type Progress = 0 | 1 | 2 | 3 | 4 | 5;
export type ServiceClass = 'web' | 'smb' | 'db' | 'remote' | 'file' | 'mail' | 'other';
export type GraphLayer = 'topology' | 'services' | 'thread' | 'oos' | 'fog';

// ------------------------------------------------------------------ Fehler (1.5, 18.10)
export type ApiErrorCode =
  | 'unauthorized' | 'forbidden' | 'policy' | 'not_found' | 'method' | 'no_project' | 'project_mismatch'
  | 'conflict' | 'too_large' | 'host' | 'validation' | 'locked' | 'rate_limited' | 'not_implemented'
  | 'unavailable' | 'internal' | 'clipboard_tool' | 'clipboard_session'
  | 'shot_display' | 'shot_wayland' | 'shot_window' | 'shot_region' | 'shot_failed';

export interface ApiErrorBody {
  error: {
    code: ApiErrorCode;
    /** fester deutscher Text pro Code; die UI übersetzt nur über `code` */
    message: string;
    /** nur bei 422, ohne Werte */
    detail?: { loc: (string | number)[]; type: string }[];
  };
}

// ------------------------------------------------------------------ Gemeinsame Typen (2, 18.1)
export interface StageView {
  depth: number;
  kind: StageKind;
  host_id: string | null;
  host_label: string | null;
  user: string | null;
  state: 'active' | 'suspended';
  source: StageSource;
  auto: boolean;
  candidate: string | null;
  opened_at: number;
}

export interface CommandRef {
  cmd_id: string;
  cmd_ref: string;
  text: string | null;
  started_at: string;
  ended_at: string | null;
  exit: number | null;
  src_ip: string | null;
  origin: 'local' | 'remote_reconstructed';
}

export interface EvidenceRef {
  claim_key: string | null;
  unit_id: string | null;
  lines: [number, number] | null;
  label: string;
  /** Zeit der Quelle (18.12, Belege von Denkanstössen); das Label selbst ist ohne Uhrzeit */
  ts?: string | null;
}

export interface QuietCounts {
  heuristic: number;
  out_of_scope: number;
  mentions: number;
  system_accounts: number;
  own_address?: number;
}

/** Terminal-Bezug: «T1 scan» (18.1). */
export interface TermRef {
  terminal_id: string;
  ordinal: number | null;
  label: string | null;
}

/** Text in Teilen; `target` = stammt aus Zieldaten (gepunktet unterstrichen). */
export interface TextPart {
  text: string;
  target: boolean;
}

// ------------------------------------------------------------------ Anmeldung (3)
export interface SessionView {
  session_id: string;
  origin: 'local' | 'sshd';
  created_at: string;
  expires_at: string;
}
export interface SessionResponse {
  token: string;
  expires_at: string;
  session: SessionView;
}

// ------------------------------------------------------------------ Status (4, 18.4, 18.8)
export interface ProjectBrief {
  id: string;
  slug: string;
  name: string;
  profile: Profile;
  chain_head_ok: boolean;
}

export interface TerminalState {
  terminal_id: string;
  short_id: string;
  tty: string | null;
  state: TermState;
  pause_until: string | null;
  held_slug: string | null;
  preroll_s: number;
  mux: boolean;
  context_label: string | null;
  ctrl: boolean;
  /** 18.8 */
  ordinal: number | null;
  label: string | null;
  opened_at: string | null;
  /** restliches Web-Pausenbudget in der gleitenden Stunde (E117), höchstens 1800 */
  web_pause_left_s: number | null;
}

export interface ScopeWarning {
  cmd_id: string;
  cmd_ref: string;
  terminal_id: string;
  ts: string;
  terminal: TermRef;
  text: string | null;
  ctrl: boolean;
  targets: { value: string; verdict: Verdict; ctrl: boolean }[];
  scope: string[];
  acked: boolean;
}

export type LlmMode = 'off' | 'local' | 'cloud';

export interface Status {
  version: string;
  api_version: 2;
  server_time: string;
  session: SessionView;
  operator: { exists: boolean; unlocked: boolean; own_secrets: number | null };
  project: ProjectBrief | null;
  active: { slug: string; stopped: boolean; end_reason: 'stop' | 'idle' | 'missing' | null } | null;
  locked: boolean;
  recording: { connected: number; on: number; paused: number; held: number; mux: number };
  terminals: TerminalState[];
  idle: { idle_s: number; end_after_s: number | null } | null;
  preroll: {
    terminals: number;
    seconds: number;
    window_s: number;
    ask_terminals: number;
    ask_seconds: number;
    outage_terminals: number;
    outage_seconds: number;
  };
  presentation: boolean;
  llm: {
    mode: LlmMode;
    model: string | null;
    available: boolean;
    budget: { month_limit_usd: number; month_used_usd: number } | null;
  };
  generation: number | null;
  ingest: { active: boolean; last_error: string | null } | null;
  disk_low: boolean;
  scope_warning: ScopeWarning | null;
}

export interface PauseRequest {
  minutes?: number;
}
export interface Accepted {
  accepted: true;
}

// ------------------------------------------------------------------ Terminals (5)
export interface ContextSuggestion {
  item_key: string;
  from_off: number;
  host_id: string;
  host_label: string;
  reason: string;
}

export interface Terminal extends TerminalState {
  shell: string | null;
  connected: boolean;
  stack: StageView[];
  last_command: CommandRef | null;
  remote_segment: { since: string; lines: number } | null;
  suggestion: ContextSuggestion | null;
}

export type ContextOp =
  | { op: 'set'; host?: string | null; user?: string | null; kind?: StageKind; from_off?: number }
  | { op: 'push'; kind?: StageKind; host?: string | null; user?: string | null }
  | { op: 'pop' }
  | { op: 'accept'; item_key: string };

export interface ContextResult {
  stored: boolean;
  stack: StageView[] | null;
  warnings: { code: 'scope_out' | 'scope_excluded' | 'scope_unknown' | 'host_unknown'; host: string }[];
  /** 18.12: Entscheid von `set` und `accept` («Rückgängig» per d.revoke), sonst null */
  decision_id: string | null;
}

// ------------------------------------------------------------------ Projekt (6)
export interface ProjectView extends ProjectBrief {
  created_at: string;
  scope: { include: string[]; exclude: string[]; version: number };
  lab_guard: { public_targets: boolean; confirmed_not_customer: boolean } | null;
  started_at: string | null;
  chain: { head_seq: number; head_hash: string; head_ok: boolean };
  ctrl: boolean;
}

// ------------------------------------------------------------------ Karte (7, 18.8)
export interface KaliNode {
  kind: 'kali';
  id: 'kali';
  label: 'Kali';
  addresses: string[];
}
export interface SegmentNode {
  kind: 'segment';
  id: string;
  cidr: string;
  label: string;
  origin: 'scope' | 'observed';
}
export interface HostNode {
  kind: 'host';
  id: string;
  segment: string | null;
  label: string;
  ctrl: boolean;
  addresses: string[];
  names: string[];
  claim_state: ClaimState;
  knowledge: Knowledge;
  access: AccessLevel;
  work: WorkStatus;
  work_reason: string | null;
  progress: Progress;
  os: string | null;
  services_total: number;
  service_classes: Record<ServiceClass, number>;
  conflicts: number;
  auto: boolean;
  ai: boolean;
  on_thread: boolean;
  hint: 'conflict' | 'ai' | 'services' | null;
  tags: string[];
  /** 18.8 */
  ports: number[];
  conflict_brief: { predicate: string; port: number | null } | null;
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
  ctrl: boolean;
  class: ServiceClass;
  state: 'open' | 'filtered' | 'closed' | null;
  claim_state: ClaimState;
  conflicts: number;
}
export type GraphNode = KaliNode | SegmentNode | HostNode | ServiceNode;

export interface ThreadEdge {
  kind: 'thread';
  id: string;
  seq: number;
  step: Keystep;
  source: string;
  target: string;
  ts: string;
  note: string | null;
  decision_id: string | null;
}
export interface MemberEdge {
  kind: 'member';
  id: string;
  source: string;
  target: string;
}
export type GraphEdge = ThreadEdge | MemberEdge;

export interface UnitBrief {
  unit_id: string;
  kind: 'command' | 'segment' | 'file';
  cmd_id: string | null;
  cmd_ref: string | null;
  title: string;
  ctrl: boolean;
  terminal_id: string | null;
  parser: string | null;
  ts: string | null;
}

export interface OosItem {
  identifier: string;
  label: string;
  ctrl: boolean;
  verdict: 'out' | 'excluded' | 'outside_window' | 'unknown';
  rule: string | null;
  mentions: number;
  first_unit: string | null;
  /** 18.8 */
  source: UnitBrief | null;
  punycode: string | null;
  note: 'same_mac' | 'forged_callback' | null;
  related: string | null;
}

export interface GraphView {
  project_id: string;
  generation: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  oos: { total: number; items: OosItem[] };
  summary: { hosts: number; fog: number; with_access: number; services: number; conflicts: number };
  table_only: boolean;
  /** 18.8: Zeit der Generation («Stand 16:54») */
  as_of: string;
}

export type ChangeEntity = 'host' | 'service' | 'claim' | 'inbox' | 'keystep' | 'unit' | 'finding' | 'credential' | 'url' | 'other';
export interface ChangeSet {
  project_id: string;
  from: number;
  to: number;
  reset: boolean;
  changes: { generation: number; entity: ChangeEntity; entity_key: string; change: 'added' | 'updated' | 'removed' }[];
}

export interface PositionsView {
  positions: Record<string, { x: number; y: number }>;
  updated_at: string | null;
}

// ------------------------------------------------------------------ Hosts und Services (8, 18.8)
export interface HostSummary extends Omit<HostNode, 'kind'> {
  first_seen: string | null;
  last_seen: string | null;
  quiet: QuietCounts;
}

export interface Fact {
  claim_key: string;
  subject: string;
  subject_label: string;
  predicate: string;
  value: string;
  ctrl: boolean;
  is_secret: boolean;
  state: ClaimState;
  lane: Lane;
  lane_reason: string | null;
  confidence: ConfidenceLevel;
  trust: Trust;
  parser: string | null;
  from_target: boolean;
  suspect: boolean;
  verdict: Verdict | null;
  sources: number;
  first_seen: string | null;
  last_seen: string | null;
  conflict_key: string | null;
  history: boolean;
}

export interface Conflict {
  conflict_key: string;
  subject: string;
  subject_label: string;
  predicate: string;
  state: 'open' | 'resolved' | 'kept_open';
  values: { claim_key: string; value: string; ctrl: boolean; sources: number; trust: Trust; state: ClaimState }[];
  choice: string | null;
}

export interface ServiceView {
  service_id: string;
  host_id: string;
  host_label: string;
  proto: 'tcp' | 'udp';
  port: number;
  name: string | null;
  product: string | null;
  version: string | null;
  ctrl: boolean;
  class: ServiceClass;
  state: 'open' | 'filtered' | 'closed' | null;
  claim_state: ClaimState;
  verdict: Verdict | null;
  work: WorkStatus | null;
  conflicts: number;
  cves: string[];
  history: {
    predicate: 'service.state' | 'service.version' | 'service.product' | 'service.name';
    value: string;
    ctrl: boolean;
    until: string | null;
    claim_key: string;
  }[];
  /** 18.8 */
  banner: string | null;
  from_target: boolean;
  suspect: boolean;
}

/** Im Detail ist `conflicts` die Liste (web-api.md 17), in Karte und Tabelle die Zahl. */
export interface HostDetail extends Omit<HostSummary, 'conflicts'> {
  conflicts: Conflict[];
  identifiers: {
    key: string;
    label: string;
    type: string;
    verdict: Verdict;
    rule: string | null;
    ctrl: boolean;
    punycode: string | null;
  }[];
  services: ServiceView[];
  facts: Fact[];
  facts_truncated: boolean;
  open_items: string[];
  thread: ThreadEdge[];
  note: string | null;
  commands: (CommandRef & { terminal_id: string; unit_id: string })[];
  /** 18.8 */
  candidate_claims: string[];
  access_by: { source: 'decision' | 'keystep' | 'value'; decision_id: string | null; ts: string | null } | null;
  first_source: UnitBrief | null;
}

// ------------------------------------------------------------------ Als Nächstes (9, 18.6, 18.8)
export interface CtxExcerpt {
  unit_id: string;
  lines: [number, number];
  text: string[];
  ctrl: boolean;
  note: 'second_callback' | 'callback' | null;
  /** Zeit der Quelle (18.12) */
  ts: string | null;
}

/** Stabile Nummer einer Klärung («K2», 18.12), vergeben beim ersten Auftreten. */
interface NextBase {
  ordinal: number | null;
}

export type NextItem = NextBase &
  (
  | {
      kind: 'decide_value';
      item_key: string;
      group_ref: string;
      ts: string;
      fact: Fact;
      reason: string;
      unit: UnitBrief | null;
      ctrl?: boolean;
    }
  | { kind: 'conflict'; item_key: string; ts: string; conflict: Conflict; ctrl?: boolean }
  | {
      kind: 'ctx_unknown';
      item_key: string;
      ts: string;
      terminal_id: string | null;
      from_off: number | null;
      stage_kind: StageKind | null;
      candidate: string | null;
      units: number;
      unit: UnitBrief | null;
      terminal: TermRef | null;
      from_ts: string | null;
      excerpt: CtxExcerpt | null;
      ctrl?: boolean;
    }
  | {
      kind: 'ctx_suggestion';
      item_key: string;
      ts: string;
      terminal_id: string;
      from_off: number;
      stage_kind: StageKind | null;
      units: number;
      suggested_host: string;
      suggested_label: string;
      reason: string;
      claim_key: string | null;
      terminal: TermRef | null;
      from_ts: string | null;
      /** Integration v0.1: Zeit des Callbacks für «Grund … um 16:52:31» (additiv, kann fehlen) */
      reason_ts?: string | null;
      excerpt: CtxExcerpt | null;
      ctrl?: boolean;
    }
  | {
      kind: 'merge_suggestion';
      item_key: string;
      ts: string;
      identifiers: { key: string; label: string; verdict: Verdict | null }[];
      shared: string;
      reason: string;
      ctrl?: boolean;
    }
  | {
      kind: 'orphan_decision';
      item_key: string;
      ts: string;
      decision_id: string;
      decision_kind: string;
      reason: string;
      ref: string | null;
      ctrl?: boolean;
    }
  | { kind: 'mass_find'; item_key: string; ts: string; unit: UnitBrief; hosts: number; candidates: number; ctrl?: boolean }
  | {
      /** E130: nmap ordnet einen Namen einer IP im Scope zu; Vorschlag, den Namen aufzunehmen (nie automatisch) */
      kind: 'scope_suggestion';
      item_key: string;
      ts: string;
      /** Name aus der Ausgabe (Zieldaten) */
      name: string;
      /** IP im Scope, zu der nmap den Namen zeigt */
      ip: string;
      /** Vorschläge: genauer Name, Domain-Wildcard (nie die IP, die ist schon im Scope) */
      options: ScopeOption[];
      unit: UnitBrief | null;
      ctrl?: boolean;
    }
  );

export type NextItemKind = NextItem['kind'];

export interface NextGroup {
  group_ref: string;
  title: string;
  unit: UnitBrief | null;
  items: Extract<NextItem, { kind: 'decide_value' }>[];
  summary: { hosts: number; services: number; other: number; out_of_scope: number; low_confidence: number };
}

export type PlaceholderType = 'ip' | 'port' | 'hostname' | 'cidr' | 'url' | 'word' | 'words' | 'path' | 'user' | 'share';

export interface CommandTemplate {
  template_id: string;
  tool: string;
  label: string;
  rendered: boolean;
  command: string | null;
  parts: TextPart[];
  values: {
    slot: string;
    type: PlaceholderType;
    label: string;
    value: string;
    ctrl: boolean;
    target: boolean;
    safe: boolean;
  }[];
  /** `own_secret`: der Redaktor am Ausgang hätte ein eigenes Secret ersetzt (Korrektur SEC-RULES-1) */
  blocked_reason: 'shell_meta' | 'control' | 'newline' | 'non_ascii' | 'invalid' | 'out_of_scope' | 'own_secret' | null;
}

export type SuggestionState = 'open' | 'done' | 'dismissed';

export interface Suggestion {
  suggestion_key: string;
  /** `ai`: KI-Denkanstoss (v0.1-KI), sonst Regel */
  origin: 'rule' | 'ai';
  rule_id: string;
  goal_id: string | null;
  kind: 'goal' | 'question' | 'hypothesis' | 'hint';
  title: string;
  ctrl: boolean;
  title_parts: TextPart[];
  host_id: string | null;
  service_id: string | null;
  host_label: string | null;
  reason: string;
  ctrl_reason: boolean;
  evidence: EvidenceRef[];
  stages: { question: string; direction: string };
  templates: CommandTemplate[];
  state: SuggestionState;
  decision_id: string | null;
  basis: string;
  flags: ('from_target' | 'injection_suspect' | 'ai')[];
  ts: string | null;
  /** nur bei `origin: 'ai'`: Modell und Kriterien (Modelltext, geprüft, nur als Text) */
  ai: AiSuggestionMeta | null;
  /** E119: Liste pro Dienst mit je einer Vorlage (sonst leer); ältere Server ohne Feld */
  items?: SuggestionItemView[];
}
export interface AiSuggestionMeta {
  model: string;
  confirmed_if: string;
  refuted_if: string;
  job_id: string;
  created_at: string;
}
export interface SuggestionItemView {
  service_id: string;
  port: number;
  proto: string;
  label: string;
  ctrl: boolean;
  label_parts: TextPart[];
  template: CommandTemplate;
}

export interface NextView {
  clarify: NextItem[];
  confirm: NextGroup[];
  suggestions: Suggestion[];
  suggestions_available: boolean;
  /** E120: nicht quittierte Scope-Warnung als erster Eintrag (ältere Server ohne Feld) */
  scope_warning?: ScopeWarning | null;
  quiet: QuietCounts;
  open: number;
}

export interface SuggestionsResponse {
  suggestions: Suggestion[];
  truncated: boolean;
}

// ------------------------------------------------------------------ Zeitachse (10, 18.8)
export interface InputView {
  seq: number;
  terminal_id: string;
  stream_off: number;
  out_end: number;
  ts: string;
  ts_ns: string;
  length: number | null;
  paste: boolean;
  redacted: boolean;
  hidden: boolean;
  reason: 'tty_no_echo' | 'no_echo_seen' | 'no_output' | null;
  revealed: boolean;
  text: string;
}

export type TimelineType = 'command' | 'segment' | 'file' | 'keystep' | 'context' | 'decision' | 'gap' | 'project' | 'input' | 'callback';

interface TimelineBase {
  id: string;
  ts: string;
  ts_ns: string;
  terminal_id: string | null;
  context_label: string | null;
  host_id: string | null;
  ctrl: boolean;
  /** 18.8 */
  terminal: TermRef | null;
}

export type TimelineItem = TimelineBase &
  (
    | {
        type: 'command';
        cmd: CommandRef;
        unit_id: string;
        adopted: number;
        distrusted: { decision_id: string; rejected: number; weakened: number } | null;
        scope_warning: { targets: { value: string; verdict: Verdict }[] } | null;
        flags: ('partial' | 'truncated' | 'gap' | 'altscreen' | 'marker_forged')[];
        files: { unit_id: string; path: string }[];
        lines: number;
        result: { hosts_new: number; services: number; values: number; out_of_scope: number; conflicts: number };
      }
    | { type: 'segment'; unit_id: string; lines: number; state: 'open' | 'provisional' | 'final'; evaluate_after: string | null }
    | { type: 'file'; unit_id: string; path: string; cmd_id: string | null }
    | {
        type: 'keystep';
        step: Keystep;
        host_label: string | null;
        note: string | null;
        ordinal: number;
        decision_id: string;
      }
    | {
        type: 'context';
        change: 'set' | 'push' | 'pop' | 'auto';
        stack_label: string;
        source: StageSource;
        /** 18.12: Host der Stufe einzeln («192.168.56.101»), Art und Benutzer */
        host_label: string | null;
        stage_kind: StageKind | null;
        user: string | null;
        /** Sitzungsnummer des Callbacks bei `auto` («msf session 1») */
        session: string | null;
      }
    | {
        type: 'decision';
        decision_id: string;
        kind: string;
        summary: string;
        detail: string | null;
        reason: string | null;
        ref: string | null;
        effect: { rejected: number; weakened: number } | null;
      }
    | {
        /** Korrektur D15 (18.12): Callback eines Listeners, der den Kontext nicht automatisch setzte */
        type: 'callback';
        unit_id: string;
        /** «192.168.56.101:49158» (Zieldaten) */
        remote: string | null;
        /** «nc:4445» */
        listener: string | null;
        scope: Verdict | null;
        session: string | null;
        lines: [number, number] | null;
      }
    | { type: 'gap'; reason: GapReason; until: string | null; bytes_lost: number }
    | { type: 'project'; change: 'start' | 'end' | 'preroll'; reason: string | null; detail: string | null }
    | { type: 'input'; input: InputView }
  );

export interface TimelinePage {
  items: TimelineItem[];
  next_cursor: string | null;
}

export interface TimelineQuery {
  types?: TimelineType[];
  terminal?: string;
  host?: string;
  cursor?: string;
  limit?: number;
}

// ------------------------------------------------------------------ Belege (11, 18.8)
export type SourceView =
  | {
      t: 'stream';
      unit_id: string;
      terminal_id: string;
      cmd: CommandRef | null;
      context: StageView[];
      lines: [number, number] | null;
      parser: string;
      trust: Trust;
      confidence: ConfidenceLevel;
      flags: string[];
      distrusted: boolean;
    }
  | {
      t: 'file';
      unit_id: string;
      path: string;
      sha256: string | null;
      lines: [number, number] | null;
      parser: string;
      trust: Trust;
      produced_by_cmd: string | null;
    }
  | { t: 'user'; decision_id: string; kind: string; ts: string };

export interface FactSources {
  fact: Fact;
  sources: SourceView[];
}

export interface UnitView extends UnitBrief {
  exit: number | null;
  started_at: string | null;
  ended_at: string | null;
  duration_ms: number | null;
  src_ip: string | null;
  context: StageView[];
  line_count: number;
  flags: string[];
  chain_ok: boolean;
  /** 18.8 */
  terminal: TermRef | null;
  chain_break_line: number | null;
  /** Gerät des Terminals («/dev/pts/2», 18.12) */
  tty: string | null;
  /** Integration v0.1: offene Einheit (laufender Listener, Remote-Segment vor der Auswertung) */
  state?: 'open' | 'provisional' | 'final';
  /** Integration v0.1: SHA-256 einer Datei-Einheit */
  sha256?: string | null;
}

export interface SgrSpan {
  col_start: number;
  col_end: number;
  fg: string | null;
  bg: string | null;
  bold: boolean;
}

export interface LogLine {
  n: number;
  text: string;
  ctrl: boolean;
  sgr: SgrSpan[];
  prompt_echo: boolean;
  concealed: boolean;
  overwritten: boolean;
  masked: { col_start: number; col_end: number; kind: string }[];
}

export interface LinesPage {
  unit_id: string;
  total: number;
  from: number;
  lines: LogLine[];
}

export interface LinesQuery {
  from?: number;
  count?: number;
  reveal_hidden?: boolean;
}

// ------------------------------------------------------------------ Entscheide (12, 18.5, 18.6)
export interface DecisionInput {
  kind: DecisionKind;
  payload: Record<string, unknown>;
  client_ref?: string;
}
export type DecisionKind =
  | 'd.claim.confirm' | 'd.claim.reject' | 'd.claim.edit' | 'd.conflict.resolve' | 'd.entity.merge'
  | 'd.entity.split' | 'd.status.work' | 'd.status.access' | 'd.note.set' | 'd.tag.add' | 'd.tag.remove'
  | 'd.terminal.label' | 'd.keystep.mark' | 'd.revoke' | 'd.unit.distrust' | 'd.suggestion.done'
  | 'd.suggestion.dismiss' | 'd.finding.create' | 'd.finding.update' | 'd.finding.evidence.add'
  | 'd.finding.evidence.remove' | 'd.finding.delete'
  /** Entwurf ui (E130): Klärung «In den Scope aufnehmen?» verwerfen */
  | 'd.scope.dismiss';

export interface DecisionResult {
  decision_id: string | null;
  seq: number | null;
  client_ref: string | null;
  effect: { rejected: number; weakened: number } | null;
}
export interface DecisionResponse {
  results: DecisionResult[];
}

export interface ConfirmGroupResult {
  confirmed: number;
  excluded: Record<'own_address' | 'context' | 'out_of_scope' | 'conflict' | 'merge' | 'ai' | 'suspect' | 'low_confidence', number>;
}

// ------------------------------------------------------------------ Suche, Warteliste, Secrets (13, 18.7, 18.8)
export interface SearchResult {
  items: {
    unit_id: string;
    line: number;
    text: string;
    ctrl: boolean;
    kind: string;
    context_label: string;
    host_id: string | null;
    cmd: string | null;
    ts: string;
  }[];
  truncated: boolean;
}

export type PendingReason =
  | 'outside_workspace' | 'symlink' | 'hardlink' | 'owner' | 'not_regular' | 'other_fs' | 'path' | 'too_large';

export interface PendingFile {
  path: string;
  reason: PendingReason | string;
  cmd_id: string | null;
  terminal_id: string | null;
  ts: string;
  ctrl: boolean;
  size: number | null;
}
export interface PendingResponse {
  files: PendingFile[];
  truncated: boolean;
}

export type SecretRef = { ref: 'input'; seq: number } | { ref: 'claim'; claim_key: string };
export interface RevealResponse {
  value: string;
  ctrl: boolean;
}
export interface CopyResult {
  copied: true;
  target: 'kali';
  clear_after_s: 30;
  tool: 'xclip' | 'xsel' | 'wl-copy';
}

// ------------------------------------------------------------------ Vorlieben, Neu seit (18.2, 18.3)
export type Theme = 'system' | 'light' | 'dark';
export type Density = 'comfortable' | 'compact';
export interface Prefs {
  theme: Theme;
  density: Density;
  learning: boolean;
}
export interface PrefsView {
  prefs: Prefs;
  updated_at: string | null;
}

export interface NewSince {
  since: string;
  count: number;
  hosts: string[];
  access: string[];
  services: string[];
  items: string[];
  keysteps: string[];
}
export interface SeenView {
  seen_at: string | null;
  new: NewSince | null;
}

// ------------------------------------------------------------------ Findings (18.5)
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingStatus = 'draft' | 'final';
export type FindingWarning = 'evidence_distrusted' | 'evidence_missing' | 'no_evidence' | 'no_severity';

export interface FindingSummary {
  finding_id: string;
  ordinal: number;
  title: string;
  ctrl: boolean;
  severity: Severity | null;
  status: FindingStatus;
  affected: { subject: string; label: string; ctrl: boolean }[];
  evidence_count: number;
  warnings: FindingWarning[];
  created_at: string;
  updated_at: string;
}

export interface FindingEvidence {
  evidence_id: string;
  ref: EvidenceRef;
  label: string;
  ctrl: boolean;
  terminal: TermRef | null;
  ts: string | null;
  state: 'ok' | 'distrusted' | 'missing';
  added_at: string;
  decision_id: string;
}

export interface FindingDetail extends FindingSummary {
  description: string;
  remediation: string;
  attack: { id: string; supported: boolean; hypothesis: boolean }[];
  cves: { id: string; supported: boolean; hypothesis: boolean }[];
  evidence: FindingEvidence[];
  created_from: EvidenceRef | null;
  history: { decision_id: string; kind: string; ts: string }[];
}

export interface FindingsResponse {
  findings: FindingSummary[];
}

/** Eingaben für d.finding.* (events.py DFinding*). */
export interface FindingRefIn {
  id: string;
  supported?: boolean;
}
export interface EvidenceRefIn {
  claim_key?: string;
  unit_id?: string;
  lines?: [number, number];
}

// ------------------------------------------------------------------ Scope erweitern (E129, E130), Entwurf ui
/**
 * Entwurf der UI für die Routen aus E129 (Agent «backend» baut sie gleichzeitig; massgeblich ist
 * docs/web-api.md, sobald dort beschrieben). Die UI urteilt nie selbst über den Scope: Vorschläge,
 * öffentliche Endungen und Urteile kommen vom Server (ScopeMatcher), Einträge sind Text.
 */
export type ScopeEntryKind = 'name' | 'wildcard' | 'ip' | 'cidr' | 'range' | 'url' | 'other';
export interface ScopeOption {
  /** genauer Eintrag, so wie er in den Scope kommt (z. B. «recovery.vantis.internal», «*.vantis.internal») */
  entry: string;
  kind: ScopeEntryKind;
  /** öffentliche Endung oder öffentliche Adresse: Warnhinweis vor dem Aufnehmen */
  public: boolean;
  ctrl: boolean;
}
export interface ScopeOptions {
  value: string;
  ctrl: boolean;
  verdict: Verdict;
  options: ScopeOption[];
}
export interface ScopeWindow {
  days: string | string[] | null;
  from: string | null;
  to: string | null;
  tz: string | null;
}
export interface ScopeView {
  include: string[];
  exclude: string[];
  windows: ScopeWindow[];
  version: number;
  /** false im Profil customer: ändern nur im Terminal (`ariadne scope`) */
  editable: boolean;
}
export type ScopeOp = 'add' | 'remove' | 'exclude';
export interface ScopeChange {
  op: ScopeOp;
  entry: string;
  /** Anlass: Scope-Warnung (cmd_id), Klärung (item_key) oder Out-of-Scope-Rand (identifier) */
  source?: { cmd_id?: string; item_key?: string; identifier?: string } | null;
}
export interface ScopeChangeResult {
  /** Entscheid (rückgängig per d.revoke) */
  decision_id: string | null;
  version: number;
}

// ------------------------------------------------------------------ Ereignisstrom (14, 18.9)
export interface StreamPayloads {
  changes: { project_id: string; generation: number; entities?: Partial<Record<ChangeEntity, number>> };
  terminal: { terminal_id: string; change: 'opened' | 'closed' | 'state' | 'context' | 'command' };
  inbox: { project_id: string; open: number };
  suggestion: { project_id: string; open: number };
  project: {
    project_id: string | null;
    change: 'opened' | 'closed' | 'locked' | 'unlocked';
    locked: boolean;
    /** Entwurf ui: Grund beim Schliessen (`stop`, `idle`, `switch` …) und Kurzname, falls der Server sie nennt */
    reason?: SessionEndReason | null;
    slug?: string | null;
  };
  reset: { reason: 'reparse' | 'buffer' | 'restart' };
  presentation: { on: boolean };
  progress: {
    job_id: string;
    kind: string;
    status: string;
    pct: number | null;
    message: string | null;
    tokens_in?: number | null;
    tokens_out?: number | null;
    tokens_estimate?: number | null;
    masked?: number;
    cost_usd?: number | null;
    budget_level?: AiBudgetLevel;
  };
  screenshot: { project_id: string; id: string; trigger: ShotTrigger };
  prefs: Record<string, never>;
  /**
   * Entwurf ui (Praxistest 1): Die Sitzung endet gleich (vor dem Schliessen des Stroms), mit Grund.
   * `slug` ist der Kurzname des Projekts (fester Bezeichner, kein Zieldatum).
   */
  session: { change: 'ending'; reason: SessionEndReason; slug: string | null };
}
export type SessionEndReason = 'stop' | 'idle' | 'lock' | 'switch' | 'restart' | 'shutdown' | 'revoked' | 'expired';
export type StreamEventName = keyof StreamPayloads;
export type StreamEvent = { [K in StreamEventName]: { name: K; id: string | null; data: StreamPayloads[K] } }[StreamEventName];

// ------------------------------------------------------------------ KI (v0.1-KI, Entwurf api-ki)
export type AiProvider = 'off' | 'cloud' | 'local';
export type AiBudgetLevel = 'ok' | 'warn' | 'over';
export type AiReason = 'off' | 'config' | 'no_model' | 'no_key' | 'locked' | 'cloud_not_allowed' | 'profile' | 'public_scope' | 'busy';
export interface AiJob {
  job_id: string;
  status: 'queued' | 'running' | 'done' | 'refused' | 'failed';
  step: 'lagebild' | 'anfrage' | 'pruefung' | 'fertig';
  /** fester deutscher Text, nie Modell- oder Zieltext */
  message: string;
  started_at: string;
  ended_at: string | null;
  provider: 'cloud' | 'local';
  model: string;
  tokens_in: number | null;
  tokens_out: number | null;
  tokens_estimate: number | null;
  masked: number;
  cost_usd: number | null;
  budget_level: AiBudgetLevel;
  created: number;
  dropped: number;
  injection_suspect: number;
  /** Ablehnung des Modells, wörtlich (Modelltext, nur als Text) */
  refusal: { category: string | null; text: string } | null;
  error: null | 'unreachable' | 'auth' | 'schema' | 'truncated' | 'project_changed' | 'internal'
    | 'model' | 'overloaded' | 'tls';
}
export interface AiStatus {
  provider: AiProvider;
  model: string | null;
  ready: boolean;
  reason: AiReason | null;
  reason_text: string | null;
  budget: { month: string; limit_usd: number; used_usd: number; pct: number; level: AiBudgetLevel };
  job: AiJob | null;
}

// ------------------------------------------------------------------ Export (v0.1-Export, api-export)
export type ExportTemplate = 'cys' | 'htb';
export type ExportWarning = 'sync_folder' | 'generic_secret' | 'klartext';
export interface ExportEntry {
  export_id: string;
  template: ExportTemplate;
  created_at: string;
  path: string;
  files: number;
  klartext: boolean;
  warnings: ExportWarning[];
  chain: { seq: number; hash: string };
}
export interface ExportRunning {
  job_id: string;
  template: ExportTemplate;
  status: string;
  pct: number | null;
}
export interface ExportsView {
  exports: ExportEntry[];
  running: ExportRunning | null;
  last_error: { job_id: string; message: string } | null;
}
export interface ExportStarted {
  job_id: string;
  status: string;
  template: ExportTemplate;
}
export interface PhaseCommand {
  cmd_id: string;
  cmd_ref: string;
  command: string;
  ts: string;
  phase: string | null;
  source: 'rule' | 'decision' | 'none';
  decision_id: string | null;
  ctrl: boolean;
}
export interface PhasesView {
  template: ExportTemplate;
  phases: { key: string; label: string }[];
  commands: PhaseCommand[];
}
export interface PhaseSet {
  decision_id: string;
  cmd_id: string;
  template: ExportTemplate;
  phase: string;
}

// ------------------------------------------------------------------ Screenshots (api-screenshots)
export type ShotMode = 'window' | 'monitor' | 'region';
export type ShotTrigger = 'hotkey' | 'cli' | 'webui';
export interface Screenshot {
  id: string;
  seq: number;
  ts: string;
  blob_id: string;
  url: string;
  mime: string;
  mode: ShotMode;
  trigger: ShotTrigger;
  width: number;
  height: number;
  sha256: string;
  dhash: string;
  /** Zieldaten möglich (Fenstertitel), nur als Text; im Präsentationsmodus null */
  window_title: string | null;
  wm_class: string | null;
  terminal_id: string | null;
  stream_off: number | null;
  host: string | null;
  note: string | null;
}
export interface ScreenshotsView {
  items: Screenshot[];
  presentation: boolean;
}
export interface ShotRequest {
  mode?: ShotMode;
  region?: { x: number; y: number; width: number; height: number };
  delay_s?: number;
  terminal_id?: string;
  note?: string;
}
