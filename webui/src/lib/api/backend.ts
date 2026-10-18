/**
 * Backend-Schnittstelle der UI (Vertrag v0.1-Oberfläche, Abschnitt 3). Zwei Umsetzungen:
 * - HttpBackend: echter Daemon über /api/v1 (dieses Modul)
 * - MockBackend: Beispieldaten MS2 (Anhang A) und simulierte Ereignisse (src/lib/mock/backend.ts)
 *
 * Stores und Komponenten kennen nur dieses Interface. Besitzer: ui-fundament.
 * Jede Methode entspricht genau einer Route aus docs/web-api.md (Abschnitt in Klammern).
 */
import type { TokenStore } from './auth';
import { ApiClient, apiPath } from './client';
import { SseClient, type ConnectionState } from './sse';
import { clientRef } from '../stores/ctx';
import type {
  Accepted,
  AiJob,
  AiStatus,
  ExportsView,
  ExportStarted,
  ExportTemplate,
  PhaseSet,
  PhasesView,
  Screenshot,
  ScreenshotsView,
  ShotRequest,
  ChangeSet,
  ConfirmGroupResult,
  ContextOp,
  ContextResult,
  CopyResult,
  DecisionInput,
  DecisionResponse,
  FactSources,
  FindingDetail,
  FindingsResponse,
  FindingSummary,
  GraphLayer,
  GraphView,
  HostDetail,
  HostSummary,
  InputView,
  LinesPage,
  LinesQuery,
  NextView,
  PendingResponse,
  PositionsView,
  Prefs,
  PrefsView,
  ProjectView,
  RevealResponse,
  SearchResult,
  SecretRef,
  SeenView,
  ServiceClass,
  ServiceView,
  ScopeChange,
  ScopeChangeResult,
  ScopeOptions,
  ScopeView,
  SessionResponse,
  SessionView,
  Status,
  StreamEvent,
  SuggestionsResponse,
  SuggestionState,
  Terminal,
  TimelinePage,
  TimelineQuery,
  UnitView,
} from './types';

export interface StreamHandlers {
  onEvent: (ev: StreamEvent) => void;
  /** `cause` bei 'retrying': 'network' (keine Verbindung) oder 'ended' (Strom vom Server beendet) */
  onState?: (state: ConnectionState, cause?: 'network' | 'ended' | null) => void;
}

export interface Backend {
  readonly kind: 'http' | 'mock';

  // Anmeldung (3)
  needsLogin(): boolean;
  login(code: string): Promise<SessionResponse>;
  logout(): Promise<void>;
  /** Wird bei 401 gerufen (Token schon verworfen); gibt eine Abmeldefunktion zurück. */
  onUnauthorized(cb: () => void): () => void;
  session(signal?: AbortSignal): Promise<SessionView>;

  // Global (4, 5, 18.2)
  status(signal?: AbortSignal): Promise<Status>;
  pause(tid: string, minutes?: number): Promise<void>;
  resume(tid: string): Promise<void>;
  setPresentation(on: boolean): Promise<void>;
  terminals(signal?: AbortSignal): Promise<Terminal[]>;
  setContext(tid: string, op: ContextOp): Promise<ContextResult>;
  prefs(signal?: AbortSignal): Promise<PrefsView>;
  savePrefs(prefs: Partial<Prefs>): Promise<PrefsView>;

  // Projekt (6, 7, 18.3, 18.4)
  project(pid: string, signal?: AbortSignal): Promise<ProjectView>;
  graph(pid: string, layers?: GraphLayer[], signal?: AbortSignal): Promise<GraphView>;
  changes(pid: string, since: number, signal?: AbortSignal): Promise<ChangeSet>;
  positions(pid: string, signal?: AbortSignal): Promise<PositionsView>;
  savePositions(pid: string, positions: PositionsView['positions']): Promise<void>;
  seen(pid: string, signal?: AbortSignal): Promise<SeenView>;
  /** PUT /ui/seen mit keepalive (beim Unsichtbarwerden des Tabs) */
  markSeen(pid: string): Promise<void>;
  ackScopeWarning(pid: string, cmdId: string): Promise<void>;
  /** Scope erweitern (E129, E130; Entwurf ui, Routen von «backend») */
  scope(pid: string, signal?: AbortSignal): Promise<ScopeView>;
  /** GET /scope/options (web-api.md 20.4): Vorschläge zu einem Ziel ohne mitgelieferte `proposals` */
  scopeOptions(pid: string, value: string, signal?: AbortSignal): Promise<ScopeOptions>;
  /** POST /scope/changes mit `entries: [entry]` (web-api.md 20) */
  changeScope(pid: string, change: ScopeChange): Promise<ScopeChangeResult>;
  /** Rückgängig: POST /scope/changes mit `op: 'revert'` */
  revertScope(pid: string, decisionId: string): Promise<ScopeChangeResult>;
  /** Vorschau im Dialog: dieselbe Anfrage mit `dry_run: true` (nichts wird geschrieben) */
  previewScope(pid: string, change: ScopeChange): Promise<ScopeChangeResult>;

  // Hosts und Services (8)
  hosts(pid: string, signal?: AbortSignal): Promise<HostSummary[]>;
  host(pid: string, hostId: string, signal?: AbortSignal): Promise<HostDetail>;
  services(pid: string, q?: { host?: string; class?: ServiceClass }, signal?: AbortSignal): Promise<ServiceView[]>;

  // Als Nächstes, Denkanstösse (9, 18.6)
  next(pid: string, signal?: AbortSignal): Promise<NextView>;
  suggestions(pid: string, state?: SuggestionState | 'all', signal?: AbortSignal): Promise<SuggestionsResponse>;

  // Zeitachse, Eingaben (10)
  timeline(pid: string, q: TimelineQuery, signal?: AbortSignal): Promise<TimelinePage>;
  inputs(pid: string, q: { terminal?: string; limit?: number }, signal?: AbortSignal): Promise<InputView[]>;

  // Belege (11)
  factSources(pid: string, claimKey: string, signal?: AbortSignal): Promise<FactSources>;
  unit(pid: string, unitId: string, signal?: AbortSignal): Promise<UnitView>;
  lines(pid: string, unitId: string, q: LinesQuery, signal?: AbortSignal): Promise<LinesPage>;
  /** «Ganzes Log» als Datei (Bearer nötig, darum als Blob, nie als Link) */
  logText(pid: string, unitId: string): Promise<Blob>;

  // Entscheide (12)
  decide(pid: string, decisions: DecisionInput[]): Promise<DecisionResponse>;
  confirmGroup(pid: string, groupRef: string): Promise<ConfirmGroupResult>;

  // Suche, Warteliste, Secrets (13, 18.7)
  search(pid: string, q: string, limit?: number, signal?: AbortSignal): Promise<SearchResult>;
  pending(pid: string, signal?: AbortSignal): Promise<PendingResponse>;
  reveal(pid: string, ref: SecretRef): Promise<RevealResponse>;
  copyToKali(pid: string, ref: SecretRef): Promise<CopyResult>;

  // Findings (18.5)
  findings(pid: string, signal?: AbortSignal): Promise<FindingSummary[]>;
  finding(pid: string, findingId: string, signal?: AbortSignal): Promise<FindingDetail>;

  /** Globaler Ereignisstrom (14); gibt eine Abmeldefunktion zurück. */
  // KI (Entwurf api-ki, v0.1-KI)
  aiStatus(pid: string, signal?: AbortSignal): Promise<AiStatus>;
  aiRequest(pid: string, confirmBudget: boolean): Promise<AiJob>;
  aiJob(pid: string, jobId: string, signal?: AbortSignal): Promise<AiJob>;

  // Export (Entwurf api-export, v0.1-Export)
  exports(pid: string, signal?: AbortSignal): Promise<ExportsView>;
  startExport(pid: string, template: ExportTemplate): Promise<ExportStarted>;
  exportPhases(pid: string, template: ExportTemplate, signal?: AbortSignal): Promise<PhasesView>;
  setExportPhase(pid: string, template: ExportTemplate, cmdId: string, phase: string): Promise<PhaseSet>;

  // Screenshots und Blobs (Entwurf api-screenshots)
  screenshots(pid: string, signal?: AbortSignal): Promise<ScreenshotsView>;
  takeScreenshot(pid: string, req: ShotRequest): Promise<Screenshot>;
  blob(pid: string, blobId: string, signal?: AbortSignal): Promise<Blob>;

  subscribe(handlers: StreamHandlers): () => void;
}

export class HttpBackend implements Backend {
  readonly kind = 'http' as const;
  private readonly api: ApiClient;
  private readonly tokens: TokenStore;
  private unauthorized = new Set<() => void>();

  constructor(tokens: TokenStore, fetchImpl?: typeof fetch) {
    this.tokens = tokens;
    this.api = new ApiClient({
      tokens,
      fetch: fetchImpl,
      onUnauthorized: () => this.unauthorized.forEach((cb) => cb()),
    });
  }

  needsLogin(): boolean {
    return !this.api.hasToken();
  }
  login(code: string): Promise<SessionResponse> {
    return this.api.login(code);
  }
  logout(): Promise<void> {
    return this.api.logout();
  }
  onUnauthorized(cb: () => void): () => void {
    this.unauthorized.add(cb);
    return () => this.unauthorized.delete(cb);
  }
  session(signal?: AbortSignal) {
    return this.api.get<SessionView>('/session', { signal });
  }

  status(signal?: AbortSignal) {
    return this.api.get<Status>('/status', { signal });
  }
  async pause(tid: string, minutes?: number) {
    await this.api.post<Accepted>(apiPath('terminals', tid, 'pause'), minutes === undefined ? {} : { minutes });
  }
  async resume(tid: string) {
    await this.api.post<Accepted>(apiPath('terminals', tid, 'resume'));
  }
  async setPresentation(on: boolean) {
    await this.api.put<Accepted>('/presentation', { on });
  }
  async terminals(signal?: AbortSignal) {
    return (await this.api.get<{ terminals: Terminal[] }>('/terminals', { signal })).terminals;
  }
  setContext(tid: string, op: ContextOp) {
    return this.api.post<ContextResult>(apiPath('terminals', tid, 'context'), op);
  }
  prefs(signal?: AbortSignal) {
    return this.api.get<PrefsView>('/ui/prefs', { signal });
  }
  savePrefs(prefs: Partial<Prefs>) {
    return this.api.put<PrefsView>('/ui/prefs', prefs);
  }

  project(pid: string, signal?: AbortSignal) {
    return this.api.get<ProjectView>(apiPath('p', pid, 'project'), { signal });
  }
  graph(pid: string, layers?: GraphLayer[], signal?: AbortSignal) {
    return this.api.get<GraphView>(apiPath('p', pid, 'graph'), { query: { layers }, signal });
  }
  changes(pid: string, since: number, signal?: AbortSignal) {
    return this.api.get<ChangeSet>(apiPath('p', pid, 'changes'), { query: { since }, signal });
  }
  positions(pid: string, signal?: AbortSignal) {
    return this.api.get<PositionsView>(apiPath('p', pid, 'ui', 'positions'), { signal });
  }
  async savePositions(pid: string, positions: PositionsView['positions']) {
    await this.api.put<Accepted>(apiPath('p', pid, 'ui', 'positions'), { positions });
  }
  seen(pid: string, signal?: AbortSignal) {
    return this.api.get<SeenView>(apiPath('p', pid, 'ui', 'seen'), { signal });
  }
  async markSeen(pid: string) {
    await this.api.put<{ seen_at: string }>(apiPath('p', pid, 'ui', 'seen'), {}, { keepalive: true });
  }
  async ackScopeWarning(pid: string, cmdId: string) {
    await this.api.put<Accepted>(apiPath('p', pid, 'ui', 'scope-ack'), { cmd_id: cmdId });
  }
  scope(pid: string, signal?: AbortSignal) {
    return this.api.get<ScopeView>(apiPath('p', pid, 'scope'), { signal });
  }
  scopeOptions(pid: string, value: string, signal?: AbortSignal) {
    return this.api.get<ScopeOptions>(apiPath('p', pid, 'scope', 'options'), { query: { value }, signal });
  }
  changeScope(pid: string, change: ScopeChange) {
    return this.api.post<ScopeChangeResult>(apiPath('p', pid, 'scope', 'changes'), { op: change.op, entries: [change.entry], client_ref: clientRef() });
  }
  previewScope(pid: string, change: ScopeChange) {
    return this.api.post<ScopeChangeResult>(apiPath('p', pid, 'scope', 'changes'), { op: change.op, entries: [change.entry], dry_run: true });
  }
  revertScope(pid: string, decisionId: string) {
    return this.api.post<ScopeChangeResult>(apiPath('p', pid, 'scope', 'changes'), { op: 'revert', decision_id: decisionId, client_ref: clientRef() });
  }

  async hosts(pid: string, signal?: AbortSignal) {
    return (await this.api.get<{ hosts: HostSummary[] }>(apiPath('p', pid, 'hosts'), { signal })).hosts;
  }
  host(pid: string, hostId: string, signal?: AbortSignal) {
    return this.api.get<HostDetail>(apiPath('p', pid, 'hosts', hostId), { signal });
  }
  async services(pid: string, q: { host?: string; class?: ServiceClass } = {}, signal?: AbortSignal) {
    return (await this.api.get<{ services: ServiceView[] }>(apiPath('p', pid, 'services'), { query: q, signal })).services;
  }

  next(pid: string, signal?: AbortSignal) {
    return this.api.get<NextView>(apiPath('p', pid, 'next'), { signal });
  }
  suggestions(pid: string, state: SuggestionState | 'all' = 'open', signal?: AbortSignal) {
    return this.api.get<SuggestionsResponse>(apiPath('p', pid, 'suggestions'), { query: { state }, signal });
  }

  timeline(pid: string, q: TimelineQuery, signal?: AbortSignal) {
    return this.api.get<TimelinePage>(apiPath('p', pid, 'timeline'), {
      query: { types: q.types, terminal: q.terminal, host: q.host, cursor: q.cursor, limit: q.limit },
      signal,
    });
  }
  async inputs(pid: string, q: { terminal?: string; limit?: number }, signal?: AbortSignal) {
    return (await this.api.get<{ items: InputView[] }>(apiPath('p', pid, 'inputs'), { query: q, signal })).items;
  }

  factSources(pid: string, claimKey: string, signal?: AbortSignal) {
    return this.api.get<FactSources>(apiPath('p', pid, 'facts', claimKey, 'sources'), { signal });
  }
  unit(pid: string, unitId: string, signal?: AbortSignal) {
    return this.api.get<UnitView>(apiPath('p', pid, 'units', unitId), { signal });
  }
  lines(pid: string, unitId: string, q: LinesQuery, signal?: AbortSignal) {
    return this.api.get<LinesPage>(apiPath('p', pid, 'units', unitId, 'lines'), {
      query: { from: q.from, count: q.count, reveal_hidden: q.reveal_hidden },
      signal,
    });
  }
  logText(pid: string, unitId: string) {
    return this.api.get<Blob>(apiPath('p', pid, 'units', unitId, 'log.txt'), { expect: 'blob' });
  }

  decide(pid: string, decisions: DecisionInput[]) {
    return this.api.post<DecisionResponse>(apiPath('p', pid, 'decisions'), { decisions });
  }
  confirmGroup(pid: string, groupRef: string) {
    return this.api.post<ConfirmGroupResult>(apiPath('p', pid, 'decisions', 'confirm-group'), { group_ref: groupRef });
  }

  search(pid: string, q: string, limit = 50, signal?: AbortSignal) {
    return this.api.get<SearchResult>(apiPath('p', pid, 'search'), { query: { q, limit }, signal });
  }
  pending(pid: string, signal?: AbortSignal) {
    return this.api.get<PendingResponse>(apiPath('p', pid, 'files', 'pending'), { signal });
  }
  reveal(pid: string, ref: SecretRef) {
    return this.api.post<RevealResponse>(apiPath('p', pid, 'secrets', 'reveal'), ref);
  }
  copyToKali(pid: string, ref: SecretRef) {
    return this.api.post<CopyResult>(apiPath('p', pid, 'secrets', 'copy'), ref);
  }

  async findings(pid: string, signal?: AbortSignal) {
    return (await this.api.get<FindingsResponse>(apiPath('p', pid, 'findings'), { signal })).findings;
  }
  finding(pid: string, findingId: string, signal?: AbortSignal) {
    return this.api.get<FindingDetail>(apiPath('p', pid, 'findings', findingId), { signal });
  }

  aiStatus(pid: string, signal?: AbortSignal) {
    return this.api.get<AiStatus>(apiPath('p', pid, 'ai', 'status'), { signal });
  }
  async aiRequest(pid: string, confirmBudget: boolean) {
    return (await this.api.post<{ job: AiJob }>(apiPath('p', pid, 'ai', 'denkanstoss'), { confirm_budget: confirmBudget })).job;
  }
  async aiJob(pid: string, jobId: string, signal?: AbortSignal) {
    return (await this.api.get<{ job: AiJob }>(apiPath('p', pid, 'ai', 'jobs', jobId), { signal })).job;
  }

  exports(pid: string, signal?: AbortSignal) {
    return this.api.get<ExportsView>(apiPath('p', pid, 'exports'), { signal });
  }
  startExport(pid: string, template: ExportTemplate) {
    return this.api.post<ExportStarted>(apiPath('p', pid, 'exports'), { template });
  }
  exportPhases(pid: string, template: ExportTemplate, signal?: AbortSignal) {
    return this.api.get<PhasesView>(apiPath('p', pid, 'exports', 'phases'), { query: { template }, signal });
  }
  setExportPhase(pid: string, template: ExportTemplate, cmdId: string, phase: string) {
    return this.api.post<PhaseSet>(apiPath('p', pid, 'exports', 'phases'), { template, cmd_id: cmdId, phase });
  }

  screenshots(pid: string, signal?: AbortSignal) {
    return this.api.get<ScreenshotsView>(apiPath('p', pid, 'screenshots'), { query: { limit: 200 }, signal });
  }
  async takeScreenshot(pid: string, req: ShotRequest) {
    // Der Server wartet den Countdown ab und antwortet erst nach der Aufnahme (delay_s + etwa 1 s).
    const timeoutMs = ((req.delay_s ?? 3) + 20) * 1000;
    return (await this.api.post<{ screenshot: Screenshot }>(apiPath('p', pid, 'screenshots'), req, { timeoutMs })).screenshot;
  }
  blob(pid: string, blobId: string, signal?: AbortSignal) {
    return this.api.get<Blob>(apiPath('p', pid, 'blobs', blobId), { expect: 'blob', signal });
  }

  subscribe(handlers: StreamHandlers): () => void {
    const client = new SseClient({
      url: `${this.api.baseUrl}/events`,
      tokens: this.tokens,
      onEvent: handlers.onEvent,
      onState: (s, info) => handlers.onState?.(s, info.cause ?? null),
      onUnauthorized: () => this.unauthorized.forEach((cb) => cb()),
    });
    void client.start();
    return () => client.stop();
  }
}
