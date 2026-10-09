/**
 * Backend-Schnittstelle der UI. Zwei Implementierungen:
 * - HttpBackend: echter Daemon über /api/v1 (dieses Modul)
 * - MockBackend: Beispieldaten und simulierte Ereignisse (src/lib/mock/backend.ts)
 *
 * Stores und Komponenten kennen nur dieses Interface.
 */
import { ApiClient, apiPath } from './client';
import type { TokenStore } from './auth';
import { SseClient, type ConnectionState } from './sse';
import type {
  Accepted, ChangeSet, ContextOp, ContextResult, CredentialView, DecisionInput, DecisionResponse,
  DenkanstossRequest, FactSources, Finding, GraphQuery, GraphView, HostDetail, HostSummary, InboxView,
  Job, Lens, LinesPage, LinesQuery, Positions, QueryDsl, QueryResult, ServiceView, Status, StreamEvent,
  Suggestion, Terminal, TimelinePage, TimelineQuery,
} from './types';

export interface StreamHandlers {
  onEvent: (ev: StreamEvent) => void;
  onState?: (state: ConnectionState) => void;
}

export interface Backend {
  readonly kind: 'http' | 'mock';
  /** true, wenn noch kein Token vorliegt */
  needsLogin(): boolean;
  login(code: string): Promise<void>;
  logout(): Promise<void>;
  onUnauthorized(cb: () => void): void;

  status(signal?: AbortSignal): Promise<Status>;
  setRec(on: boolean): Promise<void>;
  setPresentation(on: boolean): Promise<void>;
  terminals(signal?: AbortSignal): Promise<Terminal[]>;
  setContext(tid: string, op: ContextOp): Promise<ContextResult>;

  graph(pid: string, q: GraphQuery, signal?: AbortSignal): Promise<GraphView>;
  changes(pid: string, since: number, signal?: AbortSignal): Promise<ChangeSet>;
  hosts(pid: string, signal?: AbortSignal): Promise<HostSummary[]>;
  host(pid: string, hostId: string, signal?: AbortSignal): Promise<HostDetail>;
  services(pid: string, signal?: AbortSignal): Promise<ServiceView[]>;
  credentials(pid: string, signal?: AbortSignal): Promise<CredentialView[]>;
  inbox(pid: string, signal?: AbortSignal): Promise<InboxView>;
  suggestions(pid: string, signal?: AbortSignal): Promise<Suggestion[]>;
  findings(pid: string, signal?: AbortSignal): Promise<Finding[]>;
  timeline(pid: string, q: TimelineQuery, signal?: AbortSignal): Promise<TimelinePage>;
  factSources(pid: string, factId: string, signal?: AbortSignal): Promise<FactSources>;
  streamLines(pid: string, tid: string, q: LinesQuery, signal?: AbortSignal): Promise<LinesPage>;
  blob(pid: string, blobId: string, signal?: AbortSignal): Promise<Blob>;
  decide(pid: string, decisions: DecisionInput[]): Promise<DecisionResponse>;
  query(pid: string, dsl: QueryDsl, signal?: AbortSignal): Promise<QueryResult>;
  denkanstoss(pid: string, req: DenkanstossRequest): Promise<Job>;
  positions(pid: string, lens: Lens, signal?: AbortSignal): Promise<Positions>;
  savePositions(pid: string, lens: Lens, positions: Positions['positions']): Promise<void>;

  /** SSE für ein Projekt; gibt eine Abmeldefunktion zurück. */
  subscribe(pid: string, handlers: StreamHandlers): () => void;
}

export class HttpBackend implements Backend {
  readonly kind = 'http' as const;
  private readonly api: ApiClient;
  private readonly tokens: TokenStore;
  private unauthorized: (() => void)[] = [];

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
  async login(code: string): Promise<void> {
    await this.api.login(code);
  }
  logout(): Promise<void> {
    return this.api.logout();
  }
  onUnauthorized(cb: () => void): void {
    this.unauthorized.push(cb);
  }

  status(signal?: AbortSignal) {
    return this.api.get<Status>('/status', { signal });
  }
  async setRec(on: boolean) {
    await this.api.put<Accepted>('/rec', { on });
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

  graph(pid: string, q: GraphQuery, signal?: AbortSignal) {
    return this.api.get<GraphView>(apiPath('p', pid, 'graph'), { query: { layer: q.layers, lens: q.lens }, signal });
  }
  changes(pid: string, since: number, signal?: AbortSignal) {
    return this.api.get<ChangeSet>(apiPath('p', pid, 'changes'), { query: { since }, signal });
  }
  async hosts(pid: string, signal?: AbortSignal) {
    return (await this.api.get<{ hosts: HostSummary[] }>(apiPath('p', pid, 'hosts'), { signal })).hosts;
  }
  host(pid: string, hostId: string, signal?: AbortSignal) {
    return this.api.get<HostDetail>(apiPath('p', pid, 'hosts', hostId), { signal });
  }
  async services(pid: string, signal?: AbortSignal) {
    return (await this.api.get<{ services: ServiceView[] }>(apiPath('p', pid, 'services'), { signal })).services;
  }
  async credentials(pid: string, signal?: AbortSignal) {
    return (await this.api.get<{ credentials: CredentialView[] }>(apiPath('p', pid, 'credentials'), { signal })).credentials;
  }
  inbox(pid: string, signal?: AbortSignal) {
    return this.api.get<InboxView>(apiPath('p', pid, 'inbox'), { signal });
  }
  async suggestions(pid: string, signal?: AbortSignal) {
    return (await this.api.get<{ suggestions: Suggestion[] }>(apiPath('p', pid, 'suggestions'), { signal })).suggestions;
  }
  async findings(pid: string, signal?: AbortSignal) {
    return (await this.api.get<{ findings: Finding[] }>(apiPath('p', pid, 'findings'), { signal })).findings;
  }
  timeline(pid: string, q: TimelineQuery, signal?: AbortSignal) {
    return this.api.get<TimelinePage>(apiPath('p', pid, 'timeline'), {
      query: { types: q.types, terminal: q.terminal, host: q.host, cursor: q.cursor, limit: q.limit },
      signal,
    });
  }
  factSources(pid: string, factId: string, signal?: AbortSignal) {
    return this.api.get<FactSources>(apiPath('p', pid, 'facts', factId, 'sources'), { signal });
  }
  streamLines(pid: string, tid: string, q: LinesQuery, signal?: AbortSignal) {
    return this.api.get<LinesPage>(apiPath('p', pid, 'streams', tid, 'lines'), {
      query: { unit: q.unit, from: q.from, count: q.count, reveal_hidden: q.reveal_hidden },
      signal,
    });
  }
  blob(pid: string, blobId: string, signal?: AbortSignal) {
    return this.api.get<Blob>(apiPath('p', pid, 'blobs', blobId), { expect: 'blob', signal });
  }
  decide(pid: string, decisions: DecisionInput[]) {
    return this.api.post<DecisionResponse>(apiPath('p', pid, 'decisions'), { decisions });
  }
  query(pid: string, dsl: QueryDsl, signal?: AbortSignal) {
    return this.api.post<QueryResult>(apiPath('p', pid, 'query'), { dsl }, { signal });
  }
  denkanstoss(pid: string, req: DenkanstossRequest) {
    return this.api.post<Job>(apiPath('p', pid, 'ai', 'denkanstoss'), req);
  }
  positions(pid: string, lens: Lens, signal?: AbortSignal) {
    return this.api.get<Positions>(apiPath('p', pid, 'ui', 'positions', lens), { signal });
  }
  async savePositions(pid: string, lens: Lens, positions: Positions['positions']) {
    await this.api.put<Accepted>(apiPath('p', pid, 'ui', 'positions', lens), { positions });
  }

  subscribe(pid: string, handlers: StreamHandlers): () => void {
    const client = new SseClient({
      url: `${this.api.baseUrl}${apiPath('p', pid, 'events')}`,
      tokens: this.tokens,
      onEvent: handlers.onEvent,
      onState: (s) => handlers.onState?.(s),
      onUnauthorized: () => this.unauthorized.forEach((cb) => cb()),
    });
    void client.start();
    return () => client.stop();
  }
}
