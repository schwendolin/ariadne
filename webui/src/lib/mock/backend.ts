/**
 * MockBackend: dieselbe Schnittstelle wie HttpBackend, Daten aus mock/data (Standbild 16:54,
 * Anhang A). Besitzer: ui-fundament (Datenteile: ui-karte, ui-verlauf).
 *
 * - Nur im Mock-Build oder im Dev-Server ohne Daemon (select.ts); im Produktions-Build entfernt.
 * - Fehler wie der Daemon: ApiError mit Code (403 policy im Präsentationsmodus, 409 conflict,
 *   404, 501 für Export und Screenshot, 503 clipboard_tool im Szenario `noclip`).
 * - Ereignisse wie der Daemon: `changes` nach jedem Entscheid, `terminal` nach Pause (mit
 *   600 ms Verzögerung, damit «wartet auf Bestätigung» sichtbar ist), `presentation`, `prefs`.
 * - Kein Browser-Speicher: Token, Positionen und Vorlieben nur im Speicher.
 */
import type { Backend, StreamHandlers } from '../api/backend';
import { ApiError } from '../api/client';
import type {
  ChangeSet,
  ContextOp,
  ContextResult,
  CopyResult,
  DecisionInput,
  DecisionResponse,
  FactSources,
  FindingDetail,
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
} from '../api/types';
import * as base from './data/base';
import * as history from './data/history';
import { applyHistoryDecision } from './handlers/history';
import { applyMapDecision } from './handlers/map';
import { createState, newDecisionId, scenarioFromLocation, type MockState, type Scenario } from './state';

const BAD_CODES = new Set(['FALSCH0000', 'FALSCH00']);
const LOCK_CODES = new Set(['SPERRE0000', 'SPERRE00']);

function clone<T>(v: T): T {
  return structuredClone(v);
}

function err(code: ConstructorParameters<typeof ApiError>[0], status: number): ApiError {
  return new ApiError(code, status, code);
}

export class MockBackend implements Backend {
  readonly kind = 'mock' as const;
  readonly state: MockState;
  private token: string | null;
  private listeners = new Set<StreamHandlers>();
  private unauthorized = new Set<() => void>();
  private eventId = 1000;
  /** Verzögerung für Antworten (ms); Tests setzen 0 */
  delay = 60;

  constructor(scenario: Scenario = scenarioFromLocation()) {
    this.state = createState(scenario);
    this.state.emit = (ev) => this.emit(ev);
    this.token = scenario === 'login' ? null : 'mock-token';
  }

  private async wait<T>(fn: () => T): Promise<T> {
    if (this.delay > 0) await new Promise((r) => setTimeout(r, this.delay));
    if (!this.token) {
      // wie HttpBackend: Token verworfen, Sitzung beendet melden (Anmeldung ohne Grund)
      for (const cb of this.unauthorized) cb();
      throw err('unauthorized', 401);
    }
    return fn();
  }

  private emit(ev: StreamEvent): void {
    const withId = { ...ev, id: String(++this.eventId) } as StreamEvent;
    for (const l of this.listeners) l.onEvent(withId);
  }

  private get hasProject(): boolean {
    return !['noproject', 'locked'].includes(this.state.scenario);
  }

  private check(pid: string): void {
    if (!this.hasProject) throw err(this.state.scenario === 'locked' ? 'locked' : 'no_project', this.state.scenario === 'locked' ? 423 : 409);
    if (pid !== base.PID) throw err('project_mismatch', 409);
  }

  // ------------------------------------------------------------------ Anmeldung
  needsLogin(): boolean {
    return this.token === null;
  }
  async login(code: string): Promise<SessionResponse> {
    if (this.delay > 0) await new Promise((r) => setTimeout(r, this.delay));
    if (LOCK_CODES.has(code.toUpperCase())) throw err('rate_limited', 429);
    if (BAD_CODES.has(code.toUpperCase())) throw err('unauthorized', 401);
    this.token = 'mock-token';
    return { token: this.token, expires_at: base.session().expires_at, session: base.session(this.state.origin) };
  }
  async logout(): Promise<void> {
    this.token = null;
  }
  onUnauthorized(cb: () => void): () => void {
    this.unauthorized.add(cb);
    return () => this.unauthorized.delete(cb);
  }
  session(): Promise<SessionView> {
    return this.wait(() => base.session(this.state.origin));
  }

  // ------------------------------------------------------------------ Global
  status(): Promise<Status> {
    return this.wait(() => {
      const s = this.state;
      const st = base.status(s.terminals, s.generation, s.presentation, s.origin);
      if (st.scope_warning) st.scope_warning = { ...st.scope_warning, acked: s.scopeAcked };
      if (s.scenario === 'noproject') {
        return { ...st, project: null, active: null, terminals: st.terminals.map((t) => ({ ...t, state: 'preroll' as const, pause_until: null, ordinal: null, label: null })), idle: null, generation: null, scope_warning: null, preroll: { ...st.preroll, terminals: 3, seconds: 900 } };
      }
      if (s.scenario === 'locked') {
        return { ...st, project: null, locked: true, terminals: st.terminals.map((t) => ({ ...t, state: 'locked' as const, pause_until: null })), generation: null, scope_warning: null, operator: { exists: true, unlocked: false, own_secrets: null } };
      }
      return st;
    });
  }
  async pause(tid: string, minutes = 10): Promise<void> {
    await this.wait(() => {
      const t = this.state.terminals.find((x) => x.terminal_id === tid);
      if (!t) throw err('not_found', 404);
      if (minutes > 30 || (t.web_pause_left_s ?? 0) < minutes * 60) throw err('policy', 403);
    });
    if (this.state.scenario === 'noconfirm') return;
    setTimeout(() => {
      this.state.terminals = this.state.terminals.map((x) =>
        x.terminal_id === tid
          ? { ...x, state: 'paused', pause_until: new Date(Date.now() + minutes * 60000).toISOString(), web_pause_left_s: Math.max(0, (x.web_pause_left_s ?? 0) - minutes * 60) }
          : x,
      );
      this.emit({ name: 'terminal', id: null, data: { terminal_id: tid, change: 'state' } });
    }, 600);
  }
  async resume(tid: string): Promise<void> {
    await this.wait(() => {
      if (!this.state.terminals.some((x) => x.terminal_id === tid)) throw err('not_found', 404);
    });
    if (this.state.scenario === 'noconfirm') return;
    setTimeout(() => {
      this.state.terminals = this.state.terminals.map((x) => (x.terminal_id === tid ? { ...x, state: 'on', pause_until: null } : x));
      this.emit({ name: 'terminal', id: null, data: { terminal_id: tid, change: 'state' } });
    }, 600);
  }
  async setPresentation(on: boolean): Promise<void> {
    await this.wait(() => undefined);
    this.state.presentation = on;
    this.emit({ name: 'presentation', id: null, data: { on } });
  }
  terminals(): Promise<Terminal[]> {
    return this.wait(() => clone(this.state.terminals));
  }
  setContext(tid: string, op: ContextOp): Promise<ContextResult> {
    return this.wait(() => {
      const t = this.state.terminals.find((x) => x.terminal_id === tid);
      if (!t) throw err('not_found', 404);
      if (op.op === 'pop' && t.stack.length <= 1) throw err('validation', 422);
      if (op.op === 'accept' || op.op === 'set') {
        this.state.next = { ...this.state.next, clarify: this.state.next.clarify.filter((i) => !(i.kind === 'ctx_suggestion' && i.terminal_id === tid)) };
        this.state.next = { ...this.state.next, open: this.state.next.clarify.length };
        this.emit({ name: 'inbox', id: null, data: { project_id: base.PID, open: this.state.next.open } });
        this.emit({ name: 'terminal', id: null, data: { terminal_id: tid, change: 'context' } });
      }
      const host = op.op === 'set' ? (op.host ?? null) : null;
      const warnings: ContextResult['warnings'] = host && !host.startsWith('192.168.56.') ? [{ code: 'scope_out', host }] : [];
      const decision_id = op.op === 'accept' || op.op === 'set' ? `0199a3c2-9b${String(Date.now() % 100).padStart(2, '0')}-7000-8000-0000000c0de1` : null;
      return { stored: true, stack: t.stack, warnings, decision_id };
    });
  }
  prefs(): Promise<PrefsView> {
    return this.wait(() => clone(this.state.prefs));
  }
  savePrefs(p: Partial<Prefs>): Promise<PrefsView> {
    return this.wait(() => {
      this.state.prefs = { prefs: { ...this.state.prefs.prefs, ...p }, updated_at: new Date().toISOString() };
      queueMicrotask(() => this.emit({ name: 'prefs', id: null, data: {} }));
      return clone(this.state.prefs);
    });
  }

  // ------------------------------------------------------------------ Projekt
  project(pid: string): Promise<ProjectView> {
    return this.wait(() => {
      this.check(pid);
      return base.project();
    });
  }
  graph(pid: string, _layers?: GraphLayer[]): Promise<GraphView> {
    return this.wait(() => {
      this.check(pid);
      return clone({ ...this.state.graph, generation: this.state.generation });
    });
  }
  changes(pid: string, since: number): Promise<ChangeSet> {
    return this.wait(() => {
      this.check(pid);
      const to = this.state.generation;
      return { project_id: pid, from: since, to, reset: since > to, changes: since < to ? [{ generation: to, entity: 'claim', entity_key: 'mock', change: 'updated' }] : [] };
    });
  }
  positions(pid: string): Promise<PositionsView> {
    return this.wait(() => {
      this.check(pid);
      return clone(this.state.positions);
    });
  }
  savePositions(pid: string, positions: PositionsView['positions']): Promise<void> {
    return this.wait(() => {
      this.check(pid);
      this.state.positions = { positions: clone(positions), updated_at: new Date().toISOString() };
    });
  }
  seen(pid: string): Promise<SeenView> {
    return this.wait(() => {
      this.check(pid);
      return clone(this.state.seen);
    });
  }
  markSeen(pid: string): Promise<void> {
    return this.wait(() => {
      this.check(pid);
      const now = new Date().toISOString();
      this.state.seen = { seen_at: now, new: { since: now, count: 0, hosts: [], access: [], services: [], items: [], keysteps: [] } };
    });
  }
  ackScopeWarning(pid: string, _cmdId: string): Promise<void> {
    return this.wait(() => {
      this.check(pid);
      this.state.scopeAcked = true;
    });
  }

  // ------------------------------------------------------------------ Hosts
  hosts(pid: string): Promise<HostSummary[]> {
    return this.wait(() => {
      this.check(pid);
      return this.state.graph.nodes
        .filter((n) => n.kind === 'host')
        .map((n) => {
          const { kind: _k, ...h } = n as Extract<typeof n, { kind: 'host' }>;
          return { ...h, first_seen: null, last_seen: null, quiet: { heuristic: 0, out_of_scope: 0, mentions: 0, system_accounts: 0 } };
        });
    });
  }
  host(pid: string, hostId: string): Promise<HostDetail> {
    return this.wait(() => {
      this.check(pid);
      const d = this.state.hosts[hostId];
      if (!d) throw err('not_found', 404);
      return clone(d);
    });
  }
  services(pid: string, q: { host?: string; class?: ServiceClass } = {}): Promise<ServiceView[]> {
    return this.wait(() => {
      this.check(pid);
      return clone(this.state.services.filter((s) => (!q.host || s.host_id === q.host) && (!q.class || s.class === q.class)));
    });
  }

  // ------------------------------------------------------------------ Als Nächstes
  next(pid: string): Promise<NextView> {
    return this.wait(() => {
      this.check(pid);
      return clone(this.state.next);
    });
  }
  suggestions(pid: string, state: SuggestionState | 'all' = 'open'): Promise<SuggestionsResponse> {
    return this.wait(() => {
      this.check(pid);
      const all = this.state.next.suggestions;
      return { suggestions: clone(state === 'all' ? all : all.filter((x) => x.state === state)), truncated: false };
    });
  }

  // ------------------------------------------------------------------ Zeitachse
  timeline(pid: string, q: TimelineQuery): Promise<TimelinePage> {
    return this.wait(() => {
      this.check(pid);
      let items = this.state.timeline;
      // wie der Server (web-api.md 10): ohne `types` keine Eingaben
      if (q.types?.length) items = items.filter((i) => q.types?.includes(i.type));
      else items = items.filter((i) => i.type !== 'input');
      if (q.terminal) items = items.filter((i) => i.terminal_id === q.terminal);
      if (q.host) items = items.filter((i) => i.host_id === q.host);
      return { items: clone(items.slice(0, q.limit ?? 200)), next_cursor: null };
    });
  }
  inputs(pid: string, q: { terminal?: string }): Promise<InputView[]> {
    return this.wait(() => {
      this.check(pid);
      return history.inputs().filter((i) => !q.terminal || i.terminal_id === q.terminal);
    });
  }

  // ------------------------------------------------------------------ Belege
  factSources(pid: string, claimKey: string): Promise<FactSources> {
    return this.wait(() => {
      this.check(pid);
      const s = history.factSources(claimKey);
      if (!s) throw err('not_found', 404);
      return s;
    });
  }
  unit(pid: string, unitId: string): Promise<UnitView> {
    return this.wait(() => {
      this.check(pid);
      const u = history.unitView(unitId);
      if (!u) throw err('not_found', 404);
      return this.state.scenario === 'chain' ? { ...u, chain_ok: false, chain_break_line: 3 } : u;
    });
  }
  lines(pid: string, unitId: string, q: LinesQuery): Promise<LinesPage> {
    return this.wait(() => {
      this.check(pid);
      const l = history.lines(unitId, q.from ?? 0, q.count ?? 400);
      if (!l) throw err('not_found', 404);
      return l;
    });
  }
  logText(pid: string, unitId: string): Promise<Blob> {
    return this.wait(() => {
      this.check(pid);
      const l = history.lines(unitId, 0, 100000);
      if (!l) throw err('not_found', 404);
      return new Blob([l.lines.map((x) => x.text).join('\n')], { type: 'text/plain' });
    });
  }

  // ------------------------------------------------------------------ Entscheide
  decide(pid: string, decisions: DecisionInput[]): Promise<DecisionResponse> {
    return this.wait(() => {
      this.check(pid);
      if (decisions.length === 0 || decisions.length > 500) throw err('validation', 422);
      const results = decisions.map((d) => {
        const id = newDecisionId();
        const r = applyMapDecision(this.state, d, id) ?? applyHistoryDecision(this.state, d, id);
        if (!r) throw err('validation', 422);
        if (r.decision_id === null) throw err('conflict', 409);
        this.state.decisions.push({ decision_id: id, kind: d.kind, payload: d.payload });
        return r;
      });
      this.state.generation++;
      queueMicrotask(() => this.emit({ name: 'changes', id: null, data: { project_id: pid, generation: this.state.generation } }));
      return { results };
    });
  }
  confirmGroup(pid: string): Promise<never> {
    return this.wait(() => {
      this.check(pid);
      throw err('not_found', 404);
    });
  }

  // ------------------------------------------------------------------ Suche, Warteliste, Secrets
  search(pid: string, q: string): Promise<SearchResult> {
    return this.wait(() => {
      this.check(pid);
      const items: SearchResult['items'] = [];
      for (const unitId of [`${base.T1}@18432`, `${base.T2}@1024`, `${base.T3}@64`]) {
        const page = history.lines(unitId, 0, 1000);
        for (const l of page?.lines ?? []) {
          if (l.text.toLowerCase().includes(q.toLowerCase())) {
            items.push({ unit_id: unitId, line: l.n, text: l.text, ctrl: false, kind: 'command', context_label: 'Kali', host_id: null, cmd: null, ts: base.NOW });
          }
        }
      }
      return { items: items.slice(0, 50), truncated: items.length > 50 };
    });
  }
  pending(pid: string): Promise<PendingResponse> {
    return this.wait(() => {
      this.check(pid);
      return clone(this.state.pending);
    });
  }
  reveal(pid: string, ref: SecretRef): Promise<RevealResponse> {
    return this.wait(() => {
      this.check(pid);
      if (this.state.presentation) throw err('policy', 403);
      if (ref.ref === 'input' && ref.seq === 47001) return { value: 'mock-Ziel-Passwort', ctrl: false };
      throw err('not_found', 404);
    });
  }
  copyToKali(pid: string, ref: SecretRef): Promise<CopyResult> {
    return this.wait(() => {
      this.check(pid);
      if (this.state.presentation) throw err('policy', 403);
      if (this.state.scenario === 'noclip') throw err('clipboard_tool', 503);
      if (ref.ref === 'input' && ref.seq !== 47001) throw err('not_found', 404);
      return { copied: true, target: 'kali', clear_after_s: 30, tool: 'xclip' };
    });
  }

  // ------------------------------------------------------------------ Findings
  findings(pid: string): Promise<FindingSummary[]> {
    return this.wait(() => {
      this.check(pid);
      return this.state.findings.map((f) => {
        const { description: _d, remediation: _r, attack: _a, cves: _c, evidence: _e, created_from: _f, history: _h, ...sum } = f;
        return clone(sum);
      });
    });
  }
  finding(pid: string, findingId: string): Promise<FindingDetail> {
    return this.wait(() => {
      this.check(pid);
      const f = this.state.findings.find((x) => x.finding_id === findingId);
      if (!f) throw err('not_found', 404);
      return clone(f);
    });
  }

  // ------------------------------------------------------------------ Ereignisse
  subscribe(handlers: StreamHandlers): () => void {
    this.listeners.add(handlers);
    if (this.state.scenario === 'offline') {
      setTimeout(() => handlers.onState?.('retrying'), 50);
    } else {
      setTimeout(() => handlers.onState?.('open'), 0);
    }
    return () => this.listeners.delete(handlers);
  }

  /** Nur für Tests: Ereignis von aussen auslösen. */
  inject(ev: StreamEvent): void {
    this.emit(ev);
  }
}
