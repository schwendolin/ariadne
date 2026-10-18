/**
 * MockBackend: dieselbe Schnittstelle wie HttpBackend, Daten aus mock/data (Standbild 16:54,
 * Anhang A). Besitzer: ui-fundament (Datenteile: ui-karte, ui-verlauf).
 *
 * - Nur im Mock-Build oder im Dev-Server ohne Daemon (select.ts); im Produktions-Build entfernt.
 * - Fehler wie der Daemon: ApiError mit Code (403 policy im Präsentationsmodus, 409 conflict,
 *   404, 422 budget_confirm, 503 clipboard_tool im Szenario `noclip`, 503 shot_display im
 *   Szenario `kigone`).
 * - Ereignisse wie der Daemon: `changes` nach jedem Entscheid, `terminal` nach Pause (mit
 *   600 ms Verzögerung, damit «wartet auf Bestätigung» sichtbar ist), `presentation`, `prefs`.
 * - Kein Browser-Speicher: Token, Positionen und Vorlieben nur im Speicher.
 */
import type { Backend, StreamHandlers } from '../api/backend';
import { ApiError } from '../api/client';
import type {
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
  ContextOp,
  ContextResult,
  CopyResult,
  DecisionInput,
  DecisionResponse,
  DecisionResult,
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
  ScopeChange,
  ScopeChangeResult,
  ScopeOptions,
  ScopeView,
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
  TimelineItem,
} from '../api/types';
import * as base from './data/base';
import * as e4 from './data/etappe4';
import * as history from './data/history';
import { applyHistoryDecision } from './handlers/history';
import { applyMapDecision } from './handlers/map';
import { applyScopeChange, revertScopeDecision, scopeOptions, scopeView, type ScopeRefusal } from './handlers/scope';

/** Fehler wie der Daemon (web-api.md 20): 422, 409 (auch no_include, noop), 403 guardrail */
function scopeError(r: ScopeRefusal): ApiError {
  if (r === 'validation') return new ApiError('validation', 422, 'validation');
  if (r === 'guardrail') return new ApiError('guardrail', 403, 'guardrail');
  if (r === 'no_include' || r === 'noop') return new ApiError(r, 409, r);
  return new ApiError('conflict', 409, 'conflict');
}
import { createState, newDecisionId, scenarioFromLocation, type MockState, type Scenario } from './state';

/**
 * Entscheide, die der Kartenteil des Mocks verarbeitet, erscheinen wie beim Server als Zeile
 * `decision` in der Zeitachse (feste Texte wie web-api.md 18.12, Korrektur K3); der Verlaufsteil
 * legt seine Zeilen selbst an. Damit kann die Spalte einen fremden Entscheid erkennen (A5).
 */
const MAP_SUMMARY: Record<string, string> = {
  'd.claim.confirm': 'Wert bestätigt',
  'd.claim.reject': 'Wert verworfen',
  'd.claim.edit': 'Wert geändert',
  'd.conflict.resolve': 'Widerspruch gelöst',
  'd.entity.merge': 'Kennungen zusammengeführt',
  'd.entity.split': 'Kennungen getrennt',
  'd.note.set': 'Notiz gesetzt',
  'd.tag.add': 'Tag hinzugefügt',
  'd.tag.remove': 'Tag entfernt',
  'd.suggestion.done': 'Denkanstoss erledigt',
  'd.suggestion.dismiss': 'Denkanstoss verworfen',
};

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
      if (s.scopeWarning) st.scope_warning = s.scopeWarning;
      if (st.scope_warning) st.scope_warning = { ...st.scope_warning, acked: s.scopeAcked };
      if (st.project) st.project = { ...st.project, profile: s.profile, scope_open: s.scope.open === true };
      if (st.project) st.scope_open = s.scope.open === true;
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
      const sc = this.state.scope;
      return { ...base.project(), profile: this.state.profile, scope: { include: [...sc.include], exclude: [...sc.exclude], version: sc.version, open: sc.open === true }, scope_open: sc.open === true };
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

  // ------------------------------------------------------------------ Scope erweitern (E129, E130)
  scope(pid: string): Promise<ScopeView> {
    return this.wait(() => {
      this.check(pid);
      return scopeView(this.state);
    });
  }
  scopeOptions(pid: string, value: string): Promise<ScopeOptions> {
    return this.wait(() => {
      this.check(pid);
      if (!value.trim()) throw err('validation', 422);
      return scopeOptions(this.state, value);
    });
  }
  changeScope(pid: string, change: ScopeChange): Promise<ScopeChangeResult> {
    return this.wait(() => {
      this.check(pid);
      // E129: im Profil customer nur im Terminal; im Präsentationsmodus nie
      if (this.state.profile === 'customer' || this.state.presentation) throw err('policy', 403);
      const r = applyScopeChange(this.state, change, newDecisionId());
      if (typeof r === 'string') throw scopeError(r);
      this.afterScopeChange(pid);
      return r;
    });
  }
  previewScope(pid: string, change: ScopeChange): Promise<ScopeChangeResult> {
    return this.wait(() => {
      this.check(pid);
      if (this.state.profile === 'customer') throw err('policy', 403);
      const r = applyScopeChange(this.state, change, '', true);
      if (typeof r === 'string') throw scopeError(r);
      return r;
    });
  }

  revertScope(pid: string, decisionId: string): Promise<ScopeChangeResult> {
    return this.wait(() => {
      this.check(pid);
      if (this.state.profile === 'customer' || this.state.presentation) throw err('policy', 403);
      const r = revertScopeDecision(this.state, decisionId, newDecisionId());
      if (r === 'not_found') throw err('not_found', 404);
      if (typeof r === 'string') throw scopeError(r);
      this.afterScopeChange(pid);
      return r;
    });
  }

  /** Wie der Daemon: `scope` sofort, die Neuauswertung meldet danach `changes` und `inbox`. */
  private afterScopeChange(pid: string): void {
    const s = this.state;
    queueMicrotask(() => this.emit({ name: 'scope', id: null, data: { project_id: pid, version: s.scope.version } }));
    setTimeout(() => {
      this.emit({ name: 'changes', id: null, data: { project_id: pid, generation: s.generation } });
      this.emit({ name: 'inbox', id: null, data: { project_id: pid, open: s.next.open } });
    }, 150);
  }

  /** E130 «Verwerfen» (d.suggestion.dismiss mit Schlüssel «scope-name:») und sein d.revoke */
  private scopeDecision(d: DecisionInput, id: string): DecisionResult | null {
    const s = this.state;
    const key = d.payload.suggestion_key;
    if (d.kind === 'd.suggestion.dismiss' && typeof key === 'string' && key.startsWith('scope-name:')) {
      const item = s.next.clarify.find((i) => i.item_key === key);
      if (!item) return { decision_id: null, seq: null, client_ref: null, effect: null };
      s.dismissedScope = [...s.dismissedScope, key];
      s.dismissedScopeItems = { ...s.dismissedScopeItems, [id]: item };
      const clarify = s.next.clarify.filter((i) => i.item_key !== key);
      s.next = { ...s.next, clarify, open: clarify.length };
      queueMicrotask(() => this.emit({ name: 'inbox', id: null, data: { project_id: base.PID, open: s.next.open } }));
      return { decision_id: id, seq: null, client_ref: null, effect: null };
    }
    if (d.kind === 'd.revoke' && typeof d.payload.decision_id === 'string' && s.dismissedScopeItems[d.payload.decision_id]) {
      const item = s.dismissedScopeItems[d.payload.decision_id];
      const { [d.payload.decision_id]: _gone, ...rest } = s.dismissedScopeItems;
      s.dismissedScopeItems = rest;
      if (item) {
        s.dismissedScope = s.dismissedScope.filter((k) => k !== item.item_key);
        const clarify = [item, ...s.next.clarify];
        s.next = { ...s.next, clarify, open: clarify.length };
        queueMicrotask(() => this.emit({ name: 'inbox', id: null, data: { project_id: base.PID, open: s.next.open } }));
      }
      return { decision_id: id, seq: null, client_ref: null, effect: null };
    }
    return null;
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
      const s = this.state;
      const st = base.status(s.terminals, s.generation, s.presentation, s.origin);
      const sw = s.scopeWarning ?? st.scope_warning;
      // E120: nicht quittierte Scope-Warnung als erster Eintrag der Spalte
      const warn = !s.scopeAcked && sw ? { ...sw, acked: false, change_allowed: s.profile !== 'customer' } : null;
      return clone({ ...s.next, scope_warning: warn });
    });
  }
  suggestions(pid: string, state: SuggestionState | 'all' = 'open'): Promise<SuggestionsResponse> {
    return this.wait(() => {
      this.check(pid);
      const all = [...this.state.next.suggestions, ...this.state.suggestionsDecided];
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
        const r = this.scopeDecision(d, id) ?? applyMapDecision(this.state, d, id) ?? applyHistoryDecision(this.state, d, id);
        if (!r) throw err('validation', 422);
        if (r.decision_id === null) throw err('conflict', 409);
        this.state.decisions.push({ decision_id: id, kind: d.kind, payload: d.payload });
        const summary = MAP_SUMMARY[d.kind];
        if (summary) {
          const ts = new Date().toISOString().replace(/\.(\d{3})Z$/, '.$1000Z');
          const item: TimelineItem = {
            id, ts, ts_ns: `${Date.parse(ts)}000000`, terminal_id: null, context_label: null, host_id: null, ctrl: false, terminal: null,
            type: 'decision', decision_id: id, kind: d.kind, summary, detail: null, reason: null, ref: null, effect: null,
          };
          this.state.timeline = [item, ...this.state.timeline];
        }
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
  // ------------------------------------------------------------------ KI (Etappe 4)
  /** Pause zwischen den Schritten eines KI-Auftrags (ms); Tests setzen kleinere Werte */
  aiStepMs = 450;

  aiStatus(pid: string): Promise<AiStatus> {
    return this.wait(() => {
      this.check(pid);
      return clone(e4.aiStatus(this.state.aiMode, this.state.aiJob));
    });
  }
  aiRequest(pid: string, confirmBudget: boolean): Promise<AiJob> {
    return this.wait(() => {
      this.check(pid);
      const s = this.state;
      if (s.presentation) throw err('policy', 403);
      const st = e4.aiStatus(s.aiMode, s.aiJob);
      if (s.aiJob && (s.aiJob.status === 'queued' || s.aiJob.status === 'running')) throw err('conflict', 409);
      if (!st.ready) throw err('policy', 403);
      if (s.aiMode === 'over' && !confirmBudget) {
        throw new ApiError('validation', 422, 'validation', [{ loc: ['body', 'confirm_budget'], type: 'budget_confirm' }]);
      }
      const job = e4.newJob(s.aiMode);
      s.aiJob = job;
      this.runAiJob(pid, job.job_id);
      return clone(job);
    });
  }
  aiJob(pid: string, jobId: string): Promise<AiJob> {
    return this.wait(() => {
      this.check(pid);
      if (!this.state.aiJob || this.state.aiJob.job_id !== jobId) throw err('not_found', 404);
      return clone(this.state.aiJob);
    });
  }

  /** Simulierter Auftrag: Fortschritt wie der Server (pct 10, 40, 90, 100), feste Texte. */
  private runAiJob(pid: string, jobId: string): void {
    const s = this.state;
    const steps: { pct: number; step: AiJob['step']; message: string; patch: Partial<AiJob> }[] = [
      { pct: 10, step: 'lagebild', message: 'Lagebild wird erstellt', patch: { status: 'running' } },
      { pct: 40, step: 'anfrage', message: 'Lagebild wird gesendet', patch: { status: 'running', tokens_in: 4212 } },
      { pct: 90, step: 'pruefung', message: 'Antwort wird geprüft', patch: { status: 'running', tokens_out: 388 } },
    ];
    const progress = (job: AiJob, pct: number, status: string) =>
      this.emit({
        name: 'progress', id: null,
        data: {
          job_id: job.job_id, kind: 'ai', status, pct, message: job.message, tokens_in: job.tokens_in, tokens_out: job.tokens_out,
          tokens_estimate: job.tokens_estimate, masked: job.masked, cost_usd: job.cost_usd, budget_level: job.budget_level,
        },
      });
    let i = 0;
    const tick = () => {
      const job = s.aiJob;
      if (!job || job.job_id !== jobId) return;
      const st = steps[i];
      if (st) {
        s.aiJob = { ...job, ...st.patch, step: st.step, message: st.message };
        progress(s.aiJob, st.pct, 'running');
        i++;
        // Szenario «kirun»: bleibt beim Senden stehen (Zustand für Screenshots und Tests)
        if (s.aiMode === 'run' && st.step === 'anfrage') return;
        setTimeout(tick, this.aiStepMs);
        return;
      }
      const end = e4.finishJob(job, s.aiMode);
      s.aiJob = end;
      if (end.status === 'done' && end.created > 0) {
        const sug = e4.aiSuggestion(end.job_id, s.aiMode === 'inject');
        s.next = { ...s.next, suggestions: [...s.next.suggestions, sug] };
        this.emit({ name: 'suggestion', id: null, data: { project_id: pid, open: s.next.suggestions.length } });
      }
      progress(end, 100, end.status === 'done' ? 'done' : 'failed');
    };
    setTimeout(tick, this.aiStepMs);
  }

  // ------------------------------------------------------------------ Export (Etappe 4)
  exportStepMs = 400;
  private exportCount = 0;

  exports(pid: string): Promise<ExportsView> {
    return this.wait(() => {
      this.check(pid);
      return clone({ exports: this.state.exports, running: this.state.exportRunning, last_error: null });
    });
  }
  startExport(pid: string, template: ExportTemplate): Promise<ExportStarted> {
    return this.wait(() => {
      this.check(pid);
      if (template !== 'cys' && template !== 'htb') throw err('validation', 422);
      if (this.state.exportRunning) throw err('conflict', 409);
      this.exportCount++;
      const job_id = `exp-${this.exportCount}`;
      this.state.exportRunning = { job_id, template, status: 'running', pct: 0 };
      const steps: [number, string, string][] = [
        [0, 'running', 'Daten sammeln'],
        [40, 'running', 'Dateien schreiben'],
        [100, 'done', 'Export fertig'],
      ];
      let i = 0;
      const tick = () => {
        const st = steps[i++];
        if (!st) return;
        const [pct, status, message] = st;
        if (status === 'done') {
          this.state.exportRunning = null;
          this.state.exports = [e4.newExport(template, this.exportCount), ...this.state.exports];
        } else if (this.state.exportRunning) {
          this.state.exportRunning = { ...this.state.exportRunning, pct };
        }
        this.emit({ name: 'progress', id: null, data: { job_id, kind: 'export', status, pct, message } });
        if (status !== 'done') setTimeout(tick, this.exportStepMs);
      };
      queueMicrotask(tick);
      return { job_id, status: 'running', template };
    });
  }
  exportPhases(pid: string, template: ExportTemplate): Promise<PhasesView> {
    return this.wait(() => {
      this.check(pid);
      const own = this.state.phaseDecisions[template];
      const commands = this.state.timeline
        .filter((i): i is Extract<typeof i, { type: 'command' }> => i.type === 'command')
        .map((i) => {
          const text = i.cmd.text ?? '';
          const decided = own[i.cmd.cmd_id];
          const rule = e4.rulePhase(template, text);
          return {
            cmd_id: i.cmd.cmd_id, cmd_ref: i.cmd.cmd_ref, command: text, ts: i.ts,
            phase: decided ?? rule, source: decided ? ('decision' as const) : rule ? ('rule' as const) : ('none' as const),
            decision_id: decided ? `0199a3c2-dddd-7000-8000-${i.cmd.cmd_id.slice(-12)}` : null, ctrl: i.ctrl,
          };
        });
      return clone({ template, phases: e4.PHASES[template], commands });
    });
  }
  setExportPhase(pid: string, template: ExportTemplate, cmdId: string, phase: string): Promise<PhaseSet> {
    return this.wait(() => {
      this.check(pid);
      if (!e4.PHASES[template]?.some((p) => p.key === phase)) throw err('validation', 422);
      if (!this.state.timeline.some((i) => i.type === 'command' && i.cmd.cmd_id === cmdId)) throw err('not_found', 404);
      this.state.phaseDecisions[template] = { ...this.state.phaseDecisions[template], [cmdId]: phase };
      return { decision_id: newDecisionId(), cmd_id: cmdId, template, phase };
    });
  }

  // ------------------------------------------------------------------ Screenshots (Etappe 4)
  private shotBusy = false;

  screenshots(pid: string): Promise<ScreenshotsView> {
    return this.wait(() => {
      this.check(pid);
      const p = this.state.presentation;
      const items = this.state.screenshots.map((x) => (p ? { ...x, window_title: null, wm_class: null, note: null } : x));
      return clone({ items, presentation: p });
    });
  }
  async takeScreenshot(pid: string, req: ShotRequest): Promise<Screenshot> {
    await this.wait(() => this.check(pid));
    if (this.shotBusy) throw err('conflict', 409);
    if (req.mode === 'region' && !req.region) throw err('validation', 422);
    this.shotBusy = true;
    try {
      await new Promise((r) => setTimeout(r, Math.max(0, req.delay_s ?? 3) * 1000));
      if (this.state.scenario === 'kigone') throw new ApiError('shot_display', 503, 'shot_display');
      const blob = req.mode === 'monitor' ? '0199a3c2-b10b-7000-8000-00000000000b' : '0199a3c2-b10b-7000-8000-00000000000a';
      const id = `0199a3c2-5c07-7000-8000-${(0xb10 + this.state.screenshots.length).toString(16).padStart(12, '0')}`;
      const shot: Screenshot = {
        ...e4.screenshots()[1]!, id, seq: 6000 + this.state.screenshots.length, ts: new Date().toISOString(), blob_id: blob,
        url: `/api/v1/p/${pid}/blobs/${blob}`, mode: req.mode ?? 'window', trigger: 'webui', note: req.note ?? null,
        window_title: this.state.presentation ? null : 'root@kali: ~', wm_class: this.state.presentation ? null : 'xfce4-terminal',
      };
      this.state.screenshots = [shot, ...this.state.screenshots];
      queueMicrotask(() => this.emit({ name: 'screenshot', id: null, data: { project_id: pid, id, trigger: 'webui' } }));
      return clone(shot);
    } finally {
      this.shotBusy = false;
    }
  }
  blob(pid: string, blobId: string): Promise<Blob> {
    return this.wait(() => {
      this.check(pid);
      if (this.state.presentation) throw err('policy', 403);
      const which = e4.SHOT_BLOBS[blobId];
      if (!which) throw err('not_found', 404);
      return new Blob([e4.pngBytes(which)], { type: 'image/png' });
    });
  }

  subscribe(handlers: StreamHandlers): () => void {
    this.listeners.add(handlers);
    if (this.state.scenario === 'offline') {
      setTimeout(() => handlers.onState?.('retrying'), 50);
    } else {
      setTimeout(() => handlers.onState?.('open'), 0);
    }
    if (this.state.scenario === 'ende' && !this.ending) {
      this.ending = true;
      setTimeout(() => this.endSession('stop'), 1500);
    }
    if (this.state.scenario === 'grow' && !this.grown) {
      this.grown = true;
      setTimeout(() => this.growHost(), 2500);
    }
    return () => this.listeners.delete(handlers);
  }

  private grown = false;
  private ending = false;

  /** Wie der Daemon bei `ariadne stop`: Ereignis `session` vor dem Ende, danach 401. */
  endSession(reason: 'stop' | 'lock' | 'switch' | 'restart' = 'stop'): void {
    this.emit({ name: 'session', id: null, data: { change: 'ending', reason, slug: 'ms2' } });
    this.token = null;
    for (const cb of this.unauthorized) cb();
  }

  /** Szenario `grow`: ein neuer Host im Scope (192.168.56.130), wie nach einem weiteren nmap. */
  private growHost(): void {
    const g = this.state.graph;
    const tpl = g.nodes.find((n) => n.kind === 'host' && n.label === '192.168.56.104');
    if (!tpl || tpl.kind !== 'host') return;
    const id = 'ip:default/192.168.56.130';
    const host = { ...tpl, id, label: '192.168.56.130', addresses: ['192.168.56.130'], work: 'open' as const, work_reason: null, os: null, ports: [22, 80], services_total: 2 };
    this.state.graph = {
      ...g,
      nodes: [...g.nodes, host],
      edges: [...g.edges, { kind: 'member' as const, id: `m:${id}`, source: tpl.segment ?? 'seg:192.168.56.0/24', target: id }],
      summary: { ...g.summary, hosts: g.summary.hosts + 1 },
    };
    this.state.generation++;
    this.emit({ name: 'changes', id: null, data: { project_id: base.PID, generation: this.state.generation } });
  }

  /** Nur für Tests: Ereignis von aussen auslösen. */
  inject(ev: StreamEvent): void {
    this.emit(ev);
  }
}
