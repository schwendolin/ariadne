/**
 * Mock-Backend: verhält sich wie der Daemon, aber mit Beispieldaten (Projekt lame)
 * und simulierten SSE-Ereignissen. Aktiv mit VITE_ARIADNE_MOCK=1, `--mode mock`
 * oder automatisch im Dev-Server ohne erreichbaren Daemon.
 *
 * Entscheide verändern den Mock-Zustand und lösen dieselben Ereignisse aus wie
 * beim echten Backend (changes, inbox, suggestion, terminal ...). Die UI merkt
 * keinen Unterschied.
 */
import type { Backend, StreamHandlers } from '../api/backend';
import { ApiError } from '../api/client';
import {
  progressOf,
  type Change, type ChangeEntity, type ChangeSet, type ContextOp, type ContextResult, type CredentialView, type DecisionInput,
  type DecisionResponse, type DenkanstossRequest, type FactSources, type Finding, type GraphQuery, type GraphView, type HostDetail,
  type HostSummary, type InboxView, type Job, type Lens, type LinesPage, type LinesQuery, type LogLine, type Positions,
  type QueryDsl, type QueryResult, type ServiceView, type Status, type StreamEvent, type StreamPayloads, type Suggestion,
  type Terminal, type TimelinePage, type TimelineQuery,
} from '../api/types';
import { readPref, writePref } from '../util/prefs';
import { createLameFixture, fakeHash, ip, TID, type MockFixture } from './fixture';
import { buildGraph } from './graph';

export interface MockOptions {
  now?: number;
  /** Verzögerung pro Aufruf in ms */
  latencyMs?: number;
  /** simulierte Ereignisse nach dem Abonnieren (Standard: an) */
  scripted?: boolean;
}

const clone = <T>(v: T): T => structuredClone(v);

export class MockBackend implements Backend {
  readonly kind = 'mock' as const;
  fx: MockFixture;
  private readonly latency: number;
  private readonly scripted: boolean;
  private listeners = new Set<StreamHandlers>();
  private timers: ReturnType<typeof setTimeout>[] = [];
  private changelog: Change[] = [];
  private seq = 1000;
  private activePid: string;
  private startGeneration: number;

  constructor(opts: MockOptions = {}) {
    this.fx = createLameFixture(opts.now ?? Date.now());
    this.latency = opts.latencyMs ?? 60;
    this.scripted = opts.scripted ?? true;
    this.activePid = this.fx.project.id;
    this.startGeneration = this.fx.generation;
  }

  // ------------------------------------------------------------ Hilfen
  private async tick(): Promise<void> {
    if (this.latency > 0) await new Promise((r) => setTimeout(r, this.latency));
  }

  private checkPid(pid: string): void {
    if (pid !== this.activePid) throw new ApiError('project_mismatch', 409, 'Projekt ist nicht aktiv');
  }

  private emit<K extends keyof StreamPayloads>(name: K, data: StreamPayloads[K]): void {
    const ev = { name, id: String(++this.seq), data } as StreamEvent;
    for (const l of this.listeners) l.onEvent(ev);
  }

  private later(ms: number, fn: () => void): void {
    this.timers.push(setTimeout(fn, ms));
  }

  private bump(entries: [ChangeEntity, string, Change['change']][]): void {
    this.fx.generation++;
    this.fx.status.generation = this.fx.generation;
    const counts: Partial<Record<ChangeEntity, number>> = {};
    for (const [entity, key, change] of entries) {
      this.changelog.push({ generation: this.fx.generation, entity, entity_key: key, change });
      counts[entity] = (counts[entity] ?? 0) + 1;
    }
    const generation = this.fx.generation;
    this.later(this.latency + 120, () => this.emit('changes', { generation, entities: counts }));
  }

  private inboxOpen(): number {
    return this.fx.inbox.reduce((n, g) => n + g.items.filter((i) => i.state === 'candidate').length, 0);
  }

  private host(id: string): HostSummary | undefined {
    return this.fx.hosts.find((h) => h.id === id);
  }

  // ------------------------------------------------------------ Sitzung
  needsLogin(): boolean {
    return false;
  }
  async login(): Promise<void> {}
  async logout(): Promise<void> {}
  onUnauthorized(): void {}

  async status(): Promise<Status> {
    await this.tick();
    return clone({ ...this.fx.status, server_time: new Date().toISOString() });
  }

  async setRec(on: boolean): Promise<void> {
    await this.tick();
    // Der Zustand ändert sich erst mit dem SSE-Ereignis (wie beim Daemon).
    this.later(350, () => {
      this.fx.status.rec = {
        on, mode: on ? 'on' : 'off', since: on ? new Date().toISOString() : null, source: 'webui',
        terminals_recording: on ? this.fx.terminals.filter((t) => t.alive).length : 0,
      };
      for (const t of this.fx.terminals) if (t.alive) t.recording = on;
      this.emit('rec', clone(this.fx.status.rec));
    });
  }

  async setPresentation(on: boolean): Promise<void> {
    await this.tick();
    this.later(150, () => {
      this.fx.status.presentation = on;
      this.emit('presentation', { on });
    });
  }

  async terminals(): Promise<Terminal[]> {
    await this.tick();
    return clone(this.fx.terminals);
  }

  async setContext(tid: string, op: ContextOp): Promise<ContextResult> {
    await this.tick();
    const t = this.fx.terminals.find((x) => x.terminal_id === tid);
    if (!t) throw new ApiError('not_found', 404, 'Terminal unbekannt');
    const warnings: ContextResult['warnings'] = [];
    const resolve = (host: string | null | undefined) => {
      if (!host) return { host: null, host_label: null, host_id: null, scope: null };
      const key = host.includes(':') ? host : ip(host);
      const h = this.host(key);
      if (!h) warnings.push({ code: 'host_unknown', identifier: key });
      else if (h.scope !== 'in') warnings.push({ code: h.scope === 'excluded' ? 'scope_excluded' : 'scope_out', identifier: key });
      return { host: key, host_label: h?.label ?? host, host_id: h?.id ?? null, scope: h?.scope ?? 'unknown' };
    };
    if (op.op === 'set') {
      const depth = op.depth ?? t.stack.length - 1;
      const st = t.stack[depth];
      if (!st) throw new ApiError('validation', 422, 'Stufe existiert nicht');
      Object.assign(st, resolve(op.host), {
        user: op.user ?? st.user,
        kind: op.kind ?? (st.kind === 'unknown' ? 'ssh' : st.kind),
        source: 'webui',
        candidate: null,
      });
      for (const g of this.fx.inbox) {
        for (const i of g.items) if (i.context?.terminal_id === tid) i.state = 'confirmed';
      }
    } else if (op.op === 'push') {
      t.stack.push({
        depth: t.stack.length, kind: op.kind ?? 'unknown', ...resolve(op.host), user: op.user ?? null, state: 'active',
        source: 'webui', candidate: null, opened_at: 0,
      });
    } else if (op.op === 'pop') {
      if (t.stack.length <= 1) throw new ApiError('validation', 422, 'Kali bleibt immer unten im Stapel');
      t.stack.pop();
    }
    this.bump([['terminal', tid, 'updated'], ['inbox', `ctx:${tid}`, 'updated']]);
    this.later(this.latency + 100, () => {
      this.emit('terminal', { terminal_id: tid, change: 'context' });
      this.emit('inbox', { open: this.inboxOpen() });
    });
    return { decision_id: `d-${fakeHash(`${tid}${Date.now()}`).slice(0, 12)}`, warnings };
  }

  // ------------------------------------------------------------ Projekt-Lesewege
  async graph(pid: string, q: GraphQuery): Promise<GraphView> {
    await this.tick();
    this.checkPid(pid);
    return clone(buildGraph(this.fx, q.layers, q.lens));
  }

  async changes(pid: string, since: number): Promise<ChangeSet> {
    await this.tick();
    this.checkPid(pid);
    // Der Mock führt das Änderungsprotokoll ab dem Startzustand; ältere Stände ergeben reset.
    return {
      project_id: pid, from: since, to: this.fx.generation, reset: since < this.startGeneration,
      changes: clone(this.changelog.filter((c) => c.generation > since)),
    };
  }

  async hosts(pid: string): Promise<HostSummary[]> {
    await this.tick();
    this.checkPid(pid);
    return clone(this.fx.hosts);
  }

  async host(pid: string, hostId: string): Promise<HostDetail> {
    await this.tick();
    this.checkPid(pid);
    const h = this.host(hostId);
    if (!h) throw new ApiError('not_found', 404, 'Host unbekannt');
    const prefix = `svc:${hostId}|`;
    const services = this.fx.services.filter((s) => s.host_id === hostId);
    const facts = this.fx.facts.filter((f) => f.subject === hostId || f.subject.startsWith(prefix) || f.subject.includes(`local:${hostId}|`));
    const credentials = this.fx.credentials.filter(
      (c) => c.identity.realm.includes(hostId) || c.valid_on.some((v) => v.service_id.startsWith(prefix)),
    );
    const commands = [...this.fx.units.values()]
      .filter((u) => u.cmd && (u.context.some((s) => s.host_id === hostId) || (u.cmd.text ?? '').includes(h.addresses[0] ?? '§')))
      .map((u) => ({ ...u.cmd!, terminal_id: u.terminal_id, unit_id: u.unit_id }));
    return clone({
      ...h,
      services,
      credentials,
      facts,
      conflicts_detail: this.fx.conflicts.filter((c) => c.subject === hostId || c.subject.startsWith(prefix)),
      note: this.fx.notes.get(hostId) ?? null,
      shots: this.fx.shots.get(hostId) ?? [],
      commands,
    });
  }

  async services(pid: string): Promise<ServiceView[]> {
    await this.tick();
    this.checkPid(pid);
    return clone(this.fx.services);
  }

  async credentials(pid: string): Promise<CredentialView[]> {
    await this.tick();
    this.checkPid(pid);
    return clone(this.fx.credentials);
  }

  async inbox(pid: string): Promise<InboxView> {
    await this.tick();
    this.checkPid(pid);
    const groups = this.fx.inbox
      .map((g) => ({ ...g, items: g.items.filter((i) => i.state === 'candidate') }))
      .filter((g) => g.items.length > 0)
      .map((g) => ({
        ...g,
        summary: {
          ...g.summary,
          hosts: g.items.filter((i) => i.subject.startsWith('ip:')).length,
          services: g.items.filter((i) => i.subject.startsWith('svc:')).length,
          credentials: g.items.filter((i) => i.subject.startsWith('id:')).length,
          out_of_scope: g.items.filter((i) => i.scope !== 'in').length,
          low_confidence: g.items.filter((i) => i.confidence_level === 'low').length,
        },
      }));
    return clone({ open: this.inboxOpen(), groups, automode: this.fx.status.automode! });
  }

  async suggestions(pid: string): Promise<Suggestion[]> {
    await this.tick();
    this.checkPid(pid);
    return clone(this.fx.suggestions);
  }

  async findings(pid: string): Promise<Finding[]> {
    await this.tick();
    this.checkPid(pid);
    return clone(this.fx.findings);
  }

  async timeline(pid: string, q: TimelineQuery): Promise<TimelinePage> {
    await this.tick();
    this.checkPid(pid);
    let items = this.fx.timeline;
    if (q.types?.length) items = items.filter((i) => q.types!.includes(i.type));
    if (q.terminal) items = items.filter((i) => i.terminal_id === q.terminal);
    if (q.host) items = items.filter((i) => i.host_id === q.host);
    const start = q.cursor ? Number(q.cursor) : 0;
    const limit = q.limit ?? 200;
    const page = items.slice(start, start + limit);
    return clone({ items: page, next_cursor: start + limit < items.length ? String(start + limit) : null });
  }

  async factSources(pid: string, factId: string): Promise<FactSources> {
    await this.tick();
    this.checkPid(pid);
    const fact = this.fx.facts.find((f) => f.fact_id === factId);
    if (!fact) throw new ApiError('not_found', 404, 'Fakt unbekannt');
    return clone({ fact, sources: this.fx.sources.get(factId) ?? [] });
  }

  async streamLines(pid: string, tid: string, q: LinesQuery): Promise<LinesPage> {
    await this.tick();
    this.checkPid(pid);
    let lines: LogLine[];
    if (q.unit) {
      const u = this.fx.units.get(q.unit);
      if (!u || u.terminal_id !== tid) throw new ApiError('not_found', 404, 'Einheit unbekannt');
      lines = u.lines;
    } else {
      lines = [...this.fx.units.values()].filter((u) => u.terminal_id === tid).flatMap((u) => u.lines).map((l, n) => ({ ...l, n }));
    }
    const presentation = this.fx.status.presentation;
    const page = lines.slice(q.from, q.from + q.count).map((l) => maskLine(l, presentation));
    return { terminal_id: tid, unit_id: q.unit ?? null, total: lines.length, from: q.from, lines: page };
  }

  async blob(pid: string, blobId: string): Promise<Blob> {
    await this.tick();
    this.checkPid(pid);
    return renderMockShot(blobId);
  }

  async query(pid: string, dsl: QueryDsl): Promise<QueryResult> {
    await this.tick();
    this.checkPid(pid);
    if (dsl.from !== 'hosts' && dsl.from !== 'services') {
      return { columns: [], rows: [], truncated: false, sql_preview: `-- Mock: Quelle ${dsl.from} nicht nachgebildet` };
    }
    const rows: Record<string, string | number | boolean | null>[] = dsl.from === 'hosts'
      ? this.fx.hosts.map((h) => ({ id: h.id, label: h.label, access: h.access, work: h.work, progress: h.progress }))
      : this.fx.services.map((s) => ({ id: s.service_id, host: s.host_label, port: s.port, name: s.name, product: s.product, version: s.version }));
    const columns = dsl.select?.length ? dsl.select : Object.keys(rows[0] ?? {});
    const limit = Math.min(dsl.limit ?? 100, 500);
    return {
      columns,
      rows: rows.slice(0, limit).map((r) => columns.map((c) => r[c] ?? null)),
      truncated: rows.length > limit,
      sql_preview: `SELECT ${columns.join(', ')} FROM v_${dsl.from.slice(0, -1)} LIMIT ?`,
    };
  }

  async denkanstoss(pid: string, _req: DenkanstossRequest): Promise<Job> {
    await this.tick();
    this.checkPid(pid);
    if (this.fx.status.llm.mode === 'off') throw new ApiError('policy', 403, 'KI ist für dieses Projekt aus');
    const job_id = `job-${++this.seq}`;
    const kind = 'ai.denkanstoss' as const;
    this.later(200, () => this.emit('progress', { job_id, kind, status: 'running', pct: 10, message: 'Lagebild erstellt (3,1k Tokens)' }));
    this.later(1600, () => this.emit('progress', { job_id, kind, status: 'running', pct: 70, message: 'Antwort wird geprüft' }));
    this.later(2600, () => {
      const s: Suggestion = {
        suggestion_key: `AI|${job_id}`, origin: { type: 'ai', model: 'claude-opus-5-5', call_id: job_id, prompt_version: 'denkanstoss@3' },
        kind: 'question', goal_id: 'PZ-CRED-REUSE', title: 'Gelten die Credentials von lame auch im internen Netz?',
        reasoning: 'Zwei Hosts im Netz 10.10.20.0/24 sind bekannt, aber noch keine Credentials getestet. msfadmin gilt bereits auf zwei Systemen.',
        subjects: [{ id: ip('10.10.20.5'), label: '10.10.20.5', kind: 'host' }], evidence: [], criteria: null,
        stages: [
          { level: 1, kind: 'question', text: 'Welche Dienste im internen Netz nehmen Passwörter an?', commands: [] },
          { level: 2, kind: 'direction', text: 'Beginne mit SSH und MySQL auf 10.10.20.5, beide sind über den Pivot erreichbar.', commands: [] },
        ],
        status: 'open', created_at: new Date().toISOString(), injection_suspect: false,
      };
      this.fx.suggestions.unshift(s);
      this.bump([['suggestion', s.suggestion_key, 'added']]);
      this.emit('progress', { job_id, kind, status: 'done', pct: 100, message: '1 Denkanstoss' });
      this.emit('suggestion', { suggestion_key: s.suggestion_key, change: 'added', open: this.openSuggestions() });
    });
    return { job_id, kind, status: 'queued' };
  }

  private openSuggestions(): number {
    return this.fx.suggestions.filter((s) => s.status === 'open').length;
  }

  async positions(pid: string, lens: Lens): Promise<Positions> {
    await this.tick();
    this.checkPid(pid);
    const stored = readPref<Positions['positions']>(`ariadne.mock.positions.${pid}.${lens}`, {}, isPositions);
    return { lens, positions: stored, updated_at: null };
  }

  async savePositions(pid: string, lens: Lens, positions: Positions['positions']): Promise<void> {
    this.checkPid(pid);
    writePref(`ariadne.mock.positions.${pid}.${lens}`, positions);
  }

  // ------------------------------------------------------------ Entscheide
  async decide(pid: string, decisions: DecisionInput[]): Promise<DecisionResponse> {
    await this.tick();
    this.checkPid(pid);
    if (!decisions.length || decisions.length > 500) throw new ApiError('validation', 422, '1 bis 500 Entscheide');
    const changes: [ChangeEntity, string, Change['change']][] = [];
    const results = decisions.map((d) => {
      this.apply(d, changes);
      return { decision_id: `d-${fakeHash(`${d.kind}${++this.seq}`).slice(0, 16)}`, seq: this.seq, ts: new Date().toISOString(), client_ref: d.client_ref ?? null };
    });
    this.bump(changes.length ? changes : [['timeline', 'decision', 'added']]);
    const open = this.inboxOpen();
    this.later(this.latency + 150, () => {
      if (changes.some(([e]) => e === 'inbox' || e === 'claim')) this.emit('inbox', { open });
      for (const [e, key, change] of changes) {
        if (e === 'suggestion') this.emit('suggestion', { suggestion_key: key, change, open: this.openSuggestions() });
        if (e === 'terminal') this.emit('terminal', { terminal_id: key, change: 'label' });
      }
    });
    return { results };
  }

  private apply(d: DecisionInput, changes: [ChangeEntity, string, Change['change']][]): void {
    const fx = this.fx;
    switch (d.kind) {
      case 'd.claim.confirm':
      case 'd.claim.reject': {
        const f = fx.facts.find((x) => x.claim_key === d.payload.claim_key);
        if (!f) throw new ApiError('conflict', 409, 'Claim unbekannt (verwaist?)');
        const state = d.kind === 'd.claim.confirm' ? 'confirmed' : 'rejected';
        f.state = state;
        for (const g of fx.inbox) for (const i of g.items) if (i.claim_key === f.claim_key) i.state = state;
        changes.push(['claim', f.claim_key, 'updated'], ['inbox', f.claim_key, 'updated']);
        if (f.subject.startsWith('ip:') && f.predicate === 'host.address') {
          const h = this.host(f.subject);
          if (h) {
            h.claim_state = state;
            changes.push(['host', h.id, 'updated']);
          }
        }
        if (f.subject.startsWith('svc:')) {
          const s = fx.services.find((x) => x.service_id === f.subject);
          if (s && state === 'confirmed') {
            s.claim_state = 'confirmed';
            changes.push(['service', s.service_id, 'updated']);
          }
        }
        break;
      }
      case 'd.claim.edit': {
        const f = fx.facts.find((x) => x.claim_key === d.payload.claim_key);
        if (!f) throw new ApiError('conflict', 409, 'Claim unbekannt');
        f.value = d.payload.value;
        f.state = 'confirmed';
        f.trust = 'user';
        changes.push(['claim', f.claim_key, 'updated'], ['inbox', f.claim_key, 'updated']);
        for (const g of fx.inbox) for (const i of g.items) if (i.claim_key === f.claim_key) i.state = 'confirmed';
        break;
      }
      case 'd.status.work': {
        const h = this.host(d.payload.subject);
        if (!h) throw new ApiError('conflict', 409, 'Subjekt unbekannt');
        h.work = d.payload.value;
        h.work_reason = d.payload.reason ?? null;
        changes.push(['host', h.id, 'updated']);
        break;
      }
      case 'd.status.access': {
        const h = this.host(d.payload.subject);
        if (!h) throw new ApiError('conflict', 409, 'Subjekt unbekannt');
        h.access = d.payload.value;
        h.progress = progressOf(h.knowledge, h.access);
        changes.push(['host', h.id, 'updated']);
        break;
      }
      case 'd.note.set':
        fx.notes.set(d.payload.subject, { text: d.payload.text, updated_at: new Date().toISOString() });
        changes.push(['note', d.payload.subject, 'updated']);
        break;
      case 'd.tag.add':
      case 'd.tag.remove': {
        const h = this.host(d.payload.subject);
        if (!h) throw new ApiError('conflict', 409, 'Subjekt unbekannt');
        const tag = d.payload.tag.trim().slice(0, 64);
        h.tags = d.kind === 'd.tag.add' ? [...new Set([...h.tags, tag])] : h.tags.filter((t) => t !== tag);
        changes.push(['host', h.id, 'updated']);
        break;
      }
      case 'd.automode.set':
        fx.status.automode = { enabled: d.payload.enabled, parsers: d.payload.parsers ?? [], auto_ctx: d.payload.auto_ctx ?? false };
        changes.push(['inbox', 'automode', 'updated']);
        break;
      case 'd.conflict.resolve': {
        const c = fx.conflicts.find((x) => x.conflict_key === d.payload.conflict_key);
        if (!c) throw new ApiError('conflict', 409, 'Konflikt unbekannt');
        c.resolved = { choice: d.payload.choice ?? null, keep_open: d.payload.keep_open ?? false };
        for (const v of c.values) {
          const f = fx.facts.find((x) => x.claim_key === v.claim_key);
          if (!f || c.resolved.keep_open) continue;
          f.state = v.value === c.resolved.choice ? 'confirmed' : 'rejected';
        }
        for (const g of fx.inbox) for (const i of g.items) if (i.conflict?.conflict_key === c.conflict_key) i.state = 'confirmed';
        const s = fx.services.find((x) => x.service_id === c.subject);
        if (s) {
          s.conflicts = 0;
          const h = this.host(s.host_id);
          if (h) h.conflicts = Math.max(0, h.conflicts - 1);
          changes.push(['service', s.service_id, 'updated'], ['host', s.host_id, 'updated']);
        }
        changes.push(['inbox', c.conflict_key, 'updated']);
        break;
      }
      case 'd.terminal.label': {
        const t = fx.terminals.find((x) => x.terminal_id === d.payload.terminal_id);
        if (!t) throw new ApiError('conflict', 409, 'Terminal unbekannt');
        t.label = d.payload.label;
        changes.push(['terminal', t.terminal_id, 'updated']);
        break;
      }
      case 'd.suggestion.done':
      case 'd.suggestion.dismiss': {
        const s = fx.suggestions.find((x) => x.suggestion_key === d.payload.suggestion_key);
        if (!s) throw new ApiError('conflict', 409, 'Denkanstoss unbekannt');
        s.status = d.kind === 'd.suggestion.done' ? 'done' : 'dismissed';
        changes.push(['suggestion', s.suggestion_key, 'updated']);
        break;
      }
      case 'd.keystep.mark': {
        const target = d.payload.host ?? 'kali';
        const last = fx.thread[fx.thread.length - 1];
        const seq = (last?.seq ?? 0) + 1;
        fx.thread.push({
          kind: 'thread', id: `thread:${seq}`, seq, step: d.payload.step, source: last?.target ?? 'kali', target,
          ts: new Date().toISOString(), decision_id: `d-keystep-${seq}`, note: d.payload.note ?? null, evidence: null,
        });
        const h = this.host(target);
        if (h) h.on_thread = true;
        changes.push(['thread', `thread:${seq}`, 'added']);
        break;
      }
      case 'd.finding': {
        const p = d.payload;
        const idx = fx.findings.findIndex((f) => f.finding_id === p.finding_id);
        if (p.action === 'delete') {
          if (idx >= 0) fx.findings.splice(idx, 1);
        } else {
          const now = new Date().toISOString();
          const base: Finding = idx >= 0 ? fx.findings[idx]! : {
            finding_id: p.finding_id, title: '', severity: 'info', assets: [], description: '', evidence: [], mitigation: '',
            attack_ids: [], cves: [], status: 'draft', created_at: now, updated_at: now,
          };
          const next: Finding = {
            ...base,
            title: p.title ?? base.title,
            severity: p.severity ?? base.severity,
            description: p.description ?? base.description,
            mitigation: p.mitigation ?? base.mitigation,
            attack_ids: p.attack_ids ?? base.attack_ids,
            assets: p.assets ? p.assets.map((id) => ({ id, label: this.host(id)?.label ?? id, kind: id.startsWith('svc:') ? 'service' : 'host' })) : base.assets,
            updated_at: now,
          };
          if (idx >= 0) fx.findings[idx] = next;
          else fx.findings.push(next);
        }
        changes.push(['finding', p.finding_id, idx >= 0 ? 'updated' : 'added']);
        break;
      }
      default:
        // Weitere Entscheide (Merge, Scope, Revoke ...) nimmt der Mock an, ohne den Zustand zu ändern.
        changes.push(['timeline', d.kind, 'added']);
    }
  }

  // ------------------------------------------------------------ SSE
  subscribe(pid: string, handlers: StreamHandlers): () => void {
    this.listeners.add(handlers);
    handlers.onState?.('connecting');
    this.later(120, () => handlers.onState?.('open'));
    if (this.scripted && this.listeners.size === 1 && pid === this.activePid) this.runScript();
    return () => {
      this.listeners.delete(handlers);
      handlers.onState?.('closed');
      if (this.listeners.size === 0) this.stopTimers();
    };
  }

  stopTimers(): void {
    for (const t of this.timers) clearTimeout(t);
    this.timers = [];
  }

  /** Simuliert einen Projektwechsel (CLI `ariadne project open ...`). Für Tests und Vorführungen. */
  simulateProjectSwitch(newPid: string | null): void {
    this.activePid = newPid ?? '';
    if (newPid) {
      this.fx = createLameFixture(Date.now());
      this.fx.project.id = newPid;
      this.fx.project.slug = 'metasploitable';
      this.fx.project.name = 'Metasploitable2';
      this.fx.status.project = this.fx.project;
    } else {
      this.fx.status.project = null;
    }
    this.changelog = [];
    this.startGeneration = this.fx.generation;
    this.emit('project', { project_id: newPid, locked: false });
  }

  /** Ablauf nach dem Abonnieren: ein neuer Host taucht auf, ein Denkanstoss folgt, ein Befehl endet. */
  private runScript(): void {
    this.later(6000, () => {
      const fx = this.fx;
      const addr = '10.10.20.11';
      if (fx.hosts.some((h) => h.id === ip(addr))) return;
      const unit = 'u-arp';
      fx.units.set(unit, {
        unit_id: unit, terminal_id: TID.msf, cmd: null, context: fx.terminals.find((t) => t.terminal_id === TID.msf)?.stack ?? [],
        parser: 'regex.net', offStart: 120_000,
        lines: [
          { n: 0, text: '? (10.10.20.1) at 08:00:27:aa:10:01 [ether] on eth1', sgr: [], prompt_echo: false, concealed: false, overwritten: false, masked: [] },
          { n: 1, text: `? (${addr}) at 08:00:27:aa:10:0b [ether] on eth1`, sgr: [], prompt_echo: false, concealed: false, overwritten: false, masked: [] },
        ],
      });
      const claim_key = fakeHash(`${ip(addr)}|host.address|${addr}`);
      const now = new Date().toISOString();
      fx.facts.push({
        fact_id: claim_key, claim_key, subject: ip(addr), subject_label: addr, predicate: 'host.address', value: addr, state: 'candidate',
        confidence: 0.4, confidence_level: 'low', trust: 'heuristic', parser: 'regex.net', ai: false, offered_by_target: false, scope: 'in',
        sources_count: 1, first_seen: now, last_seen: now, conflict_key: null, injection_suspect: false,
      });
      fx.sources.set(claim_key, [{
        t: 'stream', terminal_id: TID.msf, terminal_label: 'msfadmin@metasploitable', unit_id: unit, cmd: null,
        context: fx.units.get(unit)!.context, off: [120_072, 120_144], lines: [1, 1], parser: 'regex.net', trust: 'heuristic', truncated: false, partial: false,
      }]);
      fx.hosts.push({
        id: ip(addr), segment: 'seg:default/10.10.20.0/24', label: addr, addresses: [addr], names: [],
        identifiers: [{ key: ip(addr), scope: 'in', rule: 'include:10.10.20.0/24' }], scope: 'in', claim_state: 'candidate',
        confidence: 'low', knowledge: 'discovered', access: 'none', work: 'open', work_reason: null, progress: 1, os: null,
        service_counts: { web: 0, smb: 0, db: 0, remote: 0, file: 0, mail: 0, other: 0 }, services_total: 0, conflicts: 0, findings: 0,
        hints: { total: 0, high: 0 }, ai: false, on_thread: false, tags: [], first_seen: now, last_seen: now,
      });
      fx.inbox.unshift({
        group_id: 'grp:u-arp', kind: 'unit', title: 'arp -an (msfadmin@metasploitable)', ts: now,
        unit: { unit_id: unit, cmd_id: null, text: 'arp -an', terminal_id: TID.msf, parser: 'regex.net' },
        items: [{
          item_id: 'item:arp-11', type: 'claim', claim_key, fact_id: claim_key, subject: ip(addr), subject_label: addr, predicate: 'host.address',
          value: addr, confidence_level: 'low', scope: 'in', trust: 'heuristic', parser: 'regex.net', ai: false, offered_by_target: false,
          state: 'candidate', conflict: null, context: null, merge: null, orphan: null,
        }],
        summary: { hosts: 1, services: 0, credentials: 0, other: 0, out_of_scope: 0, low_confidence: 1 },
      });
      fx.timeline.unshift({
        id: 't-arp', ts: now, type: 'segment', terminal_id: TID.msf, host_id: ip('10.10.10.4'), host_label: 'metasploitable.localdomain',
        title: 'arp -an (remote)', detail: null, exit: null, facts: 1, evidence: { fact_id: claim_key, label: addr },
      });
      this.bump([['host', ip(addr), 'added'], ['claim', claim_key, 'added'], ['inbox', 'grp:u-arp', 'added'], ['timeline', 't-arp', 'added']]);
      this.later(this.latency + 200, () => {
        this.emit('terminal', { terminal_id: TID.msf, change: 'command' });
        this.emit('inbox', { open: this.inboxOpen() });
      });
    });
    this.later(12000, () => {
      const key = 'R-NEUER-HOST|ip:10.10.20.11';
      if (this.fx.suggestions.some((s) => s.suggestion_key === key)) return;
      this.fx.suggestions.unshift({
        suggestion_key: key, origin: { type: 'rule', rule_id: 'R-NEUER-HOST' }, kind: 'goal', goal_id: 'PZ-PORTS-ALLE',
        title: '10.10.20.11 ist noch nicht gescannt', reasoning: 'Der Host wurde aus einer ARP-Tabelle erkannt. Ports und Dienste sind unbekannt.',
        subjects: [{ id: ip('10.10.20.11'), label: '10.10.20.11', kind: 'host' }], evidence: [], criteria: null,
        stages: [
          { level: 1, kind: 'question', text: 'Welche Dienste bietet der neue Host an?', commands: [] },
          { level: 2, kind: 'direction', text: 'Der Host liegt hinter dem Pivot. Ein TCP-Connect-Scan über den SOCKS-Proxy funktioniert, SYN-Scans nicht.', commands: [] },
          {
            level: 3, kind: 'commands', text: null,
            commands: [{
              template_id: 'nmap-proxy', title: 'nmap über proxychains', renderable: true, reason: null,
              parts: [{ text: 'proxychains -q nmap -sT -Pn --top-ports 200 ', from_target: false }, { text: '10.10.20.11', from_target: true }],
              copy_text: 'proxychains -q nmap -sT -Pn --top-ports 200 10.10.20.11', values: [],
            }],
          },
        ],
        status: 'open', created_at: new Date().toISOString(), injection_suspect: false,
      });
      this.bump([['suggestion', key, 'added']]);
      this.emit('suggestion', { suggestion_key: key, change: 'added', open: this.openSuggestions() });
    });
    this.later(20000, () => {
      const t = this.fx.terminals.find((x) => x.terminal_id === TID.kali);
      if (!t) return;
      const now = new Date().toISOString();
      t.last_command = { cmd_id: `${TID.kali}@70100`, text: 'searchsploit unrealircd 3.2.8.1', started_at: now, ended_at: now, exit: 0, src_ip: null, origin: 'local' };
      t.last_activity = now;
      this.fx.timeline.unshift({
        id: 't-searchsploit', ts: now, type: 'command', terminal_id: TID.kali, host_id: null, host_label: null,
        title: 'searchsploit unrealircd 3.2.8.1', detail: null, exit: 0, facts: 0, evidence: null,
      });
      this.bump([['terminal', TID.kali, 'updated'], ['timeline', 't-searchsploit', 'added']]);
      this.emit('terminal', { terminal_id: TID.kali, change: 'command' });
    });
  }
}

function isPositions(v: unknown): v is Positions['positions'] {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  return Object.values(v as Record<string, unknown>).every(
    (p) => !!p && typeof p === 'object' && Number.isFinite((p as { x: unknown }).x) && Number.isFinite((p as { y: unknown }).y),
  );
}

/** Präsentationsmodus: der Server ersetzt Secret-Bereiche durch Punkte ohne Längenangabe. */
function maskLine(l: LogLine, presentation: boolean): LogLine {
  if (!presentation || !l.masked.length) return { ...l, masked: [] };
  let text = l.text;
  const masked: LogLine['masked'] = [];
  let shift = 0;
  for (const m of [...l.masked].sort((a, b) => a.col_start - b.col_start)) {
    const start = m.col_start + shift;
    const end = m.col_end + shift;
    const dots = '••••••••';
    text = text.slice(0, start) + dots + text.slice(end);
    masked.push({ col_start: start, col_end: start + dots.length, kind: m.kind });
    shift += dots.length - (m.col_end - m.col_start);
  }
  return { ...l, text, masked, sgr: [] };
}

/** Erzeugt ein schlichtes PNG als Platzhalter-Screenshot (nur im Browser). */
async function renderMockShot(blobId: string): Promise<Blob> {
  if (typeof document === 'undefined') return new Blob([], { type: 'image/png' });
  const canvas = document.createElement('canvas');
  canvas.width = 480;
  canvas.height = 270;
  const ctx = canvas.getContext('2d');
  if (!ctx) return new Blob([], { type: 'image/png' });
  ctx.fillStyle = '#101418';
  ctx.fillRect(0, 0, 480, 270);
  ctx.fillStyle = '#9fe870';
  ctx.font = '14px monospace';
  ['root@lame:~# id', 'uid=0(root) gid=0(root)', 'root@lame:~# hostname', 'lame', `(${blobId})`].forEach((t, i) => ctx.fillText(t, 16, 32 + i * 22));
  return new Promise((resolve) => canvas.toBlob((b) => resolve(b ?? new Blob([], { type: 'image/png' })), 'image/png'));
}
