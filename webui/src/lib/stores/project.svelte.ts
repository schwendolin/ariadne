/**
 * Store pro Projekt. Alles, was zu einem Projekt gehört, hängt an genau einer
 * Instanz. Beim SSE-Ereignis `project` verwirft die App die Instanz komplett
 * (dispose): laufende Abrufe werden abgebrochen, Blob-URLs freigegeben. So
 * mischen sich Projekte im Browser nie (Architektur 7.3).
 *
 * Grosse Listen liegen in $state.raw und werden nur als Ganzes ersetzt; das
 * spart Proxies und Speicher auf einer schwachen VM.
 */
import type { Backend } from '../api/backend';
import { isApiError } from '../api/client';
import type {
  ChangeEntity, CredentialView, Finding, GraphLayer, GraphView, HostSummary, InboxView, Lens, Suggestion, Terminal, TimelineItem,
} from '../api/types';

export const DEFAULT_LAYERS: GraphLayer[] = ['topology', 'services', 'attack', 'oos', 'fog'];

type Resource = 'graph' | 'hosts' | 'inbox' | 'suggestions' | 'findings' | 'timeline' | 'terminals' | 'credentials';

const ENTITY_RESOURCES: Record<ChangeEntity, Resource[]> = {
  host: ['graph', 'hosts'],
  service: ['graph', 'hosts'],
  claim: ['graph', 'inbox'],
  credential: ['credentials', 'graph'],
  suggestion: ['suggestions'],
  finding: ['findings', 'graph'],
  terminal: ['terminals'],
  timeline: ['timeline'],
  inbox: ['inbox'],
  thread: ['graph', 'timeline'],
  note: [],
};

export class ProjectStore {
  readonly pid: string;
  readonly backend: Backend;
  private readonly ctrl = new AbortController();
  private readonly blobUrls = new Map<string, string>();
  private pending = new Set<Resource>();
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  generation = $state<number | null>(null);
  /** Generation beim ersten Laden; Grundlage für «neu seit …» */
  baseline = $state<number | null>(null);
  baselineTs = $state<string | null>(null);
  graph = $state.raw<GraphView | null>(null);
  hosts = $state.raw<HostSummary[]>([]);
  inbox = $state.raw<InboxView | null>(null);
  suggestions = $state.raw<Suggestion[]>([]);
  findings = $state.raw<Finding[]>([]);
  timeline = $state.raw<TimelineItem[]>([]);
  terminals = $state.raw<Terminal[]>([]);
  credentials = $state.raw<CredentialView[]>([]);
  /** neu hinzugekommene Entitäten seit baseline (Schlüssel -> Art) */
  fresh = $state.raw<Record<string, ChangeEntity>>({});
  layers = $state.raw<GraphLayer[]>([...DEFAULT_LAYERS]);
  lens = $state<Lens>('karte');
  loading = $state(false);
  error = $state<string | null>(null);
  /** steigt bei jeder Änderung; Detailansichten laden dann neu */
  version = $state(0);
  disposed = $state(false);

  constructor(pid: string, backend: Backend, layers?: GraphLayer[]) {
    this.pid = pid;
    this.backend = backend;
    if (layers) this.layers = layers;
  }

  get signal(): AbortSignal {
    return this.ctrl.signal;
  }

  async loadAll(): Promise<void> {
    if (this.disposed) return;
    this.loading = true;
    this.error = null;
    try {
      await Promise.all([
        this.load('graph'), this.load('hosts'), this.load('inbox'), this.load('suggestions'), this.load('findings'),
        this.load('timeline'), this.load('terminals'), this.load('credentials'),
      ]);
      if (this.graph && this.generation === null) {
        this.generation = this.graph.generation;
      }
      if (this.baseline === null) {
        this.baseline = this.generation;
        this.baselineTs = new Date().toISOString();
      }
      this.version++;
    } catch (e) {
      if (!this.disposed && !isApiError(e, 'aborted')) this.error = isApiError(e) ? e.code : 'internal';
    } finally {
      this.loading = false;
    }
  }

  private async load(r: Resource): Promise<void> {
    if (this.disposed) return;
    const { backend: b, pid } = this;
    const s = this.signal;
    switch (r) {
      case 'graph': {
        const g = await b.graph(pid, { layers: this.layers, lens: this.lens }, s);
        if (!this.disposed) this.graph = g;
        break;
      }
      case 'hosts': {
        const v = await b.hosts(pid, s);
        if (!this.disposed) this.hosts = v;
        break;
      }
      case 'inbox': {
        const v = await b.inbox(pid, s);
        if (!this.disposed) this.inbox = v;
        break;
      }
      case 'suggestions': {
        const v = await b.suggestions(pid, s);
        if (!this.disposed) this.suggestions = v;
        break;
      }
      case 'findings': {
        const v = await b.findings(pid, s);
        if (!this.disposed) this.findings = v;
        break;
      }
      case 'timeline': {
        const v = await b.timeline(pid, { limit: 500 }, s);
        if (!this.disposed) this.timeline = v.items;
        break;
      }
      case 'terminals': {
        const v = await b.terminals(s);
        if (!this.disposed) this.terminals = v.filter((t) => t.project_id === null || t.project_id === pid);
        break;
      }
      case 'credentials': {
        const v = await b.credentials(pid, s);
        if (!this.disposed) this.credentials = v;
        break;
      }
    }
  }

  /** Mehrere Invalidierungen kurz hintereinander werden gebündelt. */
  refresh(...resources: Resource[]): void {
    if (this.disposed) return;
    for (const r of resources) this.pending.add(r);
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      const todo = [...this.pending];
      this.pending.clear();
      void Promise.all(todo.map((r) => this.load(r).catch(() => undefined))).then(() => {
        if (!this.disposed) this.version++;
      });
    }, 80);
  }

  /** SSE `changes`: Änderungen seit der eigenen Generation holen und gezielt neu laden. */
  async onChanges(generation: number): Promise<void> {
    if (this.disposed) return;
    if (this.generation !== null && generation <= this.generation) return;
    try {
      const cs = await this.backend.changes(this.pid, this.generation ?? 0, this.signal);
      if (this.disposed) return;
      if (cs.reset) {
        this.generation = null;
        await this.loadAll();
        return;
      }
      this.generation = cs.to;
      const todo = new Set<Resource>();
      const fresh = { ...this.fresh };
      for (const c of cs.changes) {
        for (const r of ENTITY_RESOURCES[c.entity] ?? []) todo.add(r);
        if (c.change === 'added' && (c.entity === 'host' || c.entity === 'service' || c.entity === 'credential')) {
          fresh[c.entity_key] = c.entity;
        }
      }
      this.fresh = fresh;
      this.refresh(...todo);
    } catch (e) {
      if (!isApiError(e, 'aborted')) this.refresh('graph', 'inbox');
    }
  }

  /** SSE `reset`: alles neu laden (z. B. nach `ariadne reparse`). */
  async onReset(): Promise<void> {
    this.generation = null;
    this.fresh = {};
    await this.loadAll();
  }

  setLayers(layers: GraphLayer[]): void {
    this.layers = layers;
    this.refresh('graph');
  }

  /** «Gesehen»: Neu-Markierungen zurücksetzen. */
  acknowledgeFresh(): void {
    this.fresh = {};
    this.baseline = this.generation;
    this.baselineTs = new Date().toISOString();
  }

  /** Bild aus /blobs als blob:-URL (CSP erlaubt img-src blob:). Wird bei dispose freigegeben. */
  async blobUrl(blobId: string): Promise<string> {
    const known = this.blobUrls.get(blobId);
    if (known) return known;
    const blob = await this.backend.blob(this.pid, blobId, this.signal);
    if (!/^image\/(png|jpeg|webp)$/.test(blob.type)) throw new Error('Kein erlaubtes Bildformat');
    if (this.disposed) throw new Error('Projekt verworfen');
    const url = URL.createObjectURL(blob);
    this.blobUrls.set(blobId, url);
    return url;
  }

  get blobUrlCount(): number {
    return this.blobUrls.size;
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.ctrl.abort();
    if (this.flushTimer) clearTimeout(this.flushTimer);
    this.flushTimer = null;
    this.pending.clear();
    for (const url of this.blobUrls.values()) URL.revokeObjectURL(url);
    this.blobUrls.clear();
    this.graph = null;
    this.hosts = [];
    this.inbox = null;
    this.suggestions = [];
    this.findings = [];
    this.timeline = [];
    this.terminals = [];
    this.credentials = [];
    this.fresh = {};
    this.generation = null;
  }
}
