/**
 * Karte: Graph, Positionen, Host-Tabelle (Briefing 5.1, E108, web-api.md 7, 8, 18.8).
 * Besitzer: ui-karte.
 *
 * - `load()` holt Graph und gespeicherte Positionen; nach `changes` an Hosts, Services, Werten,
 *   Schlüsselschritten oder der Arbeitsliste lädt der Store den Graph gebündelt nach (250 ms). Beim
 *   Nachladen bleibt der alte Stand stehen (Briefing 5.14). Neue Knoten legt die Karte selbst
 *   höchstens alle 2 s dazu (engine.ts).
 * - Positionen sind Komfort: lokal sofort, auf dem Server gebündelt (`PUT /ui/positions`); ein Fehler
 *   wird nicht gemeldet.
 * - `table` hält die Host-Tabelle (Screen 12): Hosts (`GET /hosts`) und Services (`GET /services`)
 *   werden erst geladen, wenn die Tabelle sichtbar ist.
 * - Palette: Quelle «hosts» (Hosts und Services), solange das Projekt offen ist.
 */
import type { ChangeSet, GraphView, HostNode, HostSummary, PositionsView, ServiceView, StreamEvent } from '../api/types';
import { t } from '../i18n';
import { compareHosts, hostsOf } from '../karte/model';
import { registerPaletteSource, type PaletteItem } from '../shell/palette';
import { url } from '../url/state.svelte';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

const RELOAD_ON = new Set(['host', 'service', 'claim', 'keystep', 'inbox']);

export class HostTableStore {
  hosts = $state.raw<HostSummary[] | null>(null);
  services = $state.raw<ServiceView[] | null>(null);
  error = $state<unknown>(null);
  private wantHosts = false;
  private wantServices = false;

  constructor(private readonly ctx: ProjectCtx) {}

  /** sortiert: Konflikte zuerst, dann Fortschritt, dann Adresse (Screen 12) */
  get sortedHosts(): HostSummary[] {
    return [...(this.hosts ?? [])].sort(compareHosts);
  }

  async ensure(kind: 'hosts' | 'services'): Promise<void> {
    if (kind === 'hosts') {
      this.wantHosts = true;
      if (this.hosts === null) await this.loadHosts();
    } else {
      this.wantServices = true;
      if (this.services === null) await this.loadServices();
    }
  }

  async loadHosts(): Promise<void> {
    try {
      this.hosts = await this.ctx.backend.hosts(this.ctx.pid, this.ctx.signal);
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    }
  }

  async loadServices(): Promise<void> {
    try {
      this.services = await this.ctx.backend.services(this.ctx.pid, {}, this.ctx.signal);
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    }
  }

  /** nach Änderungen: nur nachladen, was schon gebraucht wurde */
  refresh(): void {
    if (this.wantHosts) void this.loadHosts();
    if (this.wantServices) void this.loadServices();
  }
}

export class MapStore implements ProjectPart {
  graph = $state.raw<GraphView | null>(null);
  positions = $state.raw<PositionsView['positions']>({});
  positionsLoaded = $state(false);
  loading = $state(false);
  error = $state<unknown>(null);
  /** Zeit des letzten erfolgreichen Ladens (Lagebild, falls `as_of` fehlt) */
  loadedAt = $state<string | null>(null);
  readonly table: HostTableStore;
  private reloadTimer: ReturnType<typeof setTimeout> | null = null;
  private saveTimer: ReturnType<typeof setTimeout> | null = null;
  private offPalette: (() => void) | null = null;

  constructor(private readonly ctx: ProjectCtx) {
    this.table = new HostTableStore(ctx);
    this.offPalette = registerPaletteSource('hosts', () => this.paletteItems());
  }

  get hosts(): HostNode[] {
    return hostsOf(this.graph);
  }

  host(id: string): HostNode | null {
    return this.hosts.find((h) => h.id === id) ?? null;
  }

  /** ab 200 Hosts nur die Tabelle (E50, Screen 12) */
  get tableOnly(): boolean {
    return this.graph?.table_only === true;
  }

  async load(): Promise<void> {
    this.loading = true;
    try {
      const [g, p] = await Promise.all([
        this.ctx.backend.graph(this.ctx.pid, undefined, this.ctx.signal),
        this.ctx.backend.positions(this.ctx.pid, this.ctx.signal).catch((e: unknown) => {
          if (isAbort(e)) throw e;
          return { positions: {}, updated_at: null } as PositionsView;
        }),
      ]);
      this.graph = g;
      this.loadedAt = new Date().toISOString();
      this.positions = p.positions ?? {};
      this.positionsLoaded = true;
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    } finally {
      this.loading = false;
    }
    this.table.refresh();
  }

  /** nur den Graph nachladen (Positionen gehören der Karte) */
  async reload(): Promise<void> {
    try {
      this.graph = await this.ctx.backend.graph(this.ctx.pid, undefined, this.ctx.signal);
      this.loadedAt = new Date().toISOString();
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    }
    this.table.refresh();
  }

  private reloadSoon(): void {
    if (this.reloadTimer) clearTimeout(this.reloadTimer);
    this.reloadTimer = setTimeout(() => {
      this.reloadTimer = null;
      void this.reload();
    }, 250);
  }

  onChanges(cs: ChangeSet): void {
    if (cs.changes.some((c) => RELOAD_ON.has(c.entity))) this.reloadSoon();
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'presentation') this.reloadSoon();
  }

  /** Positionen lokal sofort, auf dem Server gebündelt (PUT ersetzt alle, web-api.md 17). */
  savePositions(pos: PositionsView['positions']): void {
    this.positions = pos;
    if (this.saveTimer) clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      if (this.ctx.signal.aborted || this.ctx.app.offline) return;
      const n = Object.keys(this.positions).length;
      if (n === 0 || n > 5000) return;
      this.ctx.backend.savePositions(this.ctx.pid, this.positions).catch(() => undefined);
    }, 700);
  }

  private paletteItems(): PaletteItem[] {
    const hosts = this.hosts;
    const items: PaletteItem[] = [];
    for (const h of hosts) {
      items.push({
        id: `host:${h.id}`,
        group: 'hosts',
        label: h.label,
        mono: true,
        hint: t('host.cardHint'),
        keywords: [h.label, ...h.names, ...h.addresses, h.os ?? '', ...h.tags, 'host'].join(' ').toLowerCase(),
        run: () => url.go('karte', { host: h.id, sel: null }, { keep: true }),
      });
    }
    const svcNodes = this.graph?.nodes.filter((n) => n.kind === 'service') ?? [];
    const byId = new Map(hosts.map((h) => [h.id, h]));
    for (const s of svcNodes.slice(0, 2000)) {
      if (s.kind !== 'service') continue;
      const h = byId.get(s.host);
      if (!h) continue;
      const product = [s.product, s.version].filter(Boolean).join(' ');
      items.push({
        id: `svc:${s.id}`,
        group: 'hosts',
        label: `${h.label}:${s.port} ${s.name ?? ''}${product ? ` · ${product}` : ''}`,
        mono: true,
        hint: t('host.cardHint'),
        keywords: [h.label, String(s.port), s.name ?? '', s.product ?? '', s.version ?? '', s.class, 'service'].join(' ').toLowerCase(),
        run: () => url.go('karte', { host: h.id, sel: null }, { keep: true }),
      });
    }
    return items;
  }

  dispose(): void {
    if (this.reloadTimer) clearTimeout(this.reloadTimer);
    if (this.saveTimer) clearTimeout(this.saveTimer);
    this.offPalette?.();
  }
}
