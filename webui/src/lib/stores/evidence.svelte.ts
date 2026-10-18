/**
 * Belegansicht als Tafel (Briefing 5.6, Screen 7, web-api.md 11 und 18.8). Besitzer: ui-verlauf.
 *
 * - Ziel aus der URL (`beleg=`): ein Wert (`c:<claim_key>`, mit allen Quellen; gewählt ist die
 *   erste Quelle mit Log) oder eine Einheit (`u:<unit_id>[:<von>-<bis>]`).
 * - Logzeilen lädt der Store in Blöcken zu 200 Zeilen, erst wenn die virtuelle Liste sie zeigt
 *   (lange Ausgaben wie linpeas). Verdeckte Teile (`reveal_hidden`) nur auf Wunsch, nur im Profil
 *   lab und nie im Präsentationsmodus (der Server verweigert es dann ohnehin still).
 * - Präsentationsmodus: beim Ereignis `presentation` lädt der Store Kopf und Zeilen neu (der Server
 *   maskiert dann alle Secret-Bereiche, Briefing 7.8).
 * - Nachladen ohne Springen: Nach `changes` prüft der Store den Kopf der Einheit; wächst eine noch
 *   laufende Einheit, lädt er nur den letzten Block neu. Auswahl und Scrollposition bleiben.
 */
import type { ChangeSet, FactSources, LogLine, SourceView, StreamEvent, UnitView } from '../api/types';
import type { LogEvidenceTarget as EvidenceTarget } from '../url/state.svelte';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export const CHUNK = 200;

export type LogSource = Exclude<SourceView, { t: 'user' }>;

function sameTarget(a: EvidenceTarget | null, b: EvidenceTarget | null): boolean {
  if (!a || !b) return a === b;
  if (a.kind === 'claim' && b.kind === 'claim') return a.claim_key === b.claim_key;
  if (a.kind === 'unit' && b.kind === 'unit') return a.unit_id === b.unit_id && (a.lines ?? []).join('-') === (b.lines ?? []).join('-');
  return false;
}

export class EvidenceStore implements ProjectPart {
  target = $state.raw<EvidenceTarget | null>(null);
  sources = $state.raw<FactSources | null>(null);
  sourceIndex = $state(0);
  unit = $state.raw<UnitView | null>(null);
  /** Zahl der Zeilen der Einheit */
  total = $state(0);
  /** geladene Blöcke: Index des Blocks -> Zeilen */
  chunks = $state.raw<Record<number, LogLine[]>>({});
  /** Fehler beim Laden von Quelle oder Kopf (404: «Beleg nicht mehr vorhanden») */
  error = $state<unknown>(null);
  /** Fehler beim Laden der Zeilen («Log nicht verfügbar») */
  linesError = $state<unknown>(null);
  loading = $state(false);
  revealHidden = $state(false);

  private gen = 0;
  private inflight = new Set<string>();

  constructor(private readonly ctx: ProjectCtx) {}

  get source(): SourceView | null {
    return this.sources?.sources[this.sourceIndex] ?? null;
  }

  /** Einheit, deren Log gezeigt wird */
  get unitId(): string | null {
    const t = this.target;
    if (!t) return null;
    if (t.kind === 'unit') return t.unit_id;
    const s = this.source;
    return s && s.t !== 'user' ? s.unit_id : null;
  }

  /** markierter Bereich (Zeilen der Einheit, inklusive Ende) */
  get marked(): [number, number] | null {
    const t = this.target;
    if (!t) return null;
    if (t.kind === 'unit') return t.lines;
    const s = this.source;
    return s && s.t !== 'user' ? s.lines : null;
  }

  line(n: number): LogLine | null {
    const c = this.chunks[Math.floor(n / CHUNK)];
    if (!c) return null;
    const direct = c[n % CHUNK];
    return direct && direct.n === n ? direct : (c.find((l) => l.n === n) ?? null);
  }

  /** Alle Zeilen im Bereich geladen? */
  hasLines(from: number, to: number): boolean {
    for (let n = from; n <= to; n++) if (!this.line(n)) return false;
    return true;
  }

  async load(): Promise<void> {
    if (this.target) await this.reload();
  }

  /** Öffnet ein Ziel (gleiches Ziel: nichts tun, auch nach einem Fehler; neu laden mit `reload`). */
  async open(target: EvidenceTarget | null): Promise<void> {
    if (sameTarget(target, this.target) && (this.unit || this.sources || this.loading || this.error !== null)) return;
    this.target = target;
    this.revealHidden = false;
    await this.reload();
  }

  close(): void {
    this.gen++;
    this.target = null;
    this.reset();
  }

  private reset(): void {
    this.sources = null;
    this.sourceIndex = 0;
    this.unit = null;
    this.total = 0;
    this.chunks = {};
    this.error = null;
    this.linesError = null;
    this.inflight.clear();
  }

  private async reload(keepSource = false): Promise<void> {
    const gen = ++this.gen;
    const target = this.target;
    const index = keepSource ? this.sourceIndex : 0;
    this.reset();
    if (!target) return;
    this.loading = true;
    try {
      if (target.kind === 'claim') {
        const s = await this.ctx.backend.factSources(this.ctx.pid, target.claim_key, this.ctx.signal);
        if (gen !== this.gen) return;
        this.sources = s;
        const first = s.sources.findIndex((x) => x.t !== 'user');
        this.sourceIndex = keepSource && index < s.sources.length ? index : first >= 0 ? first : 0;
      }
      const unitId = this.unitId;
      if (unitId) await this.loadUnit(unitId, gen);
    } catch (e) {
      if (!isAbort(e) && gen === this.gen) this.error = e;
    } finally {
      if (gen === this.gen) this.loading = false;
    }
  }

  private async loadUnit(unitId: string, gen: number): Promise<void> {
    const u = await this.ctx.backend.unit(this.ctx.pid, unitId, this.ctx.signal);
    if (gen !== this.gen) return;
    this.unit = u;
    this.total = u.line_count;
  }

  /** Andere Quelle eines Werts zeigen (Datei statt Terminal). */
  async selectSource(i: number): Promise<void> {
    const s = this.sources;
    if (!s || i < 0 || i >= s.sources.length || i === this.sourceIndex) return;
    const gen = ++this.gen;
    this.sourceIndex = i;
    this.unit = null;
    this.total = 0;
    this.chunks = {};
    this.linesError = null;
    this.inflight.clear();
    const unitId = this.unitId;
    if (!unitId) return;
    this.loading = true;
    try {
      await this.loadUnit(unitId, gen);
    } catch (e) {
      if (!isAbort(e) && gen === this.gen) this.error = e;
    } finally {
      if (gen === this.gen) this.loading = false;
    }
  }

  /** Lädt den Block mit Zeile `n`, falls er fehlt (aus der virtuellen Liste aufgerufen). */
  ensure(n: number): void {
    const unitId = this.unitId;
    if (!unitId || n < 0 || (this.total > 0 && n >= this.total)) return;
    const c = Math.floor(n / CHUNK);
    if (this.chunks[c]) return;
    const key = `${this.gen}:${c}`;
    if (this.inflight.has(key)) return;
    this.inflight.add(key);
    void this.loadChunk(unitId, c, this.gen, key);
  }

  private async loadChunk(unitId: string, c: number, gen: number, key: string): Promise<void> {
    try {
      const page = await this.ctx.backend.lines(
        this.ctx.pid,
        unitId,
        { from: c * CHUNK, count: CHUNK, reveal_hidden: this.revealHidden ? true : undefined },
        this.ctx.signal,
      );
      if (gen !== this.gen) return;
      this.chunks = { ...this.chunks, [c]: page.lines };
      if (page.total !== this.total) this.total = page.total;
      this.linesError = null;
    } catch (e) {
      if (!isAbort(e) && gen === this.gen) this.linesError = e;
    } finally {
      this.inflight.delete(key);
    }
  }

  /** Lädt alle Blöcke eines Bereichs und wartet darauf (Kopieren als Beleg). */
  async ensureRange(from: number, to: number): Promise<boolean> {
    const unitId = this.unitId;
    if (!unitId) return false;
    const gen = this.gen;
    const wanted: number[] = [];
    for (let c = Math.floor(Math.max(0, from) / CHUNK); c <= Math.floor(Math.max(0, to) / CHUNK); c++) if (!this.chunks[c]) wanted.push(c);
    await Promise.all(wanted.map((c) => this.loadChunk(unitId, c, gen, `${gen}:${c}:range`)));
    return gen === this.gen && this.hasLines(Math.max(0, from), Math.min(to, Math.max(0, this.total - 1)));
  }

  /** Verdeckte Teile ein- oder ausblenden (lädt die Zeilen neu, Kopf bleibt). */
  setRevealHidden(on: boolean): void {
    if (on === this.revealHidden) return;
    if (on && (this.ctx.app.presentation || this.ctx.app.profile !== 'lab')) return;
    this.revealHidden = on;
    this.gen++;
    this.chunks = {};
    this.inflight.clear();
  }

  /** «Ganzes Log» als Blob (Bearer nötig, nie als Link). */
  async fullLog(): Promise<Blob> {
    const unitId = this.unitId;
    if (!unitId) throw new Error('kein Log');
    return this.ctx.backend.logText(this.ctx.pid, unitId);
  }

  /** Kopf neu prüfen; wächst die Einheit, nur den letzten Block neu laden. */
  private async refreshUnit(): Promise<void> {
    const unitId = this.unitId;
    if (!unitId || !this.unit) return;
    const gen = this.gen;
    try {
      const u = await this.ctx.backend.unit(this.ctx.pid, unitId, this.ctx.signal);
      if (gen !== this.gen) return;
      const before = this.total;
      this.unit = u;
      if (u.line_count !== before) {
        const last = Math.floor(Math.max(0, before - 1) / CHUNK);
        const { [last]: _drop, ...rest } = this.chunks;
        this.chunks = rest;
        this.total = u.line_count;
      }
    } catch (e) {
      if (!isAbort(e) && gen === this.gen) this.error = e;
    }
  }

  onChanges(cs: ChangeSet): void {
    if (!this.target) return;
    if (cs.changes.some((c) => c.entity === 'unit' || c.entity === 'claim')) void this.refreshUnit();
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'presentation' && this.target) {
      if (ev.data.on) this.revealHidden = false;
      void this.reload(true);
    }
  }

  dispose(): void {
    this.gen++;
  }
}
