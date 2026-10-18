/**
 * Belegansicht als Tafel (Briefing 5.6, Screen 7, web-api.md 11). Besitzer: ui-verlauf.
 *
 * Gerüst aus Phase 1: hält das Ziel aus der URL (`beleg=`) und lädt Quelle, Kopf der Einheit und
 * die ersten Zeilen. Der Besitzer ergänzt virtuelle Liste, markierten Bereich, Hash-Kette,
 * Präsentationsmodus, «Als Finding», «Ganzes Log».
 */
import type { FactSources, LinesPage, SourceView, StreamEvent, UnitView } from '../api/types';
import type { EvidenceTarget } from '../url/state.svelte';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export class EvidenceStore implements ProjectPart {
  target = $state.raw<EvidenceTarget | null>(null);
  sources = $state.raw<FactSources | null>(null);
  unit = $state.raw<UnitView | null>(null);
  lines = $state.raw<LinesPage | null>(null);
  error = $state<unknown>(null);

  constructor(private readonly ctx: ProjectCtx) {}

  async load(): Promise<void> {
    if (this.target) await this.open(this.target);
  }

  async open(target: EvidenceTarget | null): Promise<void> {
    this.target = target;
    this.sources = null;
    this.unit = null;
    this.lines = null;
    this.error = null;
    if (!target) return;
    try {
      let unitId: string | null = null;
      if (target.kind === 'claim') {
        const s = await this.ctx.backend.factSources(this.ctx.pid, target.claim_key, this.ctx.signal);
        this.sources = s;
        const first = s.sources.find((x): x is Exclude<SourceView, { t: 'user' }> => x.t !== 'user');
        unitId = first?.unit_id ?? null;
      } else {
        unitId = target.unit_id;
      }
      if (unitId) {
        const [u, l] = await Promise.all([
          this.ctx.backend.unit(this.ctx.pid, unitId, this.ctx.signal),
          this.ctx.backend.lines(this.ctx.pid, unitId, { from: 0, count: 400 }, this.ctx.signal),
        ]);
        if (this.target === target) {
          this.unit = u;
          this.lines = l;
        }
      }
    } catch (e) {
      if (!isAbort(e) && this.target === target) this.error = e;
    }
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'presentation') void this.load();
  }

  dispose(): void {}
}
