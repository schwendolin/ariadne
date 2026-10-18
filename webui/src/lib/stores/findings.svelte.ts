/**
 * Findings (E113, Screen 8, web-api.md 18.5). Besitzer: ui-verlauf.
 *
 * Gerüst aus Phase 1: lädt die Liste und nach `changes` mit `entities.finding` neu.
 */
import type { ChangeSet, EvidenceRefIn, FindingDetail, FindingSummary, StreamEvent } from '../api/types';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export class FindingsStore implements ProjectPart {
  list = $state.raw<FindingSummary[]>([]);
  current = $state.raw<FindingDetail | null>(null);
  loaded = $state(false);
  error = $state<unknown>(null);
  /** «Als Finding» aus der Belegansicht: Beleg für das neue Formular (`?finding=neu`) */
  draftFrom = $state.raw<EvidenceRefIn | null>(null);

  constructor(private readonly ctx: ProjectCtx) {}

  async load(): Promise<void> {
    try {
      this.list = await this.ctx.backend.findings(this.ctx.pid, this.ctx.signal);
      this.loaded = true;
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    }
  }

  async open(findingId: string | null): Promise<void> {
    if (!findingId || findingId === 'neu') {
      this.current = null;
      return;
    }
    try {
      this.current = await this.ctx.backend.finding(this.ctx.pid, findingId, this.ctx.signal);
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    }
  }

  onChanges(cs: ChangeSet): void {
    if (cs.changes.some((c) => c.entity === 'finding' || c.entity === 'claim' || c.entity === 'unit')) void this.load();
  }

  onEvent(_ev: StreamEvent): void {}

  dispose(): void {}
}
