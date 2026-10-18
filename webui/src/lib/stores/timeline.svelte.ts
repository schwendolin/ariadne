/**
 * Zeitachse und Warteliste (Briefing 5.5, 5.8, Screen 6, web-api.md 10 und 13). Besitzer: ui-verlauf.
 *
 * Gerüst aus Phase 1: lädt die erste Seite und die Warteliste. Der Besitzer ergänzt Filter aus
 * der URL, «Ältere laden», Auswahl (`zeile`), Rückgängig inline, Eingaben mit Aufdecken.
 */
import type { ChangeSet, PendingResponse, StreamEvent, TimelineItem } from '../api/types';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export class TimelineStore implements ProjectPart {
  items = $state.raw<TimelineItem[]>([]);
  nextCursor = $state<string | null>(null);
  pending = $state.raw<PendingResponse | null>(null);
  loaded = $state(false);
  error = $state<unknown>(null);
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly ctx: ProjectCtx) {}

  async load(): Promise<void> {
    try {
      const [page, pending] = await Promise.all([
        this.ctx.backend.timeline(this.ctx.pid, { limit: 200 }, this.ctx.signal),
        this.ctx.backend.pending(this.ctx.pid, this.ctx.signal),
      ]);
      this.items = page.items;
      this.nextCursor = page.next_cursor;
      this.pending = pending;
      this.loaded = true;
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    }
  }

  private reloadSoon(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.load(), 300);
  }

  onChanges(_cs: ChangeSet): void {
    this.reloadSoon();
  }

  onEvent(ev: StreamEvent): void {
    if ((ev.name === 'terminal' && ev.data.change === 'command') || ev.name === 'presentation') this.reloadSoon();
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
  }
}
