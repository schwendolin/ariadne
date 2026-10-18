/**
 * Reiter Terminals (Briefing 5.4, Screen 5, web-api.md 5). Besitzer: ui-verlauf.
 *
 * Gerüst aus Phase 1: lädt `/terminals` und nach dem Ereignis `terminal` neu. Pause und
 * Fortsetzen laufen über AppState (gemeinsam mit dem Popover der Aufnahme).
 */
import type { StreamEvent, Terminal } from '../api/types';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export class TerminalsStore implements ProjectPart {
  list = $state.raw<Terminal[]>([]);
  loaded = $state(false);
  error = $state<unknown>(null);

  constructor(private readonly ctx: ProjectCtx) {}

  async load(): Promise<void> {
    try {
      this.list = await this.ctx.backend.terminals(this.ctx.signal);
      this.loaded = true;
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    }
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'terminal' || ev.name === 'presentation') void this.load();
  }

  dispose(): void {}
}
