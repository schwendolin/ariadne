/**
 * «Neu seit» (E106, web-api.md 18.3, BEHAVIOR «Live-Daten»). Besitzer: ui-fundament.
 *
 * Beim `visibilitychange` auf hidden meldet der Client dem Server mit `PUT /ui/seen` (keepalive),
 * dass der Tab unsichtbar wird; der Server nimmt seine Uhrzeit. Bei der Rückkehr lädt der Store
 * `GET /ui/seen` und zeigt «+N seit HH:MM». Der Wert übersteht Neuladen, weil er auf dem Server
 * liegt: Wird die Seite entladen (Neuladen, Tab zu; `pagehide` kommt vor dem letzten
 * `visibilitychange`), meldet der Store nichts, sonst setzte jedes Neuladen die Marke auf null
 * zurück. Ein Klick auf die Marke ruft `pulse()`.
 */
import type { SeenView, StreamEvent } from '../api/types';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export class SeenStore implements ProjectPart {
  view = $state.raw<SeenView | null>(null);
  private timer: ReturnType<typeof setTimeout> | null = null;
  private unloading = false;
  private readonly onVisibility = () => {
    if (document.visibilityState === 'hidden') {
      if (!this.unloading) void this.mark();
    } else {
      void this.load();
    }
  };
  private readonly onPageHide = () => {
    this.unloading = true;
  };
  private readonly onPageShow = () => {
    this.unloading = false;
  };

  constructor(private readonly ctx: ProjectCtx) {
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', this.onVisibility);
      window.addEventListener('pagehide', this.onPageHide);
      window.addEventListener('pageshow', this.onPageShow);
    }
  }

  get count(): number {
    return this.view?.new?.count ?? 0;
  }

  async load(): Promise<void> {
    try {
      this.view = await this.ctx.backend.seen(this.ctx.pid, this.ctx.signal);
    } catch (e) {
      if (!isAbort(e)) this.view = this.view ?? null;
    }
  }

  async mark(): Promise<void> {
    if (this.ctx.signal.aborted) return;
    try {
      await this.ctx.backend.markSeen(this.ctx.pid);
    } catch {
      // Tab geht weg oder Verbindung fehlt: der alte Bezugspunkt bleibt (bewusst still).
    }
  }

  /** Lässt das Neue einmal pulsieren (Klick auf «+N seit»). */
  pulse(): void {
    this.ctx.app.ui.pulse(this.view?.new ?? null);
  }

  onEvent(ev: StreamEvent): void {
    // Neues, das während der Anzeige kommt, sammelt die Marke («sammelt Neues, statt zu blinken»).
    if (ev.name === 'changes' || ev.name === 'inbox') {
      if (this.timer) clearTimeout(this.timer);
      this.timer = setTimeout(() => void this.load(), 1000);
    }
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this.onVisibility);
      window.removeEventListener('pagehide', this.onPageHide);
      window.removeEventListener('pageshow', this.onPageShow);
    }
  }
}
