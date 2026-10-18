/**
 * Export (Entwurf api-export, Briefing 5.12). Besitzer: ui.
 *
 * - `/exports` beim Öffnen des Dialogs und nach dem Ende eines Exports; SSE `progress` mit
 *   `kind: 'export'` zeigt Schritt und Prozent (feste Texte, im Client übersetzt).
 * - Klartext gibt es hier nicht (der Server lehnt `klartext: true` mit 403 ab); der Dialog nennt
 *   nur den Befehl im Terminal.
 */
import type { ExportEntry, ExportsView, ExportTemplate, PhasesView, StreamEvent } from '../api/types';
import { errorText, isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export interface ExportProgress {
  job_id: string;
  status: 'running' | 'done' | 'failed';
  pct: number | null;
  message: string | null;
}

/** Fester Text zum Schritt (der Server sendet dieselben deutschen Texte; sie werden nur zugeordnet). */
export function exportStepKey(p: ExportProgress): 'export.step.collect' | 'export.step.write' | 'export.step.done' | 'export.step.failed' {
  if (p.status === 'failed') return 'export.step.failed';
  if (p.status === 'done') return 'export.step.done';
  if (p.message === 'Dateien schreiben' || (p.pct ?? 0) >= 40) return 'export.step.write';
  return 'export.step.collect';
}

/** Befehle ohne Phase (im Writeup «Nicht zugeordnet»). */
export function openPhases(v: PhasesView | null): number {
  return v ? v.commands.filter((c) => c.phase === null).length : 0;
}

export class ExportStore implements ProjectPart {
  view = $state.raw<ExportsView | null>(null);
  loadError = $state<string | null>(null);
  progress = $state.raw<ExportProgress | null>(null);
  error = $state<string | null>(null);
  result = $state.raw<ExportEntry | null>(null);
  starting = $state(false);
  private known = new Set<string>();

  constructor(private readonly ctx: ProjectCtx) {}

  /** Nicht beim Öffnen des Projekts: erst der Dialog lädt die Liste. */
  async load(): Promise<void> {}

  async refresh(): Promise<void> {
    try {
      const v = await this.ctx.backend.exports(this.ctx.pid, this.ctx.signal);
      this.view = v;
      this.loadError = null;
      if (v.running && (!this.progress || this.progress.job_id !== v.running.job_id)) {
        this.progress = { job_id: v.running.job_id, status: 'running', pct: v.running.pct, message: null };
      }
      for (const e of v.exports) this.known.add(e.export_id);
    } catch (e) {
      if (!isAbort(e)) this.loadError = errorText(e, 'export.listFailed');
    }
  }

  phases(template: ExportTemplate): Promise<PhasesView> {
    return this.ctx.backend.exportPhases(this.ctx.pid, template, this.ctx.signal);
  }

  get running(): boolean {
    return this.starting || this.progress?.status === 'running';
  }

  async start(template: ExportTemplate): Promise<boolean> {
    if (this.running || this.ctx.app.offline) return false;
    this.starting = true;
    this.error = null;
    this.result = null;
    try {
      const r = await this.ctx.backend.startExport(this.ctx.pid, template);
      // Das erste `progress` kann vor der Antwort eintreffen; dann gilt es.
      if (this.progress?.job_id !== r.job_id) this.progress = { job_id: r.job_id, status: 'running', pct: 0, message: null };
      return true;
    } catch (e) {
      if (!isAbort(e)) this.error = errorText(e, 'export.failedPrefix');
      return false;
    } finally {
      this.starting = false;
    }
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name !== 'progress' || ev.data.kind !== 'export') return;
    const d = ev.data;
    const status = d.status === 'done' || d.status === 'failed' ? d.status : 'running';
    this.progress = { job_id: d.job_id, status, pct: d.pct, message: d.message };
    if (status === 'done') void this.afterDone();
    if (status === 'failed') this.error = null;
  }

  private async afterDone(): Promise<void> {
    const before = new Set(this.known);
    await this.refresh();
    this.result = this.view?.exports.find((e) => !before.has(e.export_id)) ?? this.view?.exports[0] ?? null;
  }

  dispose(): void {}
}
