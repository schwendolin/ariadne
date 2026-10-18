/**
 * KI-Denkanstoss auf Knopfdruck (Entwurf api-ki, Briefing 5.2). Besitzer: ui.
 *
 * - `/ai/status` beim Öffnen, nach `presentation` und nach jedem Ende eines Auftrags.
 * - SSE `progress` mit `kind: 'ai'` schreibt Schritt, Tokens, Maskierung und Kosten in den Auftrag;
 *   beim Ende holt der Store `/ai/jobs/{id}` (Ablehnung wörtlich, Zahlen) und den Status. Neue
 *   Denkanstösse bringt `/next` (Ereignis `suggestion`), die Spalte lädt selbst nach.
 * - Budget voll: der Server antwortet 422 `budget_confirm`; dann fragt die Spalte nach und sendet
 *   mit `confirm_budget: true`.
 */
import type { AiJob, AiStatus, StreamEvent } from '../api/types';
import { isApiError } from '../api/client';
import { needsBudgetConfirm } from '../ai/view';
import { errorText, isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export class AiStore implements ProjectPart {
  status = $state.raw<AiStatus | null>(null);
  job = $state.raw<AiJob | null>(null);
  /** Bestätigung bei 100 % Budget offen */
  confirm = $state(false);
  starting = $state(false);
  /** fester Fehlertext der letzten Anfrage (nie Server- oder Modelltext) */
  error = $state<string | null>(null);
  /** Auftrag dieses Tabs: Ergebnis zeigen; fremde Aufträge (anderer Tab) nur als «läuft» */
  private ownJob: string | null = null;

  constructor(private readonly ctx: ProjectCtx) {}

  async load(): Promise<void> {
    try {
      const s = await this.ctx.backend.aiStatus(this.ctx.pid, this.ctx.signal);
      this.status = s;
      if (s.job && (!this.job || this.job.job_id === s.job.job_id || s.job.started_at >= this.job.started_at)) this.job = s.job;
    } catch (e) {
      if (!isAbort(e)) this.status = this.status ?? null;
    }
  }

  async request(confirmBudget = false): Promise<boolean> {
    if (this.starting || this.ctx.app.offline) return false;
    this.starting = true;
    this.error = null;
    try {
      const job = await this.ctx.backend.aiRequest(this.ctx.pid, confirmBudget);
      this.ownJob = job.job_id;
      this.job = job;
      this.confirm = false;
      void this.load();
      return true;
    } catch (e) {
      if (isAbort(e)) return false;
      if (isApiError(e, 'validation') && needsBudgetConfirm(e.detail)) {
        this.confirm = true;
        return false;
      }
      this.error = isApiError(e, 'conflict') ? null : errorText(e, 'next.ai.failedPrefix');
      void this.load();
      return false;
    } finally {
      this.starting = false;
    }
  }

  cancelConfirm(): void {
    this.confirm = false;
  }

  dismissResult(): void {
    if (this.job && this.job.status !== 'queued' && this.job.status !== 'running') this.job = null;
    this.error = null;
  }

  isOwn(job: AiJob | null): boolean {
    return !!job && job.job_id === this.ownJob;
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'presentation') {
      void this.load();
      return;
    }
    if (ev.name !== 'progress' || ev.data.kind !== 'ai') return;
    const d = ev.data;
    const cur = this.job && this.job.job_id === d.job_id ? this.job : null;
    if (cur) {
      this.job = {
        ...cur,
        status: d.status === 'done' || d.status === 'failed' ? cur.status : 'running',
        tokens_in: d.tokens_in ?? cur.tokens_in,
        tokens_out: d.tokens_out ?? cur.tokens_out,
        tokens_estimate: d.tokens_estimate ?? cur.tokens_estimate,
        masked: d.masked ?? cur.masked,
        cost_usd: d.cost_usd ?? cur.cost_usd,
        budget_level: d.budget_level ?? cur.budget_level,
        step: d.pct === null ? cur.step : d.pct >= 90 ? 'pruefung' : d.pct >= 40 ? 'anfrage' : 'lagebild',
      };
    }
    if (d.status === 'done' || d.status === 'failed') void this.finish(d.job_id);
    else if (!cur) void this.load();
  }

  private async finish(jobId: string): Promise<void> {
    try {
      this.job = await this.ctx.backend.aiJob(this.ctx.pid, jobId, this.ctx.signal);
    } catch (e) {
      if (isAbort(e)) return;
    }
    await this.load();
  }

  dispose(): void {}
}
