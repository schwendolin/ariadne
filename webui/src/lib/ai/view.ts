/**
 * Anzeige des KI-Zustands in der Spalte (Briefing 5.2, D3, Entwurf api-ki). Reine Funktionen, damit
 * Vitest sie ohne Komponenten prüft. Besitzer: ui.
 *
 * - Knopf «Denkanstoss anfordern (KI)»: aktiv, wenn `/ai/status` `ready` meldet, keine Verbindung
 *   fehlt und kein Präsentationsmodus läuft; sonst gesperrt mit Grund (fester Text je `reason`).
 * - Zustand des Auftrags: läuft (mit Schritt, Tokens, Maskierung, Kosten), fertig (neue
 *   Denkanstösse, verworfene, Injection-Verdacht), abgelehnt (Ablehnung wörtlich, nur als Text),
 *   fehlgeschlagen (Anbieter weg und andere Fehler).
 * - Budget: Warnung ab 80 %, ab 100 % Bestätigung vor dem Senden.
 * Modelltexte (Ablehnung) bleiben Text; feste Texte kommen aus i18n, nie vom Server übernommen.
 */
import type { AiJob, AiReason, AiStatus } from '../api/types';
import { num, t, type MessageKey } from '../i18n';

export type AiPhase = 'idle' | 'running' | 'done' | 'refused' | 'failed';

export interface AiButton {
  enabled: boolean;
  /** Grund, wenn gesperrt (fester Text) */
  reason: string | null;
}

const REASONS: Record<AiReason, MessageKey> = {
  off: 'next.ai.reason.off',
  config: 'next.ai.reason.config',
  no_model: 'next.ai.reason.no_model',
  no_key: 'next.ai.reason.no_key',
  locked: 'next.ai.reason.locked',
  cloud_not_allowed: 'next.ai.reason.cloud_not_allowed',
  profile: 'next.ai.reason.profile',
  public_scope: 'next.ai.reason.public_scope',
  busy: 'next.ai.reason.busy',
};

export function aiPhase(job: AiJob | null): AiPhase {
  if (!job) return 'idle';
  if (job.status === 'queued' || job.status === 'running') return 'running';
  return job.status;
}

export function aiButton(status: AiStatus | null, job: AiJob | null, opts: { offline: boolean; presentation: boolean; starting: boolean }): AiButton {
  if (opts.offline) return { enabled: false, reason: t('err.network') };
  if (!status) return { enabled: false, reason: t('next.ai.reason.loading') };
  if (aiPhase(job) === 'running' || opts.starting) return { enabled: false, reason: t('next.ai.reason.busy') };
  if (opts.presentation) return { enabled: false, reason: t('next.ai.reason.presentation') };
  if (!status.ready) return { enabled: false, reason: t(status.reason ? REASONS[status.reason] : 'next.ai.reason.config') };
  return { enabled: true, reason: null };
}

/** Kosten in USD mit zwei bis drei Stellen («0,018 USD»). */
export function usd(v: number): string {
  return `${v.toLocaleString('de-CH', { minimumFractionDigits: 2, maximumFractionDigits: v < 0.1 ? 3 : 2 })} USD`;
}

/** Zeile unter dem Knopf: Schritt, Tokens, Maskierung, Kosten. */
export function aiFacts(job: AiJob): string[] {
  const out: string[] = [];
  const tin = job.tokens_in ?? job.tokens_estimate;
  if (tin !== null && tin !== undefined) out.push(t(job.tokens_in !== null ? 'next.ai.tokensIn' : 'next.ai.tokensEstimate', { n: num(tin) }));
  if (job.tokens_out !== null) out.push(t('next.ai.tokensOut', { n: num(job.tokens_out) }));
  out.push(t('next.ai.masked', { n: job.masked }));
  if (job.cost_usd !== null) out.push(usd(job.cost_usd));
  return out;
}

/** Schrittname (fester Text, nie der `message` des Servers ungeprüft). */
export function aiStepText(job: AiJob): string {
  switch (job.step) {
    case 'lagebild':
      return t('next.ai.step.lagebild');
    case 'anfrage':
      return t('next.ai.step.anfrage');
    case 'pruefung':
      return t('next.ai.step.pruefung');
    default:
      return t('next.ai.step.fertig');
  }
}

/** Ergebnis eines fertigen Auftrags. */
export function aiResultText(job: AiJob): string {
  if (job.status === 'done') {
    if (job.created === 0) return t('next.ai.noNew');
    return t('next.ai.created', { n: job.created });
  }
  if (job.status === 'refused') return t('next.ai.refused');
  switch (job.error) {
    case 'unreachable':
      return t(job.provider === 'local' ? 'next.ai.err.unreachableLocal' : 'next.ai.err.unreachable');
    case 'auth':
      return t('next.ai.err.auth');
    case 'schema':
      return t('next.ai.err.schema');
    case 'truncated':
      return t('next.ai.err.truncated');
    case 'project_changed':
      return t('next.ai.err.project_changed');
    default:
      return t('next.ai.err.internal');
  }
}

/** Budget-Hinweis: Warnung ab 80 %, voll ab 100 %. */
export function budgetText(status: AiStatus | null): { level: 'ok' | 'warn' | 'over'; text: string } | null {
  if (!status || status.provider === 'off') return null;
  const b = status.budget;
  const params = { pct: Math.round(b.pct), used: usd(b.used_usd), limit: usd(b.limit_usd) };
  if (b.level === 'over') return { level: 'over', text: t('next.ai.budgetOver', params) };
  if (b.level === 'warn') return { level: 'warn', text: t('next.ai.budgetWarn', params) };
  return { level: 'ok', text: t('next.ai.budgetOk', params) };
}

/** 422 mit `budget_confirm`: der Server will die Bestätigung bei 100 %. */
export function needsBudgetConfirm(detail: unknown): boolean {
  return Array.isArray(detail) && detail.some((d) => typeof d === 'object' && d !== null && (d as { type?: unknown }).type === 'budget_confirm');
}
