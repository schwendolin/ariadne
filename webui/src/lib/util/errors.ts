/**
 * Fehlertexte (Briefing 5.14, B.3): Die UI übersetzt nur über den stabilen Code, nie über den
 * Text des Servers, und nennt nie Zieldaten. Besitzer: ui-fundament.
 */
import { isApiError, type ClientErrorCode } from '../api/client';
import { t, type MessageKey } from '../i18n';

const KEYS: Record<ClientErrorCode, MessageKey> = {
  unauthorized: 'err.unauthorized',
  forbidden: 'err.forbidden',
  policy: 'err.policy',
  not_found: 'err.not_found',
  method: 'err.internal',
  no_project: 'err.no_project',
  project_mismatch: 'err.project_mismatch',
  conflict: 'err.conflict',
  too_large: 'err.too_large',
  host: 'err.forbidden',
  validation: 'err.validation',
  locked: 'err.locked',
  rate_limited: 'err.rate_limited',
  not_implemented: 'err.not_implemented',
  unavailable: 'err.unavailable',
  internal: 'err.internal',
  clipboard_tool: 'err.clipboard_tool',
  clipboard_session: 'err.clipboard_session',
  shot_display: 'err.shot_display',
  shot_wayland: 'err.shot_wayland',
  shot_window: 'err.shot_window',
  shot_region: 'err.shot_region',
  shot_failed: 'err.shot_failed',
  network: 'err.network',
  aborted: 'err.aborted',
  timeout: 'err.timeout',
  bad_response: 'err.internal',
  http: 'err.internal',
};

export function errorCode(e: unknown): ClientErrorCode {
  return isApiError(e) ? e.code : 'internal';
}

/** Fester deutscher Text für einen Fehler; `prefix` etwa «Entscheid nicht gespeichert». */
export function errorText(e: unknown, prefix?: MessageKey): string {
  const text = t(KEYS[errorCode(e)] ?? 'err.internal');
  return prefix ? `${t(prefix)}: ${text}` : text;
}

/** Abbrüche (Projektwechsel, Navigation) sind keine Fehler für die Anzeige. */
export function isAbort(e: unknown): boolean {
  return isApiError(e, 'aborted');
}
