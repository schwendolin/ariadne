import { isApiError, type ClientErrorCode } from '../api/client';
import { t } from '../i18n';

/** Fehlertext über den stabilen Code, nie über den Servertext. */
export function errText(e: unknown): string {
  return isApiError(e) ? t(`err.${e.code}`) : t('err.internal');
}

export function codeText(code: string | null): string {
  if (!code) return '';
  const known: ClientErrorCode[] = [
    'unauthorized', 'forbidden', 'policy', 'budget', 'not_found', 'no_project', 'project_mismatch', 'conflict', 'locked',
    'validation', 'rate_limited', 'llm_unavailable', 'internal', 'network', 'aborted', 'timeout', 'bad_response', 'http',
  ];
  return (known as string[]).includes(code) ? t(`err.${code as ClientErrorCode}`) : t('err.internal');
}
