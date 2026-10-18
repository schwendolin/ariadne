/**
 * Favicon und Tab-Titel (BEHAVIOR «Favicon», README «Logo»): Standardzeichen; gibt es offene
 * Klärungen, ein Punkt in --attention und der Titel «ms2 · 2 zu klären». Die beiden SVG-Dateien
 * liegen in public/ (kein data:-URI, CSP img-src 'self'). Besitzer: ui-fundament.
 */
import { t } from '../i18n';

export const FAVICON = '/favicon.svg';
export const FAVICON_ATTENTION = '/favicon-attention.svg';

export function tabTitle(slug: string | null, open: number): string {
  if (!slug) return t('app.title');
  return open > 0 ? t('app.titleOpen', { slug, n: open }) : slug;
}

/** Setzt Titel und Favicon (nur über das vorhandene <link rel="icon">, kein neues Element). */
export function applyTabState(doc: Document, slug: string | null, open: number): void {
  doc.title = tabTitle(slug, open);
  const link = doc.querySelector<HTMLLinkElement>('link[rel="icon"]');
  const want = open > 0 ? FAVICON_ATTENTION : FAVICON;
  if (link && link.getAttribute('href') !== want) link.href = want;
}
