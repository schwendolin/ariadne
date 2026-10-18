/**
 * Kleine Formatierer für wiederkehrende Anzeigen. Besitzer: ui-fundament.
 * Ergebnisse, die Zieldaten enthalten, gehen trotzdem über `Txt`/`displaySafe`.
 */
import type { TermRef, TerminalState } from '../api/types';
import { num, t } from '../i18n';

/** «T1 scan», «T2», sonst die Kurz-ID. */
export function termName(ref: Pick<TermRef, 'ordinal' | 'label'> & { terminal_id?: string; short_id?: string } | null | undefined): string {
  if (!ref) return '–';
  const base = ref.ordinal !== null && ref.ordinal !== undefined ? `T${ref.ordinal}` : (ref.short_id ?? ref.terminal_id?.slice(-8) ?? '–');
  return ref.label ? `${base} ${ref.label}` : base;
}

/**
 * Nur «T1» (ohne Namen). Ohne Nummer (held, ungebunden) das Terminal-Gerät («pts/4»), sonst die
 * Kurz-ID (letzte 8 Zeichen).
 */
export function termShort(
  ref: (Pick<TermRef, 'ordinal'> & { terminal_id?: string; short_id?: string; tty?: string | null }) | null | undefined,
): string {
  if (!ref) return '–';
  if (ref.ordinal !== null && ref.ordinal !== undefined) return `T${ref.ordinal}`;
  const tty = typeof ref.tty === 'string' ? /^\/dev\/(pts\/\d{1,5}|tty\w{1,8})$/.exec(ref.tty)?.[1] : undefined;
  return tty ?? ref.short_id ?? ref.terminal_id?.slice(-8) ?? '–';
}

export function termRefOf(ts: TerminalState): TermRef {
  return { terminal_id: ts.terminal_id, ordinal: ts.ordinal, label: ts.label };
}

/** Bytes als «2 KB», «41 KB», «1,2 MB». */
export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '–';
  if (n < 1024) return `${num(n)} B`;
  if (n < 1024 * 1024) return `${num(Math.round(n / 1024))} KB`;
  return `${(n / (1024 * 1024)).toLocaleString('de-CH', { maximumFractionDigits: 1 })} MB`;
}

/** Kurzform einer IPv4 im selben Netz: «.101» (nur Anzeige in engen Stellen). */
export function shortIp(label: string): string {
  const m = /^\d+\.\d+\.\d+\.(\d+)$/.exec(label);
  return m ? `.${m[1]}` : label;
}

/**
 * Aufnahme-Zusammenfassung der Kopfzeile (Briefing 4.2, E107): «2 von 3 Terminals nehmen auf»,
 * kompakt unter 1280 px «2 von 3 nehmen auf». Grammatik für 1 und ohne Terminals.
 */
export function recSummary(on: number, total: number, compact = false): string {
  if (total <= 0) return compact ? t('rec.noneShort') : t('rec.none');
  if (compact) return on === 1 ? t('rec.summaryShortOne', { on, total }) : t('rec.summaryShort', { on, total });
  if (total === 1) return on === 1 ? t('rec.summarySingle', { on }) : t('rec.summarySingleOff');
  return on === 1 ? t('rec.summaryOne', { on, total }) : t('rec.summary', { on, total });
}

/** «15 Minuten», «1 Minute» (gerundet, nie negativ). */
export function minutesText(seconds: number): string {
  const n = Math.max(0, Math.round(seconds / 60));
  return t('time.minutes', { n });
}

/** Ende des Leerlaufs als «12 h» bzw. «45 Minuten». */
export function endAfterText(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s >= 3600 && s % 3600 === 0) return t('time.hours', { n: s / 3600 });
  if (s >= 3600) return t('time.hours', { n: (s / 3600).toLocaleString('de-CH', { maximumFractionDigits: 1 }) });
  return minutesText(s);
}
