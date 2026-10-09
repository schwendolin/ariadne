/** Zeitanzeige: Lokalzeit in der UI, UTC im Tooltip (Architektur 7.4). */

const LOCALE = 'de-CH';

function parse(ts: string | number | Date): Date {
  return ts instanceof Date ? ts : new Date(ts);
}

export function timeLocal(ts: string | number | Date, seconds = false): string {
  const d = parse(ts);
  if (Number.isNaN(d.getTime())) return '–';
  return d.toLocaleTimeString(LOCALE, { hour: '2-digit', minute: '2-digit', ...(seconds ? { second: '2-digit' } : {}) });
}

export function dateTimeLocal(ts: string | number | Date): string {
  const d = parse(ts);
  if (Number.isNaN(d.getTime())) return '–';
  return d.toLocaleString(LOCALE, { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function utcTooltip(ts: string | number | Date): string {
  const d = parse(ts);
  if (Number.isNaN(d.getTime())) return '';
  return `${d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`;
}

/** Laufzeit als H:MM:SS bzw. M:SS. */
export function duration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const mm = String(m).padStart(h > 0 ? 2 : 1, '0');
  const ss = String(s).padStart(2, '0');
  return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

export function dayKey(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleDateString(LOCALE, { weekday: 'long', day: '2-digit', month: '2-digit', year: 'numeric' });
}
