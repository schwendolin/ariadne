/**
 * Zeitanzeige (Briefing 2.3, BEHAVIOR): Lokalzeit (CEST), UTC auf Abruf (`?utc=1`), Beleg auf ms
 * genau. Besitzer: ui-fundament.
 */

const LOCALE = 'de-CH';

function parse(ts: string | number | Date): Date {
  return ts instanceof Date ? ts : new Date(ts);
}

function valid(d: Date): boolean {
  return !Number.isNaN(d.getTime());
}

/** «16:54» (bzw. «16:54:12» mit Sekunden); `utc` zeigt UTC. */
export function hhmm(ts: string | number | Date | null | undefined, opts: { seconds?: boolean; utc?: boolean } = {}): string {
  if (ts === null || ts === undefined) return '–';
  const d = parse(ts);
  if (!valid(d)) return '–';
  return d.toLocaleTimeString(LOCALE, {
    hour: '2-digit',
    minute: '2-digit',
    ...(opts.seconds ? { second: '2-digit' } : {}),
    ...(opts.utc ? { timeZone: 'UTC' } : {}),
  });
}

/** Zeit auf Millisekunden für die Belegansicht: «2026-10-08 16:45:12.384 CEST». */
export function exactTime(ts: string | null | undefined, utc = false): string {
  if (!ts) return '–';
  const d = parse(ts);
  if (!valid(d)) return '–';
  const tz = utc ? 'UTC' : undefined;
  const date = d.toLocaleDateString('sv-SE', tz ? { timeZone: tz } : {});
  const time = d.toLocaleTimeString(LOCALE, { hour: '2-digit', minute: '2-digit', second: '2-digit', ...(tz ? { timeZone: tz } : {}) });
  const ms = String(d.getUTCMilliseconds()).padStart(3, '0');
  return `${date} ${time}.${ms} ${utc ? 'UTC' : zoneName(d)}`;
}

/** Kürzel der lokalen Zeitzone («CEST»), sonst «Lokalzeit». */
export function zoneName(d: Date = new Date()): string {
  try {
    const part = new Intl.DateTimeFormat('de-CH', { timeZoneName: 'short' }).formatToParts(d).find((p) => p.type === 'timeZoneName');
    const v = part?.value ?? '';
    if (v === 'MESZ') return 'CEST';
    if (v === 'MEZ') return 'CET';
    return v || 'Lokalzeit';
  } catch {
    return 'Lokalzeit';
  }
}

/** UTC für Tooltips: «2026-10-08 14:54:01 UTC». */
export function utcTooltip(ts: string | number | Date): string {
  const d = parse(ts);
  if (!valid(d)) return '';
  return `${d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`;
}

/** Dauer als «0 h 03 min» (Leerlauf, Briefing 4.2). */
export function hoursMinutes(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h} h ${String(m).padStart(2, '0')} min`;
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

/** Ganze Minuten bis `ts` (für «Pause bis 17:00», Countdown), nie negativ. */
export function minutesUntil(ts: string | null, now: number = Date.now()): number {
  if (!ts) return 0;
  const d = parse(ts).getTime();
  return Number.isNaN(d) ? 0 : Math.max(0, Math.ceil((d - now) / 60000));
}
