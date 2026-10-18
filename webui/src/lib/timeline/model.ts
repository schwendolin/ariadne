/**
 * Reine Hilfen der Zeitachse (Screen 6, Briefing 5.5, web-api.md 10 und 18.8). Besitzer: ui-verlauf.
 *
 * - Filter aus der URL (`typ`, `terminal`, `hostf`) und zurück.
 * - Welche Zeilen sichtbar sind: Ohne Typfilter holt die Zeitachse alle Typen samt Eingaben, zeigt
 *   von den Eingaben aber nur die verdeckten (E104); sichtbare Eingaben stünden doppelt neben ihrem
 *   Befehl (web-api.md 10). Mit dem Typ «Eingaben» im Filter erscheinen alle.
 * - Welche Zeile `zeile` meint: die TimelineItem.id, bei Befehlen auch cmd_id, cmd_ref oder unit_id
 *   (Vertrag 1.5, Punkt 4: Scope-Warnung und Host-Detail führen mit der cmd_id hierher).
 * - Ergebnis pro Befehl als fester Text mit Zahlen («1 Host, 23 Services · 141 Werte übernommen»).
 */
import type { TimelineItem, TimelineType } from '../api/types';
import { t } from '../i18n';
import type { EvidenceTarget } from '../url/state.svelte';

export const ALL_TYPES: TimelineType[] = ['command', 'segment', 'file', 'keystep', 'context', 'decision', 'gap', 'project', 'input'];

export interface TimelineFilter {
  /** null = alle Typen (verdeckte Eingaben inklusive) */
  types: TimelineType[] | null;
  terminal: string | null;
  host: string | null;
}

export const NO_FILTER: TimelineFilter = { types: null, terminal: null, host: null };

const TERMINAL_ID = /^[0-9a-f-]{8,64}$/i;

/** Filter aus den URL-Parametern; unbekannte Typen und ungültige Kennungen fallen weg. */
export function filterFromParams(typ: string | null, terminal: string | null, host: string | null): TimelineFilter {
  let types: TimelineType[] | null = null;
  if (typ) {
    const wanted = new Set(typ.split(',').map((s) => s.trim()));
    const list = ALL_TYPES.filter((x) => wanted.has(x));
    types = list.length > 0 && list.length < ALL_TYPES.length ? list : null;
  }
  return {
    types,
    terminal: terminal && TERMINAL_ID.test(terminal) ? terminal : null,
    host: host && host.length <= 300 ? host : null,
  };
}

export function filterToParams(f: TimelineFilter): { typ: string | null; terminal: string | null; hostf: string | null } {
  return { typ: f.types ? f.types.join(',') : null, terminal: f.terminal, hostf: f.host };
}

export function sameFilter(a: TimelineFilter, b: TimelineFilter): boolean {
  return (a.types ?? []).join(',') === (b.types ?? []).join(',') && a.terminal === b.terminal && a.host === b.host;
}

export function isFiltered(f: TimelineFilter): boolean {
  return f.types !== null || f.terminal !== null || f.host !== null;
}

/** Sichtbare Zeilen: sichtbare Eingaben nur mit ausdrücklichem Typfilter. */
export function visibleRows(items: TimelineItem[], f: TimelineFilter): TimelineItem[] {
  if (f.types?.includes('input')) return items;
  return items.filter((it) => it.type !== 'input' || it.input.hidden || it.input.redacted);
}

/** Wert für `zeile` in der URL (Vertrag 1.5, Punkt 4). */
export function rowKey(it: TimelineItem): string {
  return it.type === 'command' ? it.cmd.cmd_id : it.id;
}

export function rowMatches(it: TimelineItem, zeile: string | null): boolean {
  if (!zeile) return false;
  if (it.id === zeile) return true;
  if (it.type === 'command') return it.cmd.cmd_id === zeile || it.cmd.cmd_ref === zeile || it.unit_id === zeile;
  if (it.type === 'segment' || it.type === 'file') return it.unit_id === zeile;
  return false;
}

/** Belegansicht zu einer Zeile (Einheit), sonst null. */
export function evidenceOf(it: TimelineItem): EvidenceTarget | null {
  if (it.type === 'command' || it.type === 'segment' || it.type === 'file') return { kind: 'unit', unit_id: it.unit_id, lines: null };
  return null;
}

/** Ob «Rückgängig pro Befehl» angeboten wird: Befehl mit übernommenen Werten, nicht misstraut. */
export function canUndo(it: TimelineItem): boolean {
  return it.type === 'command' && it.distrusted === null && (it.adopted > 0 || it.result.values > 0);
}

/** «1 Host, 23 Services · 141 Werte übernommen», «+1 Host · 15 Werte übernommen · 1 Widerspruch»,
 *  «0 übernommen, +17 ausserhalb» (Screen 6). Leer, wenn der Befehl läuft und noch nichts kam. */
export function resultText(it: Extract<TimelineItem, { type: 'command' }>): string {
  const r = it.result;
  const running = it.cmd.ended_at === null;
  const parts: string[] = [];
  if (r.hosts_new > 0 && r.services > 0) {
    parts.push(`${t('tl.res.hostsNewFirst', { n: r.hosts_new })}, ${t('tl.res.services', { n: r.services })}`);
  } else if (r.hosts_new > 0) {
    parts.push(t('tl.res.hostsNew', { n: r.hosts_new }));
  } else if (r.services > 0) {
    parts.push(t('tl.res.services', { n: r.services }));
  }
  if (r.values > 0) {
    parts.push(t('tl.res.values', { n: r.values }));
  } else if (r.out_of_scope > 0) {
    parts.push(`${t('tl.res.none')}, ${t('tl.res.outside', { n: r.out_of_scope })}`);
  } else if (!running && parts.length === 0) {
    parts.push(t('tl.res.none'));
  }
  if (r.conflicts > 0) parts.push(t('tl.res.conflicts', { n: r.conflicts }));
  return parts.join(' · ');
}

/** Kurzname eines Befehls für Texte: erstes Wort und Zeit («nmap 14:02»). */
export function shortCommand(text: string | null, time: string): string {
  const word = (text ?? '').trim().split(/\s+/)[0] ?? '';
  const w = [...word].slice(0, 24).join('');
  return w ? `${w} ${time}` : time;
}

/** Vergleich der Shim-Zeit (Dezimalstrings über 2^53), neueste zuerst. */
export function newerFirst(a: TimelineItem, b: TimelineItem): number {
  const x = BigInt(/^\d+$/.test(a.ts_ns) ? a.ts_ns : '0');
  const y = BigInt(/^\d+$/.test(b.ts_ns) ? b.ts_ns : '0');
  return x === y ? 0 : x > y ? -1 : 1;
}

/** Neue erste Seite in die geladene Liste einfügen: gleiche ids ersetzen, Reihenfolge nach Zeit. */
export function mergeItems(old: TimelineItem[], fresh: TimelineItem[]): TimelineItem[] {
  const byId = new Map<string, TimelineItem>();
  for (const it of old) byId.set(it.id, it);
  for (const it of fresh) byId.set(it.id, it);
  return [...byId.values()].sort(newerFirst);
}
