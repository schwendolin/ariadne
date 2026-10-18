/**
 * Texte der Belegansicht (Screen 7, Briefing 5.6): Kontext als Zeile, «Als Beleg kopieren» als
 * Markdown-Block, Dateiname für «Ganzes Log», Bezug fürs Finding. Besitzer: ui-verlauf.
 *
 * Alles hier ist Text für die Zwischenablage des Macs bzw. für Beschriftungen, nie HTML. Werte aus
 * Zieldaten gehen durch `visible()` (Steuerzeichen sichtbar). Secrets sind schon vom Server durch
 * «••••••••» ersetzt (im Präsentationsmodus alle Secret-Bereiche): kopiert wird genau das, was die
 * Ansicht zeigt.
 */
import type { EvidenceRefIn, LogLine, StageView, UnitView } from '../api/types';
import { t } from '../i18n';
import { visible } from '../safe/displaySafe';
import type { EvidenceTarget } from '../url/state.svelte';
import { termName } from '../util/format';

const KIND: Record<string, string> = {
  local: '', su: 'su', ssh: 'ssh', winrm: 'winrm', remote: 'remote', revshell: 'Reverse Shell', msf: 'msf',
  meterpreter: 'meterpreter', db: 'Datenbank', unknown: 'unbekannt',
};

/** «Kali › 192.168.56.101 [msf] (auto)» */
export function stackText(stack: StageView[]): string {
  const parts = ['Kali'];
  for (const s of stack.filter((x) => x.depth > 0)) {
    let p = s.host_label ? visible(s.host_label) : '?';
    if (KIND[s.kind]) p += ` [${KIND[s.kind]}]`;
    if (s.user) p += ` (${visible(s.user)})`;
    if (s.auto) p += ` (${t('common.auto')})`;
    parts.push(p);
  }
  return parts.join(' › ');
}

/** «Zeile 6» bzw. «Zeilen 45 bis 48» (für Menschen ab 1 gezählt) */
export function linesLabel(lines: [number, number] | null): string | null {
  if (!lines) return null;
  return lines[0] === lines[1] ? t('ev.copyLine', { n: lines[0] + 1 }) : t('ev.copyLines', { from: lines[0] + 1, to: lines[1] + 1 });
}

/** Beschriftung eines Belegs («T2 msf · msfconsole -q · Zeilen 45 bis 48») */
export function evidenceLabel(unit: UnitView | null, lines: [number, number] | null, value: string | null = null): string {
  const parts: string[] = [];
  if (unit?.terminal) parts.push(termName(unit.terminal));
  if (unit) parts.push([...visible(unit.title)].slice(0, 80).join(''));
  const l = linesLabel(lines);
  if (l) parts.push(l);
  if (value) parts.push([...visible(value)].slice(0, 60).join(''));
  return parts.join(' · ') || t('ev.title');
}

/** Bezug fürs Finding (d.finding.create / evidence.add) */
export function refFor(target: EvidenceTarget, marked: [number, number] | null): EvidenceRefIn {
  if (target.kind === 'claim') return { claim_key: target.claim_key };
  return marked ? { unit_id: target.unit_id, lines: marked } : { unit_id: target.unit_id };
}

/**
 * «Als Beleg kopieren · Mac»: Markdown-Block mit Kopf (Quelle, Zeit, Kontext, Hash-Kette) und den
 * Zeilen mit Nummern. Ohne Zeilenumbruch am Ende.
 */
export function evidenceMarkdown(opts: {
  head: string;
  time: string;
  context: string | null;
  chainOk: boolean;
  lines: LogLine[];
}): string {
  const meta = [opts.time, opts.context, opts.chainOk ? `${t('ev.k.chain')} ${t('ev.chainOk')}` : null].filter(Boolean).join(' · ');
  const width = String(Math.max(1, ...opts.lines.map((l) => l.n + 1))).length;
  const body = opts.lines.map((l) => `${String(l.n + 1).padStart(width, ' ')}  ${visible(l.text)}`).join('\n');
  const fence = body.includes('```') ? '~~~' : '```';
  return `**${t('ev.copyHead')}** ${visible(opts.head)}\n${meta}\n\n${fence}text\n${body}\n${fence}`;
}

/** Dateiname für «Ganzes Log»: nie aus Zieldaten, nur ein Hash der unit_id */
export function logFileName(unitId: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;
  for (const ch of unitId) {
    h1 = Math.imul(h1 ^ ch.charCodeAt(0), 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ ch.charCodeAt(0), 0x85ebca6b) >>> 0;
  }
  return `unit-${(h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0')).slice(0, 12)}.txt`;
}
