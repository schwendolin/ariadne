/**
 * Titel der Denkanstösse in der Spalte (Korrekturen D6, D14). Besitzer: ui-karte.
 */
import type { Suggestion, TextPart } from '../api/types';

/**
 * Eingeklappte Zeile ohne Ziel-Anhang «(.101:21)» am Ende (Korrektur D6): Er stünde vor dem
 * Produkt und kürzte es («vsftpd 2.3.4 (.101:…»). Der aufgeklappte Titel behält ihn wie im Design.
 * Nur, wenn davor noch Zieldaten stehen; sonst bleibt der Titel, wie er ist.
 */
export function collapsedParts(parts: TextPart[]): TextPart[] {
  const last = parts[parts.length - 1];
  if (!last || last.target || last.text.trim() !== ')') return parts;
  for (let i = parts.length - 2; i > 0; i--) {
    const p = parts[i];
    if (!p || p.target) continue;
    if (!p.text.endsWith('(')) return parts;
    const head = p.text.slice(0, -1).replace(/\s+$/, '');
    const before = parts.slice(0, i);
    if (!before.some((x) => x.target)) return parts;
    return head ? [...before, { text: head, target: false }] : before;
  }
  return parts;
}

/** true, wenn keine Vorlage gerendert ist, weil ein Wert verdächtig ist (Shell-Sonderzeichen usw.). */
export function hasSuspectValues(s: Suggestion): boolean {
  return s.templates.length > 0 && s.templates.every((t) => !t.rendered) && s.templates.some((t) => t.blocked_reason !== null && t.blocked_reason !== 'out_of_scope');
}

/**
 * Titel ohne Zieldaten, wenn die Vorlage wegen eines verdächtigen Werts gesperrt ist (Korrektur
 * D14, Screen 4 D2-Variante): «Version recherchieren» statt «Version recherchieren: vsftpd'; !sh …».
 * Der Wert steht dann nur gekennzeichnet in der Liste der Einzelwerte.
 */
export function titleParts(s: Suggestion): TextPart[] {
  if (!hasSuspectValues(s)) return s.title_parts;
  const head: TextPart[] = [];
  for (const p of s.title_parts) {
    if (p.target) break;
    head.push(p);
  }
  const last = head[head.length - 1];
  if (last) head[head.length - 1] = { ...last, text: last.text.replace(/[\s:·(-]+$/, '') };
  return head.filter((p) => p.text !== '');
}
