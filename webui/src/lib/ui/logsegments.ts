/**
 * Zerlegt eine bereinigte Logzeile in Abschnitte mit CSS-Klassen.
 * Farben kommen als SGR-Spannen vom Server; OSC und andere Sequenzen sind schon
 * entfernt. Steuerzeichen, die trotzdem im Text stehen, macht visible() sichtbar.
 */
import type { LogLine } from '../api/types';
import { visible } from '../safe/displaySafe';

const COLORS = new Set(['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']);

export interface Segment {
  text: string;
  classes: string;
}

function colorClass(prefix: 'fg' | 'bg', c: string | null): string | null {
  if (!c) return null;
  const name = c.replace(/^bright_/, '');
  return COLORS.has(name) ? `${prefix}-${name}` : null;
}

export function expandTabs(text: string, width = 8): string {
  if (!text.includes('\t')) return text;
  let out = '';
  for (const ch of text) {
    if (ch === '\t') out += ' '.repeat(width - (out.length % width));
    else out += ch;
  }
  return out;
}

export function segments(line: LogLine, showHidden: boolean): Segment[] {
  const text = line.text;
  const cuts = new Set<number>([0, text.length]);
  for (const s of line.sgr) {
    cuts.add(Math.max(0, Math.min(text.length, s.col_start)));
    cuts.add(Math.max(0, Math.min(text.length, s.col_end)));
  }
  for (const m of line.masked) {
    cuts.add(Math.max(0, Math.min(text.length, m.col_start)));
    cuts.add(Math.max(0, Math.min(text.length, m.col_end)));
  }
  const points = [...cuts].sort((a, b) => a - b);
  const out: Segment[] = [];
  for (let i = 0; i < points.length - 1; i++) {
    const a = points[i]!;
    const b = points[i + 1]!;
    if (b <= a) continue;
    const classes: string[] = [];
    let concealed = false;
    for (const s of line.sgr) {
      if (s.col_start <= a && s.col_end >= b) {
        const fg = colorClass('fg', s.fg);
        const bg = colorClass('bg', s.bg);
        if (fg) classes.push(fg);
        if (bg) classes.push(bg);
        if (s.bold) classes.push('b');
      }
    }
    if (line.masked.some((m) => m.col_start <= a && m.col_end >= b)) classes.push('masked');
    let part = text.slice(a, b);
    if (line.concealed && line.masked.some((m) => m.kind === 'concealed' && m.col_start <= a && m.col_end >= b)) concealed = true;
    if (concealed) {
      classes.push('concealed');
      if (!showHidden) part = '·'.repeat(Math.min(part.length, 8));
    }
    out.push({ text: visible(expandTabs(part)), classes: classes.join(' ') });
  }
  if (!out.length) out.push({ text: '', classes: '' });
  return out;
}
