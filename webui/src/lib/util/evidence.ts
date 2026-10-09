/**
 * «Als Beleg kopieren»: Markdown-Block mit Befehl, Zeit, Kontext und Ausschnitt.
 * Zieldaten stehen nur in einem Codeblock mit Info-String `text` und einer Fence,
 * die länger ist als jede Backtick-Folge im Inhalt (Architektur 8.7).
 */
import type { LogLine, SourceView, StageView } from '../api/types';
import { visible } from '../safe/displaySafe';

export function fenceFor(content: string): string {
  let longest = 0;
  for (const m of content.matchAll(/`+/g)) longest = Math.max(longest, m[0].length);
  return '`'.repeat(Math.max(3, longest + 1));
}

/** Escapt Markdown-Steuerzeichen in Fliesstext (Kurzfassung von md_text()). */
export function mdText(s: string): string {
  return visible(s).replace(/[\\`*_{}[\]()#+!|<>$%=^~-]/g, (c) => `\\${c}`);
}

export function stackText(stack: StageView[]): string {
  return stack
    .map((s) => {
      if (s.depth === 0 && s.kind === 'local') return 'Kali';
      const host = s.host_label ?? s.candidate ?? 'unbekannt';
      return s.user ? `${host} (${s.user})` : host;
    })
    .join(' > ');
}

export function evidenceMarkdown(src: Extract<SourceView, { t: 'stream' }>, lines: LogLine[]): string {
  const body = [
    ...(src.cmd?.text ? [`$ ${visible(src.cmd.text)}`] : []),
    ...lines.map((l) => visible(l.text)),
  ].join('\n');
  const fence = fenceFor(body);
  const meta = [
    `- Zeit (UTC): ${src.cmd?.started_at ?? 'unbekannt'}`,
    `- Terminal: ${mdText(src.terminal_label ?? src.terminal_id)}`,
    `- Kontext: ${mdText(stackText(src.context))}`,
    ...(src.cmd?.exit !== null && src.cmd?.exit !== undefined ? [`- Exit-Code: ${src.cmd.exit}`] : []),
    ...(src.cmd?.src_ip ? [`- Quell-IP: ${mdText(src.cmd.src_ip)}`] : []),
    `- Zeilen: ${src.lines[0] + 1} bis ${src.lines[1] + 1} (Einheit ${mdText(src.unit_id)}, Parser ${mdText(src.parser)})`,
  ];
  return [...meta, '', `${fence}text`, body, fence].join('\n');
}
