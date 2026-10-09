import { describe, expect, it } from 'vitest';
import { evidenceMarkdown, fenceFor, mdText } from '../src/lib/util/evidence';
import { segments } from '../src/lib/ui/logsegments';
import { createLameFixture } from '../src/lib/mock/fixture';

describe('Beleg als Markdown', () => {
  it('wählt eine Fence, die länger ist als jede Backtick-Folge', () => {
    expect(fenceFor('kein code')).toBe('```');
    expect(fenceFor('a ```` b')).toBe('`````');
  });

  it('escapt Markdown-Steuerzeichen und macht Steuerzeichen sichtbar', () => {
    expect(mdText('![x](http://e)')).toBe('\\!\\[x\\]\\(http://e\\)');
    expect(mdText('a\u001bb')).toBe('a\\<ESC\\>b');
  });

  it('setzt Befehl und Zeilen in einen text-Codeblock', () => {
    const fx = createLameFixture(Date.parse('2026-10-08T14:00:00Z'));
    const fact = fx.facts.find((f) => f.predicate === 'service.version' && f.value === '3.0.20-Debian')!;
    const src = fx.sources.get(fact.fact_id)!.find((s) => s.t === 'stream')!;
    if (src.t !== 'stream') throw new Error('stream erwartet');
    const unit = fx.units.get(src.unit_id)!;
    const md = evidenceMarkdown(src, unit.lines.slice(src.lines[0], src.lines[1] + 1));
    expect(md).toContain('```text\n$ nmap -sV -sC -oA scans/lame 10.10.10.3\n445/tcp');
    expect(md).toContain('- Kontext: Kali');
    expect(md.trimEnd().endsWith('```')).toBe(true);
  });
});

describe('Logzeilen', () => {
  it('teilt Zeilen an Farbspannen und kennt nur benannte Farben', () => {
    const segs = segments(
      {
        n: 0, text: 'Sudo version 1.6.9p10', prompt_echo: false, concealed: false, overwritten: false, masked: [],
        sgr: [{ col_start: 13, col_end: 21, fg: 'bright_red', bg: '#ffff00', bold: true, concealed: false }],
      },
      false,
    );
    expect(segs).toEqual([
      { text: 'Sudo version ', classes: '' },
      { text: '1.6.9p10', classes: 'fg-red b' },
    ]);
  });

  it('verbirgt verdeckten Text, bis er aufgedeckt wird', () => {
    const line = {
      n: 0, text: 'pw: hunter2', prompt_echo: false, concealed: true, overwritten: false, masked: [],
      sgr: [{ col_start: 4, col_end: 11, fg: null, bg: null, bold: false, concealed: true }],
    };
    expect(segments(line, false).map((s) => s.text).join('')).not.toContain('hunter2');
    expect(segments(line, true).map((s) => s.text).join('')).toContain('hunter2');
  });
});
