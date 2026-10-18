// Feindliche Zieldaten in den gemeinsamen Bausteinen (Briefing 9.1, E13): nur als Text, Steuer- und
// Bidi-Zeichen sichtbar, gekürzt mit vollem Wert im title, Secrets verdeckt. Besitzer: ui-fundament.
import { render } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import { HOSTILE_IMG, INJECTION_TITLE, LONG_SMTP, RLO_VERSION_RAW } from '../../src/lib/mock/data/hostile';
import SafeMarkdown from '../../src/lib/safe/SafeMarkdown.svelte';
import Txt from '../../src/lib/ui/Txt.svelte';

const RLO = String.fromCodePoint(0x202e);
const ESC = String.fromCodePoint(0x1b);
const BEL = String.fromCodePoint(0x07);

function noActiveContent(root: ParentNode): void {
  expect(root.querySelector('img[onerror], script, iframe, object, embed, a')).toBeNull();
  for (const el of Array.from(root.querySelectorAll('*'))) {
    for (const attr of Array.from(el.attributes)) {
      expect(attr.name.startsWith('on'), `${el.tagName} ${attr.name}`).toBe(false);
      expect(attr.name, el.tagName).not.toBe('style');
    }
  }
}

describe('Txt', () => {
  it('zeigt HTML aus Zieldaten als Text', () => {
    const { container } = render(Txt, { props: { value: HOSTILE_IMG } });
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain(HOSTILE_IMG);
    noActiveContent(container);
  });

  it('macht Bidi- und Steuerzeichen sichtbar und kennzeichnet sie', () => {
    const { container } = render(Txt, { props: { value: `${RLO_VERSION_RAW} ${ESC}]0;x${BEL}` } });
    const text = container.textContent ?? '';
    expect(text).toContain('<U+202E>');
    expect(text).toContain('<ESC>]0;x<BEL>');
    expect(text).not.toContain(RLO);
    expect(text).toContain('enthält Steuerzeichen');
  });

  it('kürzt lange Werte mit «…» und behält den vollen Wert im title', () => {
    const { container } = render(Txt, { props: { value: LONG_SMTP, max: 60 } });
    const span = container.querySelector('.txt') as HTMLElement;
    expect(span.textContent?.endsWith('…')).toBe(true);
    expect(span.title).toBe(LONG_SMTP);
  });

  it('übernimmt Injection-Texte wörtlich, ohne Sonderbehandlung als Anweisung', () => {
    const { container } = render(Txt, { props: { value: INJECTION_TITLE } });
    expect(container.textContent).toContain(INJECTION_TITLE);
  });
});

describe('SafeMarkdown', () => {
  it('führt kein HTML aus, keine Links, nur blob:-Bilder', () => {
    const source = [
      '# Titel',
      '<img src=x onerror=alert(1)>',
      '<script>alert(1)</script>',
      '[klick](javascript:alert(1))',
      '[extern](https://example.invalid/)',
      '![extern](https://tracker.example/p.png)',
      '![lokal](blob:http://127.0.0.1:7330/abc)',
      '**fett** und `code`',
    ].join('\n\n');
    const { container } = render(SafeMarkdown, { props: { source } });
    const md = container.querySelector('.md') as HTMLElement;
    expect(md.querySelector('h1')?.textContent).toBe('Titel');
    expect(md.querySelector('script, a, iframe')).toBeNull();
    const imgs = Array.from(md.querySelectorAll('img'));
    expect(imgs).toHaveLength(1);
    expect(imgs[0]?.getAttribute('src')).toMatch(/^blob:/);
    expect(md.textContent).toContain('<img src=x onerror=alert(1)>');
    noActiveContent(md);
  });
});
