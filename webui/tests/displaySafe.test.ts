import { describe, expect, it } from 'vitest';
import { displaySafe, hasHiddenChars, punycodeHint, visible } from '../src/lib/safe/displaySafe';

// Gleiche Erwartungen wie src/ariadne/termsafe.py (term_safe / visible).
describe('visible', () => {
  it('benennt bekannte Steuerzeichen', () => {
    expect(visible('a\u001b[31mb')).toBe('a<ESC>[31mb');
    expect(visible('\u0007\u0008\u007f\r\n\t')).toBe('<BEL><BS><DEL><CR><LF><TAB>');
  });

  it('zeigt übrige C0- und C1-Zeichen als Hex', () => {
    expect(visible('\u0000\u0001\u001f')).toBe('<0x00><0x01><0x1F>');
    expect(visible('\u0085\u009b')).toBe('<0x85><0x9B>');
  });

  it('macht Bidi- und Zero-Width-Zeichen sichtbar', () => {
    expect(visible('‮gnp.exe')).toBe('<U+202E>gnp.exe');
    expect(visible('ad​min')).toBe('ad<U+200B>min');
    expect(visible('⁦x⁩')).toBe('<U+2066>x<U+2069>');
    expect(visible('﻿BOM')).toBe('<U+FEFF>BOM');
    expect(visible('؜᠎')).toBe('<U+061C><U+180E>');
  });

  it('macht Unicode-Tag-Zeichen sichtbar (versteckte Prompt-Injection)', () => {
    const tagged = 'ok' + String.fromCodePoint(0xe0041, 0xe0042);
    expect(visible(tagged)).toBe('ok<U+E0041><U+E0042>');
  });

  it('macht Format-, Private-Use- und einzelne Surrogat-Zeichen sichtbar', () => {
    expect(visible('­')).toBe('<0xAD>'); // Soft Hyphen, Kategorie Cf
    expect(visible('')).toBe('<U+E000>'); // Private Use
    expect(visible('x\ud800y')).toBe('x<U+D800>y'); // einzelnes Surrogat
  });

  it('lässt normalen Text, Umlaute, Emoji-freie Symbole und Box-Zeichen unverändert', () => {
    const s = 'Grüsse aus Zürich: ä ö ü, ╔══ linpeas ══╗, 10.10.10.3:445';
    expect(visible(s)).toBe(s);
    expect(hasHiddenChars(s)).toBe(false);
  });

  it('lässt HTML-Zeichen als Text stehen (escapen macht Svelte)', () => {
    expect(visible('<img src=x onerror=alert(1)>')).toBe('<img src=x onerror=alert(1)>');
  });
});

describe('displaySafe', () => {
  it('kürzt auf max Codepoints mit Auslassungszeichen', () => {
    expect(displaySafe('abcdef', 4)).toBe('abc…');
    expect(displaySafe('abcd', 4)).toBe('abcd');
    expect(displaySafe('abc', 0)).toBe('abc');
  });

  it('kürzt nach dem Sichtbarmachen, wie term_safe', () => {
    expect(displaySafe('\u001b\u001b', 6)).toBe('<ESC>…');
  });

  it('zählt Codepoints, nicht UTF-16-Einheiten', () => {
    const astral = String.fromCodePoint(0x1d11e).repeat(5); // Notenschlüssel, ausserhalb der BMP
    expect(Array.from(displaySafe(astral, 3))).toHaveLength(3);
  });

  it('wandelt Nicht-Strings um und übersteht null', () => {
    expect(displaySafe(445)).toBe('445');
    expect(displaySafe(null)).toBe('');
    expect(displaySafe(undefined)).toBe('');
    expect(displaySafe(true)).toBe('true');
  });

  it('enthält nach dem Encoder nie ESC, C0, C1, DEL, Bidi oder Zero-Width', () => {
    let all = '';
    for (let cp = 0; cp < 0x250; cp++) all += String.fromCharCode(cp);
    all += '​‎‪‮⁦⁩﻿';
    const out = displaySafe(all, 0);
    // eslint-disable-next-line no-control-regex
    expect(out).not.toMatch(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/);
  });
});

describe('punycodeHint', () => {
  it('zeigt internationale Namen zusätzlich in Punycode', () => {
    expect(punycodeHint('bücher.htb')).toBe('xn--bcher-kva.htb');
  });
  it('gibt null für ASCII-Namen und für Namen mit Steuerzeichen', () => {
    expect(punycodeHint('lame.htb')).toBeNull();
    expect(punycodeHint('bü‮cher.htb')).toBeNull();
  });
});
