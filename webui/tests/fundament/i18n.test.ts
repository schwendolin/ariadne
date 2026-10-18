// @vitest-environment node
// Wörterbücher (Vertrag v0.1-Oberfläche, Abschnitt 6): keine doppelten Schlüssel, Präfixe passen
// zum Besitzer, kein «ß», keine Emojis, Platzhalter sauber. Besitzer: ui-fundament.
import { describe, expect, it } from 'vitest';
import { dictionaries, t, tKey } from '../../src/lib/i18n';

const PREFIXES: Record<keyof typeof dictionaries, string[]> = {
  de: ['app', 'nav', 'header', 'rec', 'login', 'state', 'menu', 'settings', 'palette', 'help', 'err', 'copy', 'secret', 'common', 'time', 'keys', 'present', 'scope', 'notice'],
  deKarte: ['karte', 'lage', 'oos', 'layers', 'table', 'next', 'sug', 'host'],
  deVerlauf: ['term', 'ctx', 'tl', 'pending', 'ev', 'fd', 'export', 'shot'],
};

const SHARP_S = String.fromCodePoint(0xdf);

describe('Wörterbücher', () => {
  it('kein Schlüssel steht in zwei Wörterbüchern', () => {
    const seen = new Map<string, string>();
    const dupes: string[] = [];
    for (const [name, dict] of Object.entries(dictionaries)) {
      for (const key of Object.keys(dict)) {
        if (seen.has(key)) dupes.push(`${key} (${seen.get(key)} und ${name})`);
        seen.set(key, name);
      }
    }
    expect(dupes).toEqual([]);
  });

  it('Präfixe passen zum Besitzer', () => {
    const wrong: string[] = [];
    for (const [name, dict] of Object.entries(dictionaries) as [keyof typeof dictionaries, Record<string, string>][]) {
      for (const key of Object.keys(dict)) {
        const prefix = key.split('.')[0] ?? '';
        if (!PREFIXES[name].includes(prefix)) wrong.push(`${name}: ${key}`);
      }
    }
    expect(wrong).toEqual([]);
  });

  it('Schweizer Rechtschreibung ohne scharfes s, keine Emojis, keine Steuerzeichen', () => {
    const bad: string[] = [];
    for (const dict of Object.values(dictionaries) as Record<string, string>[]) {
      for (const [key, text] of Object.entries(dict)) {
        if (text.includes(SHARP_S)) bad.push(`${key}: scharfes s`);
        if (/\p{Extended_Pictographic}/u.test(text)) bad.push(`${key}: Emoji`);
        // eslint-disable-next-line no-control-regex
        if (/[\u0000-\u001f\u007f]/.test(text)) bad.push(`${key}: Steuerzeichen`);
        if (text.trim() !== text) bad.push(`${key}: Leerraum am Rand`);
      }
    }
    expect(bad).toEqual([]);
  });

  it('Platzhalter sind wohlgeformt', () => {
    const bad: string[] = [];
    for (const dict of Object.values(dictionaries) as Record<string, string>[]) {
      for (const [key, text] of Object.entries(dict)) {
        const stripped = text.replace(/\{[a-zA-Z]\w*\}/g, '');
        if (/[{}]/.test(stripped)) bad.push(key);
      }
    }
    expect(bad).toEqual([]);
  });

  it('t ersetzt Platzhalter und wählt Einzahl oder Mehrzahl über n', () => {
    expect(t('app.titleOpen', { slug: 'ms2', n: 2 })).toBe('ms2 · 2 zu klären');
    expect(t('settings.ownSecrets.value', { n: 1 })).toMatch(/^1 Eintrag,/);
    expect(t('settings.ownSecrets.value', { n: 3 })).toMatch(/^3 Einträge,/);
    expect(tKey('gibt.es.nicht', 'Ersatz')).toBe('Ersatz');
  });
});
