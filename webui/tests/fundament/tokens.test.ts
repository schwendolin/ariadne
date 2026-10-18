// @vitest-environment node
// Teil 1 von src/theme/tokens.css ist eine wörtliche Kopie von docs/ui/design-v01/tokens.css
// (Vertrag v0.1-Oberfläche, Abschnitt 6). Besitzer: ui-fundament.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const webui = fileURLToPath(new URL('../..', import.meta.url));
const design = readFileSync(`${webui}/../docs/ui/design-v01/tokens.css`, 'utf8');
const ours = readFileSync(`${webui}/src/theme/tokens.css`, 'utf8');

function part1(css: string): string {
  const start = css.indexOf('Teil 1: Design (wörtlich) */');
  const end = css.indexOf('/* ----', start);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  return css.slice(css.indexOf('\n', start) + 1, end);
}

/** Definierte Variablen: `--x: …` in CSS und `'--x': …` in styleProps-Objekten (CSSOM). */
function customProps(css: string): Set<string> {
  return new Set(Array.from(css.matchAll(/(--[a-z0-9-]+)['"]?\s*:/g), (m) => m[1] as string));
}

describe('Design-Tokens', () => {
  it('Teil 1 entspricht der Design-Datei wörtlich', () => {
    expect(part1(ours).trim()).toBe(design.trim());
  });

  it('jede verwendete CSS-Variable ist definiert (Tokens oder abgeleitet)', async () => {
    const { readdirSync, statSync } = await import('node:fs');
    const { join } = await import('node:path');
    const defined = customProps(ours);
    const walk = (dir: string): string[] =>
      readdirSync(dir).flatMap((n) => {
        const p = join(dir, n);
        return statSync(p).isDirectory() ? walk(p) : /\.(svelte|css)$/.test(n) ? [p] : [];
      });
    const missing = new Set<string>();
    for (const file of walk(`${webui}/src`)) {
      const text = readFileSync(file, 'utf8');
      for (const p of customProps(text)) defined.add(p); // lokal gesetzte Variablen (z. B. --x: …)
      for (const m of text.matchAll(/var\((--[a-z0-9-]+)/g)) missing.add(m[1] as string);
    }
    const undefinedVars = [...missing].filter((v) => !defined.has(v));
    expect(undefinedVars).toEqual([]);
  });

  it('nur Systemschriften, keine Schriftdateien', () => {
    expect(ours).not.toMatch(/@font-face|url\(/);
  });
});
