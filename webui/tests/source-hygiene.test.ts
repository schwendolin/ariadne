// @vitest-environment node
// Schutz gegen «Trojan Source»: im Quelltext keine unsichtbaren Bidi-, Zero-Width- oder
// Steuerzeichen. Testwerte stehen als \u-Escape im Code, nie als rohes Zeichen.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('..', import.meta.url));
// eslint-disable-next-line no-control-regex
const HIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/u;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return files(p);
    return /\.(ts|js|svelte|css|html|json|md)$/.test(name) ? [p] : [];
  });
}

describe('Quelltext-Hygiene', () => {
  it('enthält keine unsichtbaren oder richtungsumkehrenden Zeichen', () => {
    const all = [...files(join(root, 'src')), ...files(join(root, 'tests')), join(root, 'index.html'), join(root, 'README.md')];
    const offenders = all.filter((p) => {
      try {
        return HIDDEN.test(readFileSync(p, 'utf8'));
      } catch {
        return false;
      }
    });
    expect(offenders).toEqual([]);
  });
});
