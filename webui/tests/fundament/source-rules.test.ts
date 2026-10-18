// @vitest-environment node
// Quelltextregeln, die ESLint nicht abdeckt (Vertrag v0.1-Oberfläche, Abschnitt 5 und 7):
// - keine Svelte-Übergänge per Direktive (transition:, in:, out:, animate:): sie fügen <style>
//   ein, was die CSP verbietet; Bewegung nur über util/motion.ts (Web Animations API)
// - keine style=- und style:-Attribute im Markup; dynamische Werte nur per styleProps (CSSOM)
// - {@html} nur in SafeMarkdown
// - kein href/src aus Variablen in Svelte-Markup (keine klickbaren Links aus Zieldaten)
// - keine Webfonts, keine Fremdressourcen (http/https-URLs) in index.html, CSS und Markup
// Besitzer: ui-fundament.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../..', import.meta.url));

function walk(dir: string, re: RegExp): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p, re) : re.test(n) ? [p] : [];
  });
}

/** Markup eines Svelte-Bausteins ohne <script> und <style> und ohne Kommentare. */
function markup(src: string): string {
  return src
    .replace(/<script[\s\S]*?<\/script>/g, '')
    .replace(/<style[\s\S]*?<\/style>/g, '')
    .replace(/<!--[\s\S]*?-->/g, '');
}

const svelteFiles = walk(join(root, 'src'), /\.svelte$/);

function offenders(test: (m: string, file: string) => boolean): string[] {
  return svelteFiles.filter((f) => test(markup(readFileSync(f, 'utf8')), f)).map((f) => relative(root, f));
}

describe('Svelte-Markup', () => {
  it('keine Übergangs- oder Animationsdirektiven', () => {
    expect(offenders((m) => /\s(transition|in|out|animate):[a-zA-Z]/.test(m))).toEqual([]);
  });

  it('keine style-Attribute und keine style:-Direktiven', () => {
    expect(offenders((m) => /\sstyle(=|:[a-z-])/.test(m))).toEqual([]);
  });

  it('{@html} nur in SafeMarkdown', () => {
    expect(offenders((m, f) => m.includes('{@html') && !f.endsWith('SafeMarkdown.svelte'))).toEqual([]);
  });

  it('keine Links oder Quellen aus Variablen (href={…}, src={…}) ausser über url.href', () => {
    expect(
      offenders((m) => {
        for (const match of m.matchAll(/\s(href|src|action|formaction)=\{([^}]*)\}/g)) {
          const expr = match[2] ?? '';
          if (!/^url\.href\(/.test(expr.trim())) return true;
        }
        return false;
      }),
    ).toEqual([]);
  });

  it('keine Event-Handler als Zeichenkette', () => {
    expect(offenders((m) => /\son[a-z]+="/.test(m))).toEqual([]);
  });
});

describe('Ressourcen', () => {
  it('keine Fremdressourcen und keine Schriftdateien', () => {
    const files = [...walk(join(root, 'src'), /\.(svelte|css|ts)$/), join(root, 'index.html')];
    const bad = files.filter((f) => {
      const text = readFileSync(f, 'utf8');
      return /@font-face|@import\s+url\(|<link[^>]+https?:|src=["']https?:|url\(["']?https?:/.test(text);
    });
    expect(bad.map((f) => relative(root, f))).toEqual([]);
  });

  it('index.html ohne Inline-Skripte und Inline-Styles', () => {
    const html = readFileSync(join(root, 'index.html'), 'utf8');
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/);
    expect(html).not.toMatch(/<style|\sstyle=/);
  });
});
