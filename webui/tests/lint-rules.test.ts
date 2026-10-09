// @vitest-environment node
// Stellt sicher, dass die Sicherheitsregeln aus eslint.config.js aktiv bleiben (Architektur 7.7).
import { ESLint } from 'eslint';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const cwd = fileURLToPath(new URL('..', import.meta.url));
const eslint = new ESLint({ cwd });

async function rules(code: string, filePath: string): Promise<string[]> {
  const [res] = await eslint.lintText(code, { filePath });
  return (res?.messages ?? []).map((m) => m.ruleId ?? `fatal: ${m.message}`);
}

describe('ESLint-Sicherheitsregeln', () => {
  it.each([
    ['innerHTML', 'export function f(el: HTMLElement, s: string) { el.innerHTML = s; }'],
    ['outerHTML', 'export function f(el: HTMLElement, s: string) { el.outerHTML = s; }'],
    ['insertAdjacentHTML', "export function f(el: HTMLElement, s: string) { el.insertAdjacentHTML('beforeend', s); }"],
    ['document.write', 'export function f(s: string) { document.write(s); }'],
  ])('verbietet %s', async (_name, code) => {
    expect(await rules(code, 'src/lib/x.ts')).toContain('no-restricted-properties');
  });

  it('verbietet Bibliotheksoptionen, die HTML erlauben', async () => {
    expect(await rules('export const o = { allowHTML: true };', 'src/lib/x.ts')).toContain('no-restricted-syntax');
    expect(await rules('export const o = { html: true };', 'src/lib/x.ts')).toContain('no-restricted-syntax');
    expect(await rules('export const o = { html: false };', 'src/lib/x.ts')).not.toContain('no-restricted-syntax');
  });

  it('verbietet Style- und Event-Attribute per setAttribute', async () => {
    expect(await rules("export function f(el: HTMLElement) { el.setAttribute('style', 'x'); }", 'src/lib/x.ts')).toContain('no-restricted-syntax');
    expect(await rules("export function f(el: HTMLElement) { el.setAttribute('onclick', 'x'); }", 'src/lib/x.ts')).toContain('no-restricted-syntax');
  });

  it('verbietet localStorage ausserhalb von prefs.ts (Token nie in localStorage)', async () => {
    expect(await rules("export const t = localStorage.getItem('ariadne.token');", 'src/lib/x.ts')).toContain('no-restricted-globals');
    expect(await rules("export const t = window.localStorage.getItem('x');", 'src/lib/x.ts')).toContain('no-restricted-properties');
  });

  it('erlaubt DOMPurify und markdown-it nur in SafeMarkdown.svelte', async () => {
    expect(await rules("import DOMPurify from 'dompurify';\nexport default DOMPurify;", 'src/lib/x.ts')).toContain('no-restricted-imports');
    expect(await rules("import MarkdownIt from 'markdown-it';\nexport default MarkdownIt;", 'src/lib/x.ts')).toContain('no-restricted-imports');
  });

  it('verbietet {@html} und Style-Attribute in Svelte-Komponenten', async () => {
    const html = '<script lang="ts">\n  let { s }: { s: string } = $props();\n</script>\n\n<div>{@html s}</div>\n';
    expect(await rules(html, 'src/lib/X.svelte')).toContain('svelte/no-at-html-tags');
    const style = '<div style="color: red">x</div>\n';
    expect(await rules(style, 'src/lib/X.svelte')).toContain('svelte/no-inline-styles');
  });

  it('verbietet eval und new Function', async () => {
    expect(await rules('export const v = eval("1");', 'src/lib/x.ts')).toContain('no-eval');
    expect(await rules('export const f = new Function("return 1");', 'src/lib/x.ts')).toContain('no-new-func');
  });

  it('lässt den echten Code ohne Befund durch, auch SafeMarkdown.svelte', async () => {
    const results = await eslint.lintFiles(['src/lib/safe/SafeMarkdown.svelte', 'src/lib/util/prefs.ts', 'src/lib/api/auth.ts']);
    expect(results.flatMap((r) => r.messages)).toEqual([]);
  });
});
