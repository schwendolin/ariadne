/**
 * Gemeinsame Test-Hilfen für alle Browsertests (Besitzer: ui-fundament).
 *
 * - `test` ersetzt `@playwright/test`s `test`: Jeder Test bricht ab, wenn die Seite eine
 *   CSP-Verletzung (`securitypolicyviolation`, Konsolenmeldung «Content Security Policy») oder
 *   einen Seitenfehler meldet, oder wenn ein `<style>`-Element mit Inhalt oder ein Element mit
 *   style-Attribut aus dem Markup im DOM steht.
 * - `openMock(page, scenario, path)`: Mock-Build mit Szenario (`?mock=`), siehe src/lib/mock/state.ts.
 * - `loginDaemon(page, path)`: holt über ctl.sock einen Code und öffnet die Startadresse mit
 *   `#c=<code>` wie die Startdatei (das Fragment geht nie an den Server).
 */
import { expect, test as base, type Page } from '@playwright/test';
import { readFileSync, existsSync } from 'node:fs';
import { createConnection } from 'node:net';
import { resolve } from 'node:path';

export const DAEMON_STATE = resolve(import.meta.dirname, '../.e2e/daemon.json');

interface Guard {
  violations: string[];
  errors: string[];
}

export const test = base.extend<{ guard: Guard }>({
  guard: [
    async ({ page }, use) => {
      const g: Guard = { violations: [], errors: [] };
      await page.addInitScript(() => {
        const w = window as unknown as { __csp: string[] };
        w.__csp = [];
        document.addEventListener('securitypolicyviolation', (e) => {
          w.__csp.push(`${e.violatedDirective} ${e.blockedURI}`);
        });
      });
      page.on('console', (msg) => {
        if (/Content Security Policy|Refused to (apply|load|execute)/i.test(msg.text())) g.violations.push(msg.text());
      });
      page.on('pageerror', (err) => g.errors.push(String(err)));
      await use(g);
      const fromPage = await page
        .evaluate(() => {
          const w = window as unknown as { __csp?: string[] };
          const styles = Array.from(document.querySelectorAll('style')).filter((s) => (s.textContent ?? '').trim() !== '');
          return { csp: w.__csp ?? [], styles: styles.length };
        })
        .catch(() => ({ csp: [] as string[], styles: 0 }));
      expect([...g.violations, ...fromPage.csp], 'CSP-Verletzungen').toEqual([]);
      expect(g.errors, 'Seitenfehler').toEqual([]);
      expect(fromPage.styles, '<style>-Elemente mit Inhalt').toBe(0);
    },
    { auto: true },
  ],
});

export { expect };

export async function openMock(page: Page, scenario = 'normal', path = '/karte'): Promise<void> {
  const sep = path.includes('?') ? '&' : '?';
  await page.goto(`${path}${sep}mock=${scenario}`);
}

export interface DaemonState {
  base: string;
  port: number;
  ctl: string;
  project_id: string | null;
  home: string;
  scenario: string;
}

export async function daemonState(timeoutMs = 90_000): Promise<DaemonState> {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (existsSync(DAEMON_STATE)) return JSON.parse(readFileSync(DAEMON_STATE, 'utf8')) as DaemonState;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('Fixture-Daemon nicht bereit (tests/e2e/ui_fixture.py)');
}

/** ctl-Operation über den Unix-Socket des Daemons (gleicher Benutzer). */
export function ctl(sock: string, op: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return new Promise((resolveP, reject) => {
    const c = createConnection(sock);
    let buf = '';
    c.on('connect', () => c.write(`${JSON.stringify({ op, args })}\n`));
    c.on('data', (d) => {
      buf += d.toString('utf8');
      if (buf.endsWith('\n')) {
        c.end();
        const res = JSON.parse(buf) as { ok: boolean; result?: Record<string, unknown>; error?: unknown };
        if (res.ok && res.result) resolveP(res.result);
        else reject(new Error(`ctl ${op} fehlgeschlagen`));
      }
    });
    c.on('error', reject);
  });
}

/** Anmeldung wie über die Startdatei: Code aus dem Daemon, `#c=` im Fragment. */
export async function loginDaemon(page: Page, path = '/karte'): Promise<DaemonState> {
  const st = await daemonState();
  const res = await ctl(st.ctl, 'ui.code', { via: 'local', typed: false });
  await page.goto(`${path}#c=${String(res.code)}`);
  await expect(page.getByRole('banner')).toBeVisible();
  return st;
}
