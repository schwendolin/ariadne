/**
 * Fundament gegen den echten Daemon (Besitzer: ui-fundament): Anmeldung über `#c=` (Fragment sofort
 * weg, Token nur in sessionStorage), Kopfzeile mit echtem Status und Herkunft «lokal», Pause und
 * Fortsetzen über das Popover (Bestätigung per SSE), Präsentationsmodus per Shift+P, Vorlieben auf
 * dem Server, Favicon und Tab-Titel aus /next, Rohlog-Suche, falscher Code, Abmelden; dazu eigene
 * Fixture-Daemons für «kein Projekt» und «gesperrt». Unter der echten Shell-CSP des Daemons; jeder
 * Test scheitert bei einer CSP-Verletzung (fixtures.ts).
 *
 * Tests, die etwas am gemeinsamen Daemon ändern (Pause, Präsentation, Theme), stellen den Zustand
 * am Ende wieder her, damit die Tests von ui-karte und ui-verlauf denselben Daemon nutzen können.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import type { Page } from '@playwright/test';
import { ctl, daemonState, expect, loginDaemon, test, type DaemonState } from '../fixtures';

const header = (page: Page) => page.locator('header.header');
const REPO = resolve(import.meta.dirname, '../../..');
const PYTHON = process.env.ARIADNE_PYTHON ?? resolve(REPO, '.venv/bin/python');
const STATIC = resolve(import.meta.dirname, '../../.e2e/dist-prod');

/** Token dieses Tabs (nur zum Prüfen; die Oberfläche selbst liest es nur in api/auth.ts). */
function readToken(page: Page): Promise<string | null> {
  // eslint-disable-next-line no-restricted-globals -- der Test liest den Speicher nur aus
  return page.evaluate(() => sessionStorage.getItem('ariadne.token'));
}

function storageCount(page: Page): Promise<number> {
  // eslint-disable-next-line no-restricted-globals -- der Test liest den Speicher nur aus
  return page.evaluate(() => sessionStorage.length);
}

async function api(page: Page, path: string, init: { method?: string; body?: unknown } = {}): Promise<{ status: number; body: unknown }> {
  const token = await readToken(page);
  return page.evaluate(
    async ({ path, init, token }) => {
      const res = await fetch(`/api/v1${path}`, {
        method: init.method ?? 'GET',
        mode: 'cors',
        headers: { Authorization: `Bearer ${token}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}) },
        body: init.body ? JSON.stringify(init.body) : undefined,
      });
      const body: unknown = await res.json().catch(() => null);
      return { status: res.status, body };
    },
    { path, init, token },
  );
}

test.describe.configure({ mode: 'serial' });

test('Anmeldung über die Startadresse: Fragment weg, Token nur in sessionStorage, Kopfzeile echt', async ({ page }) => {
  await loginDaemon(page);
  await expect(page).not.toHaveURL(/#/);
  await expect(header(page)).toContainText('ms2');
  await expect(header(page).locator('.origin')).toHaveText('lokal');
  await expect(header(page)).toContainText(/\d von \d Terminals? n(ehmen|immt) auf/);
  await expect(header(page)).toHaveAttribute('data-variant', /normal|pause|held/);
  // eslint-disable-next-line no-restricted-globals -- der Test liest den Speicher nur aus
  const storage = await page.evaluate(() => ({ local: localStorage.length, keys: Object.keys(sessionStorage), url: location.href }));
  expect(storage.local).toBe(0);
  expect(storage.keys.sort()).toEqual(['ariadne.token', 'ariadne.token.expires']);
  expect(storage.url).not.toMatch(/token|#c=/);
  for (const key of ['2', '3', '4', '1']) {
    await page.keyboard.press(key);
    await page.waitForTimeout(250);
  }
  await expect(page.getByRole('alert')).toHaveCount(0);
});

test('Aufnahme-Popover: echte Terminals; Pause wartet auf die Bestätigung, Fortsetzen stellt zurück', async ({ page }) => {
  await loginDaemon(page);
  const rec = header(page).locator('button.rec');
  await expect(rec).toContainText('3 von 3 Terminals nehmen auf');
  await rec.click();
  const pop = page.getByRole('dialog', { name: 'Aufnahme' });
  await expect(pop.locator('.term')).toHaveCount(3);
  await expect(pop).toContainText('lokal, Browser in der Kali');
  await expect(pop).toContainText(/ms2 · .* · lab/);
  const pauseBtn = pop.locator('.term').first().getByRole('button', { name: /^Pause für / });
  await pauseBtn.click();
  // «wartet auf Bestätigung» erscheint sofort oder wird vom Ereignis schnell abgelöst
  await expect(header(page)).toHaveAttribute('data-variant', /waiting|pause/);
  await expect(header(page)).toHaveAttribute('data-variant', 'pause', { timeout: 10_000 });
  await expect(header(page).locator('[data-badge="pause"]')).toContainText(/Pause bis \d\d:\d\d/);
  await expect(rec).toContainText('2 von 3 Terminals nehmen auf');
  await expect(pop.locator('.term').first()).toContainText(/Pause bis \d\d:\d\d/);
  await pop.locator('.term').first().getByRole('button', { name: /fortsetzen/ }).click();
  await expect(header(page)).toHaveAttribute('data-variant', 'normal', { timeout: 10_000 });
  await expect(rec).toContainText('3 von 3 Terminals nehmen auf');
});

test('Präsentationsmodus per Shift+P an allen Stellen sichtbar, per SSE bestätigt; wieder aus', async ({ page }) => {
  await loginDaemon(page);
  await expect(header(page)).toBeVisible();
  await page.keyboard.press('Shift+P');
  await expect(header(page).locator('[data-badge="presentation"]')).toHaveText('Präsentation', { timeout: 10_000 });
  const st = (await api(page, '/status')).body as { presentation: boolean };
  expect(st.presentation).toBe(true);
  // Aufdecken ist jetzt auf dem Server gesperrt (403 policy)
  const reveal = await api(page, `/p/${(await daemonState()).project_id}/secrets/reveal`, { method: 'POST', body: { ref: 'input', seq: 1 } });
  expect([403, 404]).toContain(reveal.status);
  await page.keyboard.press('Shift+P');
  await expect(header(page).locator('[data-badge="presentation"]')).toHaveCount(0, { timeout: 10_000 });
});

test('Favicon und Tab-Titel folgen der Zahl offener Klärungen aus /next', async ({ page }) => {
  const st = await loginDaemon(page);
  await expect(header(page)).toBeVisible();
  const next = (await api(page, `/p/${st.project_id}/next`)).body as { open: number };
  const want = next.open > 0 ? `ms2 · ${next.open} zu klären` : 'ms2';
  await expect(page).toHaveTitle(want);
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', next.open > 0 ? '/favicon-attention.svg' : '/favicon.svg');
  expect((await page.request.get('/favicon.svg')).status()).toBe(200);
});

test('Vorlieben auf dem Server: Dunkel bleibt nach Neuladen, ohne Browser-Speicher', async ({ page }) => {
  await loginDaemon(page);
  await expect(header(page)).toBeVisible();
  const probe = await api(page, '/ui/prefs');
  test.skip(probe.status !== 200, `GET /ui/prefs antwortet ${probe.status} (Route von backend-ui noch nicht gebaut)`);
  await page.emulateMedia({ colorScheme: 'light' });
  await page.getByRole('button', { name: 'Menü' }).click();
  await page.getByRole('menuitem', { name: 'Einstellungen' }).click();
  await page.getByRole('radio', { name: 'Dunkel' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect.poll(async () => ((await api(page, '/ui/prefs')).body as { prefs: { theme: string } }).prefs.theme).toBe('dark');
  await page.reload();
  await expect(header(page)).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  // eslint-disable-next-line no-restricted-globals -- der Test liest den Speicher nur aus
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  // zurück auf System für die anderen Tests
  const back = await api(page, '/ui/prefs', { method: 'PUT', body: { theme: 'system', density: 'comfortable', learning: true } });
  expect(back.status).toBe(200);
  await expect(page.locator('html')).not.toHaveAttribute('data-theme', /.+/);
});

test('Neu seit: Unsichtbarwerden meldet PUT /ui/seen, Neuladen meldet nichts', async ({ page }) => {
  await loginDaemon(page);
  await expect(header(page)).toBeVisible();
  const put = page.waitForRequest((r) => r.method() === 'PUT' && r.url().endsWith('/ui/seen'));
  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  const req = await put;
  expect(req.postData()).toBe('{}');
  expect(req.headers()['authorization']).toMatch(/^Bearer /);
  expect(req.url()).not.toMatch(/token=/);
  // Neuladen: kein PUT (sonst stünde «+N seit» nach jedem Neuladen auf null)
  const seenPuts: string[] = [];
  page.on('request', (r) => {
    if (r.method() === 'PUT' && r.url().endsWith('/ui/seen')) seenPuts.push(r.url());
  });
  await page.evaluate(() => Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true }));
  await page.reload();
  await expect(header(page)).toBeVisible();
  await page.waitForTimeout(500);
  expect(seenPuts).toEqual([]);
});

test('Palette: Rohlog-Suche über GET /search, Treffer öffnet den Beleg', async ({ page }) => {
  await loginDaemon(page);
  await expect(header(page)).toBeVisible();
  await page.keyboard.press('Control+k');
  await page.keyboard.type('vsftpd');
  await page.getByText('Im Rohlog suchen: «vsftpd»').click();
  const hit = page.locator('[role="option"]').filter({ hasText: /vsftpd/i }).last();
  await expect(hit).toBeVisible({ timeout: 10_000 });
  await hit.locator('button').click();
  await expect(page).toHaveURL(/beleg=u%3A|beleg=u:/);
});

test('falscher Code: Fehler unter dem Feld (401); Abmelden beendet die Sitzung', async ({ page }) => {
  await page.goto('/karte#c=FALSCH0000000000000000');
  await expect(page.getByRole('alert')).toHaveText('Code unbekannt, abgelaufen oder schon benutzt.');
  await expect(page).not.toHaveURL(/#/);
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
  // getippter falscher Code
  await page.getByLabel('Anmeldecode').fill('ABCDE-FGHJK');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('alert')).toHaveText('Code unbekannt, abgelaufen oder schon benutzt.');
  // gültige Anmeldung (anderer Pfad: volle Navigation statt nur Fragmentwechsel), dann Abmelden
  await loginDaemon(page, '/terminals');
  const token = await readToken(page);
  expect(token).toBeTruthy();
  await page.getByRole('button', { name: 'Menü' }).click();
  await page.getByRole('menuitem', { name: /Abmelden/ }).click();
  await expect(page.getByLabel('Anmeldecode')).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(await storageCount(page)).toBe(0);
  const old = await page.evaluate(async (t) => (await fetch('/api/v1/status', { headers: { Authorization: `Bearer ${t}` } })).status, token);
  expect(old).toBe(401);
});

// ------------------------------------------------------------------ eigene Fixture-Daemons

function freePort(): Promise<number> {
  return new Promise((resolveP, reject) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      s.close(() => (typeof addr === 'object' && addr ? resolveP(addr.port) : reject(new Error('kein Port'))));
    });
  });
}

async function startFixture(scenario: 'noproject' | 'locked' | 'empty'): Promise<{ proc: ChildProcess; st: DaemonState }> {
  const port = await freePort();
  const stateFile = resolve(import.meta.dirname, `../../.e2e/daemon-${scenario}.json`);
  rmSync(stateFile, { force: true });
  const proc = spawn(
    PYTHON,
    ['-m', 'tests.e2e.ui_fixture', '--port', String(port), '--static', STATIC, '--state-file', stateFile, '--scenario', scenario, '--watch-stdin'],
    { cwd: REPO, stdio: ['pipe', 'pipe', 'pipe'] },
  );
  const until = Date.now() + 90_000;
  while (!existsSync(stateFile)) {
    if (proc.exitCode !== null) throw new Error(`Fixture ${scenario} beendet (${proc.exitCode})`);
    if (Date.now() > until) throw new Error(`Fixture ${scenario} nicht bereit`);
    await new Promise((r) => setTimeout(r, 200));
  }
  return { proc, st: JSON.parse(readFileSync(stateFile, 'utf8')) as DaemonState };
}

async function stopFixture(proc: ChildProcess): Promise<void> {
  proc.stdin?.end();
  await new Promise<void>((r) => {
    if (proc.exitCode !== null) return r();
    const tm = setTimeout(() => {
      proc.kill('SIGTERM');
      r();
    }, 15_000);
    proc.on('exit', () => {
      clearTimeout(tm);
      r();
    });
  });
}

async function loginAt(page: Page, st: DaemonState): Promise<void> {
  const res = await ctl(st.ctl, 'ui.code', { via: 'local', typed: false });
  await page.goto(`${st.base}/karte#c=${String(res.code)}`);
  await expect(page.getByRole('banner')).toBeVisible();
}

test.describe('Zustände mit eigenem Daemon', () => {
  test.describe.configure({ timeout: 150_000 });

  test('kein Projekt: «kein Projekt», Startbefehl, Reiter ohne Wirkung, Titel «Ariadne»', async ({ page }) => {
    test.skip(!existsSync(resolve(STATIC, 'index.html')), 'Produktions-Build fehlt (.e2e/dist-prod)');
    const { proc, st } = await startFixture('noproject');
    try {
      await loginAt(page, st);
      await expect(header(page)).toHaveAttribute('data-variant', 'noproject');
      await expect(header(page).locator('.slug')).toHaveText('kein Projekt');
      await expect(header(page)).toContainText(/Vorlauf: \d+ Terminals?, .* im Arbeitsspeicher|Kein Vorlauf im Arbeitsspeicher/);
      await expect(page.getByRole('heading', { name: 'Kein aktives Projekt' })).toBeVisible();
      await page.keyboard.press('3');
      await expect(page).toHaveURL(/\/karte/);
      await expect(page).toHaveTitle('Ariadne');
    } finally {
      await stopFixture(proc);
    }
  });

  test('gesperrt: Projektdaten weg, kein Passphrase-Feld, Hinweis ariadne start', async ({ page }) => {
    test.skip(!existsSync(resolve(STATIC, 'index.html')), 'Produktions-Build fehlt (.e2e/dist-prod)');
    const { proc, st } = await startFixture('locked');
    try {
      await loginAt(page, st);
      await expect(header(page)).toHaveAttribute('data-variant', 'locked');
      await expect(header(page)).toContainText('Gesperrt · im Terminal ariadne start');
      await expect(page.getByRole('heading', { name: /Projekt ms2 ist gesperrt/ })).toBeVisible();
      await expect(page.locator('input')).toHaveCount(0);
      const graph = (await api(page, `/p/${st.project_id}/graph`)).status;
      expect([409, 423]).toContain(graph);
    } finally {
      await stopFixture(proc);
    }
  });
});
