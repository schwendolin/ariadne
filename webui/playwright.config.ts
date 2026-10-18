/**
 * Browsertests der Oberfläche (Vertrag v0.1-Oberfläche, Abschnitt 8). Besitzer: ui-fundament.
 *
 * - Chromium aus /opt/pw-browsers (nie `playwright install`), Playwright 1.56.x, headless.
 * - Projekte:
 *     mock    `*.mock.spec.ts`   gegen `vite preview` des Mock-Builds (dist/), mit der CSP des Daemons
 *     daemon  `*.daemon.spec.ts` gegen einen echten Daemon mit Fixture-Projekt MS2
 *             (tests/e2e/ui_fixture.py, Produktions-Build nach .e2e/dist-prod)
 *     shots   `*.shots.spec.ts`  Screenshots je Screen bei 1440x900 dunkel und hell nach
 *             .e2e/shots/ (Augenprüfung gegen die Design-Screenshots, kein Pixelvergleich)
 * - Welche Server starten, steuert ARIADNE_E2E (mock | daemon | all); die npm-Skripte setzen es.
 * - Freie Ports: einmal im Runner gewählt und über die Umgebung an die Worker gegeben.
 * - Jeder Test bricht ab, wenn die Seite eine CSP-Verletzung oder einen Seitenfehler meldet
 *   (e2e/fixtures.ts).
 */
import { defineConfig } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const CHROMIUM = process.env.ARIADNE_CHROMIUM ?? '/opt/pw-browsers/chromium-1194/chrome-linux/chrome';
const MODE = process.env.ARIADNE_E2E ?? 'mock';
const REPO = resolve(import.meta.dirname, '..');
const PYTHON = process.env.ARIADNE_PYTHON ?? resolve(REPO, '.venv/bin/python');

function freePort(): number {
  const out = execFileSync(process.execPath, [
    '-e',
    "const s=require('net').createServer();s.listen(0,'127.0.0.1',()=>{process.stdout.write(String(s.address().port));s.close()})",
  ]);
  return Number(String(out).trim());
}

if (!process.env.ARIADNE_E2E_MOCK_PORT) process.env.ARIADNE_E2E_MOCK_PORT = String(freePort());
if (!process.env.ARIADNE_E2E_DAEMON_PORT) process.env.ARIADNE_E2E_DAEMON_PORT = String(freePort());
const MOCK_PORT = Number(process.env.ARIADNE_E2E_MOCK_PORT);
const DAEMON_PORT = Number(process.env.ARIADNE_E2E_DAEMON_PORT);
// Zustandsdatei des Fixture-Daemons je Lauf (parallele Läufe stören sich nicht); die Worker lesen
// sie über ARIADNE_E2E_STATE (e2e/fixtures.ts).
if (!process.env.ARIADNE_E2E_STATE) process.env.ARIADNE_E2E_STATE = resolve(import.meta.dirname, `.e2e/daemon-${process.pid}.json`);
export const DAEMON_STATE = process.env.ARIADNE_E2E_STATE;

const servers = [];
if (MODE === 'mock' || MODE === 'all') {
  servers.push({
    command: `npm run build:mock --silent && npx vite preview --outDir dist --port ${MOCK_PORT} --strictPort`,
    url: `http://127.0.0.1:${MOCK_PORT}/`,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: 'ignore' as const,
    stderr: 'pipe' as const,
  });
}
if (MODE === 'daemon' || MODE === 'all') {
  servers.push({
    command:
      `npx vite build --outDir .e2e/dist-prod --emptyOutDir --logLevel warn && ` +
      `cd .. && ${PYTHON} -m tests.e2e.ui_fixture --port ${DAEMON_PORT} --static webui/.e2e/dist-prod --state-file ${DAEMON_STATE}`,
    url: `http://127.0.0.1:${DAEMON_PORT}/api/v1/status`,
    reuseExistingServer: false,
    timeout: 180_000,
    stdout: 'pipe' as const,
    stderr: 'pipe' as const,
    gracefulShutdown: { signal: 'SIGTERM' as const, timeout: 10_000 },
  });
}

if (!existsSync(CHROMIUM)) {
  throw new Error(`Chromium fehlt: ${CHROMIUM} (ARIADNE_CHROMIUM setzen; nie playwright install)`);
}

export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: [['list']],
  webServer: servers,
  use: {
    headless: true,
    viewport: { width: 1440, height: 900 },
    colorScheme: 'dark',
    locale: 'de-CH',
    timezoneId: 'Europe/Zurich',
    launchOptions: {
      executablePath: CHROMIUM,
      args: process.getuid?.() === 0 ? ['--no-sandbox'] : [],
    },
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'mock', testMatch: /\.mock\.spec\.ts$/, use: { baseURL: `http://127.0.0.1:${MOCK_PORT}` } },
    { name: 'daemon', testMatch: /\.daemon\.spec\.ts$/, use: { baseURL: `http://127.0.0.1:${DAEMON_PORT}` } },
    { name: 'shots', testMatch: /\.shots\.spec\.ts$/, use: { baseURL: `http://127.0.0.1:${MOCK_PORT}` } },
  ],
});
