/**
 * Terminals, Zeitachse, Belegansicht und Findings gegen einen echten Daemon mit MS2
 * (tests/e2e/ui_fixture.py; Besitzer: ui-verlauf).
 *
 * Eigener Fixture-Daemon mit eigener Zustandsdatei (.e2e/daemon-verlauf.json), weil die Tests den
 * Stand ändern (Rückgängig, Finding, Kontext, Pause) und andere Teile gleichzeitig gegen den
 * gemeinsamen Daemon testen. Ablauf seriell: Rückgängig mit Grund und Rückmeldung, Wieder vertrauen
 * (beides über die API geprüft), Beleg öffnen und mit Esc schliessen (Fokus zurück), Finding aus
 * dem Beleg anlegen (über die API geprüft), verdeckte Eingabe aufdecken, Kontext setzen (über die
 * API geprüft), Pause und Fortsetzen. Unter der echten Shell-CSP des Daemons; jeder Test scheitert
 * bei einer CSP-Verletzung (fixtures.ts).
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import type { Page } from '@playwright/test';
import { ctl, expect, test, type DaemonState } from '../fixtures';

const REPO = resolve(import.meta.dirname, '../../..');
const PYTHON = process.env.ARIADNE_PYTHON ?? resolve(REPO, '.venv/bin/python');
const STATIC = process.env.ARIADNE_VERLAUF_STATIC ?? resolve(import.meta.dirname, '../../.e2e/dist-prod');
const STATE = resolve(import.meta.dirname, '../../.e2e/daemon-verlauf.json');

interface Stage {
  depth: number;
  host_label: string | null;
  user: string | null;
}
interface Term {
  terminal_id: string;
  ordinal: number | null;
  label: string | null;
  state: string;
  stack: Stage[];
  suggestion: { item_key: string; host_label: string } | null;
}
interface Item {
  id: string;
  type: string;
  cmd?: { cmd_id: string; text: string };
  unit_id?: string;
  distrusted?: { decision_id: string; rejected: number; weakened: number } | null;
}
interface FindingSummary {
  finding_id: string;
  ordinal: number;
  title: string;
  severity: string | null;
  evidence_count: number;
}

let proc: ChildProcess | null = null;
let st: DaemonState;

function freePort(): Promise<number> {
  return new Promise((resolveP, reject) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      s.close(() => (typeof addr === 'object' && addr ? resolveP(addr.port) : reject(new Error('kein Port'))));
    });
  });
}

async function login(page: Page, path: string): Promise<void> {
  const res = await ctl(st.ctl, 'ui.code', { via: 'local', typed: false });
  await page.goto(`${st.base}${path}#c=${String(res.code)}`);
  await expect(page.getByRole('banner')).toBeVisible();
}

function token(page: Page): Promise<string | null> {
  // eslint-disable-next-line no-restricted-globals -- der Test liest das Token dieses Tabs nur aus
  return page.evaluate(() => sessionStorage.getItem('ariadne.token'));
}

/** GET auf die API mit dem Token des Tabs (nur zum Prüfen des Daemon-Stands). */
async function api<T>(page: Page, path: string): Promise<T> {
  const tok = await token(page);
  return page.evaluate(
    async ({ path, tok }) => {
      const res = await fetch(`/api/v1${path}`, { headers: { Authorization: `Bearer ${tok}` } });
      if (!res.ok) throw new Error(`${path}: ${res.status}`);
      return (await res.json()) as T;
    },
    { path, tok },
  );
}

async function terminals(page: Page): Promise<Term[]> {
  return (await api<{ terminals: Term[] }>(page, '/terminals')).terminals;
}

async function termByLabel(page: Page, label: string): Promise<Term> {
  const t = (await terminals(page)).find((x) => x.label === label);
  if (!t) throw new Error(`Terminal ${label} fehlt`);
  return t;
}

async function nmapItem(page: Page): Promise<Item> {
  const r = await api<{ items: Item[] }>(page, `/p/${st.project_id}/timeline?types=command&limit=200`);
  const it = r.items.find((x) => x.type === 'command' && x.cmd?.text.startsWith('nmap -sV -sC'));
  if (!it) throw new Error('nmap-Befehl fehlt in der Zeitachse');
  return it;
}

/** Scope-Warnung aus dem ping quittieren, damit die Meldung (ui-fundament) nichts verdeckt. */
async function ackScopeWarning(): Promise<void> {
  const res = await ctl(st.ctl, 'ui.code', { via: 'local', typed: false });
  const headers = { Origin: st.base, 'Content-Type': 'application/json' };
  const sess = (await (await fetch(`${st.base}/api/v1/session`, { method: 'POST', headers, body: JSON.stringify({ code: res.code }) })).json()) as {
    token: string;
  };
  const auth = { ...headers, Authorization: `Bearer ${sess.token}` };
  const status = (await (await fetch(`${st.base}/api/v1/status`, { headers: auth })).json()) as { scope_warning: { cmd_id: string } | null };
  if (status.scope_warning) {
    const put = await fetch(`${st.base}/api/v1/p/${st.project_id}/ui/scope-ack`, {
      method: 'PUT',
      headers: auth,
      body: JSON.stringify({ cmd_id: status.scope_warning.cmd_id }),
    });
    expect(put.status).toBe(202);
  }
  await fetch(`${st.base}/api/v1/session`, { method: 'DELETE', headers: auth });
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  test.skip(!existsSync(resolve(STATIC, 'index.html')), 'Produktions-Build fehlt (.e2e/dist-prod)');
  test.setTimeout(150_000);
  const port = await freePort();
  rmSync(STATE, { force: true });
  proc = spawn(PYTHON, ['-m', 'tests.e2e.ui_fixture', '--port', String(port), '--static', STATIC, '--state-file', STATE, '--watch-stdin'], {
    cwd: REPO,
    stdio: ['pipe', 'ignore', 'pipe'],
  });
  let err = '';
  proc.stderr?.on('data', (d: Buffer) => {
    err = (err + d.toString('utf8')).slice(-4000);
  });
  const until = Date.now() + 120_000;
  while (!existsSync(STATE)) {
    if (proc.exitCode !== null) throw new Error(`ui_fixture beendet (${proc.exitCode}): ${err}`);
    if (Date.now() > until) throw new Error(`ui_fixture nicht bereit: ${err}`);
    await new Promise((r) => setTimeout(r, 200));
  }
  st = JSON.parse(readFileSync(STATE, 'utf8')) as DaemonState;
  await ackScopeWarning();
});

test.afterAll(async () => {
  const p = proc;
  if (!p) return;
  p.stdin?.end();
  await new Promise<void>((r) => {
    if (p.exitCode !== null) return r();
    const kill = setTimeout(() => p.kill('SIGKILL'), 10_000);
    p.once('exit', () => {
      clearTimeout(kill);
      r();
    });
    p.kill('SIGTERM');
  });
  rmSync(STATE, { force: true });
});

test('Zeitachse: Rückgängig mit Grund, Rückmeldung inline, Wieder vertrauen', async ({ page }) => {
  await login(page, '/zeitachse');
  const nmap = await nmapItem(page);
  expect(nmap.distrusted ?? null).toBeNull();
  const r = page.locator(`li.item[data-row="${nmap.id}"]`);
  await expect(r).toContainText('nmap -sV -sC');
  await r.click();
  await expect(r).toHaveAttribute('aria-current', 'true');
  await page.keyboard.press('u');
  const form = page.getByRole('form', { name: 'Werte aus diesem Befehl verwerfen?' });
  await expect(form).toBeVisible();
  await form.getByLabel('Grund (optional)').fill('Banner manipuliert');
  await form.getByRole('button', { name: 'Rückgängig machen' }).click();
  await expect(r).toContainText(/\d+ verworfen, \d+ geschwächt/);
  const after = await nmapItem(page);
  expect(after.distrusted?.rejected ?? 0).toBeGreaterThan(0);
  await expect(r).toContainText(`${after.distrusted?.rejected} verworfen, ${after.distrusted?.weakened} geschwächt`);
  await expect(r).toContainText('misstraut');
  // der Entscheid steht mit Grund in der Zeitachse
  await expect(page.getByRole('region', { name: 'Zeitachse' })).toContainText('Banner manipuliert');

  await r.getByRole('button', { name: 'Wieder vertrauen' }).first().click();
  await expect(r).toContainText('Wieder vertraut');
  await expect.poll(async () => (await nmapItem(page)).distrusted ?? null).toBeNull();
  await expect(r).not.toContainText('misstraut');
});

test('Beleg öffnen mit ↵ und mit Esc schliessen, Fokus zurück auf die Zeile', async ({ page }) => {
  await login(page, '/zeitachse');
  const nmap = await nmapItem(page);
  const r = page.locator(`li.item[data-row="${nmap.id}"]`);
  await r.click();
  await page.keyboard.press('Enter');
  const p = page.getByRole('region', { name: 'Beleg' });
  await expect(p).toBeVisible();
  await expect(p.locator('h2')).toHaveText(/^Beleg · T1 scan · \d\d:\d\d:\d\d$/);
  await expect(p.locator('dl.meta')).toContainText('nmap -sV -sC -oA scans/ms2 192.168.56.101');
  await expect(p.locator('dl.meta')).toContainText('✓ geprüft');
  await expect(p.locator('.line').first()).toBeVisible();
  await expect(p.locator('.line').first()).toContainText(/Nmap|Starting|nmap/);
  await page.keyboard.press('Escape');
  await expect(p).toBeHidden();
  await expect(page).not.toHaveURL(/beleg=/);
  await expect(r).toBeFocused();
});

test('Finding aus dem Beleg anlegen, über die API geprüft', async ({ page }) => {
  await login(page, '/zeitachse');
  const nmap = await nmapItem(page);
  const before = (await api<{ findings: FindingSummary[] }>(page, `/p/${st.project_id}/findings`)).findings;
  await page.locator(`li.item[data-row="${nmap.id}"]`).dblclick();
  const p = page.getByRole('region', { name: 'Beleg' });
  await expect(p.locator('.line').first()).toBeVisible();
  await p.getByRole('button', { name: 'Als Finding' }).click();
  await expect(page).toHaveURL(/\/findings\?.*finding=neu/);
  const form = page.getByRole('form', { name: 'Neues Finding' });
  await expect(form).toContainText('T1 scan · nmap -sV -sC');
  await expect(form).toContainText('angelegt aus dem Beleg');
  await form.getByLabel('Titel').fill('Samba 3.x auf 192.168.56.101');
  await form.getByRole('radio', { name: 'Mittel' }).click();
  await form.getByRole('button', { name: /^Speichern/ }).click();
  await expect(page).not.toHaveURL(/finding=neu/);
  await expect(page.locator('a.card.sel')).toContainText('Samba 3.x auf 192.168.56.101');
  const list = (await api<{ findings: FindingSummary[] }>(page, `/p/${st.project_id}/findings`)).findings;
  expect(list.length).toBe(before.length + 1);
  const f = list.find((x) => x.title === 'Samba 3.x auf 192.168.56.101');
  expect(f).toMatchObject({ severity: 'medium', evidence_count: 1 });
  const detail = await api<{ created_from: { unit_id: string | null } | null }>(page, `/p/${st.project_id}/findings/${f?.finding_id}`);
  expect(detail.created_from?.unit_id).toBe(nmap.unit_id);
  await expect(page.locator('a.card.sel')).toContainText(`F${f?.ordinal}`);
});

test('verdeckte Eingabe in T3 einzeln aufdecken und wieder verdecken', async ({ page }) => {
  await login(page, '/terminals');
  const t3 = await termByLabel(page, 'listener');
  const row = page.locator(`li[data-terminal="${t3.terminal_id}"]`);
  await expect(row).toContainText('Eingabe ohne Echo');
  await expect(row).toContainText('••••••••');
  await expect(row).not.toContainText('geheim-731');
  await row.getByRole('button', { name: 'Aufdecken' }).first().click();
  await expect(row).toContainText('geheim-731');
  await row.getByRole('button', { name: 'Verdecken' }).first().click();
  await expect(row).not.toContainText('geheim-731');
});

test('Kontext setzen für T2 über den Dialog, über die API geprüft', async ({ page }) => {
  await login(page, '/terminals');
  const t2 = await termByLabel(page, 'msf');
  const row = page.locator(`li[data-terminal="${t2.terminal_id}"]`);
  const top = t2.stack[t2.stack.length - 1];
  expect(top?.host_label ?? null).toBeNull();
  await row.getByRole('button', { name: t2.suggestion ? /^Anderer Host/ : /^Kontext setzen/ }).click();
  const dlg = page.getByRole('dialog', { name: /Kontext für T2/ });
  await expect(dlg).toBeVisible();
  await dlg.getByLabel('Host').fill('192.168.56.101');
  await dlg.getByLabel('Benutzer').fill('root');
  await dlg.getByRole('button', { name: 'Setzen' }).click();
  await expect(dlg.getByRole('status').or(page.getByText('Kontext gesetzt'))).toBeVisible();
  if (await dlg.isVisible()) await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(dlg).toBeHidden();
  await expect
    .poll(async () => {
      const t = await termByLabel(page, 'msf');
      const s = t.stack[t.stack.length - 1];
      return `${s?.host_label ?? '-'} ${s?.user ?? '-'}`;
    })
    .toBe('192.168.56.101 root');
  await expect(row).toContainText('192.168.56.101');
});

test('Pause 10 min für T1: wartet auf Bestätigung, Pause bis, Fortsetzen', async ({ page }) => {
  await login(page, '/terminals');
  const t1 = await termByLabel(page, 'scan');
  expect(t1.state).toBe('on');
  const row = page.locator(`li[data-terminal="${t1.terminal_id}"]`);
  await row.getByRole('button', { name: /^Pause für T1/ }).click();
  await expect(row).toContainText(/Pause bis \d\d:\d\d/, { timeout: 10_000 });
  await expect.poll(async () => (await termByLabel(page, 'scan')).state).toBe('paused');
  await row.getByRole('button', { name: /fortsetzen/ }).click();
  await expect(row).toContainText('nimmt auf', { timeout: 10_000 });
  await expect.poll(async () => (await termByLabel(page, 'scan')).state).toBe('on');
});
