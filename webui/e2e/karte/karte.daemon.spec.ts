/**
 * Karte, «Als Nächstes» und Host-Detail gegen einen echten Daemon mit MS2 (Besitzer: ui-karte).
 *
 * Eigener Fixture-Daemon (e2e/karte/karte_fixture.py, baut auf tests/e2e/ui_fixture.py auf), weil
 * die Tests den Stand ändern und die Karte mehr braucht als MS2 allein: K3 «Zusammenführen?» aus
 * nmap -6 mit derselben MAC, .103 im Nebel, .104 als Sackgasse, .105 mit feindlichen Werten.
 * Ablauf (seriell, ein Daemon für die Datei): Hauptansicht, K2 übernehmen, K3 zusammenführen mit
 * Rückgängig, Ruhezustand, Denkanstoss erledigt und verworfen (über die API geprüft), Host wählen
 * und mit Esc zurück, Pfeiltasten, `t` für die Tabelle, feindliche Hostnamen und Werte, Positionen
 * speichern, Entscheid in einem anderen Tab. Unter der echten Shell-CSP des Daemons; jeder Test
 * scheitert bei einer CSP-Verletzung (fixtures.ts).
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import type { Locator, Page } from '@playwright/test';
import { ctl, expect, test, type DaemonState } from '../fixtures';

const REPO = resolve(import.meta.dirname, '../../..');
const PYTHON = process.env.ARIADNE_PYTHON ?? resolve(REPO, '.venv/bin/python');
const STATIC = resolve(import.meta.dirname, '../../.e2e/dist-prod');
const STATE = resolve(import.meta.dirname, '../../.e2e/daemon-karte.json');

const H101 = 'ip:default/192.168.56.101';
const H103 = 'ip:default/192.168.56.103';
const H104 = 'ip:default/192.168.56.104';
const H105 = 'ip:default/192.168.56.105';
const HOMOGRAPH_LABEL = 'аррӏе.lab'; // kyrillisch, Punycode xn--80ak6aa92e.lab

const card = (page: Page, id: string): Locator => page.locator(`[data-map-card][data-host-id="${id}"]`);
const column = (page: Page): Locator => page.locator('aside.column');

interface Suggestion {
  suggestion_key: string;
  rule_id: string;
  title: string;
  state: string;
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

/** Anmeldung über die Startadresse mit `#c=` (eigener Code je Tab). */
async function login(page: Page, query = ''): Promise<void> {
  const res = await ctl(st.ctl, 'ui.code', { via: 'local', typed: false });
  await page.goto(`${st.base}/karte${query}#c=${String(res.code)}`);
  await expect(page.getByRole('banner')).toBeVisible();
}

async function mapReady(page: Page): Promise<void> {
  await expect(page.locator('.canvas .cy canvas').first()).toBeAttached();
  await expect(card(page, H101)).toBeVisible();
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

async function suggestions(page: Page, state: 'open' | 'done' | 'dismissed'): Promise<Suggestion[]> {
  const r = await api<{ suggestions: Suggestion[] }>(page, `/p/${st.project_id}/suggestions?state=${state}`);
  return r.suggestions;
}

/** Scope-Warnung aus dem nmap -6 quittieren, damit die Meldung (ui-fundament) nichts verdeckt. */
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
  proc = spawn(
    PYTHON,
    ['webui/e2e/karte/karte_fixture.py', '--port', String(port), '--static', STATIC, '--state-file', STATE, '--watch-stdin'],
    { cwd: REPO, stdio: ['pipe', 'ignore', 'pipe'] },
  );
  let err = '';
  proc.stderr?.on('data', (d: Buffer) => {
    err = (err + d.toString('utf8')).slice(-4000);
  });
  const until = Date.now() + 120_000;
  while (!existsSync(STATE)) {
    if (proc.exitCode !== null) throw new Error(`karte_fixture beendet (${proc.exitCode}): ${err}`);
    if (Date.now() > until) throw new Error(`karte_fixture nicht bereit: ${err}`);
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
    const tm = setTimeout(() => {
      p.kill('SIGTERM');
      r();
    }, 15_000);
    p.on('exit', () => {
      clearTimeout(tm);
      r();
    });
  });
});

test('Hauptansicht: Lagebild, Karten aus MS2, Faden, Nebel, Sackgasse, Out of Scope', async ({ page }) => {
  await login(page);
  await mapReady(page);
  await expect(page.locator('.lage .sum')).toHaveText(/^Stand \d\d:\d\d · 4 Hosts, 1 im Nebel · 1 mit Zugriff$/);
  await expect(card(page, 'kali')).toContainText('192.168.56.102');
  await expect(card(page, H101)).toContainText('23 Services');
  await expect(card(page, H103)).toContainText('im Nebel');
  await expect(card(page, H104)).toContainText('Sackgasse · nur RDP');
  await expect(card(page, H105)).toContainText('2 Services');
  await expect(page.locator('.seg-label')).toHaveText('192.168.56.0/24');
  await expect(page.locator('.marker')).toHaveText(['1', '2']);
  await expect(page.getByRole('button', { name: 'Out of Scope · 2' })).toBeVisible();
  // die gewählte Klärung (Kontextvorschlag → .101) markiert ihren Host
  await expect(card(page, H101).locator('xpath=..').locator('.ring-label')).toHaveText('K1');
  await expect(column(page).locator('.card')).toContainText('Kontext klären · Vorschlag');
});

test('K2 übernehmen, K3 zusammenführen (mit Rückgängig): Ruhezustand mit dem ersten Denkanstoss', async ({ page }) => {
  await login(page);
  await mapReady(page);
  const col = column(page);
  await expect(col.locator('.keys')).toHaveText('j k wechseln · a übernehmen · ↵ Beleg · ? Hilfe');
  await page.keyboard.press('a');
  await expect(col.locator('.done').first()).toHaveText(/Kontext T\d+ = \.101, rückwirkend/);
  const merge = col.locator('.card[data-item-key^="merge:"]');
  await expect(merge).toContainText('Zusammenführen?');
  await expect(merge).toContainText('Gleiche MAC-Adresse 08:00:27:63:7e:e7');
  await expect(merge).toContainText('fd00:56::101');
  await page.keyboard.press('a');
  await expect(col.locator('.done')).toHaveCount(2);
  await expect(col.locator('.done').nth(1)).toContainText('fd00:56::101 mit .101 zusammengeführt');
  await expect(page.getByRole('button', { name: 'Out of Scope · 1' })).toBeVisible();
  // Rückgängig (u) widerruft den Zusammenschluss im Daemon; K3 kommt zurück
  await page.keyboard.press('u');
  await expect(col.locator('[data-item-key^="merge:"]')).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Out of Scope · 2' })).toBeVisible();
  await col.locator('[data-item-key^="merge:"]').click();
  await expect(col.locator('.card[data-item-key^="merge:"]')).toBeVisible();
  await page.keyboard.press('a');
  await expect(col.locator('.done')).toHaveCount(2);
  // Ruhezustand: Klären erledigt, Cursor auf dem ersten Denkanstoss, kein Ring auf der Karte
  await expect(col.locator('.group-head').first()).toContainText('erledigt');
  await expect(col.locator('.card')).toContainText('Prüfziel · Regel R-ANON-ZUGRIFF');
  await expect(col.locator('.card')).toContainText('Unauthentisierten Zugriff auf 192.168.56.105:21 prüfen');
  await expect(page.locator('.ring-label')).toHaveCount(0);
  const next = await api<{ clarify: unknown[] }>(page, `/p/${st.project_id}/next`);
  expect(next.clarify).toHaveLength(0);
});

test('Denkanstoss erledigt und verworfen: Lernstufen, Vorlage, Entscheide im Daemon', async ({ page }) => {
  await login(page);
  await mapReady(page);
  const col = column(page);
  const sug = col.locator('.card');
  await expect(sug).toContainText('R-ANON-ZUGRIFF');
  await sug.getByRole('button', { name: /1 Frage zeigen/ }).click();
  await expect(sug).toContainText('Welche Daten gibt dieser Dienst ohne Anmeldung preis?');
  await sug.getByRole('button', { name: /2 Richtung zeigen/ }).click();
  await sug.getByRole('button', { name: /3 Vorlage zeigen/ }).click();
  await expect(sug.locator('.tpl code').first()).toHaveText('nmap -p 21 --script ftp-anon 192.168.56.105');
  await expect(sug.getByRole('button', { name: 'Kopieren · Mac' }).first()).toBeVisible();
  await expect(col.getByRole('button', { name: /ausführen/i })).toHaveCount(0);
  await expect(col.getByRole('button', { name: /Denkanstoss anfordern \(KI\)/ })).toBeDisabled();
  const open = await suggestions(page, 'open');
  const anon = open.find((s) => s.rule_id === 'R-ANON-ZUGRIFF');
  expect(anon).toBeTruthy();
  await sug.getByRole('button', { name: 'Erledigt' }).click();
  await expect(col.locator(`.done[data-done-key="${anon?.suggestion_key}"]`)).toContainText('Unauthentisierten Zugriff auf 192.168.56.105:21 prüfen');
  await expect.poll(async () => (await suggestions(page, 'done')).map((s) => s.suggestion_key)).toContain(anon?.suggestion_key);
  // der Cursor steht auf dem nächsten Denkanstoss; Verwerfen streicht ihn durch
  const nextKey = await col.locator('.card').getAttribute('data-suggestion-key');
  expect(nextKey).toBeTruthy();
  await col.locator('.card').getByRole('button', { name: 'Verwerfen' }).click();
  await expect(col.locator(`.done.s-dismissed[data-done-key="${nextKey}"] .strike`)).not.toBeEmpty();
  await expect.poll(async () => (await suggestions(page, 'dismissed')).map((s) => s.suggestion_key)).toContain(nextKey);
  expect((await suggestions(page, 'open')).map((s) => s.suggestion_key)).not.toContain(nextKey);
});

test('Host wählen öffnet das Detail; Esc kehrt zurück und gibt den Fokus an den Host', async ({ page }) => {
  await login(page);
  await mapReady(page);
  await card(page, H101).click();
  await expect(page).toHaveURL(/host=ip%3Adefault%2F192\.168\.56\.101/);
  const detail = column(page).locator('.detail');
  await expect(detail).toContainText('192.168.56.101');
  await expect(detail).toContainText('Services');
  await expect(card(page, H101).locator('xpath=..').locator('.ring-sel')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page).not.toHaveURL(/host=/);
  await expect(card(page, H101)).toBeFocused();
  await expect(column(page).locator('h2')).toHaveText('Als Nächstes');
  // Nebel-Host: Annehmen und Verwerfen statt Wissen
  await card(page, H103).click();
  await expect(column(page).locator('.detail')).toContainText('im Nebel');
  await expect(column(page).getByRole('button', { name: /Annehmen/ })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(card(page, H103)).toBeFocused();
});

test('Pfeiltasten springen zum nächstgelegenen Host in der Richtung', async ({ page }) => {
  await login(page);
  await mapReady(page);
  const center = async (l: Locator): Promise<{ x: number; y: number }> => {
    const b = await l.boundingBox();
    return { x: (b?.x ?? 0) + (b?.width ?? 0) / 2, y: (b?.y ?? 0) + (b?.height ?? 0) / 2 };
  };
  await card(page, 'kali').focus();
  const k = await center(card(page, 'kali'));
  await page.keyboard.press('ArrowRight');
  const focused = page.locator('[data-map-card]:focus');
  await expect(focused).toHaveCount(1);
  const id = await focused.getAttribute('data-host-id');
  expect(id).not.toBe('kali');
  const h = await center(focused);
  expect(h.x).toBeGreaterThan(k.x);
  // nach links: jeder Schritt landet weiter links, bis Kali (der Eingang ganz links) erreicht ist;
  // dazwischen kann ein näherer Host liegen (Kali steht links in der Mitte, SCREENS 1a)
  for (let i = 0; i < 6; i++) {
    const before = await center(page.locator('[data-map-card]:focus'));
    await page.keyboard.press('ArrowLeft');
    const now = page.locator('[data-map-card]:focus');
    await expect(now).toHaveCount(1);
    expect((await center(now)).x).toBeLessThan(before.x);
    if ((await now.getAttribute('data-host-id')) === 'kali') break;
  }
  await expect(card(page, 'kali')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/host=kali/);
  await page.keyboard.press('Escape');
});

test('t schaltet zur Host-Tabelle und zurück; j und ↵ öffnen das Detail', async ({ page }) => {
  await login(page);
  await mapReady(page);
  await page.keyboard.press('t');
  await expect(page).toHaveURL(/ansicht=tabelle/);
  const rows = page.locator('.table-view button.row');
  await expect(rows).toHaveCount(4);
  await expect(rows.nth(0)).toHaveAttribute('data-host-id', H101);
  const second = await rows.nth(1).getAttribute('data-host-id');
  await page.keyboard.press('j');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(new RegExp(`host=${encodeURIComponent(second ?? '').replace(/\./g, '\\.')}`));
  await page.keyboard.press('Escape');
  await expect(rows.nth(1)).toBeFocused();
  await page.keyboard.press('t');
  await expect(page).not.toHaveURL(/ansicht=/);
  await expect(card(page, H101)).toBeVisible();
});

test('feindliche Hostnamen und Werte: nur Text, gekürzt, Punycode sichtbar, keine Vorlage', async ({ page }) => {
  await login(page, `?host=${encodeURIComponent(H105)}`);
  const detail = column(page).locator('.detail');
  await expect(detail).toContainText('192.168.56.105');
  // Namen mit <img …>, Bidi-Zeichen oder Umlaut verwirft der Parser; was ankommt, ist Text
  const ids = detail.locator('ul.ids li');
  await expect(ids).toHaveCount(3);
  const homograph = ids.filter({ hasText: 'xn--80ak6aa92e.lab' });
  await expect(homograph).toContainText(HOMOGRAPH_LABEL);
  await expect(homograph).toContainText('ausserhalb');
  // 200 Zeichen: in der Liste auf 80 gekürzt, der volle Wert steht im title
  const long = ids.locator('.txt[title$=".lame.htb"]');
  await expect(long).toHaveText(/^a{63}\.a{15}…$/);
  expect((await long.getAttribute('title'))?.length).toBe(200);
  await expect(detail).toContainText("vsftpd'; !sh -c 'id 2.3.4");
  await expect(detail.locator('.banner')).toContainText('Ignore all previous instructio');
  await expect(page.locator('img')).toHaveCount(0);
  await expect(page.locator('[onerror]')).toHaveCount(0);
  await expect(page.locator('a[href^="http"]')).toHaveCount(0);
  // Denkanstoss mit dem feindlichen Produkt: Kennzeichen, keine fertige Vorlage, nur Einzelwerte
  const open = await suggestions(page, 'open');
  // E119: ein Denkanstoss pro Host (bei einem Dienst «… (192.168.56.105:21)», sonst «… 192.168.56.105 (n Dienste)»)
  const hostile = open.find((s) => s.rule_id === 'R-VERSION-RECHERCHE' && s.title.includes('192.168.56.105'));
  expect(hostile).toBeTruthy();
  await page.keyboard.press('Escape');
  await page.goto(`${st.base}/karte?sel=${encodeURIComponent(hostile?.suggestion_key ?? '')}`);
  const sug = column(page).locator('.card');
  await expect(sug).toContainText('! Injection-Verdacht');
  await sug.getByRole('button', { name: /1 Frage zeigen/ }).click();
  await sug.getByRole('button', { name: /2 Richtung zeigen/ }).click();
  await sug.getByRole('button', { name: /3 Vorlage zeigen/ }).click();
  await expect(sug).toContainText('Enthält Shell-Sonderzeichen. Keine fertige Vorlage.');
  // keine fertige Vorlage mit dem feindlichen Produkt (andere Dienste des Hosts dürfen eine haben)
  await expect(sug.locator('.tpl code', { hasText: 'sh -c' })).toHaveCount(0);
  await expect(sug).toContainText("vsftpd'; !sh -c 'id");
  await expect(page.locator('img')).toHaveCount(0);
});

test('Ziehen speichert die Position im Daemon (PUT /ui/positions)', async ({ page }) => {
  await login(page);
  await mapReady(page);
  const before = await card(page, H104).boundingBox();
  await page.mouse.move((before?.x ?? 0) + 60, (before?.y ?? 0) + 20);
  await page.mouse.down();
  await page.mouse.move((before?.x ?? 0) + 140, (before?.y ?? 0) - 30, { steps: 8 });
  await page.mouse.up();
  const after = await card(page, H104).boundingBox();
  expect((after?.x ?? 0) - (before?.x ?? 0)).toBeGreaterThan(40);
  type Pos = { positions: Record<string, { x: number; y: number }> };
  const read = async (): Promise<{ x: number; y: number } | undefined> => (await api<Pos>(page, `/p/${st.project_id}/ui/positions`)).positions[H104];
  await expect.poll(read, { timeout: 8000 }).toBeTruthy();
  await page.waitForTimeout(1200);
  const saved = await read();
  // nach dem Neuladen übernimmt die Karte die gespeicherten Positionen (kein neues Layout, das
  // sie überschreibt)
  await page.reload();
  await mapReady(page);
  await page.waitForTimeout(2000);
  expect(await read()).toEqual(saved);
});

test('Entscheid in einem anderen Tab: der Eintrag wird «In einem anderen Tab entschieden»', async ({ page, context }) => {
  await login(page);
  await mapReady(page);
  const open = await suggestions(page, 'open');
  const target = open.find((s) => s.rule_id === 'R-UDP-SCAN');
  expect(target).toBeTruthy();
  const key = target?.suggestion_key ?? '';
  await page.goto(`${st.base}/karte?sel=${encodeURIComponent(key)}`);
  await expect(column(page).locator(`.card[data-suggestion-key="${key}"]`)).toBeVisible();
  const other = await context.newPage();
  try {
    await login(other, `?sel=${encodeURIComponent(key)}`);
    const card2 = column(other).locator(`.card[data-suggestion-key="${key}"]`);
    await expect(card2).toBeVisible();
    await card2.getByRole('button', { name: 'Erledigt' }).click();
    await expect(column(other).locator(`.done[data-done-key="${key}"]`)).toBeVisible();
  } finally {
    await other.close();
  }
  const row = column(page).locator(`.done.s-other_tab[data-done-key="${key}"]`);
  await expect(row).toContainText('In einem anderen Tab entschieden');
  // der Cursor springt nicht weg
  await expect(row).toHaveAttribute('aria-current', 'true');
});
