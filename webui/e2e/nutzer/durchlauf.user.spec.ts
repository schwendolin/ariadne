/**
 * Echter Durchlauf als Nutzer (Integration v0.1-Oberfläche, Auftrag 2).
 *
 * Ablauf wie im Alltag in der Kali, nur isoliert (tests/e2e/user_lab.py): eigenes HOME,
 * `ariadne setup`, `ariadne init`, Daemon mit Web-Server, `ariadne ui` liefert den Code, Chromium
 * meldet sich an. Danach die MS2-Session aus Anhang A des Briefings mit echten zsh-Terminals:
 * `ariadne start ms2`, nmap gegen .101, Sweep mit .103 im Nebel und .104, nmap -6 (Scope-Warnung,
 * Zusammenführen), Honeypot .110 mit feindlichem Banner und Produkt, UDP-Scan nach ausserhalb
 * (Warteliste), msfconsole (Kontext automatisch), nc-Listener mit zweitem Callback (Kontextvorschlag),
 * Eingabe ohne Echo, Schlüsselschritte. Alle Entscheide fallen in der Oberfläche.
 *
 * Die Oberfläche ist der Produktions-Build in src/ariadne/web/static (`npm run build`), ausgeliefert
 * vom Daemon unter seiner strengen CSP. Jeder Screen aus SCREENS.md wird bei 1440x900 dunkel und hell
 * aufgenommen (Ordner ARIADNE_SHOTS_DIR, sonst .e2e/shots-nutzer). Der Test scheitert bei jeder
 * CSP-Verletzung, jedem Seitenfehler und jeder Konsolenmeldung, die nicht ausdrücklich erwartet ist
 * (abgelehnte Codes, Daemon gestoppt).
 */
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Locator, Page } from '@playwright/test';
import { expect, test } from '../fixtures';
import { REPO, UserLab } from './lab';

const STATIC = resolve(REPO, 'src/ariadne/web/static');
const SHOTS = process.env.ARIADNE_SHOTS_DIR ?? resolve(import.meta.dirname, '../../.e2e/shots-nutzer');
const H101 = 'ip:default/192.168.56.101';
const H103 = 'ip:default/192.168.56.103';
const H104 = 'ip:default/192.168.56.104';
const H110 = 'ip:default/192.168.56.110';

const card = (page: Page, id: string): Locator => page.locator(`[data-map-card][data-host-id="${id}"]`);
const column = (page: Page): Locator => page.locator('aside.column');
const header = (page: Page): Locator => page.locator('header.header');

/** Erwartete Konsolenmeldungen gelten nur in einem Abschnitt (`allow`), alles andere scheitert. */
class Console {
  private allowed: RegExp[] = [];
  readonly unexpected: string[] = [];
  readonly seen: string[] = [];
  attach(page: Page): void {
    page.on('console', (m) => {
      // mit Adresse (bei «Failed to load resource» die Anfrage), damit ein Fehlschlag die Ursache nennt
      const where = m.location().url;
      const line = `${m.type()}: ${m.text()}${where ? ` @ ${where}` : ''}`;
      this.seen.push(line);
      if (!this.allowed.some((r) => r.test(m.text()))) this.unexpected.push(line);
    });
  }
  async allow<T>(patterns: RegExp[], fn: () => Promise<T>): Promise<T> {
    const before = this.allowed;
    this.allowed = [...before, ...patterns];
    try {
      return await fn();
    } finally {
      this.allowed = before;
    }
  }
}

/** Screenshot dunkel und hell (Vorlieben bleiben auf «System», das Medium schaltet um). */
async function shot(page: Page, name: string): Promise<void> {
  for (const scheme of ['dark', 'light'] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.waitForTimeout(250);
    await page.screenshot({ path: resolve(SHOTS, `${name}-${scheme}.png`) });
  }
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.waitForTimeout(100);
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

async function setVisibility(page: Page, state: 'hidden' | 'visible'): Promise<void> {
  await page.evaluate((s) => {
    Object.defineProperty(document, 'visibilityState', { value: s, configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
  }, state);
}

interface Status {
  project: { id: string; slug: string } | null;
  terminals: { terminal_id: string; ordinal: number | null; label: string | null; state: string; context_label: string | null }[];
  scope_warning: { cmd_id: string; acked: boolean } | null;
}
interface NextView {
  open: number;
  clarify: { kind: string; item_key: string; ordinal: number | null }[];
  suggestions: { suggestion_key: string; rule_id: string; title: string; host_id: string | null; templates: { rendered: boolean }[] }[];
}
interface TimelineItem {
  id: string;
  type: string;
  cmd?: { cmd_id: string; text: string };
  unit_id?: string;
  terminal_id?: string | null;
  lines?: number;
  state?: string;
  distrusted?: { rejected: number; weakened: number } | null;
}

test.describe.configure({ mode: 'serial' });

let lab: UserLab | null = null;

test.beforeAll(() => {
  const index = resolve(STATIC, 'index.html');
  if (!existsSync(index)) throw new Error('Produktions-Build fehlt: zuerst `npm run build` (schreibt nach src/ariadne/web/static)');
  const age = Date.now() - statSync(index).mtimeMs;
  if (age > 6 * 3600_000) throw new Error('Produktions-Build ist älter als 6 Stunden: `npm run build`');
  mkdirSync(SHOTS, { recursive: true });
});

test.afterAll(async () => {
  await lab?.close();
  lab = null;
});

test('Durchlauf als Nutzer: Anmeldung, MS2-Session, alle Screens, Neustart, Wechsel', async ({ page, context }) => {
  test.setTimeout(900_000);
  const con = new Console();
  con.attach(page);
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  // Die Seite darf in die Zwischenablage schreiben («Kopieren · Mac»), lesen nur der Test
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);

  lab = await UserLab.start();
  const L = lab;
  const setup = await L.call<{ home: string; base: string; secrets_add: number }>('setup');
  expect(setup.secrets_add).toBe(0);
  const base = L.base;
  const ids: Record<string, string> = {};

  // ------------------------------------------------------------------ 9 Anmeldung
  await test.step('9 Anmeldung: Seite, ungültige Eingabe, unbekannter Code', async () => {
    await page.goto(`${base}/`);
    const field = page.getByLabel('Anmeldecode');
    await expect(field).toBeVisible();
    await expect(page.getByText('Ariadne fragt hier nie nach Passphrasen.')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toHaveCount(0);
    await shot(page, '9-anmeldung');
    await field.fill('k7q2 m4');
    await page.keyboard.press('Enter');
    await expect(page.getByRole('alert')).toHaveText('Eingabe ungültig.');
    await shot(page, '9-anmeldung-ungueltig');
    await con.allow([/status of 401/], async () => {
      await field.fill('K7Q2-M4XP');
      await page.keyboard.press('Enter');
      await expect(page.getByRole('alert')).toHaveText('Code unbekannt, abgelaufen oder schon benutzt.');
    });
    await shot(page, '9-anmeldung-unbekannt');
  });

  await test.step('9 Kein Projekt: Anmeldung über die Startadresse von `ariadne ui`', async () => {
    const start = await L.uiUrl();
    expect(start).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/#c=/);
    await page.goto(start);
    await expect(header(page)).toHaveAttribute('data-variant', 'noproject');
    await expect(page).not.toHaveURL(/#c=/);
    await expect(page.getByText('Kein aktives Projekt')).toBeVisible();
    await expect(header(page).locator('.origin')).toHaveText('lokal');
    await shot(page, '9-kein-projekt');
  });

  // ------------------------------------------------------------------ Projekt und Terminals
  await test.step('9 Leeres Projekt: ariadne start ms2, Erste Schritte', async () => {
    const out = await L.cli(['start', 'ms2', '--target', '192.168.56.0/24', '--preroll', 'no'], true);
    expect(out).toContain('Projekt ms2 angelegt');
    await expect(header(page)).toContainText('ms2', { timeout: 15_000 });
    await expect(column(page)).toContainText('Erste Schritte');
    await expect(page.locator('.lage .sum')).toContainText('noch keine Hosts');
    await expect(page.locator('.seg-label')).toHaveText('192.168.56.0/24');
    await page.waitForTimeout(800);
    await shot(page, '9-leeres-projekt');
  });

  await test.step('S2 Erster nmap-Lauf: Host tritt ohne Klick aus dem Nebel', async () => {
    ids.T1 = (await L.call<{ terminal_id: string }>('term_open', { name: 'T1' })).terminal_id;
    await L.call('run', { name: 'T1', cmd: 'cd ~/ariadne/ms2' });
    await L.call('run', { name: 'T1', cmd: 'nmap -sV -sC -oA scans/ms2 192.168.56.101' });
    await expect(card(page, H101)).toContainText('23 Services', { timeout: 30_000 });
    await expect(card(page, 'kali')).toContainText('192.168.56.102');
    // Der Tab wird unsichtbar (Mac zugeklappt): alles Folgende ist «neu seit»
    const put = page.waitForRequest((r) => r.method() === 'PUT' && r.url().endsWith('/ui/seen'));
    await setVisibility(page, 'hidden');
    await put;
    await setVisibility(page, 'visible');
  });

  await test.step('Sweep, Widerspruch in der Spalte entscheiden', async () => {
    await L.call('run', { name: 'T1', cmd: 'nmap -O -v -oX scans/sweep.xml 192.168.56.103-104' });
    await expect(card(page, H103)).toContainText('im Nebel', { timeout: 30_000 });
    await expect(card(page, H104)).toBeVisible();
    const conflict = column(page).locator('.card', { hasText: 'Widerspruch' });
    // Korrektur A4: eine neue Klärung reisst die Auswahl nicht an sich; sie erscheint als Zeile,
    // und der Mensch klappt sie selbst auf.
    const line = column(page).locator('button.line', { hasText: 'Widerspruch' });
    await expect(line.or(conflict).first()).toBeVisible({ timeout: 15_000 });
    if ((await conflict.count()) === 0) await line.first().click();
    await expect(conflict).toBeVisible({ timeout: 15_000 });
    await conflict.locator('.row, li, div', { hasText: 'netbios-ssn' }).getByRole('button', { name: 'Diesen Wert' }).first().click();
    await expect(column(page).locator('.done').first()).toBeVisible({ timeout: 15_000 });
  });

  await test.step('10 Scope-Warnung: nmap -6 gegen fd00:56::101', async () => {
    await L.call('run', { name: 'T1', cmd: 'nmap -6 -sV -oX scans/v6.xml fd00:56::101' });
    const warn = page.getByRole('alert', { name: /Ziel ausserhalb des Scopes/ });
    await expect(warn).toBeVisible({ timeout: 20_000 });
    await expect(warn).toContainText('fd00:56::101');
    await expect(header(page).locator('[data-badge="scope"]')).toBeVisible();
    await shot(page, '10-scope-warnung');
    await warn.getByRole('button', { name: 'Quittieren' }).click();
    await expect(warn).toBeHidden();
    await expect(header(page).locator('[data-badge="scope"]')).toHaveCount(0);
    await expect.poll(async () => (await api<Status>(page, '/status')).scope_warning?.acked).toBe(true);
  });

  await test.step('Honeypot .110, UDP-Scan nach ausserhalb (Warteliste), msf, Listener, Eingabe ohne Echo', async () => {
    await L.call('run', { name: 'T1', cmd: 'nmap -sV -sC -oX scans/h110.xml 192.168.56.110' });
    await expect(card(page, H110)).toBeVisible({ timeout: 30_000 });
    await L.call('run', { name: 'T1', cmd: 'mkdir -p ~/privat' });
    await L.call('run', { name: 'T1', cmd: 'nmap -sU --top-ports 20 -oX ~/privat/udp.xml -oN ~/privat/udp.nmap 192.168.56.101' });
    ids.T2 = (await L.call<{ terminal_id: string }>('term_open', { name: 'T2' })).terminal_id;
    await L.call('send', { name: 'T2', text: 'msfconsole -q', expect: 'session 1 opened' });
    ids.T3 = (await L.call<{ terminal_id: string }>('term_open', { name: 'T3' })).terminal_id;
    await L.call('send', { name: 'T3', text: 'nc -lvnp 4445', expect: '31337' });
    await L.call('send', { name: 'T3', text: 'id', expect: 'uid=0' });
    await L.call('hidden_input', { name: 'T1' });
    // F12 k in T2 (wie der Hotkey): Schlüsselschritt Foothold
    await L.cli(['mark', 'foothold', '--host', '192.168.56.101', '--note', 'vsftpd 2.3.4 Backdoor', '--terminal', ids.T2]);
    await expect
      .poll(async () => (await api<NextView>(page, `/p/${(await api<Status>(page, '/status')).project?.id}/next`)).clarify.map((c) => c.kind).sort(), {
        timeout: 30_000,
      })
      .toEqual(['ctx_suggestion', 'merge_suggestion']);
  });

  const pid = (await api<Status>(page, '/status')).project?.id ?? '';
  expect(pid).not.toBe('');

  await test.step('5 Terminals: Namen ändern, Kontext als Brotkrume, Vorschlag', async () => {
    await page.keyboard.press('2');
    await expect(page).toHaveURL(/\/terminals/);
    for (const [k, name] of [['T1', 'scan'], ['T2', 'msf'], ['T3', 'listener']] as const) {
      const row = page.locator(`li[data-terminal="${ids[k]}"]`);
      await row.getByRole('button', { name: /^Name von T\d+ ändern$/ }).click();
      await row.getByLabel('Name des Terminals').fill(name);
      await row.getByRole('button', { name: 'Speichern' }).click();
      await expect(row.locator('.who .name')).toHaveText(new RegExp(`^${k}\\s*${name}$`), { timeout: 10_000 });
    }
    const t3 = page.locator(`li[data-terminal="${ids.T3}"]`);
    await expect(t3).toContainText('Reverse Shell');
    await expect(t3.getByRole('button', { name: /Vorschlag übernehmen/ })).toBeVisible();
    await expect(page.locator(`li[data-terminal="${ids.T2}"]`)).toContainText('192.168.56.101');
    await expect(page.locator(`li[data-terminal="${ids.T1}"]`)).toContainText('••••••••');
    await expect(page.locator('.notices .notice')).toHaveCount(0, { timeout: 10_000 }); // «Name gespeichert» ist weg
    await shot(page, '5-terminals');
  });

  await test.step('10 Kontext setzen (Dialog aus dem Reiter Terminals)', async () => {
    await page.locator(`li[data-terminal="${ids.T2}"]`).getByRole('button', { name: /Kontext setzen|Anderer Host/ }).click();
    const dlg = page.getByRole('dialog', { name: /Kontext für T2/ });
    await expect(dlg).toBeVisible();
    await shot(page, '10-kontext');
    await page.keyboard.press('Escape');
    await expect(dlg).toBeHidden();
  });

  // ------------------------------------------------------------------ Host-Detail
  await test.step('3 Host-Detail .101: Zugriff root, in Arbeit, Tag, Notiz, Schlüsselschritt Loot', async () => {
    await page.keyboard.press('1');
    await card(page, H101).click();
    const detail = column(page).locator('.detail');
    await expect(detail).toContainText('192.168.56.101');
    await detail.getByRole('button', { name: /ändern/ }).first().click();
    await page.getByRole('menuitemradio', { name: 'root' }).click();
    await expect(detail).toContainText(/root, per Entscheid \d\d:\d\d/, { timeout: 10_000 });
    await detail.getByRole('button', { name: /^offen/ }).click();
    await page.getByRole('menuitemradio', { name: 'in Arbeit' }).click();
    await expect(detail.getByRole('button', { name: /^in Arbeit/ })).toBeVisible({ timeout: 10_000 });
    await detail.getByRole('button', { name: '+ Tag' }).click();
    await detail.getByLabel('Neuer Tag').fill('linux');
    await detail.getByRole('button', { name: 'Speichern' }).click();
    await expect(detail.locator('.tag', { hasText: 'linux' })).toBeVisible({ timeout: 10_000 });
    await detail.getByRole('button', { name: '+ Notiz' }).click();
    await detail.getByLabel('Notiz (Markdown ohne HTML)').fill('vsftpd-Backdoor geht, Samba noch prüfen');
    await detail.getByRole('button', { name: 'Speichern' }).click();
    await expect(detail.locator('.note')).toContainText('vsftpd-Backdoor geht', { timeout: 10_000 });
    await detail.getByRole('button', { name: /Schlüsselschritt markieren/ }).click();
    await page.getByLabel('Notiz zum Schritt (optional)').fill('/etc/shadow');
    await page.getByRole('button', { name: 'Loot' }).click();
    await expect(detail).toContainText('/etc/shadow', { timeout: 10_000 });
    await expect(card(page, H101)).toContainText('#');
    await expect(page.locator('.marker')).toHaveText(['1', '2'], { timeout: 10_000 });
    await detail.evaluate((el) => (el.scrollTop = 0));
    await shot(page, '3-host-101');
  });

  await test.step('3 Host-Detail .104 Sackgasse, .103 im Nebel', async () => {
    await page.keyboard.press('Escape');
    await card(page, H104).click();
    const detail = column(page).locator('.detail');
    await expect(detail).toContainText('192.168.56.104');
    await detail.getByRole('button', { name: /^offen/ }).click();
    await page.getByRole('menuitemradio', { name: 'Sackgasse' }).click();
    await detail.getByLabel('Grund der Sackgasse').fill('nur RDP');
    await detail.getByRole('button', { name: 'Sackgasse setzen' }).click();
    await expect(card(page, H104)).toContainText('Sackgasse · nur RDP', { timeout: 10_000 });
    await page.keyboard.press('Escape');
    await card(page, H103).click();
    await expect(column(page).locator('.detail')).toContainText('im Nebel');
    await expect(column(page).getByRole('button', { name: /Annehmen/ })).toBeVisible();
    await shot(page, '3-host-103');
    await page.keyboard.press('Escape');
    await expect(card(page, H103)).toBeFocused();
  });

  // ------------------------------------------------------------------ 5 Aufnahme
  await test.step('5 Aufnahme-Popover, Pause für T1 bis zur Bestätigung', async () => {
    await header(page).locator('button.rec').click();
    const pop = page.getByRole('dialog', { name: 'Aufnahme' });
    await expect(pop.locator('.term')).toHaveCount(3);
    await expect(pop).toContainText('lokal, Browser in der Kali');
    await shot(page, '5-aufnahme-popover');
    await pop.getByRole('button', { name: /^Pause für T1/ }).click();
    await expect(header(page)).toHaveAttribute('data-variant', /waiting|pause/);
    await expect(header(page)).toHaveAttribute('data-variant', 'pause', { timeout: 15_000 });
    await expect(pop.getByRole('button', { name: /Aufnahme von T1 fortsetzen/ })).toBeVisible();
    await shot(page, '5-aufnahme-popover-pause');
    await page.keyboard.press('Escape');
    await expect(header(page)).toContainText(/T1 Pause bis \d\d:\d\d/);
    await expect(header(page)).toContainText('2 von 3 Terminals nehmen auf');
    await shot(page, '5-kopfzeile-pause');
  });

  // ------------------------------------------------------------------ 1a Hauptansicht
  await test.step('1a Hauptansicht: Lagebild mit «+N seit», K2 aufgeklappt, verknüpfter Host', async () => {
    // wie im Design: der Kontextvorschlag aus T3 ist gewählt und aufgeklappt
    const ctxItem = (await api<NextView>(page, `/p/${pid}/next`)).clarify.find((c) => c.kind === 'ctx_suggestion');
    expect(ctxItem).toBeTruthy();
    await page.goto(`${base}/karte?sel=${encodeURIComponent(ctxItem?.item_key ?? '')}`);
    await expect(card(page, H101)).toBeVisible();
    await expect(page.locator('.lage .sum')).toHaveText(/^Stand \d\d:\d\d · 4 Hosts, 1 im Nebel · 1 mit Zugriff$/);
    const neu = page.locator('.lage button.new');
    await expect(neu).toHaveText(/^\+\d+ seit \d\d:\d\d$/);
    const first = column(page).locator('.card');
    await expect(first).toContainText('Kontext klären · Vorschlag');
    await expect(first).toContainText('Darum mehrdeutig');
    await expect(first).toContainText('10.66.66.66');
    await expect(card(page, H101).locator('xpath=..').locator('.ring-label')).toHaveText(/^K\d+$/);
    await expect(page).toHaveTitle(/^ms2 · 2 zu klären$/);
    await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', '/favicon-attention.svg');
    await expect(column(page).getByRole('button', { name: /Denkanstoss anfordern \(KI\)/ })).toBeDisabled();
    await shot(page, '1a-hauptansicht');
    await neu.click();
    await shot(page, '1a-neu-seit-puls');
  });

  await test.step('10 Out of Scope und Ebenen', async () => {
    await page.getByRole('button', { name: /^Out of Scope · \d+$/ }).click();
    const pop = page.getByRole('dialog', { name: /Out of Scope/ });
    await expect(pop).toContainText('fd00:56::101');
    await expect(pop).toContainText('10.66.66.66');
    await shot(page, '10-out-of-scope');
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: 'Ebenen und Legende' }).click();
    await shot(page, '1a-ebenen');
    await page.keyboard.press('Escape');
  });

  // ------------------------------------------------------------------ 4 Einträge
  await test.step('4 Zusammenführen und Denkanstösse (Lernmodus, Vorlage, Sonderzeichen)', async () => {
    const col = column(page);
    const mergeItem = (await api<NextView>(page, `/p/${pid}/next`)).clarify.find((c) => c.kind === 'merge_suggestion');
    await page.goto(`${base}/karte?sel=${encodeURIComponent(mergeItem?.item_key ?? '')}`);
    const merge = col.locator('.card[data-item-key^="merge:"]');
    await expect(merge).toContainText('Zusammenführen?');
    await expect(merge).toContainText('Gleiche MAC-Adresse');
    await shot(page, '4-zusammenfuehren');
    // Denkanstoss D1 im Lernmodus (Stufen auf Klick)
    const next = await api<NextView>(page, `/p/${pid}/next`);
    const anon = next.suggestions.find((s) => s.rule_id === 'R-ANON-ZUGRIFF') ?? next.suggestions[0];
    await page.goto(`${base}/karte?sel=${encodeURIComponent(anon?.suggestion_key ?? '')}`);
    const sug = col.locator('.card');
    await sug.getByRole('button', { name: /1 Frage zeigen/ }).click();
    await sug.getByRole('button', { name: /2 Richtung zeigen/ }).click();
    await shot(page, '4-lernmodus');
    await sug.getByRole('button', { name: /3 Vorlage zeigen/ }).click();
    await expect(sug.getByRole('button', { name: 'Kopieren · Mac' }).first()).toBeVisible();
    await expect(col.getByRole('button', { name: /ausführen/i })).toHaveCount(0);
    // feindliches Produkt auf .110: keine fertige Vorlage, nur Einzelwerte
    const hostile = next.suggestions.find((s) => s.rule_id === 'R-VERSION-RECHERCHE' && s.host_id === H110 && s.title.includes(':21'));
    expect(hostile, 'Denkanstoss zum feindlichen Produkt').toBeTruthy();
    expect(hostile?.templates.every((x) => !x.rendered)).toBe(true);
    await page.goto(`${base}/karte?sel=${encodeURIComponent(hostile?.suggestion_key ?? '')}`);
    await sug.getByRole('button', { name: /1 Frage zeigen/ }).click();
    await sug.getByRole('button', { name: /2 Richtung zeigen/ }).click();
    await sug.getByRole('button', { name: /3 Vorlage zeigen/ }).click();
    await expect(sug).toContainText('Enthält Shell-Sonderzeichen. Keine fertige Vorlage.');
    await expect(sug).toContainText("vsftpd'; !sh -c 'id");
    await expect(sug.locator('.tpl code')).toHaveCount(0);
    await shot(page, '4-sonderzeichen');
  });

  await test.step('11 Menü und Einstellungen: Lernmodus aus', async () => {
    await page.getByRole('button', { name: 'Menü' }).click();
    await expect(page.getByRole('menu')).toBeVisible();
    await shot(page, '11-menue');
    await page.getByRole('menuitem', { name: 'Einstellungen' }).click();
    const panel = page.getByRole('dialog', { name: 'Einstellungen' });
    await expect(panel).toBeVisible();
    await expect(panel).toContainText('••••••••');
    await expect(panel).not.toContainText('Eigenes-Sudo-Geheimnis');
    await shot(page, '11-einstellungen');
    await panel.getByRole('switch', { name: 'Lernmodus' }).click();
    await expect(panel.getByRole('switch', { name: 'Lernmodus' })).toHaveAttribute('aria-checked', 'false');
    await page.keyboard.press('Escape');
    await expect(panel).toBeHidden();
  });

  await test.step('4 D2 mit Vorlage (Lernmodus aus)', async () => {
    const next = await api<NextView>(page, `/p/${pid}/next`);
    const ver = next.suggestions.find((s) => s.rule_id === 'R-VERSION-RECHERCHE' && s.host_id === H101 && s.title.includes(':21'));
    expect(ver).toBeTruthy();
    await page.goto(`${base}/karte?sel=${encodeURIComponent(ver?.suggestion_key ?? '')}`);
    const sug = column(page).locator('.card');
    await expect(sug.locator('.tpl code').first()).toHaveText('searchsploit vsftpd 2.3.4');
    await shot(page, '4-vorlage');
  });

  await test.step('1a Ruhezustand: K2 übernehmen, K3 zusammenführen', async () => {
    const ctxItem = (await api<NextView>(page, `/p/${pid}/next`)).clarify.find((c) => c.kind === 'ctx_suggestion');
    await page.goto(`${base}/karte?sel=${encodeURIComponent(ctxItem?.item_key ?? '')}`);
    const col = column(page);
    await expect(col.locator('.card')).toContainText('Kontext klären · Vorschlag');
    await page.keyboard.press('a');
    await expect(col.locator('.done', { hasText: /Kontext T3/ })).toBeVisible({ timeout: 15_000 });
    await expect(col.locator('.card[data-item-key^="merge:"]')).toBeVisible({ timeout: 10_000 });
    await page.keyboard.press('a');
    await expect(col.locator('.group-head').first()).toContainText('erledigt', { timeout: 15_000 });
    await expect(col.locator('.card[data-suggestion-key]')).toBeVisible();
    await expect(page).toHaveTitle('ms2');
    await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', '/favicon.svg');
    await shot(page, '1a-ruhezustand');
  });

  // ------------------------------------------------------------------ 6 Zeitachse
  let h110cmd = '';
  await test.step('6 Zeitachse, Warteliste, Rückgängig mit Grund (Honeypot)', async () => {
    await page.keyboard.press('3');
    await expect(page).toHaveURL(/\/zeitachse/);
    const strip = page.locator('.pending');
    await expect(strip).toContainText(/2 Dateien nicht übernommen/, { timeout: 15_000 });
    await shot(page, '6-zeitachse');
    await strip.getByRole('button').first().click();
    await expect(strip).toContainText('~/privat/udp.xml');
    await expect(strip).toContainText(/gehört vermutlich zu nmap \d\d:\d\d/);
    await expect(strip.getByRole('button', { name: /Import-Befehl · Mac/ }).first()).toBeVisible();
    await shot(page, '6-warteliste');
    await strip.getByRole('button').first().click();
    const items = await api<{ items: TimelineItem[] }>(page, `/p/${pid}/timeline?types=command&limit=200`);
    const it = items.items.find((x) => x.cmd?.text.includes('192.168.56.110'));
    expect(it).toBeTruthy();
    h110cmd = it?.id ?? '';
    const row = page.locator(`li.item[data-row="${h110cmd}"]`);
    await row.click();
    await page.keyboard.press('u');
    const form = page.getByRole('form', { name: 'Werte aus diesem Befehl verwerfen?' });
    await form.getByLabel('Grund (optional)').fill('Banner manipuliert, vermutlich Honeypot');
    await shot(page, '6-rueckgaengig');
    await form.getByRole('button', { name: 'Rückgängig machen' }).click();
    await expect(row).toContainText(/\d+ verworfen, \d+ geschwächt/, { timeout: 15_000 });
    await expect(row).toContainText('misstraut');
    await shot(page, '6-rueckgaengig-ergebnis');
  });

  // ------------------------------------------------------------------ 7 Belegansicht, 8 Findings
  await test.step('8 Findings leer, 7 Beleg der msf-Zeilen, Als Finding', async () => {
    await page.keyboard.press('4');
    await expect(page.getByText('Noch keine Findings.')).toBeVisible();
    await shot(page, '8-findings-leer');
    await page.keyboard.press('3');
    const items = await api<{ items: TimelineItem[] }>(page, `/p/${pid}/timeline?types=segment&limit=200`);
    // wie im Design: die msf-Zeilen in T2, offenes Remote-Segment (msfconsole läuft, vorläufige Zeilen)
    const msf = items.items.find((x) => x.type === 'segment' && x.terminal_id === ids.T2);
    expect(msf).toBeTruthy();
    expect(msf?.state).not.toBe('final');
    const row = page.locator(`li.item[data-row="${msf?.id}"]`);
    await expect(row).toContainText(/Remote-Segment · rekonstruiert · \d+ Zeilen?/);
    await expect(row).toContainText(/wird frühestens \d\d:\d\d:\d\d ausgewertet/);
    await row.click();
    await page.keyboard.press('Enter');
    const panel = page.getByRole('dialog', { name: 'Beleg' });
    await expect(panel).toBeVisible();
    await expect(panel.locator('h2')).toHaveText(/^Beleg · T2 msf · \d\d:\d\d:\d\d$/);
    await expect(panel.locator('dl.meta')).toContainText('msfconsole -q');
    await expect(panel.locator('dl.meta')).toContainText(/Kali\s*›\s*192\.168\.56\.101\s*\[msf\]\s*\(auto\)/);
    await expect(panel.locator('dl.meta')).toContainText('läuft');
    await expect(panel.locator('dl.meta')).toContainText('remote, rekonstruiert');
    await expect(panel.locator('dl.meta')).toContainText('✓ geprüft');
    await expect(panel.locator('.line', { hasText: 'Command shell session 1 opened' })).toBeVisible();
    await shot(page, '7-beleg');
    await panel.getByRole('button', { name: 'Als Finding' }).click();
    await expect(page).toHaveURL(/\/findings\?.*finding=neu/);
    const form = page.getByRole('form', { name: 'Neues Finding' });
    await form.getByLabel('Titel').fill('vsftpd 2.3.4 mit Hintertür: Root-Shell ohne Anmeldung');
    await form.getByRole('radio', { name: 'Kritisch' }).click();
    await shot(page, '8-finding-formular');
    await form.getByRole('button', { name: /^Speichern/ }).click();
    await expect(page).not.toHaveURL(/finding=neu/, { timeout: 10_000 });
    await expect(page.locator('a.card.sel')).toContainText('F1');
    const list = await api<{ findings: { title: string; severity: string; evidence_count: number }[] }>(page, `/p/${pid}/findings`);
    expect(list.findings).toEqual([expect.objectContaining({ severity: 'critical', evidence_count: 1 })]);
    await shot(page, '8-findings');
  });

  await test.step('7 Beleg einer Datei (SHA-256) und im Präsentationsmodus', async () => {
    await page.keyboard.press('3');
    // Dateien eines Befehls stehen in seiner Unterzeile («Datei scans/ms2.xml erkannt»), der Name öffnet ihren Beleg
    const withFile = await api<{ items: TimelineItem[] }>(page, `/p/${pid}/timeline?types=command&limit=200`);
    const ms2 = withFile.items.find((x) => x.cmd?.text.startsWith('nmap -sV -sC -oA'));
    expect(ms2).toBeTruthy();
    const ms2row = page.locator(`li.item[data-row="${ms2?.id}"]`);
    await ms2row.click();
    await expect(ms2row).toContainText(/Datei scans\/ms2\.xml erkannt \+2/);
    await ms2row.getByRole('button', { name: 'scans/ms2.xml' }).click();
    const panel = page.getByRole('dialog', { name: 'Beleg' });
    await expect(panel).toContainText('SHA-256');
    await expect(panel.locator('h2')).toContainText('Datei');
    await shot(page, '7-beleg-datei');
    await page.keyboard.press('Escape');
    await page.keyboard.press('Shift+P');
    await expect(header(page).locator('[data-badge="presentation"]')).toBeVisible({ timeout: 10_000 });
    await shot(page, '5-kopfzeile-praesentation');
    // Beleg mit der Eingabe ohne Echo: verdeckt, Aufdecken gesperrt
    await page.keyboard.press('2');
    await expect(page.locator(`li[data-terminal="${ids.T1}"]`)).toContainText('••••••••');
    await expect(page.locator(`li[data-terminal="${ids.T1}"]`).getByRole('button', { name: 'Aufdecken' })).toBeDisabled();
    await page.keyboard.press('3');
    const cmds = await api<{ items: TimelineItem[] }>(page, `/p/${pid}/timeline?types=command&limit=200`);
    const nmap = cmds.items.find((x) => x.cmd?.text.startsWith('nmap -sV -sC -oA'));
    await page.locator(`li.item[data-row="${nmap?.id}"]`).click();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog', { name: 'Beleg' })).toBeVisible();
    await shot(page, '7-beleg-praesentation');
    await page.keyboard.press('Escape');
    await page.keyboard.press('Shift+P');
    await expect(header(page).locator('[data-badge="presentation"]')).toHaveCount(0, { timeout: 10_000 });
  });

  // ------------------------------------------------------------------ 10 Dialoge, 12 Tabelle
  await test.step('10 Palette, Hilfe, Export, Screenshot', async () => {
    await page.keyboard.press('1');
    await expect(page.locator('.notices .notice')).toHaveCount(0, { timeout: 10_000 }); // «Präsentationsmodus ausgeschaltet» ist weg
    await page.keyboard.press('Control+k');
    const pal = page.getByRole('dialog', { name: 'Befehlspalette' });
    await expect(pal).toBeVisible();
    await page.keyboard.type('vsftpd');
    await expect(pal.locator('[role="option"]').first()).toBeVisible();
    await shot(page, '10-palette');
    await page.keyboard.press('Escape');
    await page.keyboard.press('?');
    await expect(page.getByRole('dialog', { name: 'Hilfe' })).toBeVisible();
    await shot(page, '10-hilfe');
    await page.keyboard.press('Escape');
    for (const [item, name] of [['Bericht exportieren …', '10-export'], ['Screenshot der Kali …', '10-screenshot']] as const) {
      await page.getByRole('button', { name: 'Menü' }).click();
      await page.getByRole('menuitem', { name: item }).click();
      const dlg = page.getByRole('dialog').last();
      await expect(dlg).toContainText(/kommt in einer späteren Version/i);
      await shot(page, name);
      await page.keyboard.press('Escape');
      await expect(dlg).toBeHidden();
    }
  });

  await test.step('12 Host-Tabelle per t', async () => {
    await page.keyboard.press('t');
    await expect(page).toHaveURL(/ansicht=tabelle/);
    await expect(page.locator('.table-view button.row').first()).toBeVisible();
    await shot(page, '12-tabelle');
    await page.keyboard.press('t');
    await expect(page).not.toHaveURL(/ansicht=/);
  });

  await test.step('5 Kopfzeile kompakt unter 1280 px', async () => {
    await page.setViewportSize({ width: 1200, height: 900 });
    await page.waitForTimeout(400);
    await expect(header(page)).toContainText('2 von 3 nehmen auf');
    await shot(page, '5-kopfzeile-kompakt');
    await page.setViewportSize({ width: 1440, height: 900 });
  });

  // ------------------------------------------------------------------ 9 Zustände: offline, gesperrt
  await test.step('9 Keine Verbindung: Daemon gestoppt', async () => {
    await con.allow([/ERR_CONNECTION_REFUSED|ERR_EMPTY_RESPONSE|ERR_CONNECTION_RESET|net::ERR_|status of 50\d/], async () => {
      await L.call('daemon_stop');
      await expect(header(page)).toHaveAttribute('data-variant', 'offline', { timeout: 30_000 });
      // Korrektur A11: gedämpft und gesperrt (aria-busy, Klicks abgefangen), aber nicht inert
      await expect(page.locator('main')).toHaveAttribute('aria-busy', 'true');
      await expect(page.locator('main')).toHaveClass(/offline-dim/);
      await expect(page.locator('main')).not.toHaveAttribute('inert', /.*/);
      await shot(page, '9-keine-verbindung');
    });
  });

  await test.step('9 Gesperrt nach Neustart: Sitzung beendet, neue Anmeldung ohne Passphrase', async () => {
    await con.allow([/ERR_CONNECTION_REFUSED|net::ERR_|status of 401|status of 50\d/], async () => {
      await L.call('daemon_start');
      await expect(page.getByLabel('Anmeldecode')).toBeVisible({ timeout: 45_000 });
    });
    await page.goto(await L.uiUrl());
    await expect(header(page)).toHaveAttribute('data-variant', 'locked', { timeout: 15_000 });
    await expect(page.locator('main')).toContainText(/Projekt\s*ms2\s*ist gesperrt/);
    await expect(page.locator('input')).toHaveCount(0);
    await shot(page, '9-gesperrt');
    await L.cli(['start'], true);
    await expect(header(page)).toHaveAttribute('data-variant', /normal|pause/, { timeout: 20_000 });
    await expect(card(page, H101)).toBeVisible({ timeout: 20_000 });
  });

  await test.step('5 held: Wechsel zu lame, die msf-Sitzung in T2 gehört zu ms2', async () => {
    await L.cli(['start', 'lame', '--target', '10.10.10.3', '--preroll', 'no'], true);
    await expect(header(page)).toContainText('lame', { timeout: 20_000 });
    await expect(header(page)).toHaveAttribute('data-variant', 'held', { timeout: 20_000 });
    // im neuen Projekt hat das Terminal noch keine Nummer (18.12): Gerät statt «T2»
    await expect(header(page)).toContainText(/(T2|pts\/\d+): Remote-Sitzung bei\s*ms2, nicht gespeichert/);
    // T2 (msf) und T3 (Listener) halten beide eine Sitzung von ms2: ein Kennzeichen mit «+1 weitere»
    await expect(header(page).locator('[data-badge="held"]')).toHaveCount(1);
    await expect(header(page).locator('[data-badge="held"]')).toContainText('+1 weitere');
    await shot(page, '5-kopfzeile-held');
  });

  await test.step('9 Zu viele Versuche: Abmelden, falsche Codes bis zur Sperre', async () => {
    await page.getByRole('button', { name: 'Menü' }).click();
    // Abmelden: der Browser wendet Clear-Site-Data des Daemons an und meldet das als Info
    await con.allow([/Clear-Site-Data header .*Cleared data types/], async () => {
      await page.getByRole('menuitem', { name: /Abmelden/ }).click();
      await expect(page.getByLabel('Anmeldecode')).toBeVisible();
    });
    const field = page.getByLabel('Anmeldecode');
    await expect(field).toBeVisible();
    await con.allow([/status of 401|status of 429/], async () => {
      for (let i = 0; i < 12; i++) {
        const alert = page.getByRole('alert');
        if ((await alert.count()) > 0 && (await alert.first().textContent())?.includes('Zu viele Versuche')) break;
        await field.fill(`FALSCH${String(1000 + i)}`);
        await page.keyboard.press('Enter');
        await expect(page.getByRole('alert')).toBeVisible();
      }
      await expect(page.getByRole('alert')).toHaveText('Zu viele Versuche. Neuen Code im Terminal holen.');
    });
    await shot(page, '9-anmeldung-gesperrt');
  });

  expect(con.unexpected, 'unerwartete Konsolenmeldungen').toEqual([]);
  // Keine Spur eines Tokens oder Codes in der Adresse, kein Browser-Speicher ausser dem Token
  // eslint-disable-next-line no-restricted-globals -- der Test liest den Speicher nur aus
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  expect(readFileSync(resolve(STATIC, 'index.html'), 'utf8')).not.toMatch(/<script>(?!\s*<\/script>)|style=/);
});
