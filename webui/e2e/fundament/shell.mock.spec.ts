/**
 * Fundament gegen den Mock-Build unter der Daemon-CSP (Besitzer: ui-fundament): Kopfzeile in allen
 * Varianten, kompakt unter 1280 px, Aufnahme-Popover mit E117, Anmeldung mit allen Fehlern, Zustände,
 * Tastatur, Präsentationsmodus, Favicon und Tab-Titel, hell und dunkel, Scope-Warnung, kein
 * Browser-Speicher. fixtures.ts prüft nach jedem Test: keine CSP-Verletzung, kein Seitenfehler,
 * kein <style>-Element mit Inhalt.
 */
import type { Page } from '@playwright/test';
import { expect, openMock, test } from '../fixtures';

const header = (page: Page) => page.locator('header.header');

test.describe('Kopfzeile', () => {
  const VARIANTS: [scenario: string, variant: string, text: RegExp][] = [
    ['allon', 'normal', /ms2\s*3 von 3 Terminals nehmen auf/],
    ['normal', 'pause', /2 von 3 Terminals nehmen auf.*T1 Pause bis \d\d:\d\d/],
    ['held', 'held', /Remote-Sitzung bei\s*lame, nicht gespeichert/],
    ['locked', 'locked', /ms2\s*Gesperrt · im Terminal ariadne start\s*Aufnahme puffert im Arbeitsspeicher/],
    ['noproject', 'noproject', /kein Projekt\s*Vorlauf: 3 Terminals, 15 Minuten im Arbeitsspeicher/],
  ];
  for (const [scenario, variant, text] of VARIANTS) {
    test(`Variante ${variant} (${scenario})`, async ({ page }) => {
      await openMock(page, scenario);
      await expect(header(page)).toHaveAttribute('data-variant', variant);
      await expect(header(page)).toContainText(text);
      await expect(header(page).locator('.origin')).toHaveText('über sshd');
      await expect(header(page)).not.toContainText(/zu klären|Klären \(|Denkanstösse/);
      const box = await header(page).boundingBox();
      expect(box?.height).toBe(52); // 52 px einschliesslich Trenner (border-box)
    });
  }

  test('Variante waiting: Pause aus dem Popover, bis der Daemon bestätigt', async ({ page }) => {
    await openMock(page, 'allon');
    await header(page).locator('button.rec').click();
    const pop = page.getByRole('dialog', { name: 'Aufnahme' });
    await pop.getByRole('button', { name: 'Pause für T2, 10 Minuten' }).click();
    await expect(header(page)).toHaveAttribute('data-variant', 'waiting');
    await expect(header(page)).toContainText('T2 Pause · wartet auf Bestätigung');
    await expect(pop).toContainText('wartet auf Bestätigung');
    // Mock bestätigt nach 600 ms über das Ereignis terminal
    await expect(header(page)).toHaveAttribute('data-variant', 'pause');
    await expect(header(page)).toContainText(/T2 Pause bis \d\d:\d\d/);
  });

  test('Variante offline: nach 5 s ohne Strom gedämpft, Aktionen gesperrt', async ({ page }) => {
    await openMock(page, 'offline');
    await expect(header(page)).toHaveAttribute('data-variant', 'offline', { timeout: 9000 });
    await expect(header(page)).toContainText(/Keine Verbindung · Stand \d\d:\d\d · verbindet neu …/);
    const main = page.locator('main#main');
    await expect(main).toHaveClass(/offline-dim/);
    // Korrektur A11: nicht inert (Fokus und Eingaben bleiben, Stand lesbar), Aktionen gesperrt
    await expect(main).not.toHaveAttribute('inert', /.*/);
    await expect(main).toHaveAttribute('aria-busy', 'true');
    await page.locator('[data-map-card][data-host-id="ip:default/192.168.56.101"]').click();
    await expect(page).not.toHaveURL(/host=/);
    await expect(header(page).locator('.origin')).toBeVisible();
    // Shift+P bleibt ohne Wirkung
    await page.keyboard.press('Shift+P');
    await expect(header(page)).not.toContainText('Präsentation');
  });

  test('Präsentation per Shift+P, Kennzeichen, Herkunft «lokal»; nochmals Shift+P schaltet aus', async ({ page }) => {
    await openMock(page, 'local');
    await expect(header(page).locator('.origin')).toHaveText('lokal');
    await page.keyboard.press('Shift+P');
    await expect(header(page).locator('[data-badge="presentation"]')).toHaveText('Präsentation');
    await expect(page.getByRole('status').filter({ hasText: 'Präsentationsmodus eingeschaltet' })).toBeVisible();
    await page.keyboard.press('Shift+P');
    await expect(header(page).locator('[data-badge="presentation"]')).toHaveCount(0);
  });

  test('Shift+P im Eingabefeld (Palette) schaltet nichts', async ({ page }) => {
    await openMock(page, 'normal');
    await expect(header(page)).toBeVisible();
    await page.keyboard.press('Control+k');
    const input = page.getByRole('combobox', { name: 'Befehlspalette' });
    await expect(input).toBeFocused();
    await page.keyboard.press('Shift+P');
    await expect(input).toHaveValue('P');
    await page.keyboard.press('Escape');
    await expect(header(page).locator('[data-badge="presentation"]')).toHaveCount(0);
  });

  test('kompakt unter 1280 px: kurze Aufnahme, Suche nur als Kürzel, Herkunft bleibt', async ({ page }) => {
    await page.setViewportSize({ width: 1200, height: 900 });
    await openMock(page, 'normal');
    const rec = header(page).locator('button.rec');
    await expect(rec.locator('.short')).toBeVisible();
    await expect(rec.locator('.short')).toHaveText('2 von 3 nehmen auf');
    await expect(rec.locator('.long')).toBeHidden();
    await expect(header(page).locator('.search .long')).toBeHidden();
    await expect(header(page).locator('.search kbd')).toBeVisible();
    await expect(header(page).locator('.origin')).toBeVisible();
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect(rec.locator('.long')).toBeVisible();
    await expect(header(page).locator('.search .long')).toHaveText('Suchen');
  });

  test('bei 1000 px läuft nichts über: Badges kürzen sich, Reiter und Menü bleiben sichtbar', async ({ page }) => {
    await page.setViewportSize({ width: 1000, height: 800 });
    await openMock(page, 'held');
    for (const sel of ['nav.tabs', 'button.dots', '.origin']) await expect(header(page).locator(sel)).toBeVisible();
    const overflow = await header(page).evaluate((h) => h.scrollWidth - h.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    const held = header(page).locator('[data-badge="held"]');
    const nav = header(page).locator('nav.tabs');
    const [hb, nb] = [await held.boundingBox(), await nav.boundingBox()];
    expect((hb?.x ?? 0) + (hb?.width ?? 0)).toBeLessThanOrEqual(nb?.x ?? 0);
  });
});

test.describe('Aufnahme-Popover', () => {
  test('Terminals, Projekt, Sitzung, Leerlauf, KI, Hinweis F12 r; Esc schliesst mit Fokus zurück', async ({ page }) => {
    await openMock(page, 'normal');
    const rec = header(page).locator('button.rec');
    await rec.click();
    const pop = page.getByRole('dialog', { name: 'Aufnahme' });
    await expect(pop).toContainText(/T1\s*scan\s*· Pause bis \d\d:\d\d/);
    await expect(pop).toContainText(/T2\s*msf\s*· nimmt auf/);
    await expect(pop).toContainText('Metasploitable2 Lab');
    await expect(pop).toContainText('über sshd, vom Mac');
    await expect(pop).toContainText('Ende nach 12 h');
    await expect(pop).toContainText('Im Terminal: F12 r Pause, nochmals hebt sie auf');
    await page.keyboard.press('Escape');
    await expect(pop).toBeHidden();
    await expect(rec).toBeFocused();
  });

  test('E117: Ablehnung des Servers bleibt am Terminal sichtbar', async ({ page }) => {
    await openMock(page, 'budget');
    await header(page).locator('button.rec').click();
    const pop = page.getByRole('dialog', { name: 'Aufnahme' });
    await expect(pop.getByRole('button', { name: 'Pause für T3, 5 Minuten' })).toHaveText('Pause 5 min');
    await pop.getByRole('button', { name: 'Pause für T2, 10 Minuten' }).click();
    await expect(pop).toContainText('Pausenbudget aus dem Dashboard erschöpft (30 min pro Stunde). Im Terminal: F12 r');
    await expect(pop.getByRole('button', { name: 'Pause für T2, 10 Minuten' })).toBeDisabled();
    await expect(page.getByRole('alert').filter({ hasText: 'Pausenbudget' })).toBeVisible();
  });

  test('Klick ausserhalb schliesst; höchstens ein Popover offen', async ({ page }) => {
    await openMock(page, 'normal');
    await header(page).locator('button.rec').click();
    await expect(page.getByRole('dialog', { name: 'Aufnahme' })).toBeVisible();
    await page.getByRole('button', { name: 'Menü' }).click();
    await expect(page.getByRole('dialog', { name: 'Aufnahme' })).toBeHidden();
    await expect(page.getByRole('menu')).toBeVisible();
    await page.mouse.click(700, 600);
    await expect(page.getByRole('menu')).toBeHidden();
  });
});

test.describe('Anmeldung', () => {
  test('nie ein Passphrase-Feld; Fehler unbekannt, zu viele Versuche, ungültig; dann Anmeldung', async ({ page }) => {
    await openMock(page, 'login', '/');
    const field = page.getByLabel('Anmeldecode');
    await expect(field).toBeFocused();
    await expect(page.locator('input[type="password"]')).toHaveCount(0);
    await expect(page.getByText('Ariadne fragt hier nie nach Passphrasen.')).toBeVisible();

    await field.fill('k7q2 m4');
    await page.getByRole('button', { name: 'Anmelden' }).click();
    await expect(page.getByRole('alert')).toHaveText('Eingabe ungültig.');

    await field.fill('FALSCH00');
    await page.keyboard.press('Enter');
    await expect(page.getByRole('alert')).toHaveText('Code unbekannt, abgelaufen oder schon benutzt.');

    await field.fill('SPERRE00');
    await page.keyboard.press('Enter');
    await expect(page.getByRole('alert')).toHaveText('Zu viele Versuche. Neuen Code im Terminal holen.');
    await expect(field).toBeDisabled();
    await expect(field).toHaveAttribute('placeholder', 'gesperrt');
    await page.getByRole('button', { name: 'Neuen Code eingeben' }).click();
    await expect(field).toBeEnabled();

    await field.fill('abcde-fghjk');
    await page.keyboard.press('Enter');
    await expect(header(page)).toHaveAttribute('data-variant', 'pause');
    await expect(page).not.toHaveURL(/[?#&](c|code|token)=/);
  });

  test('Code im Fragment wird sofort entfernt', async ({ page }) => {
    await page.goto('/karte?mock=login#c=ABCDEFGH12345678');
    await expect(header(page)).toBeVisible();
    expect(new URL(page.url()).hash).toBe('');
  });
});

test.describe('Zustände', () => {
  test('kein Projekt: Startbefehl mit «Kopieren · Mac»', async ({ page }) => {
    await openMock(page, 'noproject');
    await expect(page.getByRole('heading', { name: 'Kein aktives Projekt' })).toBeVisible();
    await expect(page.locator('.state code')).toHaveText('ariadne start ‹slug› --target ‹ziel›');
    await expect(page.getByRole('button', { name: 'Kopieren · Mac' })).toBeVisible();
    await expect(page).toHaveTitle('Ariadne');
  });

  test('gesperrt: kein Passphrase-Feld, kein Eingabefeld überhaupt', async ({ page }) => {
    await openMock(page, 'locked');
    await expect(page.getByRole('heading', { name: 'Projekt ms2 ist gesperrt' })).toBeVisible();
    await expect(page.locator('main input')).toHaveCount(0);
    await expect(page.getByText('hier gibt es kein Passphrase-Feld', { exact: false })).toBeVisible();
  });
});

test.describe('Tastatur', () => {
  test('1 bis 4 wechseln die Reiter, die URL folgt, Zurück funktioniert', async ({ page }) => {
    await openMock(page);
    await expect(header(page)).toBeVisible();
    for (const [key, path] of [['2', '/terminals'], ['3', '/zeitachse'], ['4', '/findings'], ['1', '/karte']] as const) {
      await page.keyboard.press(key);
      await expect(page).toHaveURL(new RegExp(`${path}\\b`));
      await expect(page.getByRole('link', { name: { '/karte': 'Karte', '/terminals': 'Terminals', '/zeitachse': 'Zeitachse', '/findings': 'Findings' }[path] })).toHaveAttribute('aria-current', 'page');
    }
    await page.goBack();
    await expect(page).toHaveURL(/\/findings/);
  });

  test('Palette ⌘K/Strg+K: Fokus gefangen, Einzeltasten aus, Esc schliesst, Fokus zurück', async ({ page }) => {
    await openMock(page);
    const search = page.getByRole('button', { name: 'Befehlspalette' });
    await search.focus();
    await page.keyboard.press('Control+k');
    const input = page.getByRole('combobox', { name: 'Befehlspalette' });
    await expect(input).toBeFocused();
    await page.keyboard.press('3');
    await expect(page).toHaveURL(/\/karte/);
    for (let i = 0; i < 6; i++) await page.keyboard.press('Tab');
    const inside = await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]'));
    expect(inside).toBe(true);
    await page.keyboard.press('Escape');
    await expect(input).toBeHidden();
    await expect(search).toBeFocused();
  });

  test('Palette: Aktion wählen mit Pfeilen und ↵', async ({ page }) => {
    await openMock(page);
    await expect(header(page)).toBeVisible();
    await page.keyboard.press('Control+k');
    await expect(page.getByRole('combobox', { name: 'Befehlspalette' })).toBeFocused();
    await page.keyboard.type('zeitachse');
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/zeitachse/);
  });

  test('Hilfe mit ?, Menü per Tastatur', async ({ page }) => {
    await openMock(page);
    await expect(header(page)).toBeVisible();
    await page.keyboard.press('?');
    const help = page.getByRole('dialog', { name: 'Hilfe' });
    await expect(help).toContainText('Präsentationsmodus');
    await expect(help).toContainText('F12 r');
    await page.keyboard.press('Escape');
    await expect(help).toBeHidden();
    await page.getByRole('button', { name: 'Menü' }).focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('menuitemcheckbox', { name: /Präsentationsmodus/ })).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(page.getByRole('menuitem', { name: 'Screenshot der Kali …' })).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('menu')).toBeHidden();
  });
});

test.describe('Favicon und Tab-Titel', () => {
  test('mit offenen Klärungen: Punkt im Favicon, «ms2 · 2 zu klären»', async ({ page }) => {
    await openMock(page, 'normal');
    await expect(page).toHaveTitle('ms2 · 2 zu klären');
    await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', '/favicon-attention.svg');
    const res = await page.request.get('/favicon-attention.svg');
    expect(res.status()).toBe(200);
    expect(await res.text()).toContain('#e8b14a');
  });

  test('ohne offene Klärungen: Standardzeichen, Titel nur der Slug', async ({ page }) => {
    await openMock(page, 'calm');
    await expect(page).toHaveTitle('ms2');
    await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', '/favicon.svg');
  });
});

test.describe('Hell und dunkel (E112)', () => {
  async function bg(page: Page): Promise<string> {
    return page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  }

  test('System folgt prefers-color-scheme; Einstellungen setzen Hell und Dunkel auf dem Server', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await openMock(page, 'normal', '/karte?tafel=einstellungen');
    await expect(page.getByRole('radio', { name: 'System' })).toHaveAttribute('aria-checked', 'true');
    expect(await bg(page)).toBe('rgb(244, 245, 247)');
    await page.getByRole('radio', { name: 'Dunkel' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    expect(await bg(page)).toBe('rgb(17, 20, 24)');
    await page.getByRole('radio', { name: 'Hell' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.emulateMedia({ colorScheme: 'dark' });
    expect(await bg(page)).toBe('rgb(244, 245, 247)');
    await page.getByRole('radio', { name: 'System' }).click();
    await expect(page.locator('html')).not.toHaveAttribute('data-theme', /.+/);
    expect(await bg(page)).toBe('rgb(17, 20, 24)');
    await page.getByRole('radio', { name: 'Kompakt' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-density', 'compact');
    await page.keyboard.press('Escape');
    await expect(page).not.toHaveURL(/tafel=/);
  });

  test('nur Systemschriften, keine Schriftdateien', async ({ page }) => {
    await openMock(page);
    await expect(header(page)).toBeVisible();
    const fonts = await page.evaluate(() => Array.from(document.fonts).length);
    expect(fonts).toBe(0);
    const family = await page.evaluate(() => getComputedStyle(document.body).fontFamily);
    expect(family).toMatch(/system-ui/);
  });

  test('prefers-reduced-motion: keine Animationen beim Öffnen der Tafel und der Palette', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await openMock(page);
    await page.getByRole('button', { name: 'Menü' }).click();
    await page.getByRole('menuitem', { name: 'Einstellungen' }).click();
    await page.keyboard.press('Control+k');
    const running = await page.evaluate(() => document.getAnimations().length);
    expect(running).toBe(0);
  });
});

test.describe('Scope-Warnung', () => {
  test('Meldung beim Eintreffen, Kennzeichen bis zum Quittieren, danach weg', async ({ page }) => {
    await openMock(page, 'scope');
    const card = page.getByRole('alert', { name: /Ziel ausserhalb des Scopes/ });
    await expect(card).toContainText(/T1: nmap -6 -sV -oX scans\/v6\.xml fd00:56::101/);
    await expect(card).toContainText('liegt nicht in 192.168.56.0/24');
    await expect(header(page).locator('[data-badge="scope"]')).toBeVisible();
    // nicht modal: die Tastatur der Seite wirkt weiter
    await page.locator('body').click({ position: { x: 300, y: 600 } });
    await page.keyboard.press('2');
    await expect(page).toHaveURL(/\/terminals/);
    await card.getByRole('button', { name: 'Quittieren' }).click();
    await expect(card).toBeHidden();
    await expect(header(page).locator('[data-badge="scope"]')).toHaveCount(0);
  });

  test('«In der Zeitachse» führt zur Zeile des Befehls', async ({ page }) => {
    await openMock(page, 'scope');
    await page.getByRole('alert').getByRole('button', { name: 'In der Zeitachse' }).click();
    await expect(page).toHaveURL(/\/zeitachse\?(.*&)?zeile=[^&]+%40\d+/);
  });
});

test('kein Browser-Speicher ausser dem Token dieses Tabs', async ({ page }) => {
  await openMock(page);
  await expect(header(page)).toBeVisible();
  // eslint-disable-next-line no-restricted-globals -- der Test liest den Speicher nur aus
  const storage = await page.evaluate(() => ({ local: localStorage.length, keys: Object.keys(sessionStorage) }));
  expect(storage.local).toBe(0);
  expect(storage.keys.every((k) => k.startsWith('ariadne.token'))).toBe(true);
  // eslint-disable-next-line no-restricted-globals -- der Test liest den Speicher nur aus
  const dbs = await page.evaluate(async () => (indexedDB.databases ? (await indexedDB.databases()).length : 0));
  expect(dbs).toBe(0);
});
