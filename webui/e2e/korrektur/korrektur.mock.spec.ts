/**
 * Korrekturen nach der Prüfung des Baus v0.1-Oberfläche, im echten Browser gegen den Mock-Build
 * (unter der CSP des Daemons; jeder Test scheitert bei einer CSP-Verletzung, fixtures.ts):
 * Bedienung (A1, A2, A3, A7, A13, A15, A16) und Gestaltung (D1, D2, D3, D12, D16, A12) als
 * messbare Eigenschaften.
 */
import type { Page } from '@playwright/test';
import { expect, openMock, test } from '../fixtures';

const H101 = 'ip:default/192.168.56.101';
const card = (page: Page, id: string) => page.locator(`[data-map-card][data-host-id="${id}"]`);

/** Mock öffnen und warten, bis Kopfzeile und Ansicht stehen (Kürzel wirken erst danach). */
async function open(page: Page, scenario: string, path: string): Promise<void> {
  await openMock(page, scenario, path);
  await expect(page.getByRole('banner')).toBeVisible();
  if (path.startsWith('/karte')) await expect(page.locator('[data-map-card]').first()).toBeVisible();
}

async function box(page: Page, sel: string) {
  return page.locator(sel).first().evaluate((e) => {
    const r = e.getBoundingClientRect();
    return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height), right: Math.round(r.right) };
  });
}

test.describe('Bedienung', () => {
  test('A1: Enter auf «Pause für T3» pausiert T3 und öffnet keinen Kontext-Dialog', async ({ page }) => {
    await open(page, 'allon', '/terminals');
    const btn = page.getByRole('button', { name: /^Pause für T3/ }).first();
    await btn.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog', { name: /Kontext für/ })).toHaveCount(0);
    await expect(page.getByRole('banner')).toContainText(/T3 Pause|Pause bis|wartet auf Bestätigung/);
  });

  test('A1: Zeitachse: Enter auf «UTC zeigen» schaltet um, ArrowDown im Terminal-Filter wechselt die Auswahl', async ({ page }) => {
    await open(page, 'normal', '/zeitachse');
    await page.keyboard.press('j');
    await page.getByRole('button', { name: 'UTC zeigen' }).focus();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/utc=1/);
    await expect(page).not.toHaveURL(/beleg=/);
    await page.getByRole('button', { name: /Alle Terminals/ }).click();
    const first = page.getByRole('radio').first();
    await first.focus();
    await page.keyboard.press('ArrowDown');
    await expect(page).toHaveURL(/terminal=/);
  });

  test('A2: hinter der offenen Belegtafel ändern j und x weder Auswahl noch Entscheide', async ({ page }) => {
    await open(page, 'normal', '/karte');
    await expect(page.locator('aside button.line[data-suggestion-key]').first()).toBeVisible();
    await page.keyboard.press('n');
    const sel = new URL(page.url()).searchParams.get('sel');
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog', { name: 'Beleg' })).toBeVisible();
    await page.keyboard.press('j');
    await page.keyboard.press('x');
    await expect.poll(() => new URL(page.url()).searchParams.get('sel')).toBe(sel);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog', { name: 'Beleg' })).toHaveCount(0);
    await expect(page.locator(`[data-suggestion-key="${sel}"]`)).toBeVisible();
    await expect(page.locator('.done')).toHaveCount(0);
  });

  test('A7: bei offener Tafel erreicht Tab nur die Tafel und die Kopfzeile', async ({ page }) => {
    await open(page, 'normal', '/karte');
    await expect(page.locator('aside button.line[data-suggestion-key]').first()).toBeVisible();
    await page.keyboard.press('n');
    await page.keyboard.press('Enter');
    const panel = page.getByRole('dialog', { name: 'Beleg' });
    await expect(panel).toBeVisible();
    for (let i = 0; i < 30; i++) {
      await page.keyboard.press('Tab');
      const where = await page.evaluate(() => {
        const a = document.activeElement;
        if (!a || a === document.body) return 'body';
        if (a.closest('[role="dialog"]')) return 'panel';
        if (a.closest('header')) return 'header';
        if (a.closest('.skip')) return 'skip';
        return 'other:' + (a.getAttribute('aria-label') ?? a.textContent ?? a.tagName).slice(0, 40);
      });
      expect(['panel', 'header', 'body', 'skip']).toContain(where);
    }
  });

  test('A13: Klick auf eine eingeklappte Zeile lässt den Fokus auf der Karte, nicht auf body', async ({ page }) => {
    await open(page, 'normal', '/karte');
    const line = page.locator('aside button.line[data-suggestion-key]').first();
    const key = await line.getAttribute('data-suggestion-key');
    await line.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator(`.card[data-suggestion-key="${key}"]`)).toBeFocused();
  });

  test('A15: Tab und Shift+Tab bleiben in der Palette', async ({ page }) => {
    await open(page, 'normal', '/karte');
    await page.keyboard.press('Control+k');
    await expect(page.getByRole('combobox', { name: 'Befehlspalette' })).toBeFocused();
    await page.keyboard.type('101');
    for (const key of ['Tab', 'Tab', 'Tab', 'Shift+Tab', 'Shift+Tab', 'Tab', 'Tab', 'Tab', 'Tab', 'Tab']) {
      await page.keyboard.press(key);
      expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]'))).toBe(true);
    }
  });

  test('A16: Tab auf eine Karte ausserhalb des Bildes holt sie ins Bild', async ({ page }) => {
    await open(page, 'normal', '/karte');
    await card(page, H101).focus();
    for (let i = 0; i < 5; i++) await page.keyboard.press('+');
    await page.waitForTimeout(300);
    await page.keyboard.press('Shift+Tab');
    await page.waitForTimeout(300);
    const r = await page.evaluate(() => {
      const a = document.activeElement as HTMLElement | null;
      const c = document.querySelector('.canvas') as HTMLElement;
      const ra = a?.getBoundingClientRect();
      const rc = c.getBoundingClientRect();
      return { id: a?.dataset.hostId ?? null, inside: !!ra && ra.right > rc.left && ra.left < rc.right && ra.bottom > rc.top && ra.top < rc.bottom };
    });
    expect(r.id).not.toBeNull();
    expect(r.inside).toBe(true);
  });

  test('A3: ein neuer Host verschiebt die Karten unter der Maus nicht', async ({ page }) => {
    await open(page, 'grow', '/karte');
    const c = card(page, H101);
    await c.hover();
    const before = await c.boundingBox();
    await expect(card(page, 'ip:default/192.168.56.130')).toHaveCount(1, { timeout: 8000 });
    await page.waitForTimeout(2500);
    const after = await c.boundingBox();
    expect(Math.round(after?.x ?? 0)).toBe(Math.round(before?.x ?? 0));
    expect(Math.round(after?.y ?? 0)).toBe(Math.round(before?.y ?? 0));
    expect(Math.round(after?.width ?? 0)).toBe(Math.round(before?.width ?? 0));
  });
});

test.describe('Gestaltung', () => {
  for (const w of [900, 1000, 1280, 1366]) {
    test(`D1, D16: Kopfzeile bei ${w} px ohne Überlappung, Suchknopf einzeilig (held und Pause)`, async ({ page }) => {
      await page.setViewportSize({ width: w, height: 800 });
      await open(page, 'held', '/karte');
      const m = await page.evaluate(() => {
        const left = document.querySelector('header.header .left') as HTMLElement;
        const end = Math.max(...Array.from(left.children).map((k) => k.getBoundingClientRect().right));
        const tab = (document.querySelector('header.header nav a') as HTMLElement).getBoundingClientRect();
        const search = (document.querySelector('header.header .search') as HTMLElement).getBoundingClientRect();
        const origin = (document.querySelector('header.header .origin') as HTMLElement).getBoundingClientRect();
        return { end, tab: tab.left, searchH: search.height, originW: origin.width };
      });
      expect(m.end).toBeLessThanOrEqual(m.tab);
      expect(m.searchH).toBeLessThan(40);
      expect(m.originW).toBeGreaterThan(40);
    });
  }

  for (const w of [1280, 1366]) {
    test(`A12: bei ${w} px mit Pause, Scope-Warnung und Präsentation läuft nichts in die Reiter`, async ({ page }) => {
      await page.setViewportSize({ width: w, height: 800 });
      await open(page, 'scope', '/karte');
      await page.locator('header.header button.rec').click();
      await page.getByRole('button', { name: /^Pause für T2/ }).click();
      await page.keyboard.press('Escape');
      await page.locator('main').click({ position: { x: 200, y: 600 } });
      await page.keyboard.press('Shift+P');
      await expect(page.locator('[data-badge="presentation"]')).toHaveCount(1);
      await expect(page.locator('[data-badge="scope"]')).toHaveCount(1);
      const m = await page.evaluate(() => {
        const left = document.querySelector('header.header .left') as HTMLElement;
        const end = Math.max(...Array.from(left.children).map((k) => k.getBoundingClientRect().right));
        const tab = (document.querySelector('header.header nav a') as HTMLElement).getBoundingClientRect();
        return { end, tab: tab.left };
      });
      expect(m.end).toBeLessThanOrEqual(m.tab);
    });
  }

  test('D2: held behält mindestens «… nicht gespeichert», nie nur «!»', async ({ page }) => {
    for (const w of [1000, 1366, 1440]) {
      await page.setViewportSize({ width: w, height: 800 });
      await open(page, 'held', '/karte');
      const held = page.locator('[data-badge="held"] .txt');
      const m = await held.evaluate((e) => ({ w: e.getBoundingClientRect().width, cut: e.scrollWidth > e.clientWidth, text: (e as HTMLElement).innerText }));
      expect(m.w).toBeGreaterThan(60);
      expect(m.cut).toBe(false);
      expect(m.text).toContain('nicht gespeichert');
    }
  });

  test('D3: Startbild zeigt an .101 nur «23 Services», Ports erst nach Zoom des Menschen', async ({ page }) => {
    await open(page, 'normal', '/karte');
    await expect(card(page, H101)).toContainText('23 Services');
    await expect(card(page, H101).locator('.ports')).toHaveCount(0);
    const h = (await box(page, `[data-map-card][data-host-id="${H101}"]`)).h;
    await card(page, H101).focus();
    for (let i = 0; i < 3; i++) await page.keyboard.press('+');
    await expect(card(page, H101).locator('.ports')).toHaveCount(1);
    const ports = card(page, H101).locator('.ports');
    expect(await ports.evaluate((e) => getComputedStyle(e).whiteSpace)).toBe('nowrap');
    expect(h).toBeGreaterThan(40);
  });

  test('D12: ohne Verbindung keine Fusszeile, kein Ring, keine Marke «+N seit»', async ({ page }) => {
    await open(page, 'offline', '/karte');
    await expect(page.getByRole('banner')).toContainText('Keine Verbindung', { timeout: 10_000 });
    await expect(page.locator('.next .foot')).toHaveCount(0);
    await expect(page.locator('.ring-linked')).toHaveCount(0);
    await expect(page.locator('.lage .new')).toHaveCount(0);
  });
});
