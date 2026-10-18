/**
 * Terminals, Zeitachse, Belegansicht, Findings und die Dialoge des Verlaufs im Browser gegen den
 * Mock-Build (Besitzer: ui-verlauf). Unter der CSP des Daemons; jeder Test scheitert bei einer
 * CSP-Verletzung, einem Seitenfehler oder einem <style>-Element mit Inhalt (fixtures.ts).
 *
 * Abgedeckt: Rückgängig mit Grund, Rückmeldung inline und «Wieder vertrauen»; Esc bricht ab; Beleg
 * mit ↵ öffnen, Esc schliesst, Fokus zurück auf die Zeile; «Als Finding» bis zum gespeicherten F2;
 * «Als Beleg kopieren · Mac» in die Zwischenablage; verdeckte Eingabe einzeln aufdecken; Kontext-
 * Dialog mit ↵ und Vorschlag; Warteliste aufklappen; Export- und Screenshot-Dialog gesperrt;
 * feindliche Werte (?mock=hostile) nur als Text.
 */
import type { Page } from '@playwright/test';
import { expect, openMock, test } from '../fixtures';

const T1 = '0199a3c2-7e11-7000-8000-00000000c011';
const T2 = '0199a3c2-7e12-7000-8000-00000000c022';
const T3 = '0199a3c2-7e13-7000-8000-00000000c033';
const NMAP = `${T1}@18432`;

const row = (page: Page, id: string) => page.locator(`li.item[data-row="${id}"]`);
const termRow = (page: Page, tid: string) => page.locator(`li[data-terminal="${tid}"]`);
const panel = (page: Page) => page.getByRole('dialog', { name: 'Beleg' });

async function timelineReady(page: Page, query = ''): Promise<void> {
  await openMock(page, 'normal', `/zeitachse${query}`);
  await expect(row(page, NMAP)).toBeVisible();
}

test.describe('Zeitachse', () => {
  test('alle Typen wie im Design, Warteliste eingeklappt, Lücke und Scope-Warnung', async ({ page }) => {
    await timelineReady(page);
    const tl = page.getByRole('region', { name: 'Zeitachse' });
    await expect(tl).toContainText('nmap -sV -sC -oA scans/ms2 192.168.56.101');
    await expect(tl).toContainText('23 Services');
    await expect(tl).toContainText('misstraut');
    await expect(tl).toContainText('Wieder vertrauen');
    await expect(tl).toContainText('Projektstart');
    const strip = page.getByRole('button', { name: /Warteliste/ });
    await expect(strip).toHaveAttribute('aria-expanded', 'false');
    await strip.click();
    await expect(page.locator('#pending-list')).toContainText('scans/udp.xml');
    await expect(page.locator('#pending-list').getByRole('button', { name: /Import-Befehl · Mac/ }).first()).toBeVisible();
  });

  test('Rückgängig mit Grund: Rückmeldung inline, misstraut, Wieder vertrauen hebt auf', async ({ page }) => {
    await timelineReady(page, `?zeile=${encodeURIComponent(NMAP)}`);
    const r = row(page, NMAP);
    await expect(r).toHaveAttribute('aria-current', 'true');
    await page.keyboard.press('u');
    const form = page.getByRole('form', { name: 'Werte aus diesem Befehl verwerfen?' });
    await expect(form).toBeVisible();
    await expect(form.getByLabel('Grund (optional)')).toBeFocused();
    // Esc bricht ab, Fokus zurück auf die Zeile
    await page.keyboard.press('Escape');
    await expect(form).toBeHidden();
    await expect(r).toBeFocused();
    await page.keyboard.press('u');
    await form.getByLabel('Grund (optional)').fill('Banner manipuliert');
    await form.getByRole('button', { name: 'Rückgängig machen' }).click();
    await expect(r).toContainText('141 verworfen, 0 geschwächt');
    await expect(r).toContainText('misstraut');
    await expect(page.getByRole('region', { name: 'Zeitachse' })).toContainText('Banner manipuliert');
    await r.getByRole('button', { name: 'Wieder vertrauen' }).first().click();
    await expect(r).toContainText('Wieder vertraut');
    await expect(r).not.toContainText('misstraut');
  });

  test('Beleg mit ↵ öffnen, Esc schliesst, Fokus zurück auf die Zeile', async ({ page }) => {
    await timelineReady(page, `?zeile=${encodeURIComponent(NMAP)}`);
    await row(page, NMAP).focus();
    await page.keyboard.press('Enter');
    const p = panel(page);
    await expect(p).toBeVisible();
    await expect(p.locator('h2')).toHaveText(/^Beleg · T1 scan · \d\d:\d\d:\d\d$/);
    await expect(p.locator('.line').first()).toBeVisible();
    await expect(page).toHaveURL(/beleg=u%3A/);
    await page.keyboard.press('Escape');
    await expect(p).toBeHidden();
    await expect(page).not.toHaveURL(/beleg=/);
    await expect(row(page, NMAP)).toBeFocused();
  });

  test('Filter Typ und Terminal stehen in der URL', async ({ page }) => {
    await timelineReady(page);
    await page.getByRole('button', { name: /^Alle Typen/ }).click();
    await page.getByRole('dialog', { name: 'Typen filtern' }).getByLabel('Lücken').uncheck();
    await expect(page).toHaveURL(/typ=/);
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: /^Alle Terminals/ }).click();
    await page.getByRole('dialog', { name: 'Terminal filtern' }).getByLabel(/T2/).check();
    await expect(page).toHaveURL(new RegExp(`terminal=${T2}`));
    await expect(row(page, NMAP)).toBeHidden();
  });
});

test.describe('Belegansicht und Findings', () => {
  test('Beleg mit Markierung: «40 Zeilen davor», kopieren in die Zwischenablage des Macs', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await openMock(page, 'normal', `/zeitachse?beleg=${encodeURIComponent(`u:${T2}@1024:43-46`)}`);
    const p = panel(page);
    await expect(p).toContainText('40 Zeilen davor ausgeblendet');
    await expect(p.locator('.line.marked')).toHaveCount(4);
    await p.getByRole('button', { name: 'Als Beleg kopieren · Mac' }).click();
    await expect(p).toContainText('In der Zwischenablage des Macs');
    // eslint-disable-next-line no-restricted-properties -- der Test liest nur zurück, was der Knopf kopiert hat
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip.startsWith('**Beleg** T2 msf · msfconsole -q · Zeilen 44 bis 47')).toBe(true);
    expect(clip).toContain('44  ');
  });

  test('Als Finding aus dem Beleg bis zum gespeicherten F2', async ({ page }) => {
    await openMock(page, 'normal', `/zeitachse?beleg=${encodeURIComponent(`u:${T2}@1024:43-46`)}`);
    await panel(page).getByRole('button', { name: 'Als Finding' }).click();
    await expect(page).toHaveURL(/\/findings\?.*finding=neu/);
    const form = page.getByRole('form', { name: 'Neues Finding' });
    await expect(form).toContainText('T2 msf · msfconsole -q · Zeilen 44 bis 47');
    await expect(form).toContainText('angelegt aus dem Beleg');
    await form.getByLabel('Titel').fill('Root-Shell über vsftpd');
    await form.getByRole('radio', { name: 'Hoch' }).click();
    await page.keyboard.press('Control+Enter');
    await expect(page).not.toHaveURL(/finding=neu/);
    const card = page.locator('a.card.sel');
    await expect(card).toContainText('F2');
    await expect(card).toContainText('Root-Shell über vsftpd');
    await expect(card).toContainText('1 Beleg');
  });

  test('Hash-Kette verletzt: Meldung bleibt, Knöpfe gesperrt mit Grund', async ({ page }) => {
    await openMock(page, 'chain', `/zeitachse?beleg=${encodeURIComponent(`u:${NMAP}`)}`);
    const p = panel(page);
    await expect(p.getByRole('alert').filter({ hasText: 'Hash-Kette verletzt' })).toBeVisible();
    await expect(p.getByRole('button', { name: /^Als Finding/ })).toBeDisabled();
    await expect(p.getByRole('button', { name: /^Als Beleg kopieren/ })).toHaveAttribute('title', /gesperrt/);
    await expect(p.locator('.lr.broken').first()).toBeVisible();
  });
});

test.describe('Terminals und Kontext', () => {
  test('verdeckte Eingabe einzeln aufdecken, nie in der Zwischenablage', async ({ page }) => {
    await openMock(page, 'normal', '/terminals');
    const t2 = termRow(page, T2);
    await expect(t2).toContainText('Eingabe ohne Echo');
    await expect(t2).toContainText('••••••••');
    await t2.getByRole('button', { name: 'Aufdecken' }).click();
    await expect(t2).toContainText('mock-Ziel-Passwort');
    await t2.getByRole('button', { name: 'Verdecken' }).click();
    await expect(t2).not.toContainText('mock-Ziel-Passwort');
  });

  test('↵ öffnet den Kontext-Dialog mit dem Vorschlag; Setzen schliesst ihn', async ({ page }) => {
    await openMock(page, 'normal', '/terminals');
    await expect(termRow(page, T1)).toBeVisible();
    await page.keyboard.press('j');
    await page.keyboard.press('j');
    await expect(termRow(page, T3)).toHaveAttribute('aria-current', 'true');
    await page.keyboard.press('Enter');
    const dlg = page.getByRole('dialog', { name: /Kontext für T3/ });
    await expect(dlg).toBeVisible();
    await expect(dlg.getByLabel('Host')).toHaveValue('192.168.56.101');
    await expect(dlg.getByRole('list', { name: 'Vorschläge' })).toContainText('Vorschlag aus Callback');
    await dlg.getByRole('button', { name: 'Setzen' }).click();
    await expect(dlg).toBeHidden();
    await expect(page.getByText('Kontext gesetzt')).toBeVisible();
  });

  test('Pause 10 min wartet auf Bestätigung, dann Pause bis', async ({ page }) => {
    await openMock(page, 'normal', '/terminals');
    const t2 = termRow(page, T2);
    await t2.getByRole('button', { name: /Pause für T2/ }).click();
    await expect(t2).toContainText(/wartet auf Bestätigung|Pause bis/);
    await expect(t2).toContainText(/Pause bis \d\d:\d\d/);
    await expect(t2.getByRole('button', { name: /fortsetzen/ })).toBeVisible();
  });
});

test.describe('Dialoge', () => {
  test('Export und Screenshot aus dem Menü: gesperrt mit Hinweis', async ({ page }) => {
    await openMock(page, 'normal', '/zeitachse');
    await page.getByRole('button', { name: 'Menü' }).click();
    await page.getByRole('menuitem', { name: 'Bericht exportieren …' }).click();
    const exp = page.getByRole('dialog', { name: 'Bericht exportieren' });
    await expect(exp).toContainText('späteren Version');
    await expect(exp.getByRole('button', { name: /^Exportieren/ })).toBeDisabled();
    await page.keyboard.press('Escape');
    await expect(exp).toBeHidden();
    await page.getByRole('button', { name: 'Menü' }).click();
    await page.getByRole('menuitem', { name: 'Screenshot der Kali …' }).click();
    const shot = page.getByRole('dialog', { name: 'Screenshot der Kali' });
    await expect(shot.getByRole('button', { name: /^Auslösen/ })).toBeDisabled();
    await shot.getByRole('button', { name: 'Schliessen' }).click();
    await expect(shot).toBeHidden();
  });
});

test.describe('feindliche Werte', () => {
  test('Zeitachse, Warteliste und Beleg nur als Text, Steuerzeichen sichtbar', async ({ page }) => {
    await openMock(page, 'hostile', '/zeitachse');
    const tl = page.getByRole('region', { name: 'Zeitachse' });
    await expect(tl).toContainText('<script>alert(1)</script>');
    await expect(tl).toContainText('<ESC>');
    await page.getByRole('button', { name: /Warteliste/ }).click();
    await expect(page.locator('#pending-list')).toContainText('$(id)');
    await expect(page.locator('#pending-list')).toContainText('Pfad mit Sonderzeichen');
    await row(page, `${T1}@60000`).click();
    await page.keyboard.press('Enter');
    const p = panel(page);
    await expect(p.locator('.line')).toHaveCount(3);
    await expect(p).toContainText('<U+202E>');
    const bad = await page.evaluate(() => document.querySelectorAll('main img, main script, main iframe, main a[href^="http"]').length);
    expect(bad).toBe(0);
    expect(await page.evaluate(() => (window as unknown as { __pwned?: boolean }).__pwned ?? false)).toBe(false);
  });
});
