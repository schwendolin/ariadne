/**
 * Praxistest 1 im Mock-Build unter der Daemon-CSP (CSP-Wächter aus fixtures.ts): Scope erweitern
 * aus der Scope-Warnung (E129), Klärung nach nmap (E130), Out-of-Scope-Popover, Einstellungen,
 * Profil customer, Anmeldeseite mit Code-Hinweis, Passphrase und Abmeldegrund. Screenshots nach
 * ARIADNE_PRAXIS_SHOTS (sonst .e2e/shots-praxis1/). Besitzer: ui.
 */
import type { Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, openMock, test } from '../fixtures';

const SHOTS = process.env.ARIADNE_PRAXIS_SHOTS ?? resolve(import.meta.dirname, '../../.e2e/shots-praxis1');
mkdirSync(SHOTS, { recursive: true });

test.use({ viewport: { width: 1440, height: 900 } });

const column = (page: Page) => page.locator('section[data-keyzone="next"]');
const shot = (page: Page, name: string) => page.screenshot({ path: resolve(SHOTS, `${name}.png`) });

test('Scope-Warnung: In den Scope aufnehmen, Wildcard, Neuauswertung, Warnung verschwindet', async ({ page }) => {
  await openMock(page, 'praxis');
  const entry = column(page).locator('[data-scope-entry]');
  await expect(entry).toContainText('curl http://recovery.vantis.internal/login');
  await expect(entry.getByRole('button', { name: 'Quittieren' })).toBeVisible();
  await shot(page, '01-scope-warnung');
  await entry.getByRole('button', { name: 'In den Scope aufnehmen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'In den Scope aufnehmen' });
  await expect(dlg.getByTestId('scope-add-entry')).toHaveText('recovery.vantis.internal');
  await expect(dlg).toContainText('Ariadne prüft keine Namen per DNS.');
  await shot(page, '02-dialog-name');
  await dlg.getByText('*.vantis.internal', { exact: true }).click();
  await expect(dlg.getByTestId('scope-add-entry')).toHaveText('*.vantis.internal');
  await shot(page, '03-dialog-wildcard');
  await dlg.getByRole('button', { name: 'Aufnehmen' }).click();
  await expect(dlg.getByTestId('scope-add-done')).toContainText('Neu ausgewertet.');
  await shot(page, '04-dialog-aufgenommen');
  await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(column(page).locator('[data-scope-entry]')).toHaveCount(0);
  // Die Klärung zum selben Namen ist erledigt (der Name liegt jetzt im Scope)
  await expect(column(page)).not.toContainText('recovery.vantis.internal gehört laut nmap');
});

test('E130: Klärung mit Wahl Name oder Wildcard, Warnhinweis bei öffentlicher Endung, Verwerfen', async ({ page }) => {
  await openMock(page, 'praxis', '/karte?sel=scope-name%3A5d1c0a7e2b9f4c31');
  const col = column(page);
  const card = col.locator('.card', { hasText: 'gehört laut nmap zu' });
  await expect(card).toContainText('recovery.vantis.internal gehört laut nmap zu 192.168.56.101. In den Scope aufnehmen?');
  await expect(card.getByLabel(/\*\.vantis\.internal/)).toBeVisible();
  await shot(page, '05-e130-intern');
  await card.getByRole('button', { name: /Aufnehmen/ }).click();
  const dlg = page.getByRole('dialog', { name: 'In den Scope aufnehmen' });
  await expect(dlg.getByTestId('scope-add-entry')).toHaveText('recovery.vantis.internal');
  await dlg.getByRole('button', { name: 'Abbrechen' }).click();

  await col.locator('button.line', { hasText: 'vpn.vantis-group.com' }).click();
  const pub = col.locator('.card', { hasText: 'vpn.vantis-group.com' });
  await expect(pub).toContainText('Öffentliche Endung: nur aufnehmen, wenn der Auftrag dieses Ziel ausdrücklich nennt.');
  await expect(pub).toContainText('Ausserhalb der Lab-Allowlist');
  await shot(page, '06-e130-oeffentlich');
  await pub.getByRole('button', { name: /Verwerfen/ }).click();
  await expect(col.locator('[data-done-key="scope-name:9e4b11c07d2a6f58"]')).toContainText('verworfen');
});

test('Out-of-Scope-Popover: pro Kennung «In den Scope aufnehmen …»', async ({ page }) => {
  await openMock(page, 'praxis');
  await page.getByRole('button', { name: /^Out of Scope · \d+$/ }).click();
  const oos = page.getByRole('dialog', { name: 'Out of Scope' });
  const rows = oos.locator('[data-oos-item]');
  await expect(rows.first().getByRole('button', { name: 'In den Scope aufnehmen …' })).toBeVisible();
  await shot(page, '07-oos-popover');
  await rows.first().getByRole('button', { name: 'In den Scope aufnehmen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'In den Scope aufnehmen' });
  await expect(dlg.getByTestId('scope-add-entry')).toBeVisible();
  await shot(page, '08-oos-dialog');
  await dlg.getByRole('button', { name: 'Abbrechen' }).click();
  await expect(dlg).toHaveCount(0);
});

test('Einstellungen: Scope mit Entfernen und Ausschliessen per Dialog', async ({ page }) => {
  await openMock(page, 'praxis', '/karte?tafel=einstellungen');
  const sec = page.getByTestId('settings-scope');
  await expect(sec).toContainText('192.168.56.0/24');
  await expect(sec).toContainText('mon-fri 08:00–18:00 Europe/Zurich');
  await shot(page, '09-einstellungen-scope');
  await sec.getByRole('button', { name: 'Ausschliessen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'Vom Scope ausschliessen' });
  await dlg.getByLabel('Eintrag: Adresse, Netz, Name oder *.domain').fill('192.168.56.250');
  await expect(dlg.getByTestId('scope-edit-entry')).toHaveText('192.168.56.250');
  await shot(page, '10-ausschliessen');
  await dlg.getByRole('button', { name: 'Ausschliessen', exact: true }).click();
  await expect(dlg.getByTestId('scope-edit-done')).toBeVisible();
  await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(sec).toContainText('192.168.56.250');
  await sec.locator('li', { hasText: '192.168.56.250' }).getByRole('button', { name: 'Entfernen …' }).click();
  const rm = page.getByRole('dialog', { name: 'Aus dem Scope entfernen' });
  await expect(rm.getByTestId('scope-edit-entry')).toHaveText('192.168.56.250');
  await rm.getByRole('button', { name: 'Entfernen', exact: true }).click();
  await expect(rm.getByTestId('scope-edit-done')).toBeVisible();
  await rm.getByRole('button', { name: 'Schliessen' }).click();
  await expect(sec).not.toContainText('192.168.56.250');
});

test('Profil customer: nur Anzeige mit Hinweis auf ariadne scope', async ({ page }) => {
  await openMock(page, 'customer', '/karte?tafel=einstellungen');
  const sec = page.getByTestId('settings-scope');
  await expect(sec).toContainText('Im Profil customer ändert sich der Scope nur im Terminal: ariadne scope');
  await expect(sec.getByRole('button')).toHaveCount(0);
  await expect(column(page).locator('[data-scope-entry]').getByRole('button', { name: 'In den Scope aufnehmen …' })).toBeDisabled();
  await shot(page, '11-customer');
});

test('Anmeldeseite: Code-Hinweis, Muster, Passphrase wird erkannt und nicht gesendet', async ({ page }) => {
  await openMock(page, 'login');
  const main = page.locator('main.login');
  await expect(main).toContainText('Code im Terminal holen: ariadne ui --code (oder ariadne ui öffnet den Browser direkt)');
  await expect(page.getByLabel('Anmeldecode')).toHaveAttribute('placeholder', 'XXXXX-XXXXX');
  await page.getByLabel('Anmeldecode').fill('mein geheimes passwort');
  await expect(main.getByRole('note')).toHaveText('Das ist der Einmal-Code aus dem Terminal, nicht die Passphrase.');
  await shot(page, '12-anmeldung-passphrase');
});

test('Abmeldegrund: Sitzung endet mit ariadne stop, die Anmeldeseite nennt den Grund', async ({ page }) => {
  await openMock(page, 'ende');
  await expect(page.getByTestId('login-ended')).toHaveText('Projekt ms2 wurde beendet (ariadne stop). Neue Anmeldung: ariadne ui', { timeout: 10_000 });
  await shot(page, '13-anmeldung-grund');
});
