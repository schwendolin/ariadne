/**
 * Praxistest 2 im Mock-Build unter der Daemon-CSP (CSP-Wächter aus fixtures.ts): offener Scope
 * (E131) in Einstellungen, Kopfzeile und Zeitachse; Lab-Allowlist mit Befehl fürs Terminal (E132);
 * sehr breite Einträge (E133). Screenshots nach ARIADNE_PRAXIS2_SHOTS (sonst .e2e/shots-praxis2/).
 * Besitzer: ui.
 */
import type { Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, openMock, test } from '../fixtures';

const SHOTS = process.env.ARIADNE_PRAXIS2_SHOTS ?? resolve(import.meta.dirname, '../../.e2e/shots-praxis2');
mkdirSync(SHOTS, { recursive: true });

test.use({ viewport: { width: 1440, height: 900 } });

const shot = (page: Page, name: string) => page.screenshot({ path: resolve(SHOTS, `${name}.png`) });
const badge = (page: Page) => page.locator('[data-badge="scope-open"]');

test('Öffnen mit bestätigtem «kein Kundenauftrag»: Wirkung, Kennzeichen, Rückgängig nach Bestätigung', async ({ page }) => {
  await openMock(page, 'zu', '/karte?tafel=einstellungen');
  const sec = page.getByTestId('settings-scope');
  await expect(page.getByTestId('scope-state')).toContainText('Geschlossen: nur die Einschlüsse');
  await expect(badge(page)).toHaveCount(0);
  await shot(page, '01-einstellungen-geschlossen');
  await sec.getByRole('button', { name: 'Scope öffnen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'Scope öffnen' });
  await expect(dlg.getByTestId('scope-open-text')).toContainText('auch öffentliche Ziele wie github.com');
  await expect(dlg.getByRole('button', { name: 'Scope öffnen', exact: true })).toBeEnabled();
  await shot(page, '02-dialog-oeffnen');
  await dlg.getByRole('button', { name: 'Scope öffnen', exact: true }).click();
  await expect(dlg.getByTestId('scope-open-done')).toContainText('Neu ausgewertet.');
  await expect(badge(page)).toHaveText('Scope offen');
  await expect(page.getByTestId('scope-state')).toContainText('Offen: alles gilt als im Scope, ausser Ausschlüssen');
  await shot(page, '03-geoeffnet');
  await dlg.getByRole('button', { name: 'Rückgängig', exact: true }).click();
  await expect(dlg.getByTestId('scope-open-undo-confirm')).toHaveText('Rückgängig schliesst den Scope wieder: danach gelten nur die Einschlüsse.');
  await shot(page, '04-rueckgaengig-bestaetigen');
  await dlg.getByRole('button', { name: 'Rückgängig machen' }).click();
  await expect(dlg.getByTestId('scope-open-done')).toContainText('Rückgängig gemacht.');
  await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(page.getByTestId('scope-state')).toContainText('Geschlossen');
  await expect(badge(page)).toHaveCount(0);
});

test('Öffnen ohne «kein Kundenauftrag»: gesperrt mit Hinweis auf ariadne scope open', async ({ page }) => {
  await openMock(page, 'normal', '/karte?tafel=einstellungen');
  await page.getByTestId('settings-scope').getByRole('button', { name: 'Scope öffnen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'Scope öffnen' });
  await expect(dlg.getByTestId('scope-open-blocked')).toHaveText('! Öffnen braucht einmal die Bestätigung im Terminal: ariadne scope open');
  await expect(dlg.getByRole('button', { name: /^Scope öffnen/ })).toBeDisabled();
  await shot(page, '05-oeffnen-gesperrt');
  await dlg.getByRole('button', { name: 'Abbrechen' }).click();
  await expect(page.getByTestId('scope-state')).toContainText('Geschlossen');
});

test('Offen ohne Einschlüsse: Kennzeichen, «offen», Schliessen gesperrt, Hinzufügen breit, dann Schliessen', async ({ page }) => {
  await openMock(page, 'offen', '/karte?tafel=einstellungen');
  const sec = page.getByTestId('settings-scope');
  await expect(badge(page)).toHaveText('Scope offen');
  await expect(page.getByTestId('scope-state')).toContainText('Offen: alles gilt als im Scope, ausser Ausschlüssen');
  await expect(sec).toContainText('Ziele offen');
  await shot(page, '06-offen-einstellungen');
  await sec.getByRole('button', { name: 'Scope schliessen …' }).click();
  let dlg = page.getByRole('dialog', { name: 'Scope schliessen' });
  await expect(dlg.getByTestId('scope-close-blocked')).toContainText('Zuerst einen Eintrag hinzufügen');
  await expect(dlg.getByRole('button', { name: /^Scope schliessen/ })).toBeDisabled();
  await shot(page, '07-schliessen-gesperrt');
  await dlg.getByRole('button', { name: 'Abbrechen' }).click();

  await sec.getByRole('button', { name: 'Hinzufügen …' }).click();
  const add = page.getByRole('dialog', { name: 'Zum Scope hinzufügen' });
  await add.getByLabel('Eintrag: Adresse, Netz, Bereich, Name oder *.domain').fill('10.0.0.0/8');
  await expect(add.getByTestId('scope-broad')).toContainText('Sehr breiter Eintrag: umfasst mehr als 65');
  await shot(page, '08-hinzufuegen-breit');
  await add.getByRole('button', { name: 'Hinzufügen', exact: true }).click();
  await expect(add.getByTestId('scope-edit-done')).toBeVisible();
  await add.getByRole('button', { name: 'Schliessen' }).click();
  await expect(sec).toContainText('10.0.0.0/8');

  await sec.getByRole('button', { name: 'Scope schliessen …' }).click();
  dlg = page.getByRole('dialog', { name: 'Scope schliessen' });
  await expect(dlg.getByTestId('scope-close-include')).toHaveText('10.0.0.0/8');
  await shot(page, '09-schliessen-dialog');
  await dlg.getByRole('button', { name: 'Scope schliessen', exact: true }).click();
  await expect(dlg.getByTestId('scope-open-done')).toBeVisible();
  await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(page.getByTestId('scope-state')).toContainText('Geschlossen');
  await expect(badge(page)).toHaveCount(0);
});

test('Zeitachse: «Scope geöffnet (Version 2)», Rückgängig mit richtiger Wirkung', async ({ page }) => {
  await openMock(page, 'offen', '/zeitachse');
  const row = page.locator('li', { hasText: 'Scope geöffnet (Version 2)' }).first();
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Rückgängig' }).click();
  await expect(page.getByTestId('scope-revert-confirm')).toContainText('Rückgängig schliesst den Scope wieder: danach gelten nur die Einschlüsse.');
  await shot(page, '10-zeitachse-geoeffnet');
  await page.getByTestId('scope-revert-confirm').getByRole('button', { name: 'Abbrechen' }).click();
  await expect(page.getByTestId('scope-revert-confirm')).toHaveCount(0);
});

test('E132: recovery.vantis.internal ohne Bestätigung gesperrt, mit dem Befehl fürs Terminal', async ({ page }) => {
  await openMock(page, 'praxis');
  const entry = page.locator('section[data-keyzone="next"]').locator('[data-scope-entry]');
  await entry.getByRole('button', { name: 'In den Scope aufnehmen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'In den Scope aufnehmen' });
  await expect(dlg.getByTestId('scope-add-guardrail')).toContainText('ariadne scope add recovery.vantis.internal --not-customer');
  await expect(dlg.getByRole('button', { name: /^Aufnehmen/ })).toBeDisabled();
  await expect(dlg).not.toContainText('Öffentliche Endung');
  await shot(page, '11-allowlist-befehl');
  await dlg.getByRole('button', { name: 'Abbrechen' }).click();
});
