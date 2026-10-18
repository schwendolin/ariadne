/**
 * Praxistest 1 gegen den echten Daemon (Fixture MS2, tests/e2e/ui_fixture.py, Scope
 * 192.168.56.0/24) mit Produktions-Build und CSP-Wächter: Scope-Warnung mit Vorschlägen des Servers
 * (`proposals`, web-api.md 20.4) und Vorschau per `dry_run`; Einstellungen zeigen `GET /scope`,
 * Ausschliessen per Dialog schreibt `POST /scope/changes`, «Rückgängig» nimmt es mit `op: 'revert'`
 * zurück (der gemeinsame Fixture-Daemon steht danach wieder wie vorher). Besitzer: ui.
 */
import type { Page } from '@playwright/test';
import { expect, loginDaemon, test } from '../fixtures';

const column = (page: Page) => page.locator('section[data-keyzone="next"]');

test('Scope-Warnung: Dialog mit Vorschlägen des Servers, Abbrechen ändert nichts', async ({ page }) => {
  await loginDaemon(page, '/karte');
  const entry = column(page).locator('[data-scope-entry]');
  await expect(entry).toBeVisible({ timeout: 15_000 });
  await entry.getByRole('button', { name: 'In den Scope aufnehmen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'In den Scope aufnehmen' });
  await expect(dlg.getByTestId('scope-add-entry')).toHaveText(/\S/);
  await expect(dlg).toContainText('Ariadne prüft keine Namen per DNS.');
  await dlg.getByRole('button', { name: 'Abbrechen' }).click();
  await expect(dlg).toHaveCount(0);
  await expect(entry).toBeVisible();
});

test('Einstellungen: Scope vom Server, Ausschliessen und Rückgängig', async ({ page }) => {
  await loginDaemon(page, '/karte?tafel=einstellungen');
  const sec = page.getByTestId('settings-scope');
  await expect(sec).toContainText('192.168.56.0/24', { timeout: 15_000 });
  await expect(sec).not.toContainText('192.168.56.250');
  await sec.getByRole('button', { name: 'Ausschliessen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'Vom Scope ausschliessen' });
  await dlg.getByLabel('Eintrag: Adresse, Netz, Name oder *.domain').fill('192.168.56.250');
  await dlg.getByRole('button', { name: 'Ausschliessen', exact: true }).click();
  const done = dlg.getByTestId('scope-edit-done');
  await expect(done).toBeVisible({ timeout: 15_000 });
  await expect(sec).toContainText('192.168.56.250', { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Rückgängig' }).click();
  await expect(done).toContainText('Rückgängig gemacht.', { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(sec).not.toContainText('192.168.56.250', { timeout: 15_000 });
});
