/**
 * Praxistest 1 gegen den echten Daemon (Fixture MS2, tests/e2e/ui_fixture.py, Scope
 * 192.168.56.0/24) mit Produktions-Build und CSP-Wächter: Scope-Warnung mit Vorschlägen des Servers
 * (`proposals`, web-api.md 20.4) und Vorschau per `dry_run`; Einstellungen zeigen `GET /scope`,
 * Ausschliessen per Dialog zeigt den Eintrag per `dry_run` wie gespeichert und schreibt
 * `POST /scope/changes`, «Rückgängig» nimmt es nach einer Bestätigung mit `op: 'revert'` zurück
 * (der gemeinsame Fixture-Daemon steht danach wieder wie vorher). Besitzer: ui.
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

test('Einstellungen: Scope vom Server, Ausschliessen (Eintrag wie gespeichert) und Rückgängig nach Bestätigung', async ({ page }) => {
  await loginDaemon(page, '/karte?tafel=einstellungen');
  const sec = page.getByTestId('settings-scope');
  await expect(sec).toContainText('192.168.56.0/24', { timeout: 15_000 });
  await expect(sec).not.toContainText('box.ms2.lab');
  await sec.getByRole('button', { name: 'Ausschliessen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'Vom Scope ausschliessen' });
  await dlg.getByLabel('Eintrag: Adresse, Netz, Name oder *.domain').fill('Box.MS2.Lab.');
  // dry_run: der Server zeigt den Eintrag so, wie er gespeichert wird
  await expect(dlg.getByTestId('scope-edit-entry')).toHaveText('box.ms2.lab', { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Ausschliessen', exact: true }).click();
  const done = dlg.getByTestId('scope-edit-done');
  await expect(done).toBeVisible({ timeout: 15_000 });
  await expect(dlg.getByTestId('scope-edit-saved')).toHaveText('box.ms2.lab');
  await expect(sec).toContainText('box.ms2.lab', { timeout: 15_000 });
  // Rückgängig erweitert den Scope wieder: erst Wirkung und Eintrag, dann «Rückgängig machen»
  await dlg.getByRole('button', { name: 'Rückgängig', exact: true }).click();
  await expect(dlg.getByTestId('scope-edit-undo-confirm')).toHaveText('Rückgängig hebt den Ausschluss auf: box.ms2.lab');
  await dlg.getByRole('button', { name: 'Rückgängig machen' }).click();
  await expect(done).toContainText('Rückgängig gemacht.', { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(sec).not.toContainText('box.ms2.lab', { timeout: 15_000 });
});

test('Out-of-Scope-Rand: Vorschläge vom Server (OosItem.proposals bzw. GET /scope/options), Abbrechen ändert nichts', async ({ page }) => {
  await loginDaemon(page, '/karte');
  const handle = page.getByRole('button', { name: /^Out of Scope · \d+/ });
  await expect(handle).toBeVisible({ timeout: 15_000 });
  await handle.click();
  const add = page.locator('[data-oos-item]').first().getByRole('button', { name: 'In den Scope aufnehmen …' });
  await add.click();
  const dlg = page.getByRole('dialog', { name: 'In den Scope aufnehmen' });
  await expect(dlg.getByTestId('scope-add-entry')).toHaveText(/\S/, { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Abbrechen' }).click();
  await expect(dlg).toHaveCount(0);
});

test('Scope-Warnung: Aufnehmen wirkt (Warnung weg), Rückgängig stellt den alten Scope her', async ({ page }) => {
  await loginDaemon(page, '/karte');
  const entry = column(page).locator('[data-scope-entry]');
  await expect(entry).toBeVisible({ timeout: 15_000 });
  await entry.getByRole('button', { name: 'In den Scope aufnehmen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'In den Scope aufnehmen' });
  await expect(dlg.getByTestId('scope-add-entry')).toHaveText('10.66.66.66', { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Aufnehmen', exact: true }).click();
  const done = dlg.getByTestId('scope-add-done');
  await expect(done).toContainText('Neu ausgewertet.', { timeout: 15_000 });
  await expect(entry).toHaveCount(0, { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Rückgängig' }).click();
  await expect(done).toContainText('Rückgängig gemacht.', { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(entry).toBeVisible({ timeout: 15_000 });
});
