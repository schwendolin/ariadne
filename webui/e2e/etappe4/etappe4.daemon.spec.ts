/**
 * Etappe 4 gegen den echten Daemon (Fixture MS2, tests/e2e/ui_fixture.py) mit Produktions-Build und
 * CSP-Wächter: KI aus mit Grund aus `/ai/status`, Export mit Fortschritt über SSE und Ergebnis,
 * Phasen in der Zeitachse ansehen und korrigieren (Entscheid übersteht Neuladen), Screenshot im
 * Container ohne grafische Sitzung: fester Fehlertext statt Bild, Screenshot-Liste leer.
 * Besitzer: ui.
 */
import type { Page } from '@playwright/test';
import { expect, loginDaemon, test } from '../fixtures';

const column = (page: Page) => page.locator('section[data-keyzone="next"]');

test('KI: Knopf gesperrt mit Grund aus /ai/status (KI aus)', async ({ page }) => {
  await loginDaemon(page, '/karte');
  const col = column(page);
  const btn = col.getByRole('button', { name: /Denkanstoss anfordern \(KI\)/ });
  await expect(btn).toBeDisabled();
  await expect(col.locator('[data-ai-reason]')).toContainText(/KI ist aus|eingerichtet|Modell|Schlüssel/);
});

test('Export: Fortschritt, Ergebnis mit Ordner, Liste; Phasen in der Zeitachse korrigieren', async ({ page }) => {
  await loginDaemon(page, '/zeitachse');
  await page.getByRole('button', { name: 'Menü' }).click();
  await page.getByRole('menuitem', { name: 'Bericht exportieren …' }).click();
  const dlg = page.getByRole('dialog', { name: 'Bericht exportieren' });
  await expect(dlg.locator('[data-export-phases]')).toContainText(/ohne Phase|zugeordnet/, { timeout: 15_000 });
  const before = await dlg.locator('[data-export-id]').count();
  await dlg.getByRole('button', { name: /^Exportieren/ }).click();
  await expect(dlg.locator('[data-export-result]')).toContainText('Export fertig', { timeout: 60_000 });
  await expect(dlg.locator('[data-export-result]')).toContainText(/exports\/\d{8}T\d{6}Z-cys/);
  await expect(dlg.locator('[data-export-id]')).toHaveCount(before + 1);

  await dlg.getByRole('button', { name: 'in der Zeitachse prüfen ›' }).click();
  await expect(page).toHaveURL(/phasen=cys/);
  const first = page.locator('[data-phase-of]').first();
  await expect(first).toBeVisible({ timeout: 15_000 });
  const ref = await first.getAttribute('data-phase-of');
  await first.locator('select').selectOption('reporting');
  await expect(first).toContainText('korrigiert');
  await page.reload();
  const again = page.locator(`[data-phase-of="${ref}"]`);
  await expect(again).toContainText('korrigiert', { timeout: 15_000 });
  await expect(again.locator('select')).toHaveValue('reporting');
});

test('Screenshot ohne grafische Sitzung: fester Fehlertext, keine Bilder', async ({ page }) => {
  await loginDaemon(page, '/zeitachse');
  await expect(page.locator('section[aria-label="Screenshots"]')).toHaveCount(0);
  await page.getByRole('button', { name: 'Menü' }).click();
  await page.getByRole('menuitem', { name: 'Screenshot der Kali …' }).click();
  const dlg = page.getByRole('dialog', { name: 'Screenshot der Kali' });
  await dlg.getByRole('radio', { name: '0 s', exact: true }).click();
  await dlg.getByRole('button', { name: /^Auslösen/ }).click();
  // Im Container gibt es kein X11: der Daemon meldet shot_display, shot_wayland oder shot_failed
  await expect(dlg.getByRole('alert')).toContainText(/Kein Screenshot: (Keine grafische Sitzung|Wayland|Screenshot fehlgeschlagen|Kein aktives Fenster)/, { timeout: 20_000 });
});
