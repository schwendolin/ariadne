/**
 * Praxistest 2 gegen den echten Daemon (Fixture MS2, Scope 192.168.56.0/24, Profil lab) mit
 * Produktions-Build und CSP-Wächter: offener Scope (E131).
 * 1. Ohne «kein Kundenauftrag» bleibt «Scope öffnen» gesperrt (dry_run `needs_not_customer`).
 * 2. Öffnen im Terminal (ctl `scope.change` wie `ariadne scope open --not-customer`), dann im
 *    Dashboard schliessen, wieder öffnen und das Öffnen nach Bestätigung rückgängig machen. Der
 *    Scope steht danach wieder geschlossen wie vorher; die Bestätigung «kein Kundenauftrag» bleibt
 *    im Journal des Fixture-Projekts (kein anderer Daemon-Test hängt davon ab). Besitzer: ui.
 */
import type { Page } from '@playwright/test';
import { ctl, expect, loginDaemon, test } from '../fixtures';

const badge = (page: Page) => page.locator('[data-badge="scope-open"]');

test('Öffnen ohne «kein Kundenauftrag»: gesperrt mit Hinweis auf ariadne scope open', async ({ page }) => {
  await loginDaemon(page, '/karte?tafel=einstellungen');
  const sec = page.getByTestId('settings-scope');
  await expect(page.getByTestId('scope-state')).toContainText('Geschlossen: nur die Einschlüsse', { timeout: 15_000 });
  await sec.getByRole('button', { name: 'Scope öffnen …' }).click();
  const dlg = page.getByRole('dialog', { name: 'Scope öffnen' });
  await expect(dlg.getByTestId('scope-open-blocked')).toContainText('Öffnen braucht einmal die Bestätigung im Terminal: ariadne scope open', { timeout: 15_000 });
  await expect(dlg.getByRole('button', { name: /^Scope öffnen/ })).toBeDisabled();
  await dlg.getByRole('button', { name: 'Abbrechen' }).click();
  await expect(page.getByTestId('scope-state')).toContainText('Geschlossen');
  await expect(badge(page)).toHaveCount(0);
});

test('Öffnen im Terminal, Schliessen und Öffnen im Dashboard, Rückgängig nach Bestätigung', async ({ page }) => {
  const st = await loginDaemon(page, '/karte?tafel=einstellungen');
  const sec = page.getByTestId('settings-scope');
  await expect(sec).toContainText('192.168.56.0/24', { timeout: 15_000 });
  // wie `ariadne scope open --not-customer` im Terminal
  await ctl(st.ctl, 'scope.change', { action: 'open', origin: 'cli', not_customer: true });
  await expect(page.getByTestId('scope-state')).toContainText('Offen: alles gilt als im Scope, ausser Ausschlüssen', { timeout: 15_000 });
  await expect(badge(page)).toHaveText('Scope offen', { timeout: 15_000 });

  // Schliessen: die Einschlüsse, die danach allein gelten
  await sec.getByRole('button', { name: 'Scope schliessen …' }).click();
  let dlg = page.getByRole('dialog', { name: 'Scope schliessen' });
  await expect(dlg.getByTestId('scope-close-include')).toContainText('192.168.56.0/24');
  await expect(dlg.getByRole('button', { name: 'Scope schliessen', exact: true })).toBeEnabled({ timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Scope schliessen', exact: true }).click();
  await expect(dlg.getByTestId('scope-open-done')).toContainText('Scope geschlossen', { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(page.getByTestId('scope-state')).toContainText('Geschlossen', { timeout: 15_000 });
  await expect(badge(page)).toHaveCount(0, { timeout: 15_000 });

  // Öffnen im Dashboard (bestätigt), dann Rückgängig mit Wirkung
  await sec.getByRole('button', { name: 'Scope öffnen …' }).click();
  dlg = page.getByRole('dialog', { name: 'Scope öffnen' });
  await expect(dlg.getByRole('button', { name: 'Scope öffnen', exact: true })).toBeEnabled({ timeout: 15_000 });
  await expect(dlg.getByTestId('scope-open-blocked')).toHaveCount(0);
  await dlg.getByRole('button', { name: 'Scope öffnen', exact: true }).click();
  await expect(dlg.getByTestId('scope-open-done')).toContainText('Scope geöffnet', { timeout: 15_000 });
  await expect(badge(page)).toHaveText('Scope offen', { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Rückgängig', exact: true }).click();
  await expect(dlg.getByTestId('scope-open-undo-confirm')).toHaveText('Rückgängig schliesst den Scope wieder: danach gelten nur die Einschlüsse.');
  await dlg.getByRole('button', { name: 'Rückgängig machen' }).click();
  await expect(dlg.getByTestId('scope-open-done')).toContainText('Rückgängig gemacht.', { timeout: 15_000 });
  await dlg.getByRole('button', { name: 'Schliessen' }).click();
  await expect(page.getByTestId('scope-state')).toContainText('Geschlossen', { timeout: 15_000 });
  await expect(badge(page)).toHaveCount(0, { timeout: 15_000 });

  // Zeitachse: «Scope geöffnet (Version N)» vom Server
  await page.goto('/zeitachse');
  await expect(page.locator('li', { hasText: /Scope geöffnet \(Version \d+\)/ }).first()).toBeVisible({ timeout: 15_000 });
});
