/**
 * Selbsttest des CSP-Wächters (Besitzer: ui-fundament): Die Tests hier MÜSSEN scheitern
 * (`test.fail`). Bleibt einer grün, erkennt e2e/fixtures.ts Verletzungen nicht mehr.
 */
import { expect, openMock, test } from '../fixtures';

test.fail('Wächter: style-Attribut aus Markup wird gemeldet', async ({ page }) => {
  await openMock(page);
  await expect(page.locator('header.header')).toBeVisible();
  await page.evaluate(() => {
    const el = document.createElement('div');
    // eslint-disable-next-line no-restricted-syntax -- absichtliche Verletzung für den Selbsttest
    el.setAttribute('style', 'color: red');
    document.body.append(el);
  });
  await page.waitForTimeout(100);
});

test.fail('Wächter: eingefügtes <style>-Element wird gemeldet', async ({ page }) => {
  await openMock(page);
  await expect(page.locator('header.header')).toBeVisible();
  await page.evaluate(() => {
    // eslint-disable-next-line no-restricted-syntax -- absichtliche Verletzung für den Selbsttest
    const el = document.createElement('style');
    el.textContent = 'body { color: red }';
    document.head.append(el);
  });
  await page.waitForTimeout(100);
});

test('Wächter: CSSOM-Variablen sind erlaubt (der Weg für dynamische Werte)', async ({ page }) => {
  await openMock(page);
  await expect(page.locator('header.header')).toBeVisible();
  await page.evaluate(() => document.documentElement.style.setProperty('--probe', '12px'));
  await page.waitForTimeout(100);
});
