/**
 * Etappe 4 im Browser gegen den Mock-Build mit der CSP des Daemons (CSP-Wächter aus fixtures.ts):
 * KI-Denkanstoss mit Zuständen und D3, Export mit Fortschritt und Phasen in der Zeitachse,
 * Screenshot mit Countdown und Bildern aus /blobs (blob:-URL), verdeckt im Präsentationsmodus,
 * E119 Versionen pro Host. Besitzer: ui.
 */
import type { Page } from '@playwright/test';
import { expect, openMock, test } from '../fixtures';

const column = (page: Page) => page.locator('section[data-keyzone="next"]');

test.describe('KI-Denkanstoss', () => {
  test('eingerichtet: anfordern, Ergebnis, KI-Denkanstoss mit Kriterien und Bestätigt/Widerlegt', async ({ page }) => {
    await openMock(page, 'ki');
    const col = column(page);
    const btn = col.getByRole('button', { name: 'Denkanstoss anfordern (KI)' });
    await expect(btn).toBeEnabled();
    await btn.click();
    await expect(col.locator('[data-ai-phase="done"]')).toContainText('1 neuer KI-Denkanstoss', { timeout: 10_000 });
    const line = col.locator('button.line', { hasText: 'Hypothese: Samba' });
    await expect(line).toContainText('KI');
    await line.click();
    const card = col.locator('.card', { hasText: 'bestätigt, wenn' });
    await expect(card).toContainText('widerlegt, wenn');
    await expect(card.getByRole('button', { name: 'Widerlegt' })).toBeVisible();
    await card.getByRole('button', { name: 'Bestätigt' }).click();
    await expect(col.locator('.done').last()).toContainText('bestätigt');
  });

  test('läuft: Lagebild wird gesendet mit Tokens und Maskierung', async ({ page }) => {
    await openMock(page, 'kirun');
    const col = column(page);
    await col.getByRole('button', { name: 'Denkanstoss anfordern (KI)' }).click();
    const st = col.locator('[data-ai-phase="running"]');
    await expect(st).toContainText('Lagebild wird gesendet');
    await expect(st).toContainText('Tokens gesendet');
    await expect(st).toContainText('3 Werte maskiert');
    await expect(col.getByRole('button', { name: /Denkanstoss anfordern/ })).toBeDisabled();
  });

  test('Budget voll: Rückfrage; Ablehnung wörtlich als Text; KI aus mit Grund', async ({ page }) => {
    await openMock(page, 'kiover');
    let col = column(page);
    await col.getByRole('button', { name: 'Denkanstoss anfordern (KI)' }).click();
    await expect(col.getByRole('alertdialog')).toContainText('Trotzdem senden?');
    await col.getByRole('button', { name: 'Trotzdem senden' }).click();
    await expect(col.locator('[data-ai-phase="done"]')).toBeVisible({ timeout: 10_000 });

    await openMock(page, 'kirefuse');
    col = column(page);
    await col.getByRole('button', { name: 'Denkanstoss anfordern (KI)' }).click();
    const q = col.locator('[data-ai-refusal]');
    await expect(q).toContainText('<b>Kein HTML</b>', { timeout: 10_000 });
    await expect(q.locator('b')).toHaveCount(0);

    await openMock(page, 'kioff');
    col = column(page);
    await expect(col.getByRole('button', { name: /Denkanstoss anfordern/ })).toBeDisabled();
    await expect(col.locator('[data-ai-reason]')).toContainText('allow-cloud');
  });
});

test.describe('E119: Versionen pro Host', () => {
  test('ein Eintrag mit Liste pro Dienst, je eine Vorlage', async ({ page }) => {
    await openMock(page, 'versions');
    const col = column(page);
    await col.locator('button.line', { hasText: 'Versionen recherchieren' }).click();
    const card = col.locator('.card', { hasText: 'Versionen recherchieren' });
    for (const n of ['1 Frage zeigen', '2 Richtung zeigen', '3 Vorlage zeigen']) await card.getByRole('button', { name: n }).click();
    const list = card.locator('[data-items="8"]');
    await expect(list.locator('li')).toHaveCount(8);
    await expect(list).toContainText('Apache Tomcat 5.5');
    await expect(card.locator('.tpl')).toHaveCount(8);
  });
});

test.describe('Export', () => {
  test('Exportieren mit Fortschritt und Ergebnis; Phasen in der Zeitachse ansehen und korrigieren', async ({ page }) => {
    await openMock(page, 'normal', '/zeitachse');
    await page.getByRole('button', { name: 'Menü' }).click();
    await page.getByRole('menuitem', { name: 'Bericht exportieren …' }).click();
    const dlg = page.getByRole('dialog', { name: 'Bericht exportieren' });
    await expect(dlg.locator('[data-export-id]')).toHaveCount(1);
    await expect(dlg.locator('[data-export-phases]')).toContainText(/ohne Phase|zugeordnet/);
    await dlg.getByRole('button', { name: /^Exportieren/ }).click();
    await expect(dlg.locator('[data-export-result]')).toContainText('Export fertig', { timeout: 10_000 });
    await expect(dlg.locator('[data-export-result]')).toContainText(/exports\/\d{8}T\d{6}Z-cys/);
    await expect(dlg.locator('[data-export-id]')).toHaveCount(2);
    await dlg.getByRole('button', { name: 'in der Zeitachse prüfen ›' }).click();
    await expect(page).toHaveURL(/phasen=cys/);
    const sel = page.locator('[data-phase-of] select').first();
    await expect(sel).toBeVisible();
    await sel.selectOption('reporting');
    await expect(page.locator('[data-phase-of]').first()).toContainText('korrigiert');
    await page.getByRole('radio', { name: 'htb' }).click();
    await expect(page).toHaveURL(/phasen=htb/);
    await page.getByRole('button', { name: 'Phasen ausblenden' }).click();
    await expect(page.locator('[data-phase-of]')).toHaveCount(0);
  });
});

test.describe('Screenshots', () => {
  test('Dialog mit Countdown; danach Bild aus /blobs in der Belegansicht (CSP: blob:)', async ({ page }) => {
    await openMock(page, 'normal', '/zeitachse');
    await page.getByRole('button', { name: 'Menü' }).click();
    await page.getByRole('menuitem', { name: 'Screenshot der Kali …' }).click();
    const dlg = page.getByRole('dialog', { name: 'Screenshot der Kali' });
    await dlg.getByRole('radio', { name: '3 s' }).click();
    await dlg.getByRole('button', { name: /^Auslösen/ }).click();
    await expect(dlg.locator('[data-shot-counting] .n')).toHaveText(/[123]/);
    await expect(dlg.locator('[data-shot-done]')).toBeVisible({ timeout: 10_000 });
    await expect(dlg.locator('[data-shot-done] img')).toHaveAttribute('src', /^blob:/);
    await dlg.getByRole('button', { name: 'Ansehen' }).click();
    const panel = page.getByRole('dialog', { name: /Screenshot \d\d:\d\d:\d\d/ });
    await expect(panel.locator('img')).toHaveAttribute('src', /^blob:/);
    await expect(panel).toContainText('Dashboard');
    await page.keyboard.press('Escape');
    // Streifen in der Zeitachse und im Host-Detail
    await expect(page.locator('section[aria-label="Screenshots"] [data-shot]')).toHaveCount(3);
    await page.goto('/karte?mock=normal&host=ip%3Adefault%2F192.168.56.101');
    await expect(page.locator('section[aria-label="Screenshots"] img').first()).toHaveAttribute('src', /^blob:/);
  });

  test('Präsentationsmodus: Bilder verdeckt, kein Fenstertitel', async ({ page }) => {
    await openMock(page, 'present', '/zeitachse');
    await expect(page.locator('[data-shot-hidden]').first()).toContainText('Im Präsentationsmodus verdeckt');
    await expect(page.locator('section[aria-label="Screenshots"] img')).toHaveCount(0);
    await page.locator('section[aria-label="Screenshots"] button').first().click();
    const panel = page.getByRole('dialog', { name: /Screenshot/ });
    await expect(panel.locator('[data-shot-hidden]')).toBeVisible();
    await expect(panel).not.toContainText('xfce4-terminal');
  });
});
