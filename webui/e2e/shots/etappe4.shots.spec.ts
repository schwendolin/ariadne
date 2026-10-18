/**
 * Screenshots der neuen Zustände aus Etappe 4 bei 1440x900, dunkel und hell (Augenprüfung, kein
 * Pixelvergleich): KI (bereit, läuft, Ergebnis mit D3, Budgetwarnung, Bestätigung bei 100 %,
 * Ablehnung, Anbieter weg, Injection-Verdacht, aus mit Grund), E119, E120, Export mit Ergebnis,
 * Phasen in der Zeitachse, Screenshot-Dialog mit Countdown, Belegansicht des Bildes, Streifen in
 * Zeitachse und Host-Detail, Präsentationsmodus. Ablage: ARIADNE_SHOTS_DIR oder
 * webui/.e2e/shots/v4-<name>-<dark|light>.png. Besitzer: ui.
 */
import type { Page } from '@playwright/test';
import { resolve } from 'node:path';
import { expect, openMock, test } from '../fixtures';

const SHOTS_DIR = process.env.ARIADNE_SHOTS_DIR ?? resolve(import.meta.dirname, '../../.e2e/shots');
const SHOT_B = '0199a3c2-5c07-7000-8000-000000000b02';
const HOST101 = encodeURIComponent('ip:default/192.168.56.101');

const col = (page: Page) => page.locator('section[data-keyzone="next"]');
const askAi = async (page: Page) => col(page).getByRole('button', { name: 'Denkanstoss anfordern (KI)' }).click();

interface Shot {
  name: string;
  scenario: string;
  path: string;
  prep?: (page: Page) => Promise<void>;
}

const SHOTS: Shot[] = [
  { name: 'ki-bereit', scenario: 'ki', path: '/karte', prep: async (p) => await expect(col(p).getByRole('button', { name: 'Denkanstoss anfordern (KI)' })).toBeEnabled() },
  {
    name: 'ki-laeuft',
    scenario: 'kirun',
    path: '/karte',
    prep: async (p) => {
      await askAi(p);
      await expect(col(p).locator('[data-ai-phase="running"]')).toContainText('Lagebild wird gesendet');
    },
  },
  {
    name: 'ki-ergebnis-d3',
    scenario: 'ki',
    path: '/karte',
    prep: async (p) => {
      await askAi(p);
      await expect(col(p).locator('[data-ai-phase="done"]')).toBeVisible({ timeout: 10_000 });
      await col(p).locator('button.line', { hasText: 'Hypothese: Samba' }).click();
      await expect(col(p).locator('.card', { hasText: 'bestätigt, wenn' })).toBeVisible();
    },
  },
  { name: 'ki-budgetwarnung', scenario: 'kiwarn', path: '/karte', prep: async (p) => await expect(col(p).locator('[data-ai-budget="warn"]')).toBeVisible() },
  {
    name: 'ki-budget-bestaetigen',
    scenario: 'kiover',
    path: '/karte',
    prep: async (p) => {
      await askAi(p);
      await expect(col(p).getByRole('alertdialog')).toBeVisible();
    },
  },
  {
    name: 'ki-ablehnung',
    scenario: 'kirefuse',
    path: '/karte',
    prep: async (p) => {
      await askAi(p);
      await expect(col(p).locator('[data-ai-refusal]')).toBeVisible({ timeout: 10_000 });
    },
  },
  {
    name: 'ki-anbieter-weg',
    scenario: 'kigone',
    path: '/karte',
    prep: async (p) => {
      await askAi(p);
      await expect(col(p).locator('[data-ai-phase="failed"]')).toBeVisible({ timeout: 10_000 });
    },
  },
  {
    name: 'ki-injection',
    scenario: 'kiinject',
    path: '/karte',
    prep: async (p) => {
      await askAi(p);
      await expect(col(p).locator('[data-ai-injection]')).toBeVisible({ timeout: 10_000 });
      await col(p).locator('button.line', { hasText: 'Ignore all previous' }).click();
    },
  },
  { name: 'ki-aus-grund', scenario: 'kioff', path: '/karte', prep: async (p) => await expect(col(p).locator('[data-ai-reason]')).toBeVisible() },
  {
    name: 'e119-versionen',
    scenario: 'versions',
    path: '/karte',
    prep: async (p) => {
      await col(p).locator('button.line', { hasText: 'Versionen recherchieren' }).click();
      const card = col(p).locator('.card', { hasText: 'Versionen recherchieren' });
      for (const n of ['1 Frage zeigen', '2 Richtung zeigen', '3 Vorlage zeigen']) await card.getByRole('button', { name: n }).click();
      await expect(card.locator('[data-items="8"]')).toBeVisible();
    },
  },
  { name: 'e120-scope-eintrag', scenario: 'scope', path: '/karte', prep: async (p) => await expect(p.locator('[data-scope-entry]')).toBeVisible() },
  {
    name: 'export-ergebnis',
    scenario: 'normal',
    path: '/zeitachse',
    prep: async (p) => {
      await p.getByRole('button', { name: 'Menü' }).click();
      await p.getByRole('menuitem', { name: 'Bericht exportieren …' }).click();
      const dlg = p.getByRole('dialog', { name: 'Bericht exportieren' });
      await dlg.getByRole('button', { name: /^Exportieren/ }).click();
      await expect(dlg.locator('[data-export-result]')).toBeVisible({ timeout: 10_000 });
    },
  },
  { name: 'export-phasen-zeitachse', scenario: 'normal', path: '/zeitachse?phasen=cys', prep: async (p) => await expect(p.locator('[data-phase-of]').first()).toBeVisible() },
  {
    name: 'screenshot-countdown',
    scenario: 'normal',
    path: '/zeitachse',
    prep: async (p) => {
      await p.getByRole('button', { name: 'Menü' }).click();
      await p.getByRole('menuitem', { name: 'Screenshot der Kali …' }).click();
      const dlg = p.getByRole('dialog', { name: 'Screenshot der Kali' });
      await dlg.getByRole('radio', { name: '10 s' }).click();
      await dlg.getByRole('button', { name: /^Auslösen/ }).click();
      await expect(dlg.locator('[data-shot-counting]')).toBeVisible();
    },
  },
  {
    name: 'screenshot-dialog',
    scenario: 'normal',
    path: '/zeitachse',
    prep: async (p) => {
      await p.getByRole('button', { name: 'Menü' }).click();
      await p.getByRole('menuitem', { name: 'Screenshot der Kali …' }).click();
      await p.getByRole('dialog', { name: 'Screenshot der Kali' }).getByRole('radio', { name: 'Bereich' }).click();
    },
  },
  { name: 'screenshot-beleg', scenario: 'normal', path: `/zeitachse?beleg=s:${SHOT_B}`, prep: async (p) => await expect(p.getByRole('dialog', { name: /Screenshot/ }).locator('img')).toBeVisible() },
  { name: 'screenshots-zeitachse', scenario: 'normal', path: '/zeitachse', prep: async (p) => await expect(p.locator('section[aria-label="Screenshots"] img').first()).toBeVisible() },
  { name: 'screenshots-host', scenario: 'normal', path: `/karte?host=${HOST101}`, prep: async (p) => await expect(p.locator('section[aria-label="Screenshots"] img').first()).toBeVisible() },
  { name: 'screenshots-praesentation', scenario: 'present', path: '/zeitachse', prep: async (p) => await expect(p.locator('[data-shot-hidden]').first()).toBeVisible() },
];

for (const scheme of ['dark', 'light'] as const) {
  for (const s of SHOTS) {
    test(`v4 ${s.name} ${scheme}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      await openMock(page, s.scenario, s.path);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(300);
      if (s.prep) await s.prep(page);
      await page.waitForTimeout(300);
      await page.screenshot({ path: resolve(SHOTS_DIR, `v4-${s.name}-${scheme}.png`) });
    });
  }
}
