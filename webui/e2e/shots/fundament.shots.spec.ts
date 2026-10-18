/**
 * Screenshots der Fundament-Screens bei 1440x900, dunkel und hell, zur Augenprüfung gegen die
 * Design-Shots (/tmp/…/scratchpad/design-shots, Vertrag Abschnitt 8.4). Kein Pixelvergleich.
 * Ablage: webui/.e2e/shots/<screen>-<dark|light>.png (oder ARIADNE_SHOTS_DIR).
 *
 * Kopfzeilen werden als Streifen (1440x52, kompakt 1200x52) abgelegt, Popover und Dialoge mit der
 * Seite dahinter. Besitzer: ui-fundament; ui-karte und ui-verlauf haben eigene Dateien.
 */
import type { Page } from '@playwright/test';
import { resolve } from 'node:path';
import { expect, openMock, test } from '../fixtures';

/** Ablage ausserhalb von test-results (das Playwright bei jedem Lauf leert), gitignored. */
export const SHOTS_DIR = process.env.ARIADNE_SHOTS_DIR ?? resolve(import.meta.dirname, '../../.e2e/shots');

type Prep = (page: Page) => Promise<void>;

interface Shot {
  name: string;
  scenario: string;
  path: string;
  design: string;
  prep?: Prep;
  /** nur die Kopfzeile ablegen */
  header?: boolean;
  width?: number;
}

const header = (page: Page) => page.locator('header.header');

const SHOTS: Shot[] = [
  { name: 'grundlayout-1a', scenario: 'normal', path: '/karte', design: 'Ariadne_Runde_1__1a.png' },
  { name: 'kopfzeile-normal', scenario: 'allon', path: '/karte', design: 'AriadneKopfzeile normal', header: true },
  {
    name: 'kopfzeile-waiting',
    scenario: 'noconfirm',
    path: '/karte',
    design: 'AriadneKopfzeile waiting',
    header: true,
    prep: async (page) => {
      await header(page).locator('button.rec').click();
      await page.getByRole('button', { name: /Pause für T2/ }).click();
      await page.keyboard.press('Escape');
      await expect(header(page)).toHaveAttribute('data-variant', 'waiting');
    },
  },
  { name: 'kopfzeile-pause', scenario: 'normal', path: '/karte', design: 'AriadneKopfzeile pause', header: true },
  { name: 'kopfzeile-pause-kompakt', scenario: 'normal', path: '/karte', design: 'AriadneKopfzeile pause < 1280', header: true, width: 1200 },
  { name: 'kopfzeile-held', scenario: 'held', path: '/karte', design: 'AriadneKopfzeile held', header: true },
  { name: 'kopfzeile-locked', scenario: 'locked', path: '/karte', design: 'AriadneKopfzeile locked', header: true },
  { name: 'kopfzeile-noproject', scenario: 'noproject', path: '/karte', design: 'AriadneKopfzeile noproject', header: true },
  {
    name: 'kopfzeile-offline',
    scenario: 'offline',
    path: '/karte',
    design: 'AriadneKopfzeile offline',
    header: true,
    prep: async (page) => {
      await expect(header(page)).toHaveAttribute('data-variant', 'offline', { timeout: 9000 });
    },
  },
  { name: 'kopfzeile-praesentation-lokal', scenario: 'local', path: '/karte', design: 'AriadneKopfzeile pause, lokal, present', header: true, prep: presentationOn },
  { name: 'kopfzeile-scope', scenario: 'scope', path: '/karte', design: 'Briefing 4.5, Kennzeichen', header: true, prep: closeScopeCard },
  {
    name: '5-aufnahme-popover',
    scenario: 'normal',
    path: '/karte',
    design: 'Ariadne_Runde_1 Abschnitt 5, Popover',
    prep: async (page) => {
      await header(page).locator('button.rec').click();
      await expect(page.getByRole('dialog', { name: 'Aufnahme' })).toBeVisible();
    },
  },
  { name: '9-anmeldung', scenario: 'login', path: '/', design: 'Ariadne_Runde_2__9.png' },
  { name: '9-anmeldung-unbekannt', scenario: 'login', path: '/', design: 'Ariadne_Runde_2__9.png, Fehler', prep: (page) => tryCode(page, 'FALSCH00') },
  { name: '9-anmeldung-gesperrt', scenario: 'login', path: '/', design: 'Ariadne_Runde_2__9.png, Fehler', prep: (page) => tryCode(page, 'SPERRE00') },
  { name: '9-anmeldung-ungueltig', scenario: 'login', path: '/', design: 'Ariadne_Runde_2__9.png, Fehler', prep: (page) => tryCode(page, 'k7q2 m4') },
  { name: '9-kein-projekt', scenario: 'noproject', path: '/karte', design: 'Ariadne_Runde_2__9.png' },
  { name: '9-gesperrt', scenario: 'locked', path: '/karte', design: 'Ariadne_Runde_2__9.png' },
  {
    name: '9-keine-verbindung',
    scenario: 'offline',
    path: '/karte',
    design: 'Ariadne_Runde_2__9.png',
    prep: async (page) => {
      await expect(header(page)).toHaveAttribute('data-variant', 'offline', { timeout: 9000 });
    },
  },
  { name: '9-leeres-projekt', scenario: 'empty', path: '/karte', design: 'Ariadne_Runde_2__9.png' },
  {
    name: '10-palette',
    scenario: 'normal',
    path: '/karte',
    design: 'Ariadne_Runde_2__10.png',
    prep: async (page) => {
      await page.keyboard.press('Control+k');
      await page.getByRole('combobox', { name: 'Befehlspalette' }).fill('präsentation');
    },
  },
  {
    name: '10-scope-warnung',
    scenario: 'scope',
    path: '/karte',
    design: 'Ariadne_Runde_2__10.png',
    prep: async (page) => {
      await expect(page.locator('[data-scope-entry]')).toBeVisible();
    },
  },
  {
    name: '10-hilfe',
    scenario: 'normal',
    path: '/karte',
    design: 'Ariadne_Runde_2__10.png',
    prep: async (page) => {
      await page.keyboard.press('?');
      await expect(page.getByRole('dialog', { name: 'Hilfe' })).toBeVisible();
    },
  },
  {
    name: '11-menue',
    scenario: 'normal',
    path: '/karte',
    design: 'Ariadne_Runde_2__11.png',
    prep: async (page) => {
      await page.getByRole('button', { name: 'Menü' }).click();
      await expect(page.getByRole('menu')).toBeVisible();
    },
  },
  { name: '11-einstellungen', scenario: 'normal', path: '/karte?tafel=einstellungen', design: 'Ariadne_Runde_2__11.png' },
];

async function presentationOn(page: Page): Promise<void> {
  await expect(header(page)).toBeVisible();
  await page.keyboard.press('Shift+P');
  await expect(header(page).getByText('Präsentation', { exact: true })).toBeVisible();
  // Meldung «Präsentationsmodus eingeschaltet» abwarten und schliessen, damit der Streifen ruhig ist
  await page.waitForTimeout(2700);
}

async function closeScopeCard(page: Page): Promise<void> {
  // E120: keine Karte mehr; die Warnung steht als erster Eintrag in der Spalte
  await expect(page.locator('[data-scope-entry]')).toBeVisible();
}

async function tryCode(page: Page, code: string): Promise<void> {
  await page.getByLabel('Anmeldecode').fill(code);
  await page.getByRole('button', { name: 'Anmelden' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
}

for (const scheme of ['dark', 'light'] as const) {
  for (const s of SHOTS) {
    test(`${s.name} ${scheme}`, async ({ page }, info) => {
      if (s.width) await page.setViewportSize({ width: s.width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      await openMock(page, s.scenario, s.path);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(400);
      if (s.prep) await s.prep(page);
      await page.waitForTimeout(200);
      const file = resolve(SHOTS_DIR, `${s.name}-${scheme}.png`);
      if (s.header) {
        await page.screenshot({ path: file, clip: { x: 0, y: 0, width: s.width ?? 1440, height: 52 } });
      } else {
        await page.screenshot({ path: file });
      }
      info.annotations.push({ type: 'design', description: s.design });
    });
  }
}
