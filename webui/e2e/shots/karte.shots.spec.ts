/**
 * Screenshots der Karten-Screens bei 1440x900, dunkel und hell, zur Augenprüfung gegen die
 * Design-Shots (Ariadne_Runde_1__1a.png, Ariadne_Hell__1a.png, Runde 2 #12; Vertrag Abschnitt 8.4).
 * Kein Pixelvergleich. Ablage wie bei ui-fundament: webui/.e2e/shots/karte-<screen>-<dark|light>.png
 * (oder ARIADNE_SHOTS_DIR). Besitzer: ui-karte.
 */
import type { Page } from '@playwright/test';
import { resolve } from 'node:path';
import { expect, openMock, test } from '../fixtures';

const SHOTS_DIR = process.env.ARIADNE_SHOTS_DIR ?? resolve(import.meta.dirname, '../../.e2e/shots');

type Prep = (page: Page) => Promise<void>;

interface Shot {
  name: string;
  scenario: string;
  path: string;
  design: string;
  /** Lernmodus vorher ausschalten (Design zeigt die Vorlage ohne Stufen) */
  noLearning?: boolean;
  prep?: Prep;
}

const column = (page: Page) => page.locator('aside.column');

async function mapReady(page: Page): Promise<void> {
  await expect(page.locator('[data-map-card][data-host-id="ip:default/192.168.56.101"]')).toBeVisible();
  await expect(page.locator('.marker')).toHaveCount(2);
}

const SHOTS: Shot[] = [
  { name: 'karte-1a-hauptansicht', scenario: 'normal', path: '/karte', design: 'Ariadne_Runde_1__1a.png oben, Ariadne_Hell__1a.png', prep: mapReady },
  {
    name: 'karte-1a-ruhezustand',
    scenario: 'normal',
    path: '/karte',
    design: 'Ariadne_Runde_1__1a.png unten (Ruhezustand)',
    noLearning: true,
    prep: async (page) => {
      await mapReady(page);
      await page.keyboard.press('a');
      await expect(column(page).locator('.card')).toContainText('Zusammenführen?');
      await page.keyboard.press('a');
      await expect(column(page).locator('.card')).toContainText('R-ANON-ZUGRIFF');
    },
  },
  {
    name: 'karte-3-host-detail',
    scenario: 'normal',
    path: '/karte?host=ip%3Adefault%2F192.168.56.101',
    design: 'Ariadne_Runde_1 #3 Host-Detail .101',
    prep: async (page) => {
      await mapReady(page);
      await expect(column(page).locator('.detail')).toContainText('Services');
    },
  },
  {
    name: 'karte-3-host-nebel',
    scenario: 'normal',
    path: '/karte?host=ip%3Adefault%2F192.168.56.103',
    design: 'Ariadne_Runde_1 #3 Host-Detail .103 im Nebel',
    prep: async (page) => {
      await mapReady(page);
      await expect(column(page).locator('.detail')).toContainText('im Nebel');
    },
  },
  {
    name: 'karte-4-zusammenfuehren',
    scenario: 'normal',
    path: '/karte',
    design: 'Ariadne_Runde_1 #4 K3 Zusammenführen',
    prep: async (page) => {
      await mapReady(page);
      await page.keyboard.press('j');
      await expect(column(page).locator('.card')).toContainText('Gleiche MAC-Adresse');
    },
  },
  {
    name: 'karte-4-lernmodus',
    scenario: 'calm',
    path: '/karte',
    design: 'Ariadne_Runde_1 #4 D1 im Lernmodus',
    prep: async (page) => {
      const sug = column(page).locator('.card');
      await sug.getByRole('button', { name: /1 Frage zeigen/ }).click();
      await sug.getByRole('button', { name: /2 Richtung zeigen/ }).click();
    },
  },
  {
    name: 'karte-4-sonderzeichen',
    scenario: 'hostile',
    path: '/karte',
    design: 'Ariadne_Runde_1 #4 D2 mit Shell-Sonderzeichen',
    noLearning: true,
    prep: async (page) => {
      await mapReady(page);
      await page.keyboard.press('n');
      await expect(column(page).locator('.card')).toContainText('Keine fertige Vorlage');
    },
  },
  {
    name: 'karte-oos-popover',
    scenario: 'normal',
    path: '/karte',
    design: 'Ariadne_Runde_2 #10 Popover Out of Scope',
    prep: async (page) => {
      await mapReady(page);
      await page.getByRole('button', { name: 'Out of Scope · 4' }).click();
      await expect(page.getByRole('dialog', { name: 'Out of Scope' })).toBeVisible();
    },
  },
  {
    name: 'karte-ebenen-popover',
    scenario: 'normal',
    path: '/karte',
    design: 'Ariadne_Runde_1 #1a Ebenen und Legende',
    prep: async (page) => {
      await mapReady(page);
      await page.getByRole('button', { name: 'Ebenen und Legende' }).click();
      await expect(page.getByRole('dialog', { name: 'Ebenen und Legende' })).toBeVisible();
    },
  },
  {
    name: 'karte-12-tabelle',
    scenario: 'many',
    path: '/karte',
    design: 'Ariadne_Runde_2__12.png',
    prep: async (page) => {
      await expect(page.locator('.table-view button.row').first()).toBeVisible();
    },
  },
];

async function learningOff(page: Page): Promise<void> {
  const sw = page.getByRole('switch', { name: 'Lernmodus' });
  await sw.click();
  await expect(sw).toHaveAttribute('aria-checked', 'false');
  await page.keyboard.press('Escape');
}

for (const scheme of ['dark', 'light'] as const) {
  for (const s of SHOTS) {
    test(`${s.name} ${scheme}`, async ({ page }, info) => {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      if (s.noLearning) {
        const sep = s.path.includes('?') ? '&' : '?';
        await openMock(page, s.scenario, `${s.path}${sep}tafel=einstellungen`);
        await learningOff(page);
      } else {
        await openMock(page, s.scenario, s.path);
      }
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(400);
      if (s.prep) await s.prep(page);
      // Layout (fcose) und Einpassen abwarten
      await page.waitForTimeout(600);
      await page.screenshot({ path: resolve(SHOTS_DIR, `${s.name}-${scheme}.png`) });
      info.annotations.push({ type: 'design', description: s.design });
    });
  }
}
