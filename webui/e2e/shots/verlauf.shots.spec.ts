/**
 * Screenshots der Verlaufs-Screens bei 1440x900, dunkel und hell, zur Augenprüfung gegen die
 * Design-Shots (Ariadne_Runde_2__6.png Zeitachse, __7.png Belegansicht, __8.png Findings, __10.png
 * Kontext-Dialog, Export und Screenshot; Terminals nach SCREENS 5; Vertrag Abschnitt 8.4). Kein
 * Pixelvergleich. Ablage wie bei ui-fundament: webui/.e2e/shots/verlauf-<screen>-<dark|light>.png
 * (oder ARIADNE_SHOTS_DIR). Besitzer: ui-verlauf.
 */
import type { Page } from '@playwright/test';
import { resolve } from 'node:path';
import { expect, openMock, test } from '../fixtures';

const SHOTS_DIR = process.env.ARIADNE_SHOTS_DIR ?? resolve(import.meta.dirname, '../../.e2e/shots');

const T1 = '0199a3c2-7e11-7000-8000-00000000c011';
const T2 = '0199a3c2-7e12-7000-8000-00000000c022';
const NMAP = `${T1}@18432`;
const F1 = '0199a3c2-9b10-7000-8000-00000000f001';

interface Shot {
  name: string;
  scenario: string;
  path: string;
  design: string;
  prep?: (page: Page) => Promise<void>;
}

const SHOTS: Shot[] = [
  {
    name: 'verlauf-6-zeitachse',
    scenario: 'normal',
    path: `/zeitachse?zeile=${encodeURIComponent(NMAP)}`,
    design: 'Ariadne_Runde_2__6.png (Zeitachse mit Warteliste)',
    prep: async (page) => {
      await expect(page.locator(`li.item[data-row="${NMAP}"]`)).toHaveAttribute('aria-current', 'true');
    },
  },
  {
    name: 'verlauf-6-rueckgaengig',
    scenario: 'normal',
    path: `/zeitachse?zeile=${encodeURIComponent(NMAP)}`,
    design: 'Ariadne_Runde_2__6.png (Rückgängig pro Befehl inline)',
    prep: async (page) => {
      await expect(page.locator(`li.item[data-row="${NMAP}"]`)).toHaveAttribute('aria-current', 'true');
      await page.keyboard.press('u');
      await expect(page.getByRole('form', { name: 'Werte aus diesem Befehl verwerfen?' })).toBeVisible();
    },
  },
  {
    name: 'verlauf-6-warteliste',
    scenario: 'normal',
    path: '/zeitachse',
    design: 'Ariadne_Runde_2__6.png (Warteliste aufgeklappt)',
    prep: async (page) => {
      await page.getByRole('button', { name: /Warteliste/ }).click();
      await expect(page.locator('#pending-list')).toBeVisible();
    },
  },
  {
    name: 'verlauf-7-beleg',
    scenario: 'normal',
    path: `/zeitachse?beleg=${encodeURIComponent(`u:${T2}@1024:43-46`)}`,
    design: 'Ariadne_Runde_2__7.png (Belegansicht mit Markierung)',
    prep: async (page) => {
      await expect(page.locator('.line.marked')).toHaveCount(4);
    },
  },
  {
    name: 'verlauf-7-beleg-kette',
    scenario: 'chain',
    path: `/zeitachse?beleg=${encodeURIComponent(`u:${NMAP}`)}`,
    design: 'Ariadne_Runde_2__7.png (Hash-Kette verletzt)',
    prep: async (page) => {
      await expect(page.getByText('Hash-Kette verletzt').first()).toBeVisible();
    },
  },
  {
    name: 'verlauf-8-findings',
    scenario: 'normal',
    path: `/findings?finding=${F1}`,
    design: 'Ariadne_Runde_2__8.png (Findings mit Formular)',
    prep: async (page) => {
      await expect(page.getByLabel('Titel')).toHaveValue(/vsftpd/);
    },
  },
  {
    name: 'verlauf-5-terminals',
    scenario: 'held',
    path: '/terminals',
    design: 'SCREENS 5 (Terminals, mit held-Zeile)',
    prep: async (page) => {
      await expect(page.locator('li[data-terminal]')).toHaveCount(4);
    },
  },
  {
    name: 'verlauf-10-kontext',
    scenario: 'normal',
    path: '/terminals',
    design: 'Ariadne_Runde_2__10.png (Kontext-Dialog für T3 «listener»)',
    prep: async (page) => {
      await page.keyboard.press('j');
      await page.keyboard.press('j');
      await page.keyboard.press('Enter');
      await expect(page.getByRole('dialog', { name: /Kontext für T3/ })).toBeVisible();
    },
  },
  {
    name: 'verlauf-10-export',
    scenario: 'normal',
    path: '/zeitachse',
    design: 'Ariadne_Runde_2__10.png (Export, gesperrt mit Hinweis)',
    prep: async (page) => {
      await page.getByRole('button', { name: 'Menü' }).click();
      await page.getByRole('menuitem', { name: 'Bericht exportieren …' }).click();
      await expect(page.getByRole('dialog', { name: 'Bericht exportieren' })).toBeVisible();
    },
  },
  {
    name: 'verlauf-10-screenshot',
    scenario: 'normal',
    path: '/zeitachse',
    design: 'Ariadne_Runde_2__10.png (Screenshot, gesperrt mit Hinweis)',
    prep: async (page) => {
      await page.getByRole('button', { name: 'Menü' }).click();
      await page.getByRole('menuitem', { name: 'Screenshot der Kali …' }).click();
      await expect(page.getByRole('dialog', { name: 'Screenshot der Kali' })).toBeVisible();
    },
  },
];

for (const scheme of ['dark', 'light'] as const) {
  for (const s of SHOTS) {
    test(`${s.name} ${scheme}`, async ({ page }, info) => {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      await openMock(page, s.scenario, s.path);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(300);
      if (s.prep) await s.prep(page);
      await page.waitForTimeout(300);
      await page.screenshot({ path: resolve(SHOTS_DIR, `${s.name}-${scheme}.png`) });
      info.annotations.push({ type: 'design', description: s.design });
    });
  }
}
