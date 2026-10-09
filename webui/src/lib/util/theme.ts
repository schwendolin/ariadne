/** Theme-Wahl: System, Hell oder Dunkel. Gespeichert pro Browser (prefs), gesetzt als data-theme. */
import { readPref, writePref } from './prefs';

export type ThemeChoice = 'system' | 'light' | 'dark';

const isChoice = (v: unknown): v is ThemeChoice => v === 'system' || v === 'light' || v === 'dark';

export function applyTheme(choice: ThemeChoice, persist = true): void {
  const root = document.documentElement;
  if (choice === 'system') delete root.dataset.theme;
  else root.dataset.theme = choice;
  if (persist) writePref('ariadne.theme', choice);
}

export function initTheme(): ThemeChoice {
  const choice = readPref<ThemeChoice>('ariadne.theme', 'system', isChoice);
  applyTheme(choice, false);
  return choice;
}
