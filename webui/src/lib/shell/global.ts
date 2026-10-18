/**
 * Globale Kürzel und Aktionen der Palette (BEHAVIOR «Tastatur», Briefing 4.3, 11). App.svelte
 * meldet beides beim Start an; als eigenes Modul, damit es sich ohne die Bereiche testen lässt.
 * Besitzer: ui-fundament.
 *
 * Kürzel (Basis-Ebene; in Dialogen sind sie aus, Einzeltasten nur ausserhalb von Eingabefeldern):
 *   Mod+K  Palette (auch im Eingabefeld)      ?   Hilfe
 *   1 bis 4  Reiter (nur mit Projekt)          ⇧P  Präsentationsmodus (nicht ohne Verbindung)
 * Esc schliesst Tafel, Detail, Popover und Dialoge in den jeweiligen Komponenten.
 *
 * Palette, Quelle «actions»: Reiter, Präsentationsmodus ein/aus, Darstellung, Einstellungen, Scope
 * ansehen, Hilfe, Abmelden.
 */
import { t } from '../i18n';
import { registerKeys } from '../keys/keymap';
import type { AppState } from '../stores/app.svelte';
import { ROUTES, url } from '../url/state.svelte';
import { registerPaletteSource, type PaletteItem } from './palette';

const THEMES = [
  ['system', 'settings.theme.system'],
  ['light', 'settings.theme.light'],
  ['dark', 'settings.theme.dark'],
] as const;

function ready(app: AppState): boolean {
  return app.phase !== 'boot' && app.phase !== 'login';
}

export function registerGlobalKeys(app: AppState): () => void {
  return registerKeys([
    { keys: ['Mod+K'], allowInInput: true, help: 'help.k.palette', when: () => ready(app), run: () => app.ui.openDialog({ kind: 'palette' }) },
    { keys: ['?'], help: 'help.k.help', when: () => ready(app), run: () => app.ui.openDialog({ kind: 'help' }) },
    {
      keys: ['Shift+P'],
      help: 'help.k.presentation',
      when: () => ready(app) && !app.offline,
      run: () => void app.togglePresentation(),
    },
    ...ROUTES.map((r, i) => ({
      keys: [String(i + 1)],
      help: 'help.k.tabs',
      when: () => app.phase === 'project',
      run: () => url.go(r),
    })),
  ]);
}

export function actionItems(app: AppState): PaletteItem[] {
  const project = app.phase === 'project';
  const items: PaletteItem[] = [];
  if (project) {
    ROUTES.forEach((r, i) =>
      items.push({
        id: `tab:${r}`,
        group: 'actions',
        label: t(`nav.${r}`),
        hint: String(i + 1),
        keywords: `${r} ${t(`nav.${r}`)} reiter`.toLowerCase(),
        run: () => url.go(r),
      }),
    );
  }
  if (!app.offline && ready(app)) {
    items.push({
      id: 'act:presentation',
      group: 'actions',
      label: app.presentation ? t('palette.act.presentationOff') : t('palette.act.presentationOn'),
      hint: '⇧P',
      keywords: 'präsentationsmodus praesentation presentation beamer unterricht',
      run: () => void app.togglePresentation(),
    });
  }
  for (const [v, key] of THEMES) {
    if (v === app.prefs.prefs.theme) continue;
    items.push({
      id: `act:theme:${v}`,
      group: 'actions',
      label: t('palette.act.theme', { theme: t(key) }),
      keywords: `darstellung theme ${t(key)} ${v}`.toLowerCase(),
      run: () => void app.prefs.set({ theme: v }),
    });
  }
  items.push({
    id: 'act:settings',
    group: 'actions',
    label: t('menu.settings'),
    keywords: 'einstellungen settings theme hell dunkel dichte lernmodus',
    run: () => url.set({ tafel: 'einstellungen' }, { push: true }),
  });
  if (project) {
    items.push({
      id: 'act:scope',
      group: 'actions',
      label: t('palette.act.scope'),
      keywords: 'scope ziele ausschlüsse',
      run: () => app.ui.openDialog({ kind: 'scope-view' }),
    });
  }
  items.push(
    { id: 'act:help', group: 'actions', label: t('menu.help'), hint: '?', keywords: 'hilfe help tasten kürzel', run: () => app.ui.openDialog({ kind: 'help' }) },
    { id: 'act:logout', group: 'actions', label: t('palette.act.logout'), keywords: 'abmelden logout sitzung', run: () => void app.logout() },
  );
  return items;
}

/** Kürzel und Palettenquelle anmelden; gibt die Abmeldung zurück. */
export function installGlobal(app: AppState): () => void {
  const offKeys = registerGlobalKeys(app);
  const offPalette = registerPaletteSource('actions', () => actionItems(app));
  return () => {
    offKeys();
    offPalette();
  };
}
