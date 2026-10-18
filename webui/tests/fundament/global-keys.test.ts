// Globale Kürzel und Palettenaktionen (BEHAVIOR «Tastatur», Briefing 11): ⌘K/Strg+K, ?, 1 bis 4,
// ⇧P; Einzeltasten nicht in Eingabefeldern und nicht in Dialogen; Dialoge fangen den Fokus und geben
// ihn beim Schliessen zurück. Besitzer: ui-fundament.
import { fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { installKeymap, isMac, modLabel, resetKeymapForTests } from '../../src/lib/keys/keymap';
import CommandPalette from '../../src/lib/shell/CommandPalette.svelte';
import { actionItems, installGlobal } from '../../src/lib/shell/global';
import HelpDialog from '../../src/lib/shell/HelpDialog.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, press, settle, stopAll, until } from './helpers';

beforeAll(() => {
  installKeymap(window);
});

let uninstall: (() => void) | null = null;
afterEach(() => {
  uninstall?.();
  uninstall = null;
  resetKeymapForTests();
  stopAll();
  document.body.replaceChildren();
  url.go('karte', {}, { replace: true, keep: false });
});

async function withGlobal(scenario: Parameters<typeof makeApp>[0] = 'normal') {
  const h = await makeApp(scenario);
  uninstall = installGlobal(h.app);
  return h;
}

describe('globale Kürzel', () => {
  it('1 bis 4 wechseln die Reiter (nur mit Projekt), die URL folgt', async () => {
    await withGlobal('normal');
    press('3');
    expect(url.route).toBe('zeitachse');
    expect(location.pathname).toBe('/zeitachse');
    press('4');
    expect(url.route).toBe('findings');
    press('2');
    expect(url.route).toBe('terminals');
    press('1');
    expect(url.route).toBe('karte');
  });

  it('ohne Projekt wechseln 1 bis 4 nichts', async () => {
    await withGlobal('noproject');
    press('3');
    expect(url.route).toBe('karte');
  });

  it('⌘K und Strg+K öffnen die Palette, auch aus einem Eingabefeld; ? die Hilfe', async () => {
    const { app } = await withGlobal('normal');
    const input = document.createElement('input');
    document.body.append(input);
    press('k', { ctrlKey: true }, input);
    expect(app.ui.dialog?.kind).toBe('palette');
    app.ui.closeDialog();
    press('k', { metaKey: true });
    expect(app.ui.dialog?.kind).toBe('palette');
    app.ui.closeDialog();
    press('?', { shiftKey: true });
    expect(app.ui.dialog?.kind).toBe('help');
  });

  it('? und Ziffern wirken nicht im Eingabefeld', async () => {
    const { app } = await withGlobal('normal');
    const input = document.createElement('input');
    document.body.append(input);
    press('?', { shiftKey: true }, input);
    press('3', {}, input);
    expect(app.ui.dialog).toBeNull();
    expect(url.route).toBe('karte');
  });

  it('⇧P schaltet den Präsentationsmodus; angezeigt erst nach dem Ereignis, mit Meldung', async () => {
    const { app, backend } = await withGlobal('normal');
    const spy = vi.spyOn(backend, 'setPresentation');
    press('P', { shiftKey: true });
    expect(spy).toHaveBeenCalledWith(true);
    await until(() => app.presentation);
    expect(app.ui.notices.some((n) => n.text === 'Präsentationsmodus eingeschaltet')).toBe(true);
    press('P', { shiftKey: true });
    await until(() => !app.presentation);
    expect(spy).toHaveBeenLastCalledWith(false);
    expect(app.ui.notices.some((n) => n.text === 'Präsentationsmodus ausgeschaltet')).toBe(true);
  });

  it('⇧P wirkt nicht im Eingabefeld (Webkonsole, Formulare) und nicht ohne Verbindung', async () => {
    const { app, backend } = await withGlobal('normal');
    const spy = vi.spyOn(backend, 'setPresentation');
    const area = document.createElement('textarea');
    document.body.append(area);
    press('P', { shiftKey: true }, area);
    press('p');
    expect(spy).not.toHaveBeenCalled();
    app.offline = true;
    press('P', { shiftKey: true });
    expect(spy).not.toHaveBeenCalled();
  });

  it('in einem Dialog sind die Kürzel der Seite aus; Esc schliesst, Fokus zurück zum Auslöser', async () => {
    const { app } = await withGlobal('normal');
    const opener = document.createElement('button');
    opener.textContent = 'Auslöser';
    document.body.append(opener);
    opener.focus();
    const onclose = vi.fn();
    const r = render(HelpDialog, { props: { onclose } });
    await settle();
    const dialog = screen.getByRole('dialog', { name: 'Hilfe' });
    expect(dialog.contains(document.activeElement)).toBe(true);
    press('3', {}, document.activeElement ?? document.body);
    expect(url.route).toBe('karte');
    press('k', { metaKey: true }, document.activeElement ?? document.body);
    expect(app.ui.dialog).toBeNull();
    press('Escape', {}, document.activeElement ?? document.body);
    expect(onclose).toHaveBeenCalledOnce();
    r.unmount();
    expect(document.activeElement).toBe(opener);
    press('3');
    expect(url.route).toBe('zeitachse');
  });

  it('Anzeige des Modifikators: ⌘K auf dem Mac, sonst Strg K', () => {
    expect(modLabel('K', true)).toBe('⌘K');
    expect(modLabel('K', false)).toBe('Strg K');
    expect(isMac({ platform: 'MacIntel' } as Navigator)).toBe(true);
    expect(isMac({ platform: 'Linux x86_64' } as Navigator)).toBe(false);
  });
});

describe('Palette', () => {
  it('Aktionen: Reiter, Präsentation ein/aus, Darstellung, Einstellungen, Scope, Hilfe, Abmelden', async () => {
    const { app } = await makeApp('normal');
    const labels = actionItems(app).map((i) => i.label);
    expect(labels).toEqual([
      'Karte',
      'Terminals',
      'Zeitachse',
      'Findings',
      'Präsentationsmodus einschalten',
      'Darstellung: Hell',
      'Darstellung: Dunkel',
      'Einstellungen',
      'Scope ansehen',
      'Hilfe',
      'Abmelden',
    ]);
    const none = await makeApp('noproject');
    expect(actionItems(none.app).map((i) => i.id)).not.toContain('tab:karte');
  });

  it('sucht in den Quellen, Pfeile wählen, ↵ führt aus und schliesst', async () => {
    const { app } = await withGlobal('normal');
    const onclose = vi.fn();
    render(CommandPalette, { props: { app, onclose } });
    await settle();
    const input = screen.getByRole('combobox', { name: 'Befehlspalette' }) as HTMLInputElement;
    expect(document.activeElement).toBe(input);
    await fireEvent.input(input, { target: { value: 'zeitachse' } });
    await settle();
    const options = screen.getAllByRole('option');
    expect(options[0]?.textContent).toContain('Zeitachse');
    expect(options[0]?.getAttribute('aria-selected')).toBe('true');
    press('Enter', {}, input);
    expect(onclose).toHaveBeenCalledOnce();
    expect(url.route).toBe('zeitachse');
  });

  it('Rohlog nur auf Wunsch: «Im Rohlog suchen» ruft /search, ↵ auf einem Treffer öffnet den Beleg', async () => {
    const { app, backend } = await withGlobal('normal');
    const spy = vi.spyOn(backend, 'search');
    const onclose = vi.fn();
    render(CommandPalette, { props: { app, onclose } });
    await settle();
    const input = screen.getByRole('combobox', { name: 'Befehlspalette' }) as HTMLInputElement;
    await fireEvent.input(input, { target: { value: 'vsftpd' } });
    await settle();
    expect(spy).not.toHaveBeenCalled();
    const item = screen.getByText('Im Rohlog suchen: «vsftpd»');
    await fireEvent.click(item);
    await until(() => spy.mock.calls.length > 0 && !!document.querySelector('[id^="palette-opt-"] .label'));
    expect(spy).toHaveBeenCalledWith(app.project?.pid, 'vsftpd', 50, app.project?.signal);
    await until(() => screen.queryByText('Im Rohlog suchen: «vsftpd»') === null);
    const hits = screen.getAllByRole('option').filter((o) => /vsftpd/i.test(o.textContent ?? ''));
    expect(hits.length).toBeGreaterThan(0);
    await fireEvent.click(hits[hits.length - 1]?.querySelector('button') as HTMLElement);
    expect(onclose).toHaveBeenCalled();
    expect(url.get('beleg')).toMatch(/^u:/);
  });
});
