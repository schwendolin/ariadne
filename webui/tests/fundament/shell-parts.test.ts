// Favicon und Tab-Titel, Vorlieben (Theme, Dichte, Lernmodus) auf dem Server, Einstellungen, Menü,
// Scope-Warnung als Meldung, «Neu seit» über visibilitychange (BEHAVIOR, E106, E112, Briefing 4.5).
// Besitzer: ui-fundament.
import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../src/lib/api/client';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { HOSTILE_IMG } from '../../src/lib/mock/data/hostile';
import MainMenu from '../../src/lib/shell/MainMenu.svelte';
import ScopeEntry from '../../src/lib/next/ScopeEntry.svelte';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import SettingsPanel from '../../src/lib/shell/SettingsPanel.svelte';
import { applyPrefs } from '../../src/lib/stores/prefs.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { applyTabState, FAVICON, FAVICON_ATTENTION, tabTitle } from '../../src/lib/util/favicon';
import { makeApp, settle, stopAll, until } from './helpers';

beforeAll(() => {
  installKeymap(window);
});
afterEach(() => {
  stopAll();
  resetKeymapForTests();
  document.head.querySelectorAll('link[rel="icon"]').forEach((l) => l.remove());
  url.go('karte', {}, { replace: true, keep: false });
});

describe('Favicon und Tab-Titel', () => {
  it('«ms2 · 2 zu klären» mit Punkt, sonst Slug bzw. «Ariadne»', () => {
    const link = document.createElement('link');
    link.rel = 'icon';
    link.href = FAVICON;
    document.head.append(link);
    applyTabState(document, 'ms2', 2);
    expect(document.title).toBe('ms2 · 2 zu klären');
    expect(link.getAttribute('href')).toBe(FAVICON_ATTENTION);
    applyTabState(document, 'ms2', 0);
    expect(document.title).toBe('ms2');
    expect(link.getAttribute('href')).toBe(FAVICON);
    applyTabState(document, null, 3);
    expect(document.title).toBe('Ariadne');
    expect(tabTitle('ms2', 1)).toBe('ms2 · 1 zu klären');
    expect(document.head.querySelectorAll('link[rel="icon"]')).toHaveLength(1);
  });

  it('die Zahl kommt aus «Als Nächstes» (NextStore.open), nie ein Secret im Titel', async () => {
    const { app } = await makeApp('normal');
    await until(() => (app.project?.next.open ?? 0) > 0);
    expect(tabTitle(app.project?.slug ?? null, app.project?.next.open ?? 0)).toBe('ms2 · 2 zu klären');
    const calm = await makeApp('calm');
    await until(() => calm.app.project?.next.view != null);
    expect(tabTitle(calm.app.project?.slug ?? null, calm.app.project?.next.open ?? 0)).toBe('ms2');
  });
});

describe('Vorlieben (E112)', () => {
  it('applyPrefs setzt data-theme und data-density; System entfernt das Attribut', () => {
    const root = document.documentElement;
    applyPrefs({ theme: 'dark', density: 'compact', learning: true }, root);
    expect(root.dataset.theme).toBe('dark');
    expect(root.dataset.density).toBe('compact');
    applyPrefs({ theme: 'light', density: 'comfortable', learning: false }, root);
    expect(root.dataset.theme).toBe('light');
    expect(root.dataset.density).toBeUndefined();
    applyPrefs({ theme: 'system', density: 'comfortable', learning: true }, root);
    expect(root.dataset.theme).toBeUndefined();
  });

  it('Einstellungen: Theme, Dichte und Lernmodus gehen an den Server, sofort sichtbar', async () => {
    const { app, backend } = await makeApp('normal');
    const save = vi.spyOn(backend, 'savePrefs');
    render(SettingsPanel, { props: { app } });
    await fireEvent.click(screen.getByRole('radio', { name: 'Dunkel' }));
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(save).toHaveBeenLastCalledWith({ theme: 'dark' });
    await fireEvent.click(screen.getByRole('radio', { name: 'Kompakt' }));
    expect(document.documentElement.dataset.density).toBe('compact');
    await fireEvent.click(screen.getByRole('switch', { name: 'Lernmodus' }));
    expect(save).toHaveBeenLastCalledWith({ learning: false });
    await settle();
    expect(screen.getByText('aus, Vorlagen direkt')).toBeTruthy();
    expect(backend.state.prefs.prefs).toEqual({ theme: 'dark', density: 'compact', learning: false });
  });

  it('Speichern scheitert: Anzeige zurück, Meldung ohne Servertext', async () => {
    const { app, backend } = await makeApp('normal');
    vi.spyOn(backend, 'savePrefs').mockRejectedValueOnce(new ApiError('validation', 422, 'Servertext mit <b>'));
    await app.prefs.set({ theme: 'light' });
    expect(app.prefs.prefs.theme).toBe('system');
    expect(document.documentElement.dataset.theme).toBeUndefined();
    expect(app.ui.notices.at(-1)?.text).toBe('Einstellung nicht gespeichert: Eingabe ungültig');
  });

  it('schnelle Wechsel: eine ältere Antwort überschreibt nie die jüngere Wahl', async () => {
    const { app, backend } = await makeApp('normal');
    const real = backend.savePrefs.bind(backend);
    let releaseFirst: () => void = () => undefined;
    const gate = new Promise<void>((r) => (releaseFirst = r));
    vi.spyOn(backend, 'savePrefs')
      .mockImplementationOnce(async (p) => {
        const v = await real(p);
        await gate; // erste Antwort kommt erst nach der zweiten
        return { prefs: { ...v.prefs, theme: 'dark' }, updated_at: null };
      })
      .mockImplementationOnce((p) => real(p));
    const first = app.prefs.set({ theme: 'dark' });
    const second = app.prefs.set({ theme: 'light' });
    await second;
    releaseFirst();
    await first;
    // ein verspätetes prefs-Ereignis mit dem alten Stand ebenfalls nicht
    expect(app.prefs.prefs.theme).toBe('light');
    expect(document.documentElement.dataset.theme).toBe('light');
  });

  it('Ereignis prefs (anderer Tab) lädt die Vorlieben nach', async () => {
    const { app, backend } = await makeApp('normal');
    backend.state.prefs = { prefs: { theme: 'light', density: 'comfortable', learning: true }, updated_at: null };
    backend.inject({ name: 'prefs', id: null, data: {} });
    await until(() => app.prefs.prefs.theme === 'light');
    expect(document.documentElement.dataset.theme).toBe('light');
  });

  it('eigene Secrets nur verdeckt mit Zahl, nie Werte', async () => {
    const { app } = await makeApp('normal');
    render(SettingsPanel, { props: { app } });
    const own = screen.getByTestId('own-secrets');
    expect(own.textContent?.replace(/\s+/g, ' ')).toBe('•••••••• · 2 Einträge, verwalten im Terminal mit ariadne secrets');
    expect(own.querySelector('button')).toBeNull();
  });
});

describe('Menü', () => {
  it('Einträge wie Screen 11, Pfeiltasten wechseln, Abmelden nennt die Herkunft', async () => {
    const { app } = await makeApp('normal');
    render(MainMenu, { props: { app } });
    await fireEvent.click(screen.getByRole('button', { name: 'Menü' }));
    const menu = screen.getByRole('menu');
    const items = Array.from(menu.querySelectorAll<HTMLButtonElement>('[role^="menuitem"]'));
    expect(items.map((i) => i.textContent?.replace(/\s+/g, ' ').trim())).toEqual([
      'Präsentationsmodus⇧P',
      'Screenshot der Kali …',
      'Bericht exportieren …',
      'Scope ansehen',
      'Einstellungen',
      'Hilfe?',
      'Abmelden Sitzung über sshd, vom Mac',
    ]);
    items[0]?.focus();
    await fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(items[1]);
    await fireEvent.keyDown(menu, { key: 'End' });
    expect(document.activeElement).toBe(items[6]);
    await fireEvent.click(items[4] as HTMLElement);
    expect(url.get('tafel')).toBe('einstellungen');
    expect(app.ui.popover).toBeNull();
  });

  it('ohne Projekt sind Screenshot, Export und Scope gesperrt', async () => {
    const { app } = await makeApp('noproject');
    render(MainMenu, { props: { app } });
    await fireEvent.click(screen.getByRole('button', { name: 'Menü' }));
    const disabled = Array.from(screen.getByRole('menu').querySelectorAll<HTMLButtonElement>('[role^="menuitem"]'))
      .filter((b) => b.disabled)
      .map((b) => b.textContent?.trim());
    expect(disabled).toEqual(['Screenshot der Kali …', 'Bericht exportieren …', 'Scope ansehen']);
  });
});

describe('Scope-Warnung (Briefing 4.5)', () => {
  it('E120: erster Eintrag der Spalte aus /next; Inhalt als Text; Quittieren auf dem Server, danach weg', async () => {
    const { app, backend } = await makeApp('scope');
    const project = app.project as ProjectStore;
    await until(() => project.next.view !== null);
    const w = project.next.view?.scope_warning;
    expect(w).toBeTruthy();
    if (!w) return;
    render(ScopeEntry, { props: { app, project, warning: w } });
    const entry = screen.getByRole('group', { name: /Ziel ausserhalb des Scopes/ });
    expect(entry.textContent?.replace(/\s+/g, ' ')).toMatch(/T1: nmap -6 -sV -oX scans\/v6\.xml fd00:56::101/);
    expect(entry.textContent).toMatch(/fd00:56::101\s*liegt nicht in 192\.168\.56\.0\/24 · gestartet \d\d:\d\d:\d\d/);
    const ack = vi.spyOn(backend, 'ackScopeWarning');
    await fireEvent.click(within(entry).getByRole('button', { name: 'Quittieren' }));
    await settle();
    expect(ack).toHaveBeenCalledWith(project.pid, w.cmd_id);
    await until(() => project.next.view?.scope_warning === null);
    expect(app.status?.scope_warning?.acked).toBe(true);
  });

  it('Kennzeichen der Kopfzeile: Fokus auf den Eintrag (scopeFocus)', async () => {
    const { app } = await makeApp('scope');
    const project = app.project as ProjectStore;
    await until(() => project.next.view !== null);
    const w = project.next.view?.scope_warning;
    if (!w) throw new Error('keine Warnung');
    render(ScopeEntry, { props: { app, project, warning: w } });
    app.ui.openDialog({ kind: 'scope-warning' });
    await settle();
    expect(app.ui.dialog).toBeNull();
    expect(document.activeElement?.hasAttribute('data-scope-entry')).toBe(true);
  });

  it('schliessen ohne Quittieren: Kennzeichen bleibt, dieselbe Warnung kommt nicht wieder', async () => {
    const { app } = await makeApp('scope');
    app.ui.scopeCard = false;
    await app.refreshStatus();
    expect(app.ui.scopeCard).toBe(false);
    expect(app.status?.scope_warning?.acked).toBe(false);
  });

  it('feindlicher Befehlstext nur als Text; «In der Zeitachse» führt zur Zeile', async () => {
    const { app } = await makeApp('scope');
    const project = app.project as ProjectStore;
    await until(() => project.next.view !== null);
    const base = project.next.view?.scope_warning;
    if (!base) throw new Error('keine Warnung');
    const warning = { ...base, text: `nmap ${HOSTILE_IMG}` };
    render(ScopeEntry, { props: { app, project, warning } });
    expect(document.querySelector('[data-scope-entry] img')).toBeNull();
    expect(document.querySelector('[data-scope-entry]')?.textContent).toContain(HOSTILE_IMG);
    await fireEvent.click(screen.getByRole('button', { name: 'In der Zeitachse' }));
    expect(url.route).toBe('zeitachse');
    expect(url.get('zeile')).toBe(base.cmd_id);
  });
});

describe('Neu seit (E106)', () => {
  function setVisibility(state: 'hidden' | 'visible'): void {
    Object.defineProperty(document, 'visibilityState', { value: state, configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
  }

  it('unsichtbar meldet PUT /ui/seen, sichtbar lädt GET /ui/seen; Entladen meldet nichts', async () => {
    const { app, backend } = await makeApp('normal');
    const mark = vi.spyOn(backend, 'markSeen');
    const seen = vi.spyOn(backend, 'seen');
    setVisibility('hidden');
    expect(mark).toHaveBeenCalledWith(app.project?.pid);
    setVisibility('visible');
    expect(seen).toHaveBeenCalled();
    // Neuladen: pagehide vor visibilitychange, der Bezugspunkt bleibt
    window.dispatchEvent(new Event('pagehide'));
    setVisibility('hidden');
    expect(mark).toHaveBeenCalledTimes(1);
    window.dispatchEvent(new Event('pageshow'));
    setVisibility('visible');
  });

  it('Klick auf «+N seit» lässt genau die neuen Ids pulsieren', async () => {
    const { app } = await makeApp('normal');
    await until(() => (app.project?.seen.count ?? 0) > 0);
    const before = app.ui.pulseToken;
    app.project?.seen.pulse();
    expect(app.ui.pulseToken).toBe(before + 1);
    const n = app.project?.seen.view?.new;
    for (const id of [...(n?.hosts ?? []), ...(n?.items ?? [])]) expect(app.ui.isPulsing(id)).toBe(true);
    expect(app.ui.isPulsing('gibt-es-nicht')).toBe(false);
  });
});
