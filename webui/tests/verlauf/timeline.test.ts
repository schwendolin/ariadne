// Zeitachse (Screen 6): Store gegen den Mock (alle Typen mit verdeckten Eingaben, Filter, Live),
// Rückgängig pro Befehl inline mit Grund und Rückmeldung, «Wieder vertrauen», Fehler inline,
// Tastatur j k ↵ u Esc, Sprung über `zeile`, Warteliste, Lücke «läuft noch», Scope-Warnung.
// Besitzer: ui-verlauf.
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../src/lib/api/client';
import type { TimelineQuery } from '../../src/lib/api/types';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { T1, T3 } from '../../src/lib/mock/data/base';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import TimelineView from '../../src/lib/timeline/TimelineView.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, press, settle, stopAll, until } from '../fundament/helpers';

const NMAP = `${T1}@18432`;

beforeAll(() => {
  installKeymap(window);
});

afterEach(() => {
  cleanup();
  resetKeymapForTests();
  stopAll();
  document.body.replaceChildren();
  url.go('karte', {}, { replace: true, keep: false });
});

async function mount(scenario: Parameters<typeof makeApp>[0] = 'normal', patch: Parameters<typeof url.go>[1] = {}) {
  url.go('zeitachse', patch, { replace: true, keep: false });
  const h = await makeApp(scenario);
  await until(() => !!h.app.project?.timeline.loaded && !!h.app.project.timeline.pending);
  const project = h.app.project as ProjectStore;
  const view = render(TimelineView, { props: { app: h.app, project } });
  await until(() => view.container.querySelectorAll('li.item').length > 0);
  return { ...h, project, view };
}

const row = (c: HTMLElement, id: string) => c.querySelector<HTMLElement>(`li.item[data-row="${id}"]`);

describe('Zeitachse: Store', () => {
  it('fragt alle Typen samt Eingaben ab und zeigt davon nur verdeckte', async () => {
    const h = await makeApp('normal');
    const spy = vi.spyOn(h.backend, 'timeline');
    const project = h.app.project as ProjectStore;
    await project.timeline.load();
    const q = spy.mock.calls.at(-1)?.[1] as TimelineQuery;
    expect(q.types).toContain('input');
    expect(q.types).toHaveLength(9);
    expect(project.timeline.rows.filter((r) => r.type === 'input').every((r) => r.type === 'input' && r.input.hidden)).toBe(true);
  });

  it('Filter lädt neu, gleicher Filter nicht', async () => {
    const h = await makeApp('normal');
    const project = h.app.project as ProjectStore;
    await until(() => project.timeline.loaded);
    const spy = vi.spyOn(h.backend, 'timeline');
    project.timeline.setFilter({ types: ['gap'], terminal: null, host: null });
    await until(() => project.timeline.items.length === 1);
    expect(project.timeline.items[0]?.type).toBe('gap');
    project.timeline.setFilter({ types: ['gap'], terminal: null, host: null });
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('nach `changes` lädt die Zeitachse gebündelt neu, mit der geladenen Abdeckung', async () => {
    const h = await makeApp('normal');
    const project = h.app.project as ProjectStore;
    await until(() => project.timeline.loaded);
    const spy = vi.spyOn(h.backend, 'timeline');
    project.timeline.onChanges({ project_id: project.pid, from: 1, to: 2, reset: false, changes: [{ generation: 2, entity: 'claim', entity_key: 'x', change: 'updated' }] });
    project.timeline.onChanges({ project_id: project.pid, from: 2, to: 3, reset: false, changes: [{ generation: 3, entity: 'claim', entity_key: 'y', change: 'updated' }] });
    await until(() => spy.mock.calls.length === 1, 3000);
    expect((spy.mock.calls[0]?.[1] as TimelineQuery).limit).toBe(200);
  });

  it('ältere Seiten über den Cursor, ohne Doppel; ensureRow lädt bis die Zeile da ist', async () => {
    const h = await makeApp('normal');
    const project = h.app.project as ProjectStore;
    await until(() => project.timeline.loaded);
    const all = h.backend.state.timeline;
    const spy = vi.spyOn(h.backend, 'timeline').mockImplementation(async (_pid, q) => {
      const start = q.cursor ? Number(q.cursor) : 0;
      const items = all.slice(start, start + 5);
      return { items, next_cursor: start + 5 < all.length ? String(start + 5) : null };
    });
    project.timeline.setFilter({ types: ['command', 'gap', 'keystep', 'decision', 'segment', 'context', 'project', 'file', 'input'], terminal: null, host: null });
    await until(() => project.timeline.items.length === 5);
    expect(project.timeline.nextCursor).toBe('5');
    expect(await project.timeline.ensureRow(`${T1.slice(-8)}@18432`)).toBe(true);
    expect(project.timeline.items.length).toBeGreaterThan(5);
    expect(new Set(project.timeline.items.map((x) => x.id)).size).toBe(project.timeline.items.length);
    spy.mockRestore();
  });
});

describe('Zeitachse: Ansicht', () => {
  it('zeigt Zeit, Terminal, Ereignis und Ergebnis wie im Design', async () => {
    const { view } = await mount();
    const c = view.container;
    const nmap = row(c, NMAP) as HTMLElement;
    expect(nmap.querySelector('.term')?.textContent).toBe('T1');
    expect(nmap.querySelector('.event')?.textContent).toContain('nmap -sV -sC -oA scans/ms2 192.168.56.101');
    expect(nmap.querySelector('.event')?.textContent).toContain('Exit 0 · Datei scans/ms2.xml erkannt');
    expect(nmap.querySelector('.result')?.textContent?.trim()).toBe('1 Host, 23 Services · 141 Werte übernommen');
    expect(row(c, 'g:48001')?.textContent).toContain('Lücke · Pause');
    expect(row(c, 'g:48001')?.querySelector('.result')?.textContent).toContain('läuft noch, F12 r');
    expect(row(c, 'k:31877')?.querySelector('.step')?.textContent).toBe('2');
    expect(row(c, 'k:31877')?.textContent).toContain('Loot');
    expect(row(c, `${T1}@40960`)?.textContent).toContain('! Scope-Warnung: fd00:56::101 ausserhalb');
    expect(row(c, `${T1}@40960`)?.textContent).toContain('quittiert');
    expect(row(c, `${T1}@40960`)?.querySelector('.result')?.textContent?.trim()).toBe('0 übernommen, +17 ausserhalb');
    const dist = row(c, `${T1}@51200`) as HTMLElement;
    expect(dist.classList.contains('distrusted')).toBe(true);
    expect(dist.querySelector('.result')?.textContent).toContain('misstraut');
    expect(dist.querySelector('.action')?.textContent).toContain('Wieder vertrauen');
    expect(row(c, '0199a3c2-9a00-7000-8000-00000000d000')?.textContent).toContain('«Banner manipuliert, vermutlich Honeypot»');
    expect(row(c, '0199a3c2-9a00-7000-8000-00000000d000')?.querySelector('.result')?.textContent).toContain('18 verworfen, 0 geschwächt');
    expect(row(c, `${T3}@64`)?.querySelector('.result')?.textContent).toContain('Kontext unklar');
    // verdeckte Eingabe: nur Maske, Aufdecken, In die Kali
    const inp = row(c, 'i:47001') as HTMLElement;
    expect(inp.textContent).toContain('Eingabe ohne Echo');
    expect(inp.textContent).toContain('••••••••');
    expect(inp.textContent).not.toContain('mock-Ziel-Passwort');
    expect(c.querySelector('.start')?.textContent).toMatch(/^Projektstart \d\d:\d\d$/);
  });

  it('verdeckte Eingabe einzeln aufdecken und wieder verdecken', async () => {
    const { view } = await mount();
    const inp = row(view.container, 'i:47001') as HTMLElement;
    await fireEvent.click(inp.querySelector('button.link') as HTMLElement);
    await until(() => inp.textContent?.includes('mock-Ziel-Passwort') === true);
    await fireEvent.click(screen.getByRole('button', { name: 'Verdecken' }));
    expect(inp.textContent).not.toContain('mock-Ziel-Passwort');
  });

  it('Rückgängig mit Grund: d.unit.distrust allein, Rückmeldung, Zeile misstraut, Wieder vertrauen', async () => {
    const { view, backend } = await mount();
    const c = view.container;
    await fireEvent.click(row(c, NMAP)?.querySelector('.time') as HTMLElement);
    expect(url.get('zeile')).toBe(NMAP);
    press('u');
    await until(() => c.querySelector('form.box') !== null);
    expect(c.querySelector('form.box')?.textContent).toContain('Werte aus diesem Befehl verwerfen?');
    expect(c.querySelector('form.box')?.textContent).toContain('nmap 1');
    const input = c.querySelector('form.box input') as HTMLInputElement;
    await until(() => document.activeElement === input);
    await fireEvent.input(input, { target: { value: 'Banner manipuliert' } });
    const spy = vi.spyOn(backend, 'decide');
    await fireEvent.submit(c.querySelector('form.box') as HTMLFormElement);
    await until(() => c.querySelector('.feedback') !== null);
    expect(spy).toHaveBeenCalledTimes(1);
    const sent = spy.mock.calls[0]?.[1] ?? [];
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ kind: 'd.unit.distrust', payload: { cmd_id: NMAP, reason: 'Banner manipuliert' } });
    expect(c.querySelector('.feedback')?.textContent).toContain('141 verworfen, 0 geschwächt');
    await until(() => row(c, NMAP)?.classList.contains('distrusted') === true, 3000);
    // Wieder vertrauen aus der Rückmeldung: d.revoke auf den Entscheid
    await fireEvent.click(screen.getAllByRole('button', { name: 'Wieder vertrauen' }).find((b) => b.closest('.feedback')) as HTMLElement);
    await until(() => c.querySelector('.feedback')?.textContent?.includes('Wieder vertraut') === true);
    const last = spy.mock.calls.at(-1)?.[1]?.[0];
    expect(last?.kind).toBe('d.revoke');
    await until(() => row(c, NMAP)?.classList.contains('distrusted') === false, 3000);
  });

  it('Fehler steht inline («Rückgängig nicht gespeichert: Das Projekt ist gesperrt»), keine Meldung bleibt', async () => {
    const { view, backend, app } = await mount();
    const c = view.container;
    vi.spyOn(backend, 'decide').mockRejectedValue(new ApiError('locked', 423, 'locked'));
    await fireEvent.click(row(c, NMAP)?.querySelector('.undo') as HTMLElement);
    await until(() => c.querySelector('form.box') !== null);
    await fireEvent.submit(c.querySelector('form.box') as HTMLFormElement);
    await until(() => c.querySelector('form.box .error-box') !== null);
    expect(c.querySelector('form.box .error-box')?.textContent).toBe('Rückgängig nicht gespeichert: Das Projekt ist gesperrt');
    expect(app.ui.notices).toEqual([]);
  });

  it('«Wieder vertrauen» an der misstrauten Zeile hebt mit d.revoke auf', async () => {
    const { view, backend } = await mount();
    const spy = vi.spyOn(backend, 'decide');
    await fireEvent.click(row(view.container, `${T1}@51200`)?.querySelector('.action button') as HTMLElement);
    await until(() => spy.mock.calls.length === 1);
    expect(spy.mock.calls[0]?.[1]?.[0]).toMatchObject({ kind: 'd.revoke', payload: { decision_id: '0199a3c2-9a00-7000-8000-00000000d000' } });
    await until(() => row(view.container, `${T1}@51200`)?.classList.contains('distrusted') === false, 3000);
  });

  it('Tastatur: j k wählen (URL), ↵ öffnet den Beleg, u und Esc', async () => {
    const { view } = await mount();
    press('j');
    const first = url.get('zeile');
    expect(first).toBeTruthy();
    press('j');
    expect(url.get('zeile')).not.toBe(first);
    press('k');
    expect(url.get('zeile')).toBe(first);
    // auf den nmap-Befehl springen, ↵ öffnet den Beleg der Einheit
    url.set({ zeile: NMAP });
    await settle();
    press('Enter');
    expect(url.get('beleg')).toBe(`u:${NMAP}`);
    url.set({ beleg: null });
    press('u');
    await until(() => view.container.querySelector('form.box') !== null);
    press('Escape', {}, view.container.querySelector('form.box input') as HTMLElement);
    await until(() => view.container.querySelector('form.box') === null);
  });

  it('Sprung über `zeile` mit cmd_ref wählt die Zeile', async () => {
    const { view } = await mount('normal', { zeile: `${T1.slice(-8)}@30720` });
    await until(() => row(view.container, `${T1}@30720`)?.getAttribute('aria-current') === 'true');
  });

  it('Filter aus der URL; leer: «Keine Einträge für diesen Filter»', async () => {
    const { view } = await mount('normal', { typ: 'gap' });
    await until(() => view.container.querySelectorAll('li.item').length === 1);
    expect(screen.getByRole('button', { name: /1 Typ/ })).toBeTruthy();
    url.set({ typ: 'gap', hostf: 'ip:default/192.168.56.199' });
    await until(() => view.container.querySelector('.empty') !== null);
    expect(view.container.querySelector('.empty')?.textContent).toBe('Keine Einträge für diesen Filter');
  });

  it('Typfilter im Popover schreibt `typ` in die URL', async () => {
    await mount();
    await fireEvent.click(screen.getByRole('button', { name: /Alle Typen/ }));
    await fireEvent.click(screen.getByRole('checkbox', { name: 'Lücken' }));
    expect(url.get('typ')?.split(',')).not.toContain('gap');
    expect(url.get('typ')?.split(',')).toHaveLength(8);
  });

  it('UTC zeigen schaltet die Zeiten', async () => {
    const { view } = await mount();
    const before = row(view.container, NMAP)?.querySelector('.time')?.textContent;
    await fireEvent.click(screen.getByRole('button', { name: 'UTC zeigen' }));
    expect(url.get('utc')).toBe('1');
    await settle();
    expect(row(view.container, NMAP)?.querySelector('.time')?.textContent).toBe('12:02:11');
    expect(before).toMatch(/^\d\d:\d\d:\d\d$/);
  });
});

describe('Warteliste', () => {
  it('eingeklappt mit Zahl, aufgeklappt mit Grund, Grösse und Befehl zum Kopieren nur bei sicheren Pfaden', async () => {
    const h = await makeApp('normal');
    h.backend.state.pending = {
      files: [...h.backend.state.pending.files, { path: 'scans/$(id).xml', reason: 'owner', cmd_id: null, terminal_id: T1, ts: '2026-10-08T14:49:00.000000Z', ctrl: false, size: 3 }],
      truncated: true,
    };
    url.go('zeitachse', {}, { replace: true, keep: false });
    const project = h.app.project as ProjectStore;
    await project.timeline.load();
    const view = render(TimelineView, { props: { app: h.app, project } });
    const strip = screen.getByRole('button', { name: /Warteliste/ });
    expect(strip.textContent).toMatch(/4 Dateien nicht übernommen · neueste \d\d:\d\d/);
    expect(strip.getAttribute('aria-expanded')).toBe('false');
    await fireEvent.click(strip);
    const files = Array.from(view.container.querySelectorAll('.pending .file'));
    expect(files[0]?.textContent).toMatch(/gehört vermutlich zu nmap \d\d:\d\d · 41 KB/);
    expect(files[1]?.textContent).toContain('abgelehnt: Symlink');
    expect(files[2]?.textContent).toContain('ausserhalb des Projekts · 2 KB');
    expect(files[0]?.querySelector('button')?.textContent).toContain('Import-Befehl · Mac');
    expect(files[3]?.textContent).toContain('Pfad mit Sonderzeichen');
    expect(files[3]?.querySelector('button')).toBeNull();
    expect(view.container.querySelector('.pending')?.textContent).toContain('Weitere Dateien nicht gezeigt');
    expect(view.container.querySelector('.pending .hint')?.textContent).toContain('ariadne import ‹pfad›');
  });

  it('leer: «Keine Dateien in der Warteliste»', async () => {
    const { view } = await mount('empty');
    expect(view.container.querySelector('.pending')?.textContent).toContain('Keine Dateien in der Warteliste');
  });
});
