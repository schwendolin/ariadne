// Reiter Karte als Ganzes im DOM (ohne Cytoscape: Rückfall «Hosts ohne Linien»): Host-Karten,
// Lagebild mit «+N seit», verknüpfter Host, Spalte mit K2 aufgeklappt, Tastatur (a, j, k, ↵, t, Esc),
// Host-Detail und Rückkehr mit Fokus, Tabelle, Ebenen in der URL, erste Schritte im leeren Projekt.
// Besitzer: ui-karte.
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import KarteView from '../../src/lib/karte/KarteView.svelte';
import { hostId } from '../../src/lib/mock/data/base';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, press, settle, stopAll, until } from '../fundament/helpers';

const H101 = hostId('192.168.56.101');

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

async function mount(scenario: Parameters<typeof makeApp>[0] = 'normal') {
  const h = await makeApp(scenario);
  await until(() => h.app.project?.map.graph != null && h.app.project.next.view != null && h.app.project.map.positionsLoaded);
  const project = h.app.project as ProjectStore;
  const view = render(KarteView, { props: { app: h.app, project, useLibrary: false } });
  await until(() => view.container.querySelectorAll('[data-map-card]').length > 0);
  return { ...h, project, view };
}

const card = (c: HTMLElement, id: string) => c.querySelector<HTMLElement>(`[data-map-card][data-host-id="${id}"]`);

describe('Karte', () => {
  it('Kali und Hosts als fokussierbare Karten mit genau einem Hinweis; verknüpfter Host mit K1', async () => {
    const { view } = await mount();
    const c = view.container;
    const cards = Array.from(c.querySelectorAll<HTMLElement>('[data-map-card]'));
    expect(cards.map((el) => el.dataset.hostId)).toEqual(['kali', H101, hostId('192.168.56.103'), hostId('192.168.56.104')]);
    expect(cards.every((el) => el.tagName === 'BUTTON')).toBe(true);
    expect(card(c, H101)?.textContent).toContain('23 Services');
    expect(card(c, H101)?.querySelector('.sym')?.textContent).toBe('#');
    expect(card(c, hostId('192.168.56.103'))?.textContent).toContain('im Nebel');
    expect(card(c, hostId('192.168.56.104'))?.textContent).toContain('Sackgasse · nur RDP');
    expect(card(c, 'kali')?.textContent).toContain('192.168.56.102');
    const wrap = card(c, H101)?.closest('.wrap');
    expect(wrap?.querySelector('.ring-label')?.textContent).toBe('K2');
    expect(card(c, H101)?.getAttribute('aria-label')).toContain('betrifft K2');
  });

  it('Lagebild «Stand · 3 Hosts, 1 im Nebel · 1 mit Zugriff» und «+3 seit» lässt das Neue pulsieren', async () => {
    const { app, view } = await mount();
    expect(view.container.querySelector('.lage .sum')?.textContent).toMatch(/^Stand \d\d:\d\d · 3 Hosts, 1 im Nebel · 1 mit Zugriff$/);
    const pill = screen.getByRole('button', { name: /^\+3 seit \d\d:\d\d$/ });
    await fireEvent.click(pill);
    expect(app.ui.isPulsing(H101)).toBe(true);
    expect(app.ui.isPulsing('k:31001')).toBe(true);
  });

  it('Klick wählt den Host (Detail in der Spalte), Esc schliesst und gibt den Fokus an die Karte', async () => {
    const { view } = await mount();
    await fireEvent.click(card(view.container, H101) as HTMLElement);
    expect(url.get('host')).toBe(H101);
    await until(() => view.container.querySelector('.detail h2') !== null);
    expect(view.container.querySelector('.detail')?.textContent).toContain('Versionen bekannt');
    expect(card(view.container, H101)?.getAttribute('aria-pressed')).toBe('true');
    expect(card(view.container, H101)?.closest('.wrap')?.querySelector('.ring-sel')).not.toBeNull();
    press('Escape');
    await until(() => url.get('host') === null);
    await until(() => document.activeElement === card(view.container, H101));
    expect(view.container.querySelector('.next')).not.toBeNull();
  });

  it('Pfeiltasten springen zwischen den Karten (Raster ohne Bibliothek)', async () => {
    const { view } = await mount();
    const kali = card(view.container, 'kali') as HTMLElement;
    kali.focus();
    press('ArrowRight', {}, kali);
    expect((document.activeElement as HTMLElement | null)?.dataset.hostId).not.toBe('kali');
    const now = (document.activeElement as HTMLElement).dataset.hostId;
    press('ArrowLeft', {}, document.activeElement as HTMLElement);
    expect((document.activeElement as HTMLElement).dataset.hostId).not.toBe(now);
  });

  it('Ebenen in der URL: Nebel aus blendet .103 aus, Faden aus die Marken', async () => {
    const { view } = await mount();
    await fireEvent.click(screen.getByRole('button', { name: 'Ebenen und Legende' }));
    const fog = view.container.querySelector<HTMLInputElement>('input[data-layer="fog"]') as HTMLInputElement;
    await fireEvent.change(fog, { target: { checked: false } });
    expect(url.get('ebenen')).toBe('services,thread,oos');
    await settle();
    expect(card(view.container, hostId('192.168.56.103'))).toBeNull();
    const oos = view.container.querySelector<HTMLInputElement>('input[data-layer="oos"]') as HTMLInputElement;
    await fireEvent.change(oos, { target: { checked: false } });
    await settle();
    expect(view.container.querySelector('.strip')).toBeNull();
  });

  it('t schaltet zur Host-Tabelle und zurück; j und ↵ öffnen das Detail', async () => {
    const { view, project } = await mount();
    press('t');
    expect(url.get('ansicht')).toBe('tabelle');
    await until(() => view.container.querySelectorAll('.table-view button.row').length === 3);
    const rows = Array.from(view.container.querySelectorAll<HTMLElement>('.table-view button.row'));
    expect(rows[0]?.dataset.hostId).toBe(H101);
    press('j');
    press('Enter');
    expect(url.get('host')).toBe(rows[1]?.dataset.hostId);
    url.set({ host: null });
    press('t');
    expect(url.get('ansicht')).toBeNull();
    expect(project.map.tableOnly).toBe(false);
  });

  it('ab 200 Hosts nur die Tabelle, Konflikte zuerst, Fusszeile; t wechselt nicht zur Karte', async () => {
    const h = await makeApp('many');
    await until(() => h.app.project?.map.graph != null && h.app.project.next.view != null);
    const view = render(KarteView, { props: { app: h.app, project: h.app.project as ProjectStore, useLibrary: false } });
    await until(() => view.container.querySelectorAll('.table-view button.row').length > 0);
    const first = view.container.querySelector('.table-view button.row') as HTMLElement;
    expect(first.textContent).toContain('192.168.56.17');
    expect(first.textContent).toContain('! Konflikt: Dienstname 445');
    expect(view.container.querySelector('.table-view .foot')?.textContent).toMatch(/^1 bis \d+ von 250 · j k wechseln · ↵ Host-Detail$/);
    expect(view.container.querySelector('[data-map-card]')).toBeNull();
    press('t');
    expect(url.get('ansicht')).toBeNull();
    expect(view.container.querySelector('.table-view')).not.toBeNull();
    await fireEvent.click(screen.getByRole('radio', { name: 'Services' }));
    expect(url.get('tabelle')).toBe('services');
    await until(() => view.container.querySelector('.table-view .row.svcs[data-service-id]') !== null);
  });
});

describe('Spalte «Als Nächstes»', () => {
  it('K2 aufgeklappt mit Übernehmen, K3 einzeilig; a übernimmt, dann ist K3 aufgeklappt', async () => {
    const { view, project } = await mount();
    const col = view.container.querySelector('.next') as HTMLElement;
    expect(col.textContent).toContain('21 Werte ausserhalb des Scopes, 2 Erwähnungen');
    expect(col.querySelector('.card .head')?.textContent).toContain('Kontext klären · Vorschlag');
    expect(col.querySelector('.card')?.textContent).toContain('T3 «listener» · Reverse Shell');
    expect(col.querySelector('.card')?.textContent).toMatch(/Darum mehrdeutig: zweiter Callback im Output, \d\d:53:02/);
    expect(col.querySelector('button.line[data-item-key^="merge:"]')?.textContent).toContain('Zusammenführen?');
    expect(col.querySelector('.keys')?.textContent).toBe('j k wechseln · a übernehmen · ↵ Beleg · ? Hilfe');
    press('a');
    await until(() => project.next.done.length === 1);
    await until(() => col.querySelector('.card .head')?.textContent?.includes('Zusammenführen?') === true);
    expect(col.querySelector('.done')?.textContent).toContain('Kontext T3 = .101, rückwirkend');
    expect(col.querySelector('.keys')?.textContent).toBe('j k wechseln · a zusammenführen · ? Hilfe');
    press('x');
    await until(() => project.next.done.length === 2);
    expect(col.querySelector('.group-head .word')?.textContent).toBe('erledigt');
    expect(col.querySelectorAll('.done')).toHaveLength(2);
    expect(col.querySelector('.done:nth-child(2)')?.textContent).toContain('getrennt gelassen');
  });

  it('Ruhezustand: Denkanstoss im Lernmodus Stufe für Stufe; ohne Lernmodus Vorlage mit «Kopieren · Mac»', async () => {
    const { app, view } = await mount('calm');
    const col = view.container.querySelector('.next') as HTMLElement;
    expect(col.textContent).toContain('Nichts zu klären.');
    const sug = col.querySelector('.card') as HTMLElement;
    expect(sug.querySelector('.head')?.textContent).toContain('Prüfziel · Regel R-ANON-ZUGRIFF');
    expect(sug.textContent).not.toContain('Kopieren · Mac');
    await fireEvent.click(screen.getByRole('button', { name: /1 Frage zeigen/ }));
    expect(sug.textContent).toContain('Welche Daten gibt dieser Dienst ohne Anmeldung preis?');
    await fireEvent.click(screen.getByRole('button', { name: /2 Richtung zeigen/ }));
    await fireEvent.click(screen.getByRole('button', { name: /3 Vorlage zeigen/ }));
    expect(sug.textContent).toContain('nmap -p 21 --script ftp-anon 192.168.56.101');
    await app.prefs.set({ learning: false });
    await settle();
    const sug2 = col.querySelector('.card') as HTMLElement;
    expect(sug2.textContent).toContain('Beleg: nmap -sV · 14:02 · Zeile 6');
    expect(screen.getAllByRole('button', { name: 'Kopieren · Mac' }).length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByRole('button', { name: /ausführen/i })).toBeNull();
    expect(screen.getByRole('button', { name: /Denkanstoss anfordern \(KI\)/ }).hasAttribute('disabled')).toBe(true);
  });

  it('Zustände danach: erledigt mit Titel und Rückgängig u, verworfen durchgestrichen mit «verworfen»', async () => {
    const { app, view, project } = await mount('calm');
    await app.prefs.set({ learning: false });
    await settle();
    const col = view.container.querySelector('.next') as HTMLElement;
    const first = project.next.view?.suggestions[0];
    await fireEvent.click(screen.getByRole('button', { name: 'Erledigt' }));
    await until(() => project.next.done.length === 1);
    const done = col.querySelector(`.done[data-done-key="${first?.suggestion_key}"]`) as HTMLElement;
    expect(done.querySelector('.text')?.textContent).toContain('Unauthentisierten Zugriff auf');
    expect(done.querySelector('.text')?.getAttribute('title')).toContain('192.168.56.101:21');
    expect(done.querySelector('button.right')?.textContent).toContain('Rückgängig');
    expect(done.querySelector('.right kbd')).not.toBeNull();
    // der Cursor steht auf dem nächsten Denkanstoss; Verwerfen
    await fireEvent.click(screen.getByRole('button', { name: 'Verwerfen' }));
    await until(() => project.next.done.length === 2);
    const dismissed = col.querySelector('.done.s-dismissed') as HTMLElement;
    expect(dismissed.querySelector('.strike')?.textContent).toContain('Version recherchieren');
    // nichts mehr offen: der Cursor bleibt auf dem verworfenen Eintrag, dort steht «Rückgängig u»
    expect(dismissed.getAttribute('aria-current')).toBe('true');
    expect(dismissed.querySelector('button.right')?.textContent).toContain('Rückgängig');
    expect(done.querySelector('.right kbd')).toBeNull();
    // nicht gewählt: «verworfen» wie im Design
    press('k');
    await settle();
    expect(done.getAttribute('aria-current')).toBe('true');
    expect(dismissed.querySelector('.right')?.textContent).toBe('verworfen');
    expect(done.querySelector('.right kbd')).not.toBeNull();
    press('j');
    await settle();
    press('u');
    await until(() => project.next.done.length === 1);
    await until(() => col.querySelector('.card')?.textContent?.includes('Version recherchieren') === true);
  });

  it('leeres Projekt: «Erste Schritte» statt der Liste', async () => {
    const h = await makeApp('empty');
    await until(() => h.app.project?.map.graph != null && h.app.project.next.view != null);
    const view = render(KarteView, { props: { app: h.app, project: h.app.project as ProjectStore, useLibrary: false } });
    await settle();
    expect(view.container.querySelector('.column')?.textContent).toContain('ms2');
    expect(view.container.querySelector('.next')).toBeNull();
  });
});
