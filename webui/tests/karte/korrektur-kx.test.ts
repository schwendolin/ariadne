// Korrekturen nach der Prüfung des Baus v0.1-Oberfläche (Teil Karte): Kennzeichen «enthält
// Steuerzeichen» am richtigen Wert (SEC-UI-3), Kürzel hinter der Tafel (A2), feste Zuständigkeit
// für j k ↵ zwischen Tabelle und Spalte (A8), Fokus beim Aufklappen (A13), Titel der Denkanstösse
// (D6, D14), Offline-Spalte (D12). Besitzer: ui-karte.
import { cleanup, fireEvent, render } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { Suggestion } from '../../src/lib/api/types';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import KarteView from '../../src/lib/karte/KarteView.svelte';
import { hostId } from '../../src/lib/mock/data/base';
import { collapsedParts, titleParts } from '../../src/lib/next/title';
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

async function mount(scenario: Parameters<typeof makeApp>[0] = 'normal', before?: (b: Awaited<ReturnType<typeof makeApp>>['backend']) => void) {
  const h = await makeApp(scenario);
  before?.(h.backend);
  if (before) await h.app.project?.loadAll();
  await until(() => h.app.project?.map.graph != null && h.app.project.next.view != null && h.app.project.map.positionsLoaded);
  const project = h.app.project as ProjectStore;
  const view = render(KarteView, { props: { app: h.app, project, useLibrary: false } });
  await until(() => view.container.querySelectorAll('[data-map-card]').length > 0);
  return { ...h, project, view };
}

describe('SEC-UI-3: «enthält Steuerzeichen» steht am manipulierten Wert, nicht an der Adresse', () => {
  it('saubere IP ohne Kennzeichen, auch wenn OS oder Tags des Hosts Steuerzeichen enthalten', async () => {
    const { view } = await mount('normal', (b) => {
      b.state.graph = {
        ...b.state.graph,
        nodes: b.state.graph.nodes.map((n) => (n.id === H101 && n.kind === 'host' ? { ...n, ctrl: true, os: 'Linux <U+202E>gnp.exe', tags: ['x<U+202E>gnp.exe'] } : n)),
      };
    });
    const ip = view.container.querySelector(`[data-map-card][data-host-id="${H101}"] .ip .txt`) as HTMLElement;
    expect(ip.textContent).toBe('192.168.56.101');
    expect(ip.classList.contains('hidden')).toBe(false);
    expect(view.container.querySelector(`[data-map-card][data-host-id="${H101}"] .ip`)?.textContent).not.toContain('Steuerzeichen');
  });
});

describe('A2: Kürzel der Spalte ruhen hinter der offenen Tafel', () => {
  it('j, k, x ändern bei offener Belegansicht weder Auswahl noch Entscheide', async () => {
    const { project, backend } = await mount();
    const decide = vi.spyOn(backend, 'decide');
    const before = project.next.selectedKey;
    url.set({ beleg: 'u:abc' }, { push: true });
    press('j');
    press('k');
    press('x');
    press('a');
    press('n');
    await settle();
    expect(project.next.selectedKey).toBe(before);
    expect(decide).not.toHaveBeenCalled();
    url.set({ beleg: null });
    press('j');
    expect(project.next.selectedKey).not.toBe(before);
  });
});

describe('A8: j k ↵ gehören der sichtbaren Tabelle, ausser der Fokus liegt in der Spalte', () => {
  it('unabhängig davon, wer zuletzt eingehängt wurde (direktes Laden mit ?ansicht=tabelle)', async () => {
    url.go('karte', { ansicht: 'tabelle' });
    const h = await makeApp('normal');
    await until(() => h.app.project?.map.graph != null && h.app.project.next.view != null);
    const project = h.app.project as ProjectStore;
    const view = render(KarteView, { props: { app: h.app, project, useLibrary: false } });
    await until(() => view.container.querySelectorAll('.table-view .row').length > 1);
    const sel = project.next.selectedKey;
    const cursorId = () => view.container.querySelector<HTMLElement>('.table-view .row.cursor')?.dataset.hostId;
    const start = cursorId();
    press('j');
    await settle();
    expect(cursorId()).not.toBe(start);
    expect(project.next.selectedKey).toBe(sel);
    // Fokus in der Spalte: j gehört der Spalte
    const col = view.container.querySelector('[data-keyzone="next"]') as HTMLElement;
    const btn = col.querySelector('button') as HTMLElement;
    btn.focus();
    const tableBefore = cursorId();
    press('j', {}, btn);
    await settle();
    expect(project.next.selectedKey).not.toBe(sel);
    expect(cursorId()).toBe(tableBefore);
  });
});

describe('A13: Fokus beim Aufklappen', () => {
  it('Klick auf eine eingeklappte Zeile fokussiert die aufgeklappte Karte statt body', async () => {
    const { view, project } = await mount();
    const line = view.container.querySelector<HTMLButtonElement>('button.line[data-suggestion-key]') as HTMLButtonElement;
    const key = line.dataset.suggestionKey;
    line.focus();
    await fireEvent.click(line);
    await settle();
    expect(project.next.selectedKey).toBe(key);
    const card = view.container.querySelector(`.card[data-suggestion-key="${key}"]`);
    expect(document.activeElement).toBe(card);
  });
});

describe('D12: ohne Verbindung', () => {
  it('keine Fusszeile in der Spalte, kein Ring des gewählten Eintrags, keine Marke «+N seit»', async () => {
    const { app, view } = await mount();
    expect(view.container.querySelector('.next .foot')).not.toBeNull();
    expect(view.container.querySelector('.ring-linked')).not.toBeNull();
    app.offline = true;
    await settle();
    expect(view.container.querySelector('.next .foot')).toBeNull();
    expect(view.container.querySelector('.ring-linked')).toBeNull();
    expect(view.container.querySelector('.lage .new')).toBeNull();
  });
});

describe('D6, D14: Titel der Denkanstösse', () => {
  const sug = (over: Partial<Suggestion>): Suggestion =>
    ({
      title_parts: [
        { text: 'Version recherchieren: ', target: false },
        { text: 'vsftpd 2.3.4', target: true },
        { text: ' (', target: false },
        { text: '192.168.56.101:21', target: true },
        { text: ')', target: false },
      ],
      templates: [],
      ...over,
    }) as Suggestion;

  it('eingeklappt ohne Ziel-Anhang, aufgeklappt mit', () => {
    const s = sug({});
    expect(collapsedParts(s.title_parts).map((p) => p.text).join('')).toBe('Version recherchieren: vsftpd 2.3.4');
    expect(titleParts(s).map((p) => p.text).join('')).toBe('Version recherchieren: vsftpd 2.3.4 (192.168.56.101:21)');
    // ohne Zieldaten davor bleibt der Titel unverändert
    const only = [{ text: 'Alle TCP-Ports (', target: false }, { text: '.101', target: true }, { text: ')', target: false }];
    expect(collapsedParts(only)).toEqual(only);
  });

  it('mit verdächtigem Wert (keine Vorlage): Titel ohne Zieldaten', () => {
    const tpl = { rendered: false, blocked_reason: 'shell_meta' } as Suggestion['templates'][number];
    const s = sug({ title_parts: [{ text: 'Version recherchieren: ', target: false }, { text: "vsftpd'; !sh -c 'id", target: true }], templates: [tpl] });
    expect(titleParts(s).map((p) => p.text).join('')).toBe('Version recherchieren');
    const oos = sug({ templates: [{ rendered: false, blocked_reason: 'out_of_scope' } as Suggestion['templates'][number]] });
    expect(titleParts(oos)).toEqual(oos.title_parts);
  });
});

describe('SEC-RULES-1: Vorlage mit eigenem Secret', () => {
  it('zeigt «Enthält ein eigenes Secret» und nur Einzelwerte, keinen Befehl', async () => {
    const TemplateBlock = (await import('../../src/lib/next/TemplateBlock.svelte')).default;
    const template = {
      template_id: 'mysql-root-nopass', tool: 'mysql', label: 'mysql', rendered: false, command: null, parts: [], blocked_reason: 'own_secret',
      values: [
        { slot: 'tool', type: 'word', label: 'Werkzeug', value: 'mysql', ctrl: false, target: false, safe: true },
        { slot: 'host.ip', type: 'ip', label: 'IP', value: '192.168.56.110', ctrl: false, target: true, safe: true },
      ],
    } as Suggestion['templates'][number];
    const r = render(TemplateBlock, { props: { template } });
    expect(r.container.textContent).toContain('Enthält ein eigenes Secret (verdeckt). Keine fertige Vorlage.');
    expect(r.container.querySelector('code .tpl, .tpl')).toBeNull();
    expect(r.container.querySelector('[data-blocked="own_secret"]')).not.toBeNull();
  });
});
