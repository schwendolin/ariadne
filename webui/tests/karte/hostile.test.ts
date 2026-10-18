// Feindliche Zieldaten in Karte, Spalte und Host-Detail (Briefing 9.1, E13, E68): nur als Text, nie
// als HTML, Link oder Bild; Steuer- und Bidi-Zeichen sichtbar; Vorlage mit Shell-Sonderzeichen ohne
// fertigen Befehl, nur Einzelwerte; dynamische Werte nur als CSS-Variablen (CSSOM). Besitzer: ui-karte.
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { HostNode } from '../../src/lib/api/types';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import KarteView from '../../src/lib/karte/KarteView.svelte';
import { MockBackend } from '../../src/lib/mock/backend';
import { hostId } from '../../src/lib/mock/data/base';
import { HOSTILE_IMG, INJECTION_TITLE, SHELL_PRODUCT } from '../../src/lib/mock/data/hostile';
import { AppState } from '../../src/lib/stores/app.svelte';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { settle, until } from '../fundament/helpers';

const RLO = String.fromCodePoint(0x202e);
const ESC = String.fromCodePoint(0x1b);
const H101 = hostId('192.168.56.101');
const EVIL = `${HOSTILE_IMG}${RLO}txt${ESC}[31m`;

let apps: AppState[] = [];

beforeAll(() => {
  installKeymap(window);
});

afterEach(() => {
  cleanup();
  resetKeymapForTests();
  for (const a of apps) a.stop();
  apps = [];
  document.body.replaceChildren();
  url.go('karte', {}, { replace: true, keep: false });
});

/** Mock «hostile» mit zusätzlich feindlicher Host-Bezeichnung, Klärung und Notiz. */
async function hostile() {
  const backend = new MockBackend('hostile');
  backend.delay = 0;
  const s = backend.state;
  s.graph = { ...s.graph, nodes: s.graph.nodes.map((n) => (n.kind === 'host' && n.id === H101 ? ({ ...n, label: EVIL } as HostNode) : n)) };
  const d = s.hosts[H101];
  if (d) s.hosts = { ...s.hosts, [H101]: { ...d, label: EVIL, os: `<script>alert(1)</script>`, note: `[klick](javascript:alert(1)) <img src=x onerror=alert(2)>`, tags: [`<b>x</b>`] } };
  s.next = {
    ...s.next,
    clarify: s.next.clarify.map((i) => (i.kind === 'ctx_suggestion' ? { ...i, suggested_label: EVIL, reason: `Callback von ${HOSTILE_IMG}` } : i)),
  };
  const app = new AppState(backend);
  apps.push(app);
  await app.start();
  await until(() => app.project?.map.graph != null && app.project.next.view != null && app.project.map.positionsLoaded);
  const project = app.project as ProjectStore;
  const view = render(KarteView, { props: { app, project, useLibrary: false } });
  await until(() => view.container.querySelectorAll('[data-map-card]').length > 0);
  return { app, project, view, backend };
}

function noActiveContent(root: ParentNode): void {
  expect(root.querySelector('img, script, iframe, object, embed, a, svg')).toBeNull();
  for (const el of Array.from(root.querySelectorAll('*'))) {
    for (const attr of Array.from(el.attributes)) {
      expect(attr.name.startsWith('on'), `${el.tagName} ${attr.name}`).toBe(false);
      expect(['href', 'src', 'srcdoc', 'action'].includes(attr.name), `${el.tagName} ${attr.name}`).toBe(false);
      if (attr.name === 'style') {
        // nur CSS-Variablen per CSSOM (styleProps), nie Werte aus Zieldaten
        for (const decl of attr.value.split(';').map((x) => x.trim()).filter(Boolean)) {
          expect(decl, el.tagName).toMatch(/^--[a-z-]+:\s*-?[\d.]+$/);
        }
      }
    }
  }
}

describe('feindliche Werte', () => {
  it('Karte und Spalte: HTML als Text, Bidi und ESC sichtbar, gekürzt mit vollem Wert im title', async () => {
    const { view } = await hostile();
    const c = view.container;
    const cardEl = c.querySelector<HTMLElement>(`[data-map-card][data-host-id="${H101}"]`) as HTMLElement;
    expect(cardEl.textContent).toContain('<img src=x onerror=alert(1)>');
    expect(cardEl.textContent).not.toContain(RLO);
    expect(cardEl.textContent).not.toContain(ESC);
    const title = cardEl.querySelector('.txt')?.getAttribute('title') ?? '';
    expect(title).toContain('<U+202E>txt<ESC>[31m');
    expect(title).toContain('enthält Steuerzeichen');
    expect(c.querySelector('.next .card')?.textContent).toContain('Callback von <img src=x onerror=alert(1)>.lame.htb');
    noActiveContent(c);
  });

  it('Denkanstoss mit Shell-Sonderzeichen: keine fertige Vorlage, nur Einzelwerte mit «Mac»', async () => {
    const { app, project, view } = await hostile();
    await app.prefs.set({ learning: false });
    const sug = project.next.suggestionItems.find((x) => x.title.includes(SHELL_PRODUCT));
    project.next.select(sug?.suggestion_key ?? null);
    await settle();
    const card = view.container.querySelector('.next .card') as HTMLElement;
    expect(card.textContent).toContain('! Enthält Shell-Sonderzeichen. Keine fertige Vorlage.');
    expect(card.querySelector('.tpl')).toBeNull();
    expect(card.querySelector('.blocked .vals')?.textContent).toContain(SHELL_PRODUCT);
    expect(screen.getAllByRole('button', { name: 'Mac' })).toHaveLength(2);
    expect(card.textContent).toContain('vom Ziel angeboten');
    noActiveContent(view.container);
  });

  it('Host-Detail: Titel mit Injection-Verdacht, Notiz nur als sicheres Markdown, Tags und OS als Text', async () => {
    const { view } = await hostile();
    url.set({ host: H101 });
    await until(() => view.container.querySelector('.detail .svc') !== null);
    const det = view.container.querySelector('.detail') as HTMLElement;
    expect(det.textContent).toContain(`Titel «${INJECTION_TITLE}»`.slice(0, 40));
    expect(det.textContent).toContain('! Injection-Verdacht · vom Ziel angeboten');
    expect(det.textContent).toContain('<script>alert(1)</script>');
    expect(det.textContent).toContain('<b>x</b>');
    expect(det.querySelector('.note')?.textContent).toContain('klick');
    noActiveContent(view.container);
  });

  it('Out-of-Scope-Popover: feindlicher Name als Text, Quelle öffnet nur die Belegansicht', async () => {
    const { view } = await hostile();
    await fireEvent.click(screen.getByRole('button', { name: /Out of Scope · 4/ }));
    const pop = screen.getByRole('dialog', { name: 'Out of Scope' });
    expect(pop.textContent).toContain(HOSTILE_IMG);
    expect(pop.textContent).toContain('gleiche MAC wie');
    expect(pop.textContent).toContain('gefälschter Callback');
    noActiveContent(view.container);
    const first = pop.querySelector('button.item') as HTMLElement;
    await fireEvent.click(first);
    expect(url.get('beleg')).toMatch(/^u:/);
  });
});
