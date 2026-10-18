// Korrekturen nach der Prüfung des Baus v0.1-Oberfläche (Teil Fundament): Enter, Leertaste und
// Pfeile gehören dem fokussierten Bedienelement (A1), die Fokusfalle hält Tab im Dialog (A15),
// Seiten-Kürzel ruhen hinter einer Tafel (A2), die Tafel setzt den Hintergrund inert (A7), ohne
// Verbindung ist der Inhalt nicht inert, aber Aktionen sind gesperrt (A11), ein ungespeichertes
// Formular sperrt die Reiterkürzel (A6), sichtbar gemachte Steuerzeichen im Bearbeitungsfeld
// (SEC-UI-1). Besitzer: ui-fundament.
import { fireEvent, render } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { trapFocus } from '../../src/lib/keys/focus';
import { installKeymap, isControlTarget, registerKeys, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { pageKeysActive } from '../../src/lib/keys/page';
import { hasVisibleMarkers } from '../../src/lib/safe/displaySafe';
import { registerGlobalKeys } from '../../src/lib/shell/global';
import Panel from '../../src/lib/ui/Panel.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, settle, stopAll } from './helpers';

function press(key: string, target: EventTarget = document.body, init: KeyboardEventInit = {}): KeyboardEvent {
  const ev = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...init });
  target.dispatchEvent(ev);
  return ev;
}

beforeAll(() => {
  installKeymap(window);
});

afterEach(() => {
  resetKeymapForTests();
  stopAll();
  document.body.replaceChildren();
  url.go('karte', {}, { replace: true, keep: false });
});

describe('A1: Enter, Leertaste und Pfeile gehören dem fokussierten Bedienelement', () => {
  it('Enter auf einem Knopf löst keine Seitenbindung aus, die native Aktivierung bleibt', () => {
    const page = vi.fn();
    registerKeys([{ keys: ['Enter', 'ArrowDown', ' '], run: page }]);
    const btn = document.createElement('button');
    document.body.append(btn);
    btn.focus();
    const ev = press('Enter', btn);
    expect(page).not.toHaveBeenCalled();
    expect(ev.defaultPrevented).toBe(false);
    press(' ', btn);
    press('ArrowDown', btn);
    expect(page).not.toHaveBeenCalled();
    // ohne Fokus auf einem Bedienelement wirkt die Bindung
    press('Enter');
    expect(page).toHaveBeenCalledTimes(1);
  });

  it('Pfeile in einer Radiogruppe wechseln die Auswahl (der Browser), nicht die Liste der Seite', () => {
    const page = vi.fn();
    registerKeys([{ keys: ['ArrowDown'], run: page }]);
    const radio = document.createElement('input');
    radio.type = 'radio';
    document.body.append(radio);
    const ev = press('ArrowDown', radio);
    expect(page).not.toHaveBeenCalled();
    expect(ev.defaultPrevented).toBe(false);
    for (const role of ['option', 'menuitem', 'tab', 'radio']) {
      const el = document.createElement('div');
      el.setAttribute('role', role);
      expect(isControlTarget(el)).toBe(true);
    }
    const row = document.createElement('li');
    row.tabIndex = 0;
    expect(isControlTarget(row)).toBe(false);
  });

  it('`onControl` erlaubt es ausdrücklich (Pfeile zwischen Host-Karten)', () => {
    const run = vi.fn();
    registerKeys([{ keys: ['ArrowLeft'], onControl: true, run }]);
    const card = document.createElement('button');
    document.body.append(card);
    press('ArrowLeft', card);
    expect(run).toHaveBeenCalledTimes(1);
  });

  it('Buchstaben wirken weiter mit Fokus auf einem Knopf', () => {
    const run = vi.fn();
    registerKeys([{ keys: ['j'], run }]);
    const btn = document.createElement('button');
    document.body.append(btn);
    press('j', btn);
    expect(run).toHaveBeenCalledTimes(1);
  });
});

describe('A15: Fokusfalle', () => {
  it('Tab und Shift+Tab bleiben im Dialog, auch über eine scrollbare Liste und Optionen mit tabindex -1', async () => {
    const dlg = document.createElement('div');
    const input = document.createElement('input');
    const list = document.createElement('ul');
    list.tabIndex = -1;
    const opt = document.createElement('button');
    opt.tabIndex = -1;
    list.append(opt);
    const close = document.createElement('button');
    dlg.append(input, list, close);
    document.body.append(dlg);
    const outside = document.createElement('button');
    document.body.append(outside);
    const action = trapFocus(dlg);
    await Promise.resolve();
    expect(document.activeElement).toBe(input);
    const seen: Element[] = [];
    for (let i = 0; i < 6; i++) {
      press('Tab', document.activeElement ?? document.body);
      seen.push(document.activeElement as Element);
    }
    expect(seen.every((el) => dlg.contains(el))).toBe(true);
    expect(seen.slice(0, 2)).toEqual([close, input]);
    list.focus(); // Chrome macht scrollbare Bereiche selbst fokussierbar
    press('Tab', list);
    expect(document.activeElement).toBe(close);
    press('Tab', close, { shiftKey: true });
    expect(document.activeElement).toBe(input);
    action.destroy();
  });
});

describe('A2: Seiten-Kürzel ruhen hinter einer Tafel', () => {
  it('pageKeysActive: nur auf dem Reiter und ohne beleg oder tafel', () => {
    url.go('karte', {});
    expect(pageKeysActive('karte')).toBe(true);
    expect(pageKeysActive('zeitachse')).toBe(false);
    url.set({ beleg: 'u:abc' });
    expect(pageKeysActive('karte')).toBe(false);
    url.set({ beleg: null, tafel: 'einstellungen' });
    expect(pageKeysActive('karte')).toBe(false);
  });
});

describe('A7: Tafel setzt den übrigen Inhalt inert', () => {
  it('Geschwister werden inert, beim Schliessen wieder frei; neue Ansichten auch', async () => {
    const main = document.createElement('main');
    const view = document.createElement('section');
    const behind = document.createElement('button');
    behind.textContent = 'dahinter';
    view.append(behind);
    main.append(view);
    document.body.append(main);
    const r = render(Panel, { target: main, props: { title: 'Beleg', onclose: () => undefined, children: (() => undefined) as never } });
    await settle();
    expect(view.hasAttribute('inert')).toBe(true);
    const dialog = main.querySelector('[role="dialog"]');
    expect(dialog?.getAttribute('aria-label')).toBe('Beleg');
    expect(dialog?.hasAttribute('inert')).toBe(false);
    const later = document.createElement('div');
    main.append(later);
    await settle();
    expect(later.hasAttribute('inert')).toBe(true);
    r.unmount();
    expect(view.hasAttribute('inert')).toBe(false);
    expect(later.hasAttribute('inert')).toBe(false);
  });
});

describe('A6, A11: ungespeichertes Formular und keine Verbindung', () => {
  it('Reiterkürzel wechseln nicht, solange ein Formular ungespeichert ist; Meldung statt Verlust', async () => {
    const { app } = await makeApp('normal');
    const off = registerGlobalKeys(app);
    url.go('findings', { finding: 'neu' });
    app.ui.setDirty('finding:neu', true);
    press('2');
    expect(url.route).toBe('findings');
    expect(app.ui.notices.some((n) => n.text.includes('Ungespeicherte Änderungen'))).toBe(true);
    app.ui.setDirty('finding:neu', false);
    press('2');
    expect(url.route).toBe('terminals');
    off();
  });
});

describe('SEC-UI-1: sichtbar gemachte Steuerzeichen', () => {
  it('erkennt die Marker des Servers, nicht gewöhnlichen Text', () => {
    expect(hasVisibleMarkers('a<ESC>[31m')).toBe(true);
    expect(hasVisibleMarkers('x<U+202E>y')).toBe(true);
    expect(hasVisibleMarkers('Zeile 1<LF><LF>- A')).toBe(true);
    expect(hasVisibleMarkers('<b>fett</b> und <script>')).toBe(false);
    expect(hasVisibleMarkers('Zeile 1\n\n- A')).toBe(false);
  });
});

describe('A11: ohne Verbindung', () => {
  it('Klicks auf Knöpfe im Inhalt sind gesperrt, Eingabefelder behalten Fokus (kein inert)', async () => {
    const App = (await import('../../src/App.svelte')).default;
    const { app } = await makeApp('normal');
    const r = render(App, { props: { app } });
    await settle();
    const main = r.container.querySelector('main') as HTMLElement;
    const input = document.createElement('input');
    const btn = document.createElement('button');
    const clicked = vi.fn();
    btn.addEventListener('click', clicked);
    main.append(input, btn);
    input.focus();
    app.offline = true;
    await settle();
    expect(main.hasAttribute('inert')).toBe(false);
    expect(document.activeElement).toBe(input);
    await fireEvent.click(btn);
    expect(clicked).not.toHaveBeenCalled();
    app.offline = false;
    await settle();
    await fireEvent.click(btn);
    expect(clicked).toHaveBeenCalledTimes(1);
  });
});
