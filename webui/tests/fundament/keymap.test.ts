// Tastatur-Rahmen (Vertrag v0.1-Oberfläche, Abschnitt 4): ein Listener, Einzeltasten nur ausserhalb
// von Eingabefeldern, modale Ebenen, innerste Bindung gewinnt. Besitzer: ui-fundament.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { comboOf, installKeymap, pushLayer, registerKeys, resetKeymapForTests } from '../../src/lib/keys/keymap';

function press(key: string, init: KeyboardEventInit = {}, target: EventTarget = document.body): KeyboardEvent {
  const ev = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...init });
  target.dispatchEvent(ev);
  return ev;
}

beforeAll(() => {
  installKeymap(window);
});

afterEach(() => {
  resetKeymapForTests();
  document.body.replaceChildren();
});

describe('comboOf', () => {
  it('normalisiert Buchstaben, Zeichen und Modifikatoren', () => {
    const k = (key: string, init: KeyboardEventInit = {}) => comboOf(new KeyboardEvent('keydown', { key, ...init }));
    expect(k('j')).toBe('j');
    expect(k('J', { shiftKey: true })).toBe('Shift+J');
    expect(k('p', { shiftKey: true })).toBe('Shift+P');
    expect(k('k', { metaKey: true })).toBe('Mod+K');
    expect(k('k', { ctrlKey: true })).toBe('Mod+K');
    expect(k('?', { shiftKey: true })).toBe('?');
    expect(k('Enter')).toBe('Enter');
    expect(k('Tab', { shiftKey: true })).toBe('Shift+Tab');
  });
});

describe('Bindungen', () => {
  it('Einzeltasten wirken nicht in Eingabefeldern, Mod+K mit allowInInput schon', () => {
    const single = vi.fn();
    const palette = vi.fn();
    registerKeys([
      { keys: ['j'], run: single },
      { keys: ['Mod+K'], allowInInput: true, run: palette },
    ]);
    const input = document.createElement('input');
    document.body.append(input);
    press('j', {}, input);
    expect(single).not.toHaveBeenCalled();
    press('k', { metaKey: true }, input);
    expect(palette).toHaveBeenCalledTimes(1);
    const ev = press('j');
    expect(single).toHaveBeenCalledTimes(1);
    expect(ev.defaultPrevented).toBe(true);
  });

  it('Checkboxen und Knöpfe gelten nicht als Eingabefeld', () => {
    const run = vi.fn();
    registerKeys([{ keys: ['a'], run }]);
    const box = document.createElement('input');
    box.type = 'checkbox';
    document.body.append(box);
    press('a', {}, box);
    expect(run).toHaveBeenCalledTimes(1);
  });

  it('die zuletzt angemeldete Bindung gewinnt, false reicht weiter', () => {
    const outer = vi.fn();
    const inner = vi.fn(() => false);
    registerKeys([{ keys: ['Escape'], run: outer }]);
    const off = registerKeys([{ keys: ['Escape'], run: inner }]);
    press('Escape');
    expect(inner).toHaveBeenCalledTimes(1);
    expect(outer).toHaveBeenCalledTimes(1);
    off();
    press('Escape');
    expect(inner).toHaveBeenCalledTimes(1);
    expect(outer).toHaveBeenCalledTimes(2);
  });

  it('when sperrt eine Bindung', () => {
    const run = vi.fn();
    let on = false;
    registerKeys([{ keys: ['t'], when: () => on, run }]);
    press('t');
    expect(run).not.toHaveBeenCalled();
    on = true;
    press('t');
    expect(run).toHaveBeenCalledTimes(1);
  });

  it('eine modale Ebene schaltet die Kürzel der Seite ab, bis sie zu ist', () => {
    const page = vi.fn();
    const dialog = vi.fn();
    registerKeys([{ keys: ['1'], run: page }]);
    const { layer, pop } = pushLayer();
    registerKeys([{ keys: ['Escape'], run: dialog }], layer);
    press('1');
    expect(page).not.toHaveBeenCalled();
    press('Escape');
    expect(dialog).toHaveBeenCalledTimes(1);
    pop();
    press('1');
    expect(page).toHaveBeenCalledTimes(1);
    press('Escape');
    expect(dialog).toHaveBeenCalledTimes(1);
  });

  it('unbehandelte Tasten bleiben unangetastet', () => {
    registerKeys([{ keys: ['j'], run: () => undefined }]);
    const ev = press('x');
    expect(ev.defaultPrevented).toBe(false);
  });
});
