/**
 * Tastatur: eine Stelle für alle Kürzel (BEHAVIOR «Tastatur», Briefing 11). Besitzer: ui-fundament.
 *
 * Regeln:
 * - Ein einziger `keydown`-Listener auf `window`. Komponenten melden Bindungen mit
 *   `registerKeys()` (bzw. der Action `keys` / `useKeys` in Svelte) an und beim Abbau wieder ab.
 * - Einzeltasten (ohne Strg/Cmd/Alt) wirken nur mit Fokus ausserhalb von Eingabefeldern
 *   (input, textarea, select, contenteditable). Ausnahme nur mit `allowInInput` (Escape, Mod+K).
 * - Ebenen: 'base' ist die Seite. Dialoge, Palette und Hilfe öffnen eine modale Ebene
 *   (`pushLayer`); solange sie offen ist, wirken nur ihre Bindungen (Fokus gefangen, Einzeltasten
 *   der Seite aus).
 * - Innerhalb einer Ebene gewinnt die zuletzt angemeldete Bindung (die innerste, zuletzt
 *   eingeblendete Komponente). `run` kann `false` zurückgeben, dann wird weitergesucht.
 * - Behandelte Tasten bekommen `preventDefault()`.
 * - Enter, Leertaste und Pfeiltasten gehören dem fokussierten Bedienelement (Knopf, Link,
 *   Radio, Checkbox, Rolle option/menuitem/tab …): Dann wirkt keine Bindung, ausser sie setzt
 *   `onControl` (etwa die Pfeile zwischen Host-Karten). So aktiviert Enter immer den Knopf mit dem
 *   Fokus, und die Pfeile wechseln in einer Radiogruppe (Korrektur A1, WCAG 2.1.1).
 * - Kürzel-Schreibweise: 'j', 'Enter', 'Escape', 'ArrowDown', '?', 'Shift+P', 'Mod+K'
 *   (Mod = Cmd auf dem Mac, sonst Strg; beide werden angenommen).
 */

export type KeyLayer = 'base' | 'modal';

export interface KeyBinding {
  /** Kürzel, z. B. ['j', 'ArrowDown'] */
  keys: string[];
  run: (e: KeyboardEvent) => void | boolean;
  /** zusätzliche Bedingung (z. B. nur auf dem Reiter Karte) */
  when?: () => boolean;
  /** auch mit Fokus in einem Eingabefeld (nur Escape, Mod+K, Mod+Enter) */
  allowInInput?: boolean;
  /** Text für die Hilfe (i18n-Schlüssel) */
  help?: string;
  /** Enter, Leertaste oder Pfeile auch mit Fokus auf einem Bedienelement (Korrektur A1) */
  onControl?: boolean;
}

interface Entry {
  id: number;
  layer: number;
  binding: KeyBinding;
}

const entries: Entry[] = [];
let nextId = 1;
/** Ebenenstapel: Zahl der offenen modalen Ebenen; 0 = nur die Seite */
let modalDepth = 0;
let installed: ((e: KeyboardEvent) => void) | null = null;

/** true, wenn der Fokus in einem Eingabefeld liegt (Einzeltasten aus). */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!target || !(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  if (tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (tag === 'INPUT') {
    const type = (target as HTMLInputElement).type;
    return !['button', 'checkbox', 'radio', 'submit', 'reset', 'range', 'color'].includes(type);
  }
  return false;
}

/** Tasten, die ein fokussiertes Bedienelement selbst bedient (Korrektur A1). */
const NATIVE_KEYS = new Set([
  'Enter', ' ', 'Shift+Enter', 'ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight', 'Shift+ArrowDown', 'Shift+ArrowUp', 'Home', 'End',
]);
const CONTROL_SELECTOR = [
  'button', 'a[href]', 'input', 'select', 'textarea', 'summary', '[contenteditable="true"]',
  '[role="button"]', '[role="link"]', '[role="radio"]', '[role="checkbox"]', '[role="switch"]', '[role="option"]',
  '[role="menuitem"]', '[role="menuitemradio"]', '[role="menuitemcheckbox"]', '[role="tab"]', '[role="slider"]',
  '[role="spinbutton"]', '[role="combobox"]', '[role="treeitem"]',
].join(',');

/** true, wenn der Fokus auf einem Bedienelement liegt, das Enter, Leertaste und Pfeile selbst bedient. */
export function isControlTarget(target: EventTarget | null): boolean {
  return target instanceof Element && target.matches(CONTROL_SELECTOR);
}

/**
 * Normalisiert ein KeyboardEvent auf die Schreibweise der Bindungen:
 * Buchstaben ohne Modifikator klein ('j'), mit Modifikator gross ('Shift+P', 'Mod+K');
 * andere Zeichen wie getippt ('?', '1', '+', '-'), benannte Tasten mit 'Shift+' wenn gedrückt.
 */
export function comboOf(e: KeyboardEvent): string {
  const mods: string[] = [];
  if (e.metaKey || e.ctrlKey) mods.push('Mod');
  if (e.altKey) mods.push('Alt');
  const key = e.key;
  if (key.length === 1) {
    if (/^[a-z]$/i.test(key)) {
      if (e.shiftKey) mods.push('Shift');
      return [...mods, mods.length ? key.toUpperCase() : key.toLowerCase()].join('+');
    }
    return [...mods, key].join('+');
  }
  if (e.shiftKey && key !== 'Shift') mods.push('Shift');
  return [...mods, key].join('+');
}

function isSingleKey(combo: string): boolean {
  return !combo.startsWith('Mod+') && !combo.startsWith('Alt+');
}

function handler(e: KeyboardEvent): void {
  if (e.defaultPrevented || e.isComposing) return;
  const combo = comboOf(e);
  const typing = isTypingTarget(e.target);
  const control = NATIVE_KEYS.has(combo) && isControlTarget(e.target);
  const layer = modalDepth;
  for (let i = entries.length - 1; i >= 0; i--) {
    const ent = entries[i];
    if (!ent || ent.layer !== layer) continue;
    const b = ent.binding;
    if (!b.keys.includes(combo)) continue;
    if (typing && !b.allowInInput && isSingleKey(combo)) continue;
    if (control && !b.onControl && !(typing && b.allowInInput)) continue;
    if (b.when && !b.when()) continue;
    const res = b.run(e);
    if (res === false) continue;
    e.preventDefault();
    e.stopPropagation();
    return;
  }
}

/** Installiert den einen Listener (main.ts); idempotent. */
export function installKeymap(target: Window = window): () => void {
  if (installed) return () => undefined;
  installed = handler;
  target.addEventListener('keydown', handler);
  return () => {
    target.removeEventListener('keydown', handler);
    installed = null;
  };
}

/** Meldet Bindungen auf der aktuellen Ebene an; gibt die Abmeldung zurück. */
export function registerKeys(bindings: KeyBinding[], layer: number = modalDepth): () => void {
  const ids = bindings.map((binding) => {
    const id = nextId++;
    entries.push({ id, layer, binding });
    return id;
  });
  return () => {
    for (const id of ids) {
      const i = entries.findIndex((e) => e.id === id);
      if (i >= 0) entries.splice(i, 1);
    }
  };
}

/**
 * Öffnet eine modale Ebene (Dialog, Palette, Hilfe). Gibt die Ebene und das Schliessen zurück;
 * Bindungen des Dialogs meldet man mit `registerKeys(b, layer)` auf dieser Ebene an.
 */
export function pushLayer(): { layer: number; pop: () => void } {
  modalDepth++;
  const layer = modalDepth;
  let popped = false;
  return {
    layer,
    pop: () => {
      if (popped) return;
      popped = true;
      modalDepth = Math.max(0, modalDepth - 1);
      // Bindungen dieser Ebene entfernen (falls der Dialog sie nicht selbst abgemeldet hat)
      for (let i = entries.length - 1; i >= 0; i--) if (entries[i]?.layer === layer) entries.splice(i, 1);
    },
  };
}

export function currentLayer(): number {
  return modalDepth;
}

/** Alle Bindungen mit Hilfetext (für die Hilfe `?`). */
export function helpEntries(): { keys: string[]; help: string }[] {
  return entries.filter((e) => e.binding.help).map((e) => ({ keys: e.binding.keys, help: e.binding.help as string }));
}

/** Svelte-Action: `<div use:keys={bindings}>` meldet an, solange das Element existiert. */
export function keys(_node: HTMLElement, bindings: KeyBinding[]) {
  let off = registerKeys(bindings);
  return {
    update(next: KeyBinding[]) {
      off();
      off = registerKeys(next);
    },
    destroy() {
      off();
    },
  };
}

/** Nur für Tests: alles zurücksetzen. */
export function resetKeymapForTests(): void {
  entries.splice(0, entries.length);
  modalDepth = 0;
}

/** true auf dem Mac (Anzeige «⌘K» statt «Strg+K»); die Bindung `Mod+` nimmt beides an. */
export function isMac(nav: Navigator | null = typeof navigator === 'undefined' ? null : navigator): boolean {
  const p = (nav as (Navigator & { userAgentData?: { platform?: string } }) | null)?.userAgentData?.platform ?? nav?.platform ?? '';
  return /mac|iphone|ipad/i.test(p);
}

/**
 * Anzeige eines Kürzels mit `Mod`: «⌘K» auf dem Mac, sonst «Strg+K» (ohne Leerzeichen, damit der
 * Hinweis nie umbricht; Korrektur D1, D10).
 */
export function modLabel(key: string, mac: boolean = isMac()): string {
  return mac ? `⌘${key}` : `Strg+${key}`;
}
