// Gemeinsame Hilfen der Fundament-Tests (Besitzer: ui-fundament): App-Zustand gegen den Mock, ohne
// Verzögerung, mit sauberem Abbau. Keine echten Netzwerkzugriffe, kein Browser-Speicher.
import { tick } from 'svelte';
import { MockBackend } from '../../src/lib/mock/backend';
import type { Scenario } from '../../src/lib/mock/state';
import { AppState } from '../../src/lib/stores/app.svelte';

export interface Harness {
  app: AppState;
  backend: MockBackend;
}

const live: AppState[] = [];

/** AppState mit MockBackend (delay 0); `start` meldet an und lädt den Status. */
export async function makeApp(scenario: Scenario = 'normal', opts: { start?: boolean; code?: string | null } = {}): Promise<Harness> {
  const backend = new MockBackend(scenario);
  backend.delay = 0;
  const app = new AppState(backend);
  live.push(app);
  if (opts.start !== false) {
    await app.start(opts.code ?? null);
    await settle();
  }
  return { app, backend };
}

/** Alle Mikro-Aufgaben und einen Svelte-Durchlauf abwarten. */
export async function settle(rounds = 4): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await Promise.resolve();
    await tick();
  }
}

/** Wartet (echte Zeit) bis `fn` wahr ist. */
export async function until(fn: () => boolean, timeoutMs = 2000): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (!fn()) {
    if (Date.now() > end) throw new Error('Bedingung nicht erfüllt');
    await new Promise((r) => setTimeout(r, 10));
    await tick();
  }
}

/** Nach jedem Test: alle Zustände stoppen (Timer, Strom, Projekt-Store). */
export function stopAll(): void {
  while (live.length) live.pop()?.stop();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.density;
}

export function press(key: string, init: KeyboardEventInit = {}, target: EventTarget = document.body): KeyboardEvent {
  const ev = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...init });
  target.dispatchEvent(ev);
  return ev;
}
