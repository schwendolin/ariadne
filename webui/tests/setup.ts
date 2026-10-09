// Gemeinsame Test-Umgebung (jsdom): fehlende Browser-APIs minimal nachbilden.
// Tests mit `@vitest-environment node` (z. B. lint-rules) haben kein window.
import { vi } from 'vitest';

const browser = typeof window !== 'undefined';

if (!('ResizeObserver' in globalThis)) {
  class RO {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  (globalThis as unknown as { ResizeObserver: typeof RO }).ResizeObserver = RO;
}

if (browser && !window.matchMedia) {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
}

// jsdom hat kein Canvas; ohne Stub schreibt es bei jedem Aufruf einen Fehler in die Konsole.
if (browser) HTMLCanvasElement.prototype.getContext = (() => null) as unknown as HTMLCanvasElement['getContext'];

let blobCounter = 0;
if (!URL.createObjectURL) {
  URL.createObjectURL = () => `blob:test/${++blobCounter}`;
}
if (!URL.revokeObjectURL) {
  URL.revokeObjectURL = () => undefined;
}
