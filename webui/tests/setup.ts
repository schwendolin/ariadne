// Gemeinsame Test-Umgebung (jsdom): fehlende Browser-APIs minimal nachbilden.
import { vi } from 'vitest';

if (!('ResizeObserver' in globalThis)) {
  class RO {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  (globalThis as unknown as { ResizeObserver: typeof RO }).ResizeObserver = RO;
}

if (!window.matchMedia) {
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
HTMLCanvasElement.prototype.getContext = (() => null) as unknown as HTMLCanvasElement['getContext'];

let blobCounter = 0;
if (!URL.createObjectURL) {
  URL.createObjectURL = () => `blob:test/${++blobCounter}`;
}
if (!URL.revokeObjectURL) {
  URL.revokeObjectURL = () => undefined;
}
