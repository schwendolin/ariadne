/**
 * Wählt das Backend: echter Daemon oder Mock.
 *
 * Der Mock-Code landet nur im Bundle, wenn er eingebaut ist (`--mode mock`,
 * VITE_ARIADNE_MOCK=1) oder im Dev-Server. Im normalen Build sind beide
 * Konstanten false, und der Bundler entfernt den dynamischen Import.
 */
import { createSessionTokenStore } from './auth';
import { HttpBackend, type Backend } from './backend';

async function daemonReachable(): Promise<boolean> {
  try {
    const res = await fetch('/api/v1/status', {
      headers: { Accept: 'application/json' },
      credentials: 'omit',
      cache: 'no-store',
      signal: AbortSignal.timeout(1500),
    });
    // Der Daemon antwortet immer mit JSON (auch 401). Proxy-Fehler des Dev-Servers nicht.
    return (res.headers.get('content-type') ?? '').includes('application/json');
  } catch {
    return false;
  }
}

export async function selectBackend(): Promise<Backend> {
  if (__ARIADNE_MOCK__ || (__ARIADNE_DEV_AUTOMOCK__ && !(await daemonReachable()))) {
    const { MockBackend } = await import('../mock/backend');
    return new MockBackend();
  }
  return new HttpBackend(createSessionTokenStore());
}
