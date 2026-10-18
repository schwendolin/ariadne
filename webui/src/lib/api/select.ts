/**
 * Wählt das Backend: echter Daemon oder Mock.
 *
 * Der Mock ist nur ausdrücklich an (`--mode mock`, `npm run dev:mock`, VITE_ARIADNE_MOCK=1); er
 * landet nur dann im Bundle. Ohne diese Wahl läuft die UI immer gegen die echte API, auch im
 * Dev-Server: Ist kein Daemon erreichbar, zeigt sie «Daemon nicht erreichbar» statt still auf
 * Beispieldaten umzuschalten. Im normalen Build ist die Konstante false, und der Bundler entfernt
 * den dynamischen Import.
 */
import { createSessionTokenStore } from './auth';
import { HttpBackend, type Backend } from './backend';

export async function selectBackend(): Promise<Backend> {
  if (__ARIADNE_MOCK__) {
    const { MockBackend } = await import('../mock/backend');
    return new MockBackend();
  }
  return new HttpBackend(createSessionTokenStore());
}
