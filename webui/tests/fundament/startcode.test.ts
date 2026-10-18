// Startdatei-Adresse `http://127.0.0.1:7330/#c=<code>` (Integration v0.1-Oberfläche): Der Code
// muss gelesen sein, bevor der URL-Zustand `/` auf `/karte` umleitet; sonst landet der Nutzer
// trotz gültigem Code auf der Anmeldung (Fehler im echten Durchlauf gefunden).
import { describe, expect, it, vi } from 'vitest';

describe('Einmalcode aus der Startdatei', () => {
  it('überlebt die Umleitung von / auf /karte und verschwindet sofort aus der Adresse', async () => {
    vi.resetModules();
    window.history.replaceState(null, '', '/#c=Zx9_abcdefgh12345');
    const { startCode } = await import('../../src/lib/api/startcode');
    const { url } = await import('../../src/lib/url/state.svelte');
    expect(startCode).toBe('Zx9_abcdefgh12345');
    expect(window.location.hash).toBe('');
    expect(url.route).toBe('karte');
    expect(window.location.pathname).toBe('/karte');
  });

  it('main.ts liest den Code als allererstes (Importreihenfolge)', async () => {
    const { readFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const src = readFileSync(join(process.cwd(), 'src', 'main.ts'), 'utf8');
    const imports = src.split('\n').filter((l) => l.startsWith('import '));
    expect(imports[0]).toContain('./lib/api/startcode');
  });
});
