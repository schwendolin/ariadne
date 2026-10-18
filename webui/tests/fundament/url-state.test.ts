// URL-Zustand (Vertrag v0.1-Oberfläche, Abschnitt 3): Reiter, Parameter, Belegziel, nie ein Token.
// Besitzer: ui-fundament.
import { describe, expect, it } from 'vitest';
import { UrlState, decodeEvidence, encodeEvidence } from '../../src/lib/url/state.svelte';

const KEY = 'a'.repeat(64);

describe('Belegziel in der URL', () => {
  it('kodiert und dekodiert Claims und Einheiten mit Zeilenbereich', () => {
    expect(decodeEvidence(encodeEvidence({ kind: 'claim', claim_key: KEY }))).toEqual({ kind: 'claim', claim_key: KEY });
    const unit = { kind: 'unit' as const, unit_id: 'T1@18432', lines: [3, 9] as [number, number] };
    expect(decodeEvidence(encodeEvidence(unit))).toEqual(unit);
    expect(decodeEvidence('u:T1@18432')).toEqual({ kind: 'unit', unit_id: 'T1@18432', lines: null });
  });

  it('verwirft ungültige Werte', () => {
    expect(decodeEvidence(null)).toBeNull();
    expect(decodeEvidence('c:zz')).toBeNull();
    expect(decodeEvidence('x:1')).toBeNull();
    expect(decodeEvidence('u:')).toBeNull();
    expect(decodeEvidence(`u:${'x'.repeat(301)}`)).toBeNull();
  });
});

describe('UrlState ohne Fenster', () => {
  it('Reiterwechsel verwirft die Parameter des alten Reiters, behält Ebenen und Tafel', () => {
    const u = new UrlState(null);
    u.go('karte', { host: 'h1', ebenen: 'access,thread' });
    expect(u.route).toBe('karte');
    expect(u.get('host')).toBe('h1');
    u.go('zeitachse', { zeile: 'cmd:1' });
    expect(u.get('host')).toBeNull();
    expect(u.get('zeile')).toBe('cmd:1');
    expect(u.layers).toEqual(['access', 'thread']);
  });

  it('beleg und tafel schliessen sich gegenseitig aus', () => {
    const u = new UrlState(null);
    u.set({ tafel: 'einstellungen' });
    expect(u.get('tafel')).toBe('einstellungen');
    u.set({ beleg: `c:${KEY}` });
    expect(u.get('tafel')).toBeNull();
    expect(u.evidence()).toEqual({ kind: 'claim', claim_key: KEY });
    u.set({ tafel: 'einstellungen' });
    expect(u.get('beleg')).toBeNull();
  });

  it('href baut Pfade ohne leere Parameter', () => {
    const u = new UrlState(null);
    expect(u.href('findings', { finding: 'neu', host: '' })).toBe('/findings?finding=neu');
  });
});

describe('UrlState im Fenster', () => {
  it('unbekannte Pfade werden zu /karte, Zurück stellt den Reiter wieder her', () => {
    window.history.replaceState(null, '', '/irgendwas?ebenen=access');
    const u = new UrlState(window);
    expect(window.location.pathname).toBe('/karte');
    expect(u.layers).toEqual(['access']);
    u.go('terminals');
    expect(window.location.pathname).toBe('/terminals');
    expect(u.route).toBe('terminals');
    window.history.back();
    return new Promise<void>((resolve) => {
      window.addEventListener(
        'popstate',
        () => {
          expect(u.route).toBe('karte');
          resolve();
        },
        { once: true },
      );
    });
  });
});
