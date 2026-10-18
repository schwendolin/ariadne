// Kopfzeile in allen Varianten (SCREENS 5, AriadneKopfzeile.dc.html, E87, E107): normal, waiting,
// pause, held, locked, noproject, offline, Präsentation, Scope-Kennzeichen. Herkunft immer sichtbar,
// keine Zahlen von Klärungen oder Denkanstössen. Besitzer: ui-fundament.
import { fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as base from '../../src/lib/mock/data/base';
import Header from '../../src/lib/shell/Header.svelte';
import { makeApp, settle, stopAll, until } from './helpers';

afterEach(() => {
  stopAll();
  vi.useRealTimers();
});

function header(container: HTMLElement): HTMLElement {
  return container.querySelector('header.header') as HTMLElement;
}

describe('Kopfzeile', () => {
  it('normal: Slug, «3 von 3 Terminals nehmen auf», Herkunft, Reiter, Suche, Menü', async () => {
    const { app } = await makeApp('allon');
    const { container } = render(Header, { props: { app } });
    const h = header(container);
    expect(h.dataset.variant).toBe('normal');
    expect(h.textContent).toContain('ms2');
    expect(h.textContent).toContain('3 von 3 Terminals nehmen auf');
    expect(h.textContent).toContain('3 von 3 nehmen auf'); // Kurzform für < 1280 px (per CSS)
    expect(h.textContent).toContain('über sshd');
    expect(screen.getByRole('navigation', { name: 'Reiter' }).textContent).toBe('KarteTerminalsZeitachseFindings');
    expect(screen.getByRole('button', { name: 'Befehlspalette' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Menü' })).toBeTruthy();
    expect(h.querySelector('[data-badge]')).toBeNull();
    expect(h.querySelector('svg[aria-label="ARIADNE"]')).not.toBeNull();
  });

  it('pause: «T1 Pause bis HH:MM» als Ausnahme, keine Zahlen von Klärungen (E87)', async () => {
    const { app } = await makeApp('normal');
    const { container } = render(Header, { props: { app } });
    const h = header(container);
    expect(h.dataset.variant).toBe('pause');
    expect(h.textContent).toContain('2 von 3 Terminals nehmen auf');
    expect(h.querySelector('[data-badge="pause"]')?.textContent).toMatch(/T1 Pause bis \d\d:\d\d/);
    expect(h.textContent).not.toMatch(/zu klären|Klären|Denkanst/);
  });

  it('waiting: «T2 Pause · wartet auf Bestätigung», bis der Daemon bestätigt', async () => {
    const { app } = await makeApp('noconfirm');
    const { container } = render(Header, { props: { app } });
    expect(await app.pause(base.T2)).toBeNull();
    await settle();
    const h = header(container);
    expect(h.dataset.variant).toBe('waiting');
    expect(h.querySelector('[data-badge="waiting"]')?.textContent).toContain('T2 Pause · wartet auf Bestätigung');
  });

  it('waiting endet mit dem Ereignis terminal (Mock bestätigt nach 600 ms)', async () => {
    const { app } = await makeApp('allon');
    const { container } = render(Header, { props: { app } });
    await app.pause(base.T2);
    await settle();
    expect(header(container).dataset.variant).toBe('waiting');
    await until(() => header(container).dataset.variant === 'pause', 3000);
    expect(header(container).textContent).toMatch(/T2 Pause bis \d\d:\d\d/);
  });

  it('held: «…: Remote-Sitzung bei lame, nicht gespeichert»', async () => {
    const { app } = await makeApp('held');
    const { container } = render(Header, { props: { app } });
    const held = header(container).querySelector('[data-badge="held"]');
    expect(header(container).dataset.variant).toBe('held');
    expect(held?.textContent?.replace(/\s+/g, ' ')).toMatch(/pts\/4: Remote-Sitzung bei lame, nicht gespeichert/);
    expect(held?.querySelector('code')?.textContent).toBe('lame');
  });

  it('locked: Slug, «Gesperrt · im Terminal ariadne start», kein Aufnahme-Knopf', async () => {
    const { app } = await makeApp('locked');
    const { container } = render(Header, { props: { app } });
    const h = header(container);
    expect(h.dataset.variant).toBe('locked');
    expect(h.querySelector('.slug')?.textContent).toBe('ms2');
    expect(h.textContent).toContain('Gesperrt · im Terminal ariadne start');
    expect(h.textContent).toContain('Aufnahme puffert im Arbeitsspeicher');
    expect(h.querySelector('button.rec')).toBeNull();
    expect(h.textContent).toContain('über sshd');
  });

  it('noproject: «kein Projekt» und der Vorlauf im Arbeitsspeicher', async () => {
    const { app } = await makeApp('noproject');
    const { container } = render(Header, { props: { app } });
    const h = header(container);
    expect(h.dataset.variant).toBe('noproject');
    expect(h.querySelector('.slug')?.textContent).toBe('kein Projekt');
    expect(h.textContent).toContain('Vorlauf: 3 Terminals, 15 Minuten im Arbeitsspeicher');
    expect(h.querySelector('button.rec')).toBeNull();
    // Reiter stehen da, wechseln aber nichts
    expect(screen.getByRole('link', { name: 'Terminals' }).getAttribute('aria-disabled')).toBe('true');
  });

  it('offline: nach 5 s ohne Strom «Keine Verbindung · Stand HH:MM · verbindet neu …»', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
    const { app } = await makeApp('offline');
    const { container } = render(Header, { props: { app } });
    await vi.advanceTimersByTimeAsync(100);
    expect(app.offline).toBe(false);
    await vi.advanceTimersByTimeAsync(5000);
    await settle();
    const h = header(container);
    expect(app.offline).toBe(true);
    expect(h.dataset.variant).toBe('offline');
    expect(h.textContent).toMatch(/Keine Verbindung · Stand \d\d:\d\d · verbindet neu …/);
    expect(h.querySelector('button.rec')).toBeNull();
    expect(h.textContent).toContain('über sshd');
  });

  it('Präsentation: Kennzeichen in der Kopfzeile; Herkunft «lokal» (Weg E)', async () => {
    const { app } = await makeApp('present');
    const { container } = render(Header, { props: { app } });
    expect(header(container).querySelector('[data-badge="presentation"]')?.textContent).toBe('Präsentation');
    const local = await makeApp('local');
    const r2 = render(Header, { props: { app: local.app } });
    expect(header(r2.container).querySelector('.origin')?.textContent).toBe('lokal');
  });

  it('Scope-Warnung: Kennzeichen bis zum Quittieren, öffnet die Meldung', async () => {
    const { app } = await makeApp('scope');
    const { container } = render(Header, { props: { app } });
    app.ui.scopeCard = false;
    const badge = header(container).querySelector('[data-badge="scope"]') as HTMLButtonElement;
    expect(badge.textContent).toContain('Scope-Warnung');
    await fireEvent.click(badge);
    expect(app.ui.scopeCard).toBe(true);
    expect(await app.ackScopeWarning()).toBe(true);
    await settle();
    expect(header(container).querySelector('[data-badge="scope"]')).toBeNull();
    expect(app.ui.scopeCard).toBe(false);
  });

  it('feindlicher Terminal-Name erscheint nur als Text', async () => {
    const { app, backend } = await makeApp('allon');
    backend.state.terminals = backend.state.terminals.map((x) => ({ ...x, label: '<img src=x onerror=alert(1)>' }));
    await app.refreshStatus();
    const { container } = render(Header, { props: { app } });
    await fireEvent.click(container.querySelector('button.rec') as HTMLElement);
    expect(document.querySelector('img')).toBeNull();
    const name = document.querySelector('.term .name .txt') as HTMLElement;
    expect(name.textContent).toBe('<img src=x onerror=aler…');
    expect(name.title).toBe('<img src=x onerror=alert(1)>');
  });
});
