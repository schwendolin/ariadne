// Zustände der Anwendung (SCREENS 9, Briefing 4.1): Laden, kein Projekt, gesperrt (ohne
// Passphrase-Feld), keine Verbindung (gedämpft, Aktionen gesperrt), Projektwechsel räumt alles weg,
// leeres Projekt mit «Erste Schritte». Besitzer: ui-fundament.
import { render, screen } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as base from '../../src/lib/mock/data/base';
import FirstSteps from '../../src/lib/shell/FirstSteps.svelte';
import StateView from '../../src/lib/shell/StateView.svelte';
import { makeApp, settle, stopAll } from './helpers';

afterEach(() => {
  stopAll();
  vi.useRealTimers();
});

describe('Zustände', () => {
  it('Laden, solange kein Status da ist', async () => {
    const { app } = await makeApp('normal', { start: false });
    expect(app.phase).toBe('boot');
    render(StateView, { props: { app } });
    expect(screen.getByRole('status').textContent).toBe('Lädt …');
  });

  it('kein Projekt: Startbefehl zum Kopieren auf den Mac', async () => {
    const { app } = await makeApp('noproject');
    expect(app.phase).toBe('no_project');
    const { container } = render(StateView, { props: { app } });
    expect(screen.getByRole('heading', { name: 'Kein aktives Projekt' })).toBeTruthy();
    expect(container.textContent).toContain('Im Terminal starten. Der Vorlauf im Arbeitsspeicher lässt sich dabei übernehmen.');
    expect(container.querySelector('code')?.textContent).toBe('ariadne start ‹slug› --target ‹ziel›');
    expect(screen.getByRole('button', { name: 'Kopieren · Mac' })).toBeTruthy();
    expect(app.project).toBeNull();
  });

  it('gesperrt: Projektdaten weg, Hinweis ariadne start, kein Passphrase-Feld, kein Kopierknopf', async () => {
    const { app } = await makeApp('locked');
    expect(app.phase).toBe('locked');
    expect(app.project).toBeNull();
    const { container } = render(StateView, { props: { app } });
    expect(screen.getByRole('heading').textContent?.replace(/\s+/g, ' ')).toBe('Projekt ms2 ist gesperrt');
    expect(container.textContent).toContain('hier gibt es kein Passphrase-Feld');
    expect(container.querySelector('input')).toBeNull();
    expect(container.querySelector('button')).toBeNull();
    expect(container.querySelector('.cmd code')?.textContent).toBe('ariadne start');
  });

  it('Projektwechsel (SSE project): Projekt-Store verworfen, Abrufe abgebrochen, neu aufgebaut', async () => {
    const { app, backend } = await makeApp('normal');
    const first = app.project;
    expect(first).not.toBeNull();
    backend.inject({ name: 'project', id: null, data: { project_id: base.PID, change: 'opened', locked: false } });
    await settle(8);
    expect(first?.disposed).toBe(true);
    expect(first?.signal.aborted).toBe(true);
    expect(app.project).not.toBe(first);
    expect(app.project?.pid).toBe(base.PID);
  });

  it('A19: Projektwechsel räumt Auswahl, Zeile, Finding und Beleg des alten Projekts aus der URL', async () => {
    const { url } = await import('../../src/lib/url/state.svelte');
    const { app, backend } = await makeApp('normal');
    url.go('zeitachse', { zeile: 'alt@1', beleg: 'u:alt@1' });
    // dasselbe Projekt neu geöffnet (Sperren und Entsperren): nichts geht verloren
    backend.inject({ name: 'project', id: null, data: { project_id: base.PID, change: 'opened', locked: false } });
    await settle(8);
    expect(url.get('zeile')).toBe('alt@1');
    // ein anderes Projekt: die Parameter des alten gelten nicht mehr
    const other = '0199aaaa-0000-7000-8000-0000000000ff';
    const orig = backend.status.bind(backend);
    vi.spyOn(backend, 'status').mockImplementation(async () => {
      const st = await orig();
      return st.project ? { ...st, project: { ...st.project, id: other, slug: 'lab2' } } : st;
    });
    backend.inject({ name: 'project', id: null, data: { project_id: other, change: 'opened', locked: false } });
    await settle(8);
    expect(app.project?.pid).toBe(other);
    expect(url.get('zeile')).toBeNull();
    expect(url.get('beleg')).toBeNull();
    expect(url.route).toBe('zeitachse');
    url.go('karte', {}, { replace: true, keep: false });
  });

  it('keine Verbindung: offline nach 5 s, Aktionen gesperrt (Entscheide, Pause, Präsentation)', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
    const { app, backend } = await makeApp('offline');
    await vi.advanceTimersByTimeAsync(5100);
    expect(app.offline).toBe(true);
    const decide = vi.spyOn(backend, 'decide');
    const pause = vi.spyOn(backend, 'pause');
    const present = vi.spyOn(backend, 'setPresentation');
    expect(await app.project?.decide([{ kind: 'd.tag.add', payload: { subject: 'x', tag: 'y' } }])).toBeNull();
    expect(await app.pause(base.T2)).toBe('network');
    await app.togglePresentation();
    expect(decide).not.toHaveBeenCalled();
    expect(pause).not.toHaveBeenCalled();
    expect(present).not.toHaveBeenCalled();
    expect(app.lastGoodAt).not.toBeNull();
  });

  it('keine Verbindung durch Netzfehler, zurück sobald Status und Strom gehen', async () => {
    const { app, backend } = await makeApp('normal');
    await settle();
    app.connection = 'open';
    const status = vi.spyOn(backend, 'status').mockRejectedValueOnce(new (await import('../../src/lib/api/client')).ApiError('network', 0, 'x'));
    await app.refreshStatus();
    expect(app.offline).toBe(true);
    status.mockRestore();
    await app.refreshStatus();
    expect(app.offline).toBe(false);
  });
});

describe('Erste Schritte (leeres Projekt)', () => {
  it('Checkliste mit Startbefehl, nmap -oA zum Kopieren, F12 k, export, stop, backup', () => {
    const { container } = render(FirstSteps, { props: { slug: 'ms2', scope: ['192.168.56.0/24'] } });
    const text = container.textContent?.replace(/\s+/g, ' ') ?? '';
    expect(screen.getByRole('heading', { name: 'Erste Schritte' })).toBeTruthy();
    expect(text).toContain('Projekt gestartet ariadne start ms2 --target 192.168.56.0/24');
    expect(text).toContain('nmap mit -oA, damit Ariadne die Datei liest');
    expect(text).toContain('nmap -sV -sC -oA scans/ms2 ‹ziel›');
    expect(text).toContain('Schlüsselschritt im Terminal mit F12 k');
    expect(text).toContain('Am Ende ariadne export, ariadne stop und ariadne backup');
    expect(screen.getByRole('button', { name: 'Mac' })).toBeTruthy();
  });
});
