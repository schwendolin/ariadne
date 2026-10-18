// Aufnahme-Popover (SCREENS 5, E22, E107, E117): Terminals mit Pause und Fortsetzen, «wartet auf
// Bestätigung», E117-Grenze bei Ablehnung durch den Server, Projekt, Sitzung, Leerlauf, KI, F12 r.
// Besitzer: ui-fundament.
import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { installKeymap } from '../../src/lib/keys/keymap';
import * as base from '../../src/lib/mock/data/base';
import RecordingButton from '../../src/lib/shell/RecordingButton.svelte';
import { makeApp, settle, stopAll } from './helpers';

beforeAll(() => {
  installKeymap(window);
});
afterEach(stopAll);

async function openPopover(scenario: Parameters<typeof makeApp>[0]) {
  const h = await makeApp(scenario);
  const r = render(RecordingButton, { props: { app: h.app } });
  await fireEvent.click(r.container.querySelector('button.rec') as HTMLElement);
  const pop = screen.getByRole('dialog', { name: 'Aufnahme' });
  return { ...h, ...r, pop };
}

function row(pop: HTMLElement, tid: string): HTMLElement {
  return pop.querySelector(`[data-terminal="${tid}"]`) as HTMLElement;
}

describe('Aufnahme-Popover', () => {
  it('zeigt jedes Terminal mit Nummer, Namen, Zustand und Aktion', async () => {
    const { pop } = await openPopover('normal');
    expect(within(pop).getByText('Terminals')).toBeTruthy();
    expect(row(pop, base.T1).textContent).toMatch(/T1\s*scan\s*· Pause bis \d\d:\d\d/);
    expect(within(row(pop, base.T1)).getByRole('button', { name: 'Aufnahme von T1 fortsetzen' }).textContent).toBe('Fortsetzen');
    expect(row(pop, base.T2).textContent).toMatch(/T2\s*msf\s*· nimmt auf/);
    expect(within(row(pop, base.T2)).getByRole('button', { name: 'Pause für T2, 10 Minuten' }).textContent).toBe('Pause 10 min');
  });

  it('Projekt, Sitzung, Leerlauf, KI und der Hinweis F12 r', async () => {
    const { pop } = await openPopover('normal');
    const text = pop.textContent?.replace(/\s+/g, ' ') ?? '';
    expect(text).toContain('Projekt ms2 · Metasploitable2 Lab · lab');
    expect(text).toContain('Sitzung über sshd, vom Mac');
    expect(text).toContain('Leerlauf 0 h 01 min, Ende nach 12 h');
    expect(text).toContain('KI aus');
    expect(text).toContain('Im Terminal: F12 r Pause, nochmals hebt sie auf');
  });

  it('Pause: «wartet auf Bestätigung», Knopf gesperrt, bis das Ereignis kommt', async () => {
    const { pop, app, backend } = await openPopover('noconfirm');
    const spy = vi.spyOn(backend, 'pause');
    await fireEvent.click(within(row(pop, base.T2)).getByRole('button', { name: /Pause für T2/ }));
    await settle();
    expect(spy).toHaveBeenCalledWith(base.T2, 10);
    expect(row(pop, base.T2).textContent).toContain('wartet auf Bestätigung');
    // gesperrt per aria-disabled (Korrektur A13: der Knopf behält den Fokus)
    expect(within(row(pop, base.T2)).getByRole('button', { name: /Pause für T2/ }).getAttribute('aria-disabled')).toBe('true');
    expect(app.pendingPause[base.T2]?.kind).toBe('pause');
    // Ein zweiter Klick schickt nichts doppelt
    await app.pause(base.T2);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('Fortsetzen ruft resume für genau dieses Terminal', async () => {
    const { pop, backend } = await openPopover('normal');
    const spy = vi.spyOn(backend, 'resume');
    await fireEvent.click(within(row(pop, base.T1)).getByRole('button', { name: /fortsetzen/ }));
    expect(spy).toHaveBeenCalledWith(base.T1);
  });

  it('E117: Rest des Budgets wird angeboten, Ablehnung des Servers bleibt sichtbar', async () => {
    const { pop, app, backend } = await openPopover('budget');
    // T3: noch 5 min in dieser Stunde
    expect(row(pop, base.T3).textContent).toContain('Web-Pausen: noch 5 min in dieser Stunde');
    expect(within(row(pop, base.T3)).getByRole('button', { name: /Pause für T3, 5 Minuten/ }).textContent).toBe('Pause 5 min');
    // T2: Daemon ohne Budgetangabe; der Server lehnt ab (403 policy)
    const spy = vi.spyOn(backend, 'pause');
    await fireEvent.click(within(row(pop, base.T2)).getByRole('button', { name: /Pause für T2/ }));
    await settle();
    expect(spy).toHaveBeenCalledWith(base.T2, 10);
    expect(base.T2 in app.pauseRefused).toBe(true);
    expect(row(pop, base.T2).textContent).toContain('Pausenbudget aus dem Dashboard erschöpft (30 min pro Stunde). Im Terminal: F12 r');
    expect(within(row(pop, base.T2)).getByRole('button', { name: /Pause für T2/ }).getAttribute('aria-disabled')).toBe('true');
    expect(app.ui.notices.some((n) => n.kind === 'error' && n.text.includes('Pausenbudget'))).toBe(true);
  });

  it('E117: ohne Restbudget ist die Pause gesperrt und nennt den Grund', async () => {
    const { app, backend } = await makeApp('allon');
    backend.state.terminals = backend.state.terminals.map((x) => (x.terminal_id === base.T3 ? { ...x, web_pause_left_s: 20 } : x));
    await app.refreshStatus();
    const r = render(RecordingButton, { props: { app } });
    await fireEvent.click(r.container.querySelector('button.rec') as HTMLElement);
    const pop = screen.getByRole('dialog', { name: 'Aufnahme' });
    const btn = within(row(pop, base.T3)).getByRole('button', { name: /Pause für T3/ }) as HTMLButtonElement;
    expect(btn.getAttribute('aria-disabled')).toBe('true');
    expect(btn.title).toContain('Pausenbudget');
    const spy = vi.spyOn(backend, 'pause');
    await fireEvent.click(btn);
    expect(spy).not.toHaveBeenCalled();
  });

  it('held und gesperrt ohne Pausenknopf', async () => {
    const { pop } = await openPopover('held');
    expect(row(pop, base.T4).textContent).toContain('held · lame');
    expect(within(row(pop, base.T4)).queryByRole('button')).toBeNull();
  });

  it('Esc schliesst das Popover, der Fokus geht zurück zum Auslöser', async () => {
    const { app, container } = await openPopover('normal');
    const trigger = container.querySelector('button.rec') as HTMLButtonElement;
    trigger.focus();
    expect(app.ui.popover).toBe('recording');
    trigger.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await settle();
    expect(app.ui.popover).toBeNull();
    expect(screen.queryByRole('dialog', { name: 'Aufnahme' })).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});
