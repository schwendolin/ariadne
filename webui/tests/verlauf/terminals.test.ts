// Reiter Terminals (Screen 5) und Kontext-Dialog (Screen 10) gegen den Mock: Zustände je Zeile,
// held und geschlossen ohne Aktionen, Pause mit Bestätigung und Budget, Vorschlag übernehmen (a),
// Kontext setzen (↵, e) mit Vorschlägen, accept/set/push/pop, Warnungen ohne Zieldaten in der
// Meldung, Prüfung wie der Server, beendetes Terminal nur rückwirkend, Name ändern.
// Besitzer: ui-verlauf.
import { cleanup, fireEvent, render, screen, within } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { ContextOp, DecisionInput } from '../../src/lib/api/types';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { T1, T2, T3, T4 } from '../../src/lib/mock/data/base';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import ContextDialog from '../../src/lib/terminals/ContextDialog.svelte';
import TerminalsView from '../../src/lib/terminals/TerminalsView.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, press, settle, stopAll, until } from '../fundament/helpers';

beforeAll(() => {
  installKeymap(window);
});

afterEach(() => {
  cleanup();
  resetKeymapForTests();
  stopAll();
  document.body.replaceChildren();
  url.go('karte', {}, { replace: true, keep: false });
});

async function mount(scenario: Parameters<typeof makeApp>[0] = 'normal') {
  url.go('terminals', {}, { replace: true, keep: false });
  const h = await makeApp(scenario);
  const project = h.app.project as ProjectStore;
  await until(() => project.terminals.loaded && project.terminals.inputs.length > 0);
  const view = render(TerminalsView, { props: { app: h.app, project } });
  await until(() => view.container.querySelectorAll('li[data-terminal]').length > 0);
  return { ...h, project, view };
}

const rowOf = (c: HTMLElement, tid: string) => {
  const el = Array.from(c.querySelectorAll<HTMLElement>('li[data-terminal]')).find((x) => x.dataset.terminal === tid);
  if (!el) throw new Error(`Zeile ${tid} fehlt`);
  return el;
};
const buttons = (el: HTMLElement) => Array.from(el.querySelectorAll('button')).map((b) => b.textContent?.trim() ?? '');

describe('Terminals: Zeilen', () => {
  it('zeigt Name, tty, Aufnahme, Kontext, letzten Befehl und die passenden Aktionen', async () => {
    const { view } = await mount();
    const t1 = rowOf(view.container, T1);
    expect(t1.textContent).toContain('T1');
    expect(t1.textContent).toContain('scan');
    expect(t1.textContent).toContain('pts/1');
    expect(t1.textContent).toContain('Pause bis');
    expect(t1.textContent).toContain('nmap -sV -sC 192.168.56.110');
    expect(t1.textContent).toContain('Exit 0');
    expect(buttons(t1)).toContain('Fortsetzen');
    expect(buttons(t1)).toContain('Kontext setzen');

    const t2 = rowOf(view.container, T2);
    expect(t2.textContent).toContain('nimmt auf');
    expect(t2.textContent).toContain('192.168.56.101');
    expect(t2.textContent).toContain('msfconsole -q');
    expect(t2.textContent).toContain('läuft');
    expect(t2.textContent).toContain('Remote-Segment seit');
    expect(t2.textContent).toContain('41 Zeilen ohne Befehlsgrenzen');
    // verdeckte Eingabe ohne Echo, Aufdecken einzeln, nie der Wert im Markup
    expect(t2.textContent).toContain('Eingabe ohne Echo');
    expect(t2.textContent).toContain('••••••••');
    expect(t2.textContent).not.toContain('mock-Ziel-Passwort');
    expect(buttons(t2).some((b) => b.startsWith('Pause 10 min'))).toBe(true);

    const t3 = rowOf(view.container, T3);
    expect(t3.textContent).toContain('Vorschlag');
    expect(buttons(t3).some((b) => b.startsWith('Vorschlag übernehmen'))).toBe(true);
    expect(buttons(t3).some((b) => b.startsWith('Anderer Host'))).toBe(true);
    expect(buttons(t3)).not.toContain('Kontext setzen');
    expect(t3.classList.contains('suggest')).toBe(true);

    expect(view.container.textContent).toContain('F12 h');
  });

  it('verdeckte Eingabe einzeln aufdecken und wieder verdecken', async () => {
    const { view, backend } = await mount();
    const spy = vi.spyOn(backend, 'reveal');
    const t2 = rowOf(view.container, T2);
    const reveal = within(t2).getByRole('button', { name: /aufdecken/i });
    await fireEvent.click(reveal);
    await until(() => !!t2.textContent?.includes('mock-Ziel-Passwort'));
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[1]).toEqual({ ref: 'input', seq: 47001 });
    await fireEvent.click(within(t2).getByRole('button', { name: /verdecken/i }));
    await until(() => !t2.textContent?.includes('mock-Ziel-Passwort'));
  });

  it('held: gestrichelte Zeile ohne Daten und ohne Aktionen', async () => {
    const { view } = await mount('held');
    const t4 = rowOf(view.container, T4);
    expect(t4.classList.contains('held')).toBe(true);
    expect(t4.textContent).toContain('Remote-Sitzung beim Projekt');
    expect(t4.textContent).toContain('lame');
    expect(t4.textContent).toContain('wird nicht gespeichert');
    expect(t4.querySelectorAll('button')).toHaveLength(0);
  });

  it('ein verschwundenes Terminal bleibt gedämpft als «geschlossen» stehen, ohne Aktionen', async () => {
    const { view, project, backend } = await mount();
    backend.state.terminals = backend.state.terminals.filter((x) => x.terminal_id !== T1);
    await project.terminals.load();
    await settle();
    const t1 = rowOf(view.container, T1);
    expect(t1.classList.contains('closed')).toBe(true);
    expect(t1.textContent).toContain('geschlossen');
    expect(t1.textContent).toContain('steht in der Zeitachse');
    expect(buttons(t1)).not.toContain('Fortsetzen');
    expect(buttons(t1)).not.toContain('Kontext setzen');
    expect(buttons(t1)).not.toContain('Name ändern');
    // Reihenfolge: offene zuerst, dann geschlossene
    const order = Array.from(view.container.querySelectorAll<HTMLElement>('li[data-terminal]')).map((x) => x.dataset.terminal);
    expect(order).toEqual([T2, T3, T1]);
  });

  it('leer: Hinweis statt Liste', async () => {
    url.go('terminals', {}, { replace: true, keep: false });
    const h = await makeApp('normal');
    h.backend.state.terminals = [];
    const project = h.app.project as ProjectStore;
    await project.terminals.load();
    // die eben geladenen bleiben als «geschlossen» stehen; für den Leerzustand verwerfen
    project.terminals.closed = [];
    render(TerminalsView, { props: { app: h.app, project } });
    await settle();
    expect(screen.getByText('Noch keine Terminals')).toBeTruthy();
  });
});

describe('Terminals: Pause', () => {
  it('Pause 10 min: wartet auf Bestätigung, dann «Pause bis» und Fortsetzen', async () => {
    const { view, backend } = await mount();
    const spy = vi.spyOn(backend, 'pause');
    const t2 = rowOf(view.container, T2);
    const btn = within(t2).getByRole('button', { name: /Pause für T2/ });
    await fireEvent.click(btn);
    expect(spy).toHaveBeenCalledWith(T2, 10);
    await until(() => !!rowOf(view.container, T2).textContent?.includes('wartet auf Bestätigung'));
    await until(() => !!rowOf(view.container, T2).textContent?.includes('Pause bis'), 4000);
    expect(buttons(rowOf(view.container, T2))).toContain('Fortsetzen');
  });

  it('Fortsetzen ruft resume', async () => {
    const { view, backend } = await mount();
    const spy = vi.spyOn(backend, 'resume');
    await fireEvent.click(within(rowOf(view.container, T1)).getByRole('button', { name: /Aufnahme von T1 fortsetzen/ }));
    expect(spy).toHaveBeenCalledWith(T1);
    await until(() => !!rowOf(view.container, T1).textContent?.includes('nimmt auf'), 4000);
  });

  it('Budget: Rest unter 30 min wird angezeigt und begrenzt die Pause', async () => {
    const { view, backend } = await mount('budget');
    const t3 = rowOf(view.container, T3);
    expect(t3.textContent).toContain('noch 5 min in dieser Stunde');
    const spy = vi.spyOn(backend, 'pause');
    await fireEvent.click(within(t3).getByRole('button', { name: /Pause für T3, 5 Minuten/ }));
    expect(spy).toHaveBeenCalledWith(T3, 5);
  });

  it('Budget erschöpft: Knopf gesperrt mit Grund', async () => {
    url.go('terminals', {}, { replace: true, keep: false });
    const h = await makeApp('normal');
    h.backend.state.terminals = h.backend.state.terminals.map((x) => (x.terminal_id === T2 ? { ...x, web_pause_left_s: 0 } : x));
    const project = h.app.project as ProjectStore;
    await project.terminals.load();
    const view = render(TerminalsView, { props: { app: h.app, project } });
    await settle();
    const t2 = rowOf(view.container, T2);
    expect(t2.textContent).toContain('Pausenbudget aus dem Dashboard erschöpft');
    const btn = within(t2).getByRole('button', { name: /Pause für T2/ });
    expect(btn.getAttribute('aria-disabled') === 'true' || (btn as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('Terminals: Tastatur und Vorschlag', () => {
  it('j und k wählen, a übernimmt den Vorschlag, ↵ öffnet den Kontext-Dialog', async () => {
    const { view, app, backend } = await mount();
    const spy = vi.spyOn(backend, 'setContext');
    const current = () => view.container.querySelector<HTMLElement>('li[aria-current="true"]')?.dataset.terminal;
    expect(current()).toBe(T1);
    press('j');
    await settle();
    expect(current()).toBe(T2);
    // T2 hat keinen Vorschlag: a tut nichts
    press('a');
    await settle();
    expect(spy).not.toHaveBeenCalled();
    press('j');
    await settle();
    expect(current()).toBe(T3);
    press('a');
    await until(() => spy.mock.calls.length === 1);
    expect(spy.mock.calls[0]).toEqual([T3, { op: 'accept', item_key: `ctx:${T3}@412` }]);
    await until(() => app.ui.notices.some((n) => n.text === 'Kontext übernommen'));
    press('k');
    await settle();
    expect(current()).toBe(T2);
    press('Enter');
    await settle();
    expect(app.ui.dialog).toMatchObject({ kind: 'context', terminalId: T2 });
  });

  it('Tasten wirken nicht, solange eine Tafel offen ist', async () => {
    const { view } = await mount();
    url.set({ beleg: 'u:x' }, { push: false });
    press('j');
    await settle();
    expect(view.container.querySelector<HTMLElement>('li[aria-current="true"]')?.dataset.terminal).toBe(T1);
  });

  it('Warnungen beim Übernehmen nennen keine Zieldaten in der Meldung', async () => {
    const { view, app, backend } = await mount();
    vi.spyOn(backend, 'setContext').mockResolvedValue({ stored: true, stack: [], warnings: [{ code: 'scope_out', host: 'evil\u001b[31m' }], decision_id: null });
    await fireEvent.click(within(rowOf(view.container, T3)).getByRole('button', { name: /Vorschlag übernehmen/ }));
    await until(() => app.ui.notices.some((n) => n.text.includes('ausserhalb des Scopes')));
    expect(app.ui.notices.every((n) => !n.text.includes('evil'))).toBe(true);
    expect(app.ui.notices.some((n) => n.text === 'Host liegt ausserhalb des Scopes')).toBe(true);
  });

  it('Name ändern: d.terminal.label, Esc bricht ab, über 64 Zeichen abgelehnt', async () => {
    const { view, app, backend } = await mount();
    const spy = vi.spyOn(backend, 'decide');
    const t1 = rowOf(view.container, T1);
    await fireEvent.click(within(t1).getByRole('button', { name: 'Name von T1 ändern' }));
    const input = within(t1).getByLabelText('Name des Terminals') as HTMLInputElement;
    expect(input.value).toBe('scan');
    await fireEvent.input(input, { target: { value: 'x'.repeat(65) } });
    await fireEvent.keyDown(input, { key: 'Enter' });
    await settle();
    expect(t1.textContent).toContain('Höchstens 64 Zeichen');
    expect(spy).not.toHaveBeenCalled();
    await fireEvent.input(input, { target: { value: '  recon  ' } });
    await fireEvent.keyDown(input, { key: 'Enter' });
    await until(() => spy.mock.calls.length === 1);
    const d = spy.mock.calls[0]?.[1] as DecisionInput[];
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ kind: 'd.terminal.label', payload: { terminal_id: T1, label: 'recon' } });
    await until(() => app.ui.notices.some((n) => n.text === 'Name gespeichert'));
    await until(() => !!rowOf(view.container, T1).textContent?.includes('recon'));

    await fireEvent.click(within(rowOf(view.container, T1)).getByRole('button', { name: 'Name von T1 ändern' }));
    const again = within(rowOf(view.container, T1)).getByLabelText('Name des Terminals');
    await fireEvent.keyDown(again, { key: 'Escape' });
    await settle();
    expect(within(rowOf(view.container, T1)).queryByLabelText('Name des Terminals')).toBeNull();
  });

  it('Link «Zeitachse» filtert auf das Terminal', async () => {
    const { view } = await mount();
    const link = within(rowOf(view.container, T2)).getByRole('link', { name: 'Zeitachse von T2' });
    expect(link.getAttribute('href')).toContain('terminal=');
    await fireEvent.click(link);
    expect(url.route).toBe('zeitachse');
    expect(url.get('terminal')).toBe(T2);
  });
});

async function dialog(tid: string, opts: { itemKey?: string; fromOff?: number; scenario?: Parameters<typeof makeApp>[0] } = {}) {
  const h = await makeApp(opts.scenario ?? 'normal');
  const project = h.app.project as ProjectStore;
  await until(() => project.terminals.loaded && !!project.map.graph);
  const onclose = vi.fn();
  const spy = vi.spyOn(h.backend, 'setContext');
  const view = render(ContextDialog, { props: { app: h.app, project, terminalId: tid, itemKey: opts.itemKey, fromOff: opts.fromOff, onclose } });
  await settle();
  const host = () => screen.getByLabelText('Host') as HTMLInputElement;
  const from = () => screen.getByLabelText('Gilt ab') as HTMLSelectElement;
  const mode = () => screen.getByLabelText('Wirkung') as HTMLSelectElement;
  const submit = async () => {
    await fireEvent.click(screen.getByRole('button', { name: 'Setzen' }));
    await settle();
  };
  return { ...h, project, view, onclose, spy, host, from, mode, submit };
}

describe('Kontext-Dialog', () => {
  it('Vorschlag aus dem Callback ist vorausgewählt und geht als accept', async () => {
    const d = await dialog(T3, { itemKey: `ctx:${T3}@412` });
    expect(screen.getByRole('dialog').textContent).toContain('Kontext für T3 «listener»');
    expect(d.host().value).toBe('192.168.56.101');
    expect(d.from().value).toBe('offset');
    const opts = screen.getByRole('list', { name: 'Vorschläge' });
    expect(opts.textContent).toContain('Vorschlag aus Callback');
    // die Eingabe filtert die bekannten Hosts; leer zeigt sie alle
    await fireEvent.input(d.host(), { target: { value: '' } });
    await settle();
    expect(screen.getByRole('list', { name: 'Vorschläge' }).textContent).toContain('bekannt');
    await fireEvent.click(screen.getAllByRole('button', { name: /Vorschlag aus Callback/ })[0] as HTMLElement);
    expect(d.host().value).toBe('192.168.56.101');
    await d.submit();
    await until(() => d.spy.mock.calls.length === 1);
    expect(d.spy.mock.calls[0]).toEqual([T3, { op: 'accept', item_key: `ctx:${T3}@412` }]);
    await until(() => d.onclose.mock.calls.length === 1);
    expect(d.app.ui.notices.some((n) => n.text === 'Kontext gesetzt')).toBe(true);
  });

  it('anderer Host ab dem Vorschlag geht als set mit from_off; Warnung bleibt im Dialog', async () => {
    const d = await dialog(T3, { itemKey: `ctx:${T3}@412` });
    await fireEvent.input(d.host(), { target: { value: '10.9.9.9' } });
    await settle();
    expect(screen.getByRole('list', { name: 'Vorschläge' }).textContent).toContain('unbekannter Host');
    await fireEvent.input(screen.getByLabelText('Benutzer'), { target: { value: 'www-data' } });
    await d.submit();
    await until(() => d.spy.mock.calls.length === 1);
    expect(d.spy.mock.calls[0]?.[1]).toEqual({ op: 'set', host: '10.9.9.9', user: 'www-data', from_off: 412 } satisfies ContextOp);
    await until(() => !!screen.queryByText('Gesetzt, mit Hinweis'));
    expect(screen.getByRole('status').textContent).toContain('10.9.9.9');
    expect(screen.getByRole('status').textContent).toContain('liegt ausserhalb des Scopes');
    expect(d.onclose).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Schliessen' }));
    expect(d.onclose).toHaveBeenCalled();
  });

  it('ab jetzt ohne Offset; Auswahl aus den bekannten Hosts', async () => {
    const d = await dialog(T1);
    expect(d.host().value).toBe('');
    expect(d.from().value).toBe('now');
    const known = Array.from(screen.getByRole('list', { name: 'Vorschläge' }).querySelectorAll('button'));
    expect(known.length).toBeGreaterThan(0);
    const first = known[0] as HTMLButtonElement;
    const label = first.querySelector('.mono')?.textContent ?? '';
    await fireEvent.click(first);
    expect(d.host().value).toBe(label);
    await d.submit();
    await until(() => d.spy.mock.calls.length === 1);
    expect(d.spy.mock.calls[0]?.[1]).toEqual({ op: 'set', host: label });
  });

  it('Neue Stufe öffnen mit Art; Stufe schliessen als pop', async () => {
    const d = await dialog(T2);
    expect(d.host().value).toBe('192.168.56.101');
    await fireEvent.change(d.mode(), { target: { value: 'push' } });
    await settle();
    const kind = screen.getByLabelText('Art') as HTMLSelectElement;
    await fireEvent.change(kind, { target: { value: 'ssh' } });
    await fireEvent.input(screen.getByLabelText('Benutzer'), { target: { value: 'msfadmin' } });
    await d.submit();
    await until(() => d.spy.mock.calls.length === 1);
    expect(d.spy.mock.calls[0]?.[1]).toEqual({ op: 'push', kind: 'ssh', host: '192.168.56.101', user: 'msfadmin' });

    cleanup();
    const e = await dialog(T2);
    await fireEvent.click(screen.getByRole('button', { name: 'Stufe schliessen' }));
    await until(() => e.spy.mock.calls.length === 1);
    expect(e.spy.mock.calls[0]?.[1]).toEqual({ op: 'pop' });
  });

  it('Kali-Terminal ohne Stufe: kein «Stufe schliessen»', async () => {
    await dialog(T1);
    expect(screen.queryByRole('button', { name: 'Stufe schliessen' })).toBeNull();
  });

  it('prüft wie der Server: Host fehlt, Leerzeichen, Steuerzeichen, Benutzer', async () => {
    const d = await dialog(T1);
    await d.submit();
    expect(screen.getByRole('alert').textContent).toBe('Host fehlt');
    await fireEvent.input(d.host(), { target: { value: 'a b' } });
    await d.submit();
    expect(screen.getByRole('alert').textContent).toContain('ohne Leerzeichen');
    await fireEvent.input(d.host(), { target: { value: 'host\u202e' } });
    await d.submit();
    expect(screen.getByRole('alert').textContent).toContain('Steuerzeichen');
    await fireEvent.input(d.host(), { target: { value: '10.0.0.1' } });
    await fireEvent.input(screen.getByLabelText('Benutzer'), { target: { value: 'a b' } });
    await d.submit();
    expect(screen.getByRole('alert').textContent).toContain('Benutzer');
    expect(d.spy).not.toHaveBeenCalled();
  });

  it('Fehler des Servers inline, Dialog bleibt offen', async () => {
    const d = await dialog(T1);
    d.spy.mockRejectedValue(new Error('boom'));
    await fireEvent.input(d.host(), { target: { value: '10.0.0.1' } });
    await d.submit();
    await until(() => !!screen.queryByRole('alert'));
    expect(screen.getByRole('alert').textContent).toContain('Kontext nicht gesetzt');
    expect(d.onclose).not.toHaveBeenCalled();
  });

  it('stored:false meldet «Nur der Stapel ist gesetzt»', async () => {
    const d = await dialog(T1);
    d.spy.mockResolvedValue({ stored: false, stack: [], warnings: [], decision_id: null });
    await fireEvent.input(d.host(), { target: { value: '192.168.56.101' } });
    await d.submit();
    await until(() => d.app.ui.notices.some((n) => n.text.startsWith('Nur der Stapel ist gesetzt')));
    expect(d.onclose).toHaveBeenCalled();
  });

  it('beendetes Terminal: nur rückwirkend, keine neue Stufe, kein «ab jetzt»', async () => {
    const h = await makeApp('normal');
    const project = h.app.project as ProjectStore;
    await until(() => project.terminals.loaded);
    h.backend.state.terminals = h.backend.state.terminals.filter((x) => x.terminal_id !== T2);
    await project.terminals.load();
    expect(project.terminals.isClosed(T2)).toBe(true);
    const spy = vi.spyOn(h.backend, 'setContext');
    render(ContextDialog, { props: { app: h.app, project, terminalId: T2, onclose: () => undefined } });
    await settle();
    expect(screen.getAllByText('Terminal geschlossen: nur rückwirkend setzen').length).toBeGreaterThan(0);
    const from = screen.getByLabelText('Gilt ab') as HTMLSelectElement;
    expect(from.value).toBe('stage');
    expect((from.querySelector('option[value="now"]') as HTMLOptionElement).disabled).toBe(true);
    expect((screen.getByLabelText('Wirkung').querySelector('option[value="push"]') as HTMLOptionElement).disabled).toBe(true);
    expect(screen.queryByRole('button', { name: 'Stufe schliessen' })).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Setzen' }));
    await until(() => spy.mock.calls.length === 1);
    expect(spy.mock.calls[0]?.[1]).toEqual({ op: 'set', host: '192.168.56.101', from_off: 20480 });
  });
});
