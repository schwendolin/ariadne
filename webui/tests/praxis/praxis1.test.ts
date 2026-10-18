// Praxistest 1 (ui): Scope erweitern im Dashboard (E129), Klärung nach nmap (E130), Out-of-Scope-
// Popover, Einstellungen, Anmeldeseite mit Code-Hinweis, Passphrase-Erkennung und Abmeldegrund.
// Mock wie der Daemon (web-api.md 20, src/ariadne/web/api/scope.py). Besitzer: ui.
import { cleanup, fireEvent, render, screen, within } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createMemoryTokenStore, looksLikePassphrase } from '../../src/lib/api/auth';
import { HttpBackend } from '../../src/lib/api/backend';
import type { NextItem } from '../../src/lib/api/types';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import ClarifyItem from '../../src/lib/next/ClarifyItem.svelte';
import ScopeEntry from '../../src/lib/next/ScopeEntry.svelte';
import ScopeAddDialog from '../../src/lib/scope/ScopeAddDialog.svelte';
import ScopeEditDialog from '../../src/lib/scope/ScopeEditDialog.svelte';
import LoginView from '../../src/lib/shell/LoginView.svelte';
import SettingsPanel from '../../src/lib/shell/SettingsPanel.svelte';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import type { ScopeAddRequest } from '../../src/lib/stores/ui.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, settle, stopAll, until } from '../fundament/helpers';

beforeAll(() => {
  installKeymap(window);
});
afterEach(() => {
  cleanup();
  stopAll();
  resetKeymapForTests();
  url.go('karte', {}, { replace: true, keep: false });
});

async function project(scenario: Parameters<typeof makeApp>[0] = 'praxis') {
  const h = await makeApp(scenario);
  const p = h.app.project as ProjectStore;
  await until(() => p.next.view !== null && p.info !== null && p.scope.view !== null);
  return { ...h, project: p };
}

const text = (el: Element) => (el.textContent ?? '').replace(/\s+/g, ' ').trim();
type ScopeItem = Extract<NextItem, { kind: 'scope_name' }>;

describe('Scope-Warnung: In den Scope aufnehmen (E129)', () => {
  it('Knopf neben «Quittieren» öffnet den Dialog mit den Zielen und Vorschlägen der Warnung', async () => {
    const { app, project: p } = await project();
    const w = p.next.view?.scope_warning;
    expect(w).toBeTruthy();
    render(ScopeEntry, { props: { app, project: p, warning: w! } });
    const btn = screen.getByRole('button', { name: 'In den Scope aufnehmen …' });
    expect(screen.getByRole('button', { name: 'Quittieren' })).toBeTruthy();
    await fireEvent.click(btn);
    const d = app.ui.dialog as ScopeAddRequest;
    expect(d.kind).toBe('scope-add');
    expect(d.source).toEqual({ cmd_id: w!.cmd_id });
    expect(d.values[0]?.value).toBe('http://recovery.vantis.internal/login');
    expect(d.values[0]?.proposals?.map((o) => o.entry)).toEqual(['recovery.vantis.internal', '*.vantis.internal']);
  });

  it('Dialog: Auswahl, genauer Eintrag gross, DNS-Hinweis; Aufnehmen schreibt, wertet neu aus, Rückgängig per revert', async () => {
    const { app, project: p, backend } = await project();
    const change = vi.spyOn(backend, 'changeScope');
    const revert = vi.spyOn(backend, 'revertScope');
    const req: ScopeAddRequest = {
      kind: 'scope-add',
      values: [{ value: 'http://recovery.vantis.internal/login', proposals: p.next.view!.scope_warning!.targets[0]!.proposals! }],
      source: { cmd_id: p.next.view!.scope_warning!.cmd_id },
    };
    const onclose = vi.fn();
    render(ScopeAddDialog, { props: { app, project: p, req, onclose } });
    await settle();
    const dlg = screen.getByRole('dialog', { name: 'In den Scope aufnehmen' });
    expect(text(dlg)).toContain('Ariadne prüft keine Namen per DNS.');
    expect(text(screen.getByTestId('scope-add-entry'))).toBe('recovery.vantis.internal');
    expect(text(dlg)).toContain('nur der Name aus der URL');
    // Wildcard wählen: der grosse Eintrag folgt
    await fireEvent.click(within(dlg).getByLabelText(/\*\.vantis\.internal/));
    expect(text(screen.getByTestId('scope-add-entry'))).toBe('*.vantis.internal');
    expect(text(dlg)).not.toContain('Öffentliche Endung');
    await fireEvent.click(within(dlg).getByRole('button', { name: 'Aufnehmen' }));
    await until(() => !!screen.queryByTestId('scope-add-done'));
    expect(change).toHaveBeenCalledWith(p.pid, { op: 'add', entry: '*.vantis.internal', source: req.source });
    expect(backend.state.scope.include).toContain('*.vantis.internal');
    // Neuauswertung über SSE (changes): «Neu ausgewertet.»
    await until(() => text(screen.getByTestId('scope-add-done')).includes('Neu ausgewertet.'), 3000);
    // Die Warnung ist danach weg (Ziel liegt im Scope)
    await until(() => p.next.view?.scope_warning === null, 3000);
    await fireEvent.click(within(dlg).getByRole('button', { name: 'Rückgängig' }));
    await until(() => revert.mock.calls.length === 1);
    expect(backend.state.scope.include).not.toContain('*.vantis.internal');
    expect(app.ui.notices.some((n) => n.text.includes('vantis'))).toBe(false); // Meldungen ohne Zieldaten
  });

  it('ohne mitgelieferte Vorschläge fragt der Dialog den Server; öffentliche Endung warnt', async () => {
    const { app, project: p, backend } = await project();
    const opts = vi.spyOn(backend, 'scopeOptions');
    const req: ScopeAddRequest = { kind: 'scope-add', values: [{ value: 'portal.vantis-group.com' }], source: { identifier: 'name:portal.vantis-group.com' } };
    render(ScopeAddDialog, { props: { app, project: p, req, onclose: () => undefined } });
    await until(() => opts.mock.calls.length === 1 && !!screen.queryByTestId('scope-add-entry'));
    const dlg = screen.getByRole('dialog');
    expect(text(screen.getByTestId('scope-add-entry'))).toBe('portal.vantis-group.com');
    expect(text(dlg)).toContain('Öffentliche Endung: nur aufnehmen, wenn der Auftrag dieses Ziel ausdrücklich nennt.');
  });

  it('Profil customer: kein Aufnehmen im Dashboard, Hinweis auf ariadne scope', async () => {
    const { app, project: p, backend } = await project('customer');
    const change = vi.spyOn(backend, 'changeScope');
    expect(p.scope.editable).toBe(false);
    render(ScopeEntry, { props: { app, project: p, warning: p.next.view!.scope_warning! } });
    const btn = screen.getByRole('button', { name: 'In den Scope aufnehmen …' }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    cleanup();
    const req: ScopeAddRequest = { kind: 'scope-add', values: [{ value: 'recovery.vantis.internal' }], source: {} };
    render(ScopeAddDialog, { props: { app, project: p, req, onclose: () => undefined } });
    await settle();
    const dlg = screen.getByRole('dialog');
    expect(text(dlg)).toContain('Im Profil customer ändert sich der Scope nur im Terminal:');
    expect(text(dlg)).toContain('ariadne scope');
    expect(within(dlg).queryByRole('button', { name: 'Aufnehmen' })).toBeNull();
    expect(change).not.toHaveBeenCalled();
  });

  it('Server lehnt ab (403 guardrail): fester Text im Dialog, kein Erfolg', async () => {
    const { app, project: p, backend } = await project();
    const { ApiError } = await import('../../src/lib/api/client');
    vi.spyOn(backend, 'changeScope').mockRejectedValueOnce(new ApiError('guardrail', 403, 'x'));
    const req: ScopeAddRequest = { kind: 'scope-add', values: [{ value: 'a.b.example', proposals: [{ entry: 'a.b.example', kind: 'name', public: false }] }], source: {} };
    render(ScopeAddDialog, { props: { app, project: p, req, onclose: () => undefined } });
    await settle();
    await fireEvent.click(screen.getByRole('button', { name: 'Aufnehmen' }));
    await until(() => !!screen.queryByRole('alert'));
    expect(screen.getByRole('alert').textContent).toContain('Ausserhalb der Lab-Allowlist');
    expect(screen.queryByTestId('scope-add-done')).toBeNull();
  });
});

describe('Klärung «In den Scope aufnehmen?» (E130)', () => {
  it('Text, Wahl Name oder Wildcard, Aufnehmen öffnet den Bestätigungsdialog mit der Wahl', async () => {
    const { app, project: p } = await project();
    const item = p.next.clarifyItems.find((i) => i.kind === 'scope_name' && i.name === 'recovery.vantis.internal') as ScopeItem;
    render(ClarifyItem, { props: { app, project: p, item, selected: true } });
    const card = document.querySelector(`[data-item-key="${item.item_key}"]`) as HTMLElement;
    expect(text(card)).toContain('recovery.vantis.internal gehört laut nmap zu 192.168.56.101. In den Scope aufnehmen?');
    expect(text(card)).not.toContain('Öffentliche Endung');
    await fireEvent.click(within(card).getByLabelText(/\*\.vantis\.internal/));
    await fireEvent.click(within(card).getByRole('button', { name: /Aufnehmen/ }));
    const d = app.ui.dialog as ScopeAddRequest;
    expect(d.kind).toBe('scope-add');
    expect(d.selected).toBe('*.vantis.internal');
    expect(d.source).toEqual({ item_key: item.item_key });
  });

  it('öffentliche Endung: Warnhinweis; Verwerfen ist d.suggestion.dismiss mit dem Schlüssel', async () => {
    const { app, project: p, backend } = await project();
    const decide = vi.spyOn(backend, 'decide');
    const item = p.next.clarifyItems.find((i) => i.kind === 'scope_name' && i.name === 'vpn.vantis-group.com') as ScopeItem;
    render(ClarifyItem, { props: { app, project: p, item, selected: true } });
    const card = document.querySelector(`[data-item-key="${item.item_key}"]`) as HTMLElement;
    expect(text(card)).toContain('Öffentliche Endung: nur aufnehmen, wenn der Auftrag dieses Ziel ausdrücklich nennt.');
    await fireEvent.click(within(card).getByRole('button', { name: /Verwerfen/ }));
    await until(() => decide.mock.calls.length === 1);
    expect(decide.mock.calls[0]?.[1][0]).toMatchObject({ kind: 'd.suggestion.dismiss', payload: { suggestion_key: item.item_key } });
    await until(() => !p.next.clarifyItems.some((i) => i.item_key === item.item_key), 3000);
  });

  it('nach dem Aufnehmen steht die Klärung als erledigt da; Rückgängig geht über revert', async () => {
    const { project: p, backend } = await project();
    const revert = vi.spyOn(backend, 'revertScope');
    const item = p.next.clarifyItems.find((i) => i.kind === 'scope_name' && i.name === 'recovery.vantis.internal') as ScopeItem;
    const res = await p.scope.change({ op: 'add', entry: 'recovery.vantis.internal', source: { item_key: item.item_key } });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    p.next.scopeAccepted(item.item_key, 'recovery.vantis.internal', res.result.decision_id);
    await until(() => p.next.done.some((d) => d.key === item.item_key), 3000);
    const done = p.next.done.find((d) => d.key === item.item_key)!;
    expect(done.state).toBe('done');
    expect(done.scopeRevert).toBe(true);
    expect(await p.next.undo(done)).toBe(true);
    expect(revert).toHaveBeenCalledWith(p.pid, res.result.decision_id);
  });
});

describe('Vorschau mit dry_run (web-api.md 20.2)', () => {
  it('öffentliche Domain ausserhalb der Lab-Allowlist: Aufnehmen gesperrt, Hinweis aufs Terminal', async () => {
    const { app, project: p, backend } = await project();
    const preview = vi.spyOn(backend, 'previewScope');
    const change = vi.spyOn(backend, 'changeScope');
    const item = p.next.clarifyItems.find((i) => i.kind === 'scope_name' && i.public) as ScopeItem;
    const req: ScopeAddRequest = { kind: 'scope-add', values: [{ value: item.name, proposals: item.choices }], source: { item_key: item.item_key } };
    render(ScopeAddDialog, { props: { app, project: p, req, onclose: () => undefined } });
    await until(() => preview.mock.calls.length > 0);
    const dlg = screen.getByRole('dialog');
    expect(text(dlg)).toContain('Ausserhalb der Lab-Allowlist');
    const btn = within(dlg).getByRole('button', { name: /^Aufnehmen/ }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    await fireEvent.click(btn);
    expect(change).not.toHaveBeenCalled();
  });

  it('Vorschau schreibt nichts; HttpBackend schickt dry_run', async () => {
    const { project: p, backend } = await project();
    const before = backend.state.scope.version;
    const r = await p.scope.preview({ op: 'add', entry: 'recovery.vantis.internal' });
    expect(r.ok && r.result.dry_run).toBe(true);
    expect(backend.state.scope.version).toBe(before);
    let body: unknown = null;
    const fetchImpl = (async (_u: string, init: RequestInit) => {
      body = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ decision_id: null, version: 3, dry_run: true }), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    const tokens = createMemoryTokenStore();
    tokens.set('x'.repeat(40), null);
    await new HttpBackend(tokens, fetchImpl).previewScope('p1', { op: 'add', entry: 'a.lab' });
    expect(body).toEqual({ op: 'add', entries: ['a.lab'], dry_run: true });
  });
});

describe('Einstellungen: Abschnitt Scope', () => {
  it('zeigt Ziele, Ausschlüsse und Zeitfenster; Entfernen und Ausschliessen per Dialog', async () => {
    const { app, project: p, backend } = await project();
    render(SettingsPanel, { props: { app } });
    const sec = screen.getByTestId('settings-scope');
    expect(text(sec)).toContain('192.168.56.0/24');
    expect(text(sec)).toContain('192.168.56.1');
    expect(text(sec)).toContain('mon-fri 08:00–18:00 Europe/Zurich');
    const removes = within(sec).getAllByRole('button', { name: 'Entfernen …' });
    expect(removes).toHaveLength(2);
    await fireEvent.click(removes[1]!);
    expect(app.ui.dialog).toEqual({ kind: 'scope-edit', op: 'remove', entry: '192.168.56.1', list: 'exclude' });
    await fireEvent.click(within(sec).getByRole('button', { name: 'Ausschliessen …' }));
    expect(app.ui.dialog).toEqual({ kind: 'scope-edit', op: 'exclude' });
    cleanup();
    const change = vi.spyOn(backend, 'changeScope');
    render(ScopeEditDialog, { props: { app, project: p, op: 'exclude', onclose: () => undefined } });
    await fireEvent.input(screen.getByLabelText('Eintrag: Adresse, Netz, Name oder *.domain'), { target: { value: '192.168.56.250' } });
    expect(text(screen.getByTestId('scope-edit-entry'))).toBe('192.168.56.250');
    await fireEvent.click(screen.getByRole('button', { name: 'Ausschliessen' }));
    await until(() => !!screen.queryByTestId('scope-edit-done'));
    expect(change).toHaveBeenCalledWith(p.pid, { op: 'exclude', entry: '192.168.56.250', source: null });
    expect(backend.state.scope.exclude).toContain('192.168.56.250');
  });

  it('Profil customer: nur Anzeige, Hinweis auf ariadne scope', async () => {
    const { app } = await project('customer');
    render(SettingsPanel, { props: { app } });
    const sec = screen.getByTestId('settings-scope');
    expect(within(sec).queryByRole('button')).toBeNull();
    expect(text(sec)).toContain('Im Profil customer ändert sich der Scope nur im Terminal: ariadne scope');
  });
});

describe('HttpBackend: Routen aus web-api.md 20', () => {
  it('POST /scope/changes mit entries, revert mit decision_id, GET /scope', async () => {
    const calls: { url: string; method: string; body: unknown }[] = [];
    const fetchImpl = (async (u: string, init: RequestInit) => {
      calls.push({ url: u, method: init.method ?? 'GET', body: init.body ? JSON.parse(String(init.body)) : null });
      return new Response(JSON.stringify({ decision_id: 'd1', version: 2 }), { status: 201, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    const tokens = createMemoryTokenStore();
    tokens.set('x'.repeat(40), null);
    const b = new HttpBackend(tokens, fetchImpl);
    await b.changeScope('p1', { op: 'add', entry: 'recovery.vantis.internal', source: { cmd_id: 'c1' } });
    await b.revertScope('p1', 'd1');
    await b.scope('p1');
    expect(calls[0]?.url).toBe('/api/v1/p/p1/scope/changes');
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.body).toMatchObject({ op: 'add', entries: ['recovery.vantis.internal'] });
    expect(calls[0]?.body).not.toHaveProperty('source');
    expect(calls[1]?.body).toMatchObject({ op: 'revert', decision_id: 'd1' });
    expect(calls[1]?.body).not.toHaveProperty('entries');
    expect(calls[2]).toMatchObject({ url: '/api/v1/p/p1/scope', method: 'GET' });
  });
});

describe('Anmeldeseite (Praxistest 1)', () => {
  it('Hinweis auf ariadne ui --code, Muster des Codes', async () => {
    const { app } = await makeApp('login');
    const r = render(LoginView, { props: { app } });
    expect(text(r.container)).toContain('Code im Terminal holen: ariadne ui --code (oder ariadne ui öffnet den Browser direkt)');
    const input = screen.getByLabelText('Anmeldecode') as HTMLInputElement;
    expect(input.placeholder).toBe('XXXXX-XXXXX');
    expect(input.getAttribute('aria-describedby')).toContain('login-pattern');
  });

  it('Passphrase statt Code: Hinweis, nichts geht an den Server', async () => {
    const { app, backend } = await makeApp('login');
    const spy = vi.spyOn(backend, 'login');
    render(LoginView, { props: { app } });
    const input = screen.getByLabelText('Anmeldecode') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: 'meinegeheimepassphrase!' } });
    expect(screen.getByRole('note').textContent).toBe('Das ist der Einmal-Code aus dem Terminal, nicht die Passphrase.');
    await fireEvent.input(input, { target: { value: 'geheimespasswort' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Anmelden' }));
    await settle();
    expect(screen.getByRole('alert').textContent).toBe('Das ist der Einmal-Code aus dem Terminal, nicht die Passphrase.');
    expect(spy).not.toHaveBeenCalled();
    // ein echter Tippcode ohne Bindestrich gilt nicht als Passphrase
    await fireEvent.input(input, { target: { value: 'K7Q2M4ZX9P' } });
    expect(screen.queryByRole('note')).toBeNull();
  });

  it('looksLikePassphrase: Codes nie, Sätze und Sonderzeichen ja', () => {
    expect(looksLikePassphrase('ABCDE-FGHJK')).toBe(false);
    expect(looksLikePassphrase('abcdefghjk')).toBe(false);
    expect(looksLikePassphrase('FALSCH00')).toBe(false);
    expect(looksLikePassphrase('Ab3_' + 'x'.repeat(18))).toBe(false);
    expect(looksLikePassphrase('kurz')).toBe(false);
    expect(looksLikePassphrase('correct horse battery')).toBe(true);
    expect(looksLikePassphrase('Sommer2026!')).toBe(true);
    expect(looksLikePassphrase('geheimespasswort')).toBe(true);
  });

  it('Abmeldegrund: Ereignis session vor dem Ende ergibt «Projekt ms2 wurde beendet (ariadne stop)»', async () => {
    const { app, backend } = await makeApp('normal');
    expect(app.phase).toBe('project');
    backend.endSession('stop');
    await settle();
    expect(app.phase).toBe('login');
    expect(app.endNotice).toEqual({ reason: 'stop', slug: 'ms2' });
    render(LoginView, { props: { app } });
    expect(screen.getByTestId('login-ended').textContent).toBe('Projekt ms2 wurde beendet (ariadne stop). Neue Anmeldung: ariadne ui');
  });

  it('Abmeldegrund aus project (locked) und Neustart (keine Verbindung vor dem 401)', async () => {
    const a = await makeApp('normal');
    a.backend.inject({ name: 'project', id: null, data: { project_id: null, change: 'locked', locked: true } });
    await a.backend.logout();
    await a.app.refreshStatus();
    await settle();
    expect(a.app.endNotice?.reason).toBe('lock');
    stopAll();
    const b = await makeApp('normal');
    b.app.offline = true;
    await b.backend.logout();
    await b.app.refreshStatus();
    await settle();
    expect(b.app.endNotice?.reason).toBe('restart');
  });

  it('selbst abmelden zeigt keinen Grund; neue Anmeldung löscht ihn', async () => {
    const { app, backend } = await makeApp('normal');
    await app.logout();
    expect(app.endNotice).toBeNull();
    backend.state.scenario = 'normal';
    await app.login('ABCDEFGHJK');
    expect(app.endNotice).toBeNull();
  });
});
