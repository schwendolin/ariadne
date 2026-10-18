// Praxistest 2 (ui): offener Scope (E131) in Einstellungen, Kopfzeile, Zeitachse; Lab-Allowlist (E132)
// und sehr breite Einträge (E133). Mock wie der Daemon (web-api.md 20). Besitzer: ui.
import { cleanup, fireEvent, render, screen, within } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createMemoryTokenStore } from '../../src/lib/api/auth';
import { HttpBackend } from '../../src/lib/api/backend';
import type { TimelineItem } from '../../src/lib/api/types';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { addCommand } from '../../src/lib/scope/open';
import ScopeEditDialog from '../../src/lib/scope/ScopeEditDialog.svelte';
import ScopeOpenDialog from '../../src/lib/scope/ScopeOpenDialog.svelte';
import HeaderBadges from '../../src/lib/shell/HeaderBadges.svelte';
import SettingsPanel from '../../src/lib/shell/SettingsPanel.svelte';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import TimelineRow from '../../src/lib/timeline/TimelineRow.svelte';
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

async function project(scenario: Parameters<typeof makeApp>[0] = 'zu') {
  const h = await makeApp(scenario);
  const p = h.app.project as ProjectStore;
  await until(() => p.next.view !== null && p.info !== null && p.scope.view !== null);
  return { ...h, project: p };
}

const text = (el: Element) => (el.textContent ?? '').replace(/\s+/g, ' ').trim();
const submitBtn = (dlg: HTMLElement, name: string) => within(dlg).getByRole('button', { name: new RegExp(`^${name}`) }) as HTMLButtonElement;
type Decision = Extract<TimelineItem, { type: 'decision' }>;

describe('Einstellungen: offener Scope (E131)', () => {
  it('geschlossen: Zustandszeile, «Scope öffnen …» und «Hinzufügen …» öffnen die Dialoge', async () => {
    const { app } = await project('zu');
    render(SettingsPanel, { props: { app } });
    const sec = screen.getByTestId('settings-scope');
    expect(text(screen.getByTestId('scope-state'))).toContain('Geschlossen: nur die Einschlüsse');
    await fireEvent.click(within(sec).getByRole('button', { name: 'Scope öffnen …' }));
    expect(app.ui.dialog).toEqual({ kind: 'scope-open', op: 'open' });
    await fireEvent.click(within(sec).getByRole('button', { name: 'Hinzufügen …' }));
    expect(app.ui.dialog).toEqual({ kind: 'scope-edit', op: 'add' });
  });

  it('offen ohne Einschlüsse: «offen» statt «keine», «Scope schliessen …»', async () => {
    const { app } = await project('offen');
    render(SettingsPanel, { props: { app } });
    const sec = screen.getByTestId('settings-scope');
    expect(text(screen.getByTestId('scope-state'))).toContain('Offen: alles gilt als im Scope, ausser Ausschlüssen');
    expect(text(sec)).toContain('Ziele offen');
    await fireEvent.click(within(sec).getByRole('button', { name: 'Scope schliessen …' }));
    expect(app.ui.dialog).toEqual({ kind: 'scope-open', op: 'close' });
  });

  it('Profil customer: kein Knopf zum Öffnen oder Hinzufügen', async () => {
    const { app } = await project('customer');
    render(SettingsPanel, { props: { app } });
    const sec = screen.getByTestId('settings-scope');
    expect(text(screen.getByTestId('scope-state'))).toContain('Geschlossen');
    expect(within(sec).queryByRole('button', { name: 'Scope öffnen …' })).toBeNull();
    expect(within(sec).queryByRole('button', { name: 'Hinzufügen …' })).toBeNull();
  });
});

describe('Dialog Scope öffnen (E131)', () => {
  it('mit bestätigtem «kein Kundenauftrag»: dry_run, Wirkung, Öffnen, Kennzeichen, Rückgängig nach Bestätigung', async () => {
    const { app, project: p, backend } = await project('zu');
    const preview = vi.spyOn(backend, 'previewScope');
    const change = vi.spyOn(backend, 'changeScope');
    const revert = vi.spyOn(backend, 'revertScope');
    render(ScopeOpenDialog, { props: { app, project: p, op: 'open', onclose: () => undefined } });
    await until(() => preview.mock.calls.length === 1);
    await settle();
    const dlg = screen.getByRole('dialog', { name: 'Scope öffnen' });
    expect(text(screen.getByTestId('scope-open-text'))).toBe(
      'Danach gilt alles als im Scope: jede IP, jeder Name, auch öffentliche Ziele wie github.com. Werte anerkannter Parser gehen automatisch auf die Karte, Scope-Warnungen entfallen. Ausschlüsse gelten weiter. Ariadne schickt den Zielen nichts.',
    );
    expect(screen.queryByTestId('scope-open-blocked')).toBeNull();
    expect(backend.state.scope.open).toBe(false);
    await fireEvent.click(submitBtn(dlg, 'Scope öffnen'));
    await until(() => !!screen.queryByTestId('scope-open-done'));
    expect(change).toHaveBeenCalledWith(p.pid, { op: 'open', entry: '', source: null });
    expect(backend.state.scope.open).toBe(true);
    await until(() => p.scope.view?.open === true);
    expect(app.ui.notices.some((n) => n.text === 'Scope geöffnet. Ariadne wertet neu aus.')).toBe(true);
    // Rückgängig erst nach Bestätigung mit Wirkung
    await fireEvent.click(within(dlg).getByRole('button', { name: 'Rückgängig' }));
    expect(revert).not.toHaveBeenCalled();
    expect(text(screen.getByTestId('scope-open-undo-confirm'))).toBe('Rückgängig schliesst den Scope wieder: danach gelten nur die Einschlüsse.');
    await fireEvent.click(within(dlg).getByRole('button', { name: 'Rückgängig machen' }));
    await until(() => revert.mock.calls.length === 1);
    await until(() => backend.state.scope.open === false);
  });

  it('ohne «kein Kundenauftrag»: gesperrt mit Hinweis auf ariadne scope open, nichts geschrieben', async () => {
    const { app, project: p, backend } = await project('normal');
    const change = vi.spyOn(backend, 'changeScope');
    render(ScopeOpenDialog, { props: { app, project: p, op: 'open', onclose: () => undefined } });
    await until(() => !!screen.queryByTestId('scope-open-blocked'));
    const dlg = screen.getByRole('dialog', { name: 'Scope öffnen' });
    expect(text(screen.getByTestId('scope-open-blocked'))).toContain('Öffnen braucht einmal die Bestätigung im Terminal: ariadne scope open');
    expect(submitBtn(dlg, 'Scope öffnen').disabled).toBe(true);
    expect(change).not.toHaveBeenCalled();
    // der Server lehnt ohnehin ab (403 guardrail)
    const r = await p.scope.change({ op: 'open', entry: '', source: null });
    expect(r.ok === false && r.code === 'guardrail').toBe(true);
    expect(backend.state.scope.open).toBe(false);
  });

  it('403 guardrail beim Schreiben sperrt ebenfalls', async () => {
    const { app, project: p, backend } = await project('zu');
    const { ApiError } = await import('../../src/lib/api/client');
    vi.spyOn(backend, 'changeScope').mockRejectedValueOnce(new ApiError('guardrail', 403, 'x'));
    render(ScopeOpenDialog, { props: { app, project: p, op: 'open', onclose: () => undefined } });
    await settle(8);
    const dlg = screen.getByRole('dialog', { name: 'Scope öffnen' });
    await fireEvent.click(submitBtn(dlg, 'Scope öffnen'));
    await until(() => !!screen.queryByTestId('scope-open-blocked'));
    expect(submitBtn(dlg, 'Scope öffnen').disabled).toBe(true);
  });
});

describe('Dialog Scope schliessen (E131)', () => {
  it('ohne Einschluss (409 no_include): gesperrt mit «Zuerst einen Eintrag hinzufügen»', async () => {
    const { app, project: p, backend } = await project('offen');
    const change = vi.spyOn(backend, 'changeScope');
    render(ScopeOpenDialog, { props: { app, project: p, op: 'close', onclose: () => undefined } });
    await until(() => !!screen.queryByTestId('scope-close-blocked'));
    const dlg = screen.getByRole('dialog', { name: 'Scope schliessen' });
    expect(text(screen.getByTestId('scope-close-blocked'))).toContain('Zuerst einen Eintrag hinzufügen');
    expect(submitBtn(dlg, 'Scope schliessen').disabled).toBe(true);
    expect(change).not.toHaveBeenCalled();
    const r = await p.scope.change({ op: 'close', entry: '', source: null });
    expect(r.ok === false && r.code === 'no_include').toBe(true);
    if (!r.ok) expect(r.error).toBe('Zuerst einen Eintrag hinzufügen: ariadne scope add <ziel>');
  });

  it('mit Einschluss: zeigt die Einschlüsse, die danach allein gelten, und schliesst', async () => {
    const { app, project: p, backend } = await project('offen');
    const added = await p.scope.change({ op: 'add', entry: '10.10.10.0/24', source: null });
    expect(added.ok).toBe(true);
    render(ScopeOpenDialog, { props: { app, project: p, op: 'close', onclose: () => undefined } });
    await settle(8);
    const dlg = screen.getByRole('dialog', { name: 'Scope schliessen' });
    expect(text(screen.getByTestId('scope-close-include'))).toBe('10.10.10.0/24');
    expect(screen.queryByTestId('scope-close-blocked')).toBeNull();
    await fireEvent.click(submitBtn(dlg, 'Scope schliessen'));
    await until(() => !!screen.queryByTestId('scope-open-done'));
    expect(backend.state.scope.open).toBe(false);
    await fireEvent.click(within(dlg).getByRole('button', { name: 'Rückgängig' }));
    expect(text(screen.getByTestId('scope-open-undo-confirm'))).toBe('Rückgängig öffnet den Scope wieder: alles gilt dann als im Scope, ausser Ausschlüssen.');
  });

  it('letzten Einschluss entfernen: bei offenem Scope erlaubt, bei geschlossenem nicht', async () => {
    const { project: p, backend } = await project('zu');
    const closed = await p.scope.change({ op: 'remove', entry: '192.168.56.0/24', source: null });
    expect(closed.ok).toBe(false);
    expect((await p.scope.change({ op: 'open', entry: '', source: null })).ok).toBe(true);
    const open = await p.scope.change({ op: 'remove', entry: '192.168.56.0/24', source: null });
    expect(open.ok).toBe(true);
    expect(backend.state.scope.include).toEqual([]);
  });

  it('noop: Öffnen eines offenen Scopes meldet einen festen Text', async () => {
    const { project: p } = await project('offen');
    const r = await p.scope.change({ op: 'open', entry: '', source: null });
    expect(r.ok === false && r.code === 'noop').toBe(true);
  });
});

describe('Kopfzeile: «Scope offen» (E131)', () => {
  it('Kennzeichen nur bei offenem Scope, führt zu den Einstellungen', async () => {
    const { app } = await project('offen');
    await app.refreshStatus();
    render(HeaderBadges, { props: { app } });
    const badge = document.querySelector('[data-badge="scope-open"]') as HTMLButtonElement;
    expect(badge).toBeTruthy();
    expect(text(badge)).toBe('Scope offen');
    await fireEvent.click(badge);
    expect(url.params.get('tafel')).toBe('einstellungen');
    cleanup();
    const zu = await project('zu');
    render(HeaderBadges, { props: { app: zu.app } });
    expect(document.querySelector('[data-badge="scope-open"]')).toBeNull();
  });
});

describe('Zeitachse: Öffnen, Schliessen und Rückgängig mit richtiger Wirkung', () => {
  function row(p: ProjectStore, backend: { state: { timeline: TimelineItem[] } }, sc: Partial<NonNullable<Decision['scope_change']>> & { op: NonNullable<Decision['scope_change']>['op'] }, summary: string) {
    const base = backend.state.timeline.find((x) => x.type === 'decision') as Decision;
    return {
      ...base,
      decision_id: '0199a3c2-9a20-7000-8000-00000000d020',
      kind: 'd.scope.update',
      summary,
      detail: null,
      scope_change: { entries: [], version: 3, revert_of: null, reverted_by: null, revertible: true, ...sc },
    } as Decision;
  }

  it('Szenario offen: Zeile «Scope geöffnet (Version 2)», Rückgängig schliesst wieder', async () => {
    const { app, project: p } = await project('offen');
    await until(() => p.timeline.rows.length > 0);
    const item = p.timeline.rows.find((r) => r.type === 'decision' && r.scope_change?.op === 'open') as Decision;
    expect(item.summary).toBe('Scope geöffnet (Version 2)');
    render(TimelineRow, { props: { app, project: p, item, now: Date.now(), onselect: () => {}, onopen: () => {}, onundo: () => {} } });
    expect(document.body.textContent).toContain('Scope geöffnet (Version 2)');
    await fireEvent.click(screen.getByRole('button', { name: 'Rückgängig' }));
    expect(text(screen.getByTestId('scope-revert-confirm'))).toContain('Rückgängig schliesst den Scope wieder: danach gelten nur die Einschlüsse.');
  });

  it('Schliessen: Rückgängig öffnet wieder', async () => {
    const { app, project: p, backend } = await project('zu');
    const item = row(p, backend, { op: 'close' }, 'Scope geschlossen (Version 3)');
    render(TimelineRow, { props: { app, project: p, item, now: Date.now(), onselect: () => {}, onopen: () => {}, onundo: () => {} } });
    await fireEvent.click(screen.getByRole('button', { name: 'Rückgängig' }));
    expect(text(screen.getByTestId('scope-revert-confirm'))).toContain('Rückgängig öffnet den Scope wieder');
  });

  it('Rückgängig eines Rückgängig von Öffnen (open_before/open_after): öffnet wieder', async () => {
    const { app, project: p, backend } = await project('zu');
    const item = row(p, backend, { op: 'revert', revert_of: '0199a3c2-9a10-7000-8000-00000000d010', open_before: true, open_after: false }, 'Scope-Änderung rückgängig (Version 4)');
    render(TimelineRow, { props: { app, project: p, item, now: Date.now(), onselect: () => {}, onopen: () => {}, onundo: () => {} } });
    await fireEvent.click(screen.getByRole('button', { name: 'Rückgängig' }));
    expect(text(screen.getByTestId('scope-revert-confirm'))).toContain('Rückgängig öffnet den Scope wieder');
  });

  it('Entfernen eines Ausschlusses: Rückgängig schliesst wieder aus (nicht «nimmt wieder in den Scope auf»)', async () => {
    const { app, project: p, backend } = await project('zu');
    const item = row(p, backend, { op: 'remove', entries: ['192.168.56.1'], include_added: [], include_removed: [], exclude_added: [], exclude_removed: ['192.168.56.1'] }, 'Aus dem Scope entfernt (Version 3)');
    render(TimelineRow, { props: { app, project: p, item, now: Date.now(), onselect: () => {}, onopen: () => {}, onundo: () => {} } });
    await fireEvent.click(screen.getByRole('button', { name: 'Rückgängig' }));
    const box = text(screen.getByTestId('scope-revert-confirm'));
    expect(box).toContain('Rückgängig schliesst wieder aus: 192.168.56.1');
    expect(box).not.toContain('nimmt wieder in den Scope auf');
  });

  it('Aufnehmen aus dem Ausschluss: beide Wirkungen', async () => {
    const { app, project: p, backend } = await project('zu');
    const item = row(p, backend, { op: 'add', entries: ['10.1.1.1'], include_added: ['10.1.1.1'], include_removed: [], exclude_added: [], exclude_removed: ['10.1.1.1'] }, 'Scope erweitert (Version 3)');
    render(TimelineRow, { props: { app, project: p, item, now: Date.now(), onselect: () => {}, onopen: () => {}, onundo: () => {} } });
    await fireEvent.click(screen.getByRole('button', { name: 'Rückgängig' }));
    const box = text(screen.getByTestId('scope-revert-confirm'));
    expect(box).toContain('Rückgängig nimmt wieder aus dem Scope: 10.1.1.1');
    expect(box).toContain('Rückgängig schliesst wieder aus: 10.1.1.1');
  });
});

describe('E133: sehr breite Einträge, E132: Hinweis mit dem Befehl', () => {
  it('Hinzufügen in den Einstellungen: dry_run broad zeigt den Warnhinweis, Aufnehmen bleibt möglich', async () => {
    const { app, project: p, backend } = await project('zu');
    render(ScopeEditDialog, { props: { app, project: p, op: 'add', onclose: () => undefined } });
    const dlg = screen.getByRole('dialog', { name: 'Zum Scope hinzufügen' });
    await fireEvent.input(within(dlg).getByLabelText('Eintrag: Adresse, Netz, Bereich, Name oder *.domain'), { target: { value: '10.0.0.0/8' } });
    await until(() => !!screen.queryByTestId('scope-broad'), 3000);
    expect(text(screen.getByTestId('scope-broad'))).toMatch(/Sehr breiter Eintrag: umfasst mehr als 65.536 Adressen\./);
    expect(submitBtn(dlg, 'Hinzufügen').disabled).toBe(false);
    await fireEvent.click(submitBtn(dlg, 'Hinzufügen'));
    await until(() => !!screen.queryByTestId('scope-edit-done'));
    expect(backend.state.scope.include).toContain('10.0.0.0/8');
  });

  it('/16 ist nicht breit; ohne «kein Kundenauftrag» gesperrt mit dem Befehl fürs Terminal', async () => {
    const { app, project: p } = await project('normal');
    render(ScopeEditDialog, { props: { app, project: p, op: 'add', onclose: () => undefined } });
    const dlg = screen.getByRole('dialog', { name: 'Zum Scope hinzufügen' });
    const field = within(dlg).getByLabelText('Eintrag: Adresse, Netz, Bereich, Name oder *.domain');
    await fireEvent.input(field, { target: { value: '172.16.0.0/16' } });
    await until(() => text(screen.getByTestId('scope-edit-entry')) === '172.16.0.0/16', 3000);
    await settle(8);
    expect(screen.queryByTestId('scope-broad')).toBeNull();
    await fireEvent.input(field, { target: { value: 'recovery.vantis.internal' } });
    await until(() => !!screen.queryByTestId('scope-edit-guardrail'), 3000);
    expect(text(dlg)).toContain('ariadne scope add recovery.vantis.internal --not-customer');
    expect(submitBtn(dlg, 'Hinzufügen').disabled).toBe(true);
  });

  it('Befehl nur mit engem Zeichensatz, Wildcards in Hochkommas', () => {
    expect(addCommand('recovery.vantis.internal')).toBe('ariadne scope add recovery.vantis.internal --not-customer');
    expect(addCommand('*.vantis.internal')).toBe("ariadne scope add '*.vantis.internal' --not-customer");
    expect(addCommand('a.b;rm -rf ~')).toBe('ariadne scope add … --not-customer');
    expect(addCommand('$(id).lab')).toBe('ariadne scope add … --not-customer');
  });

  it('HttpBackend: open und close ohne entries', async () => {
    const bodies: unknown[] = [];
    const fetchImpl = (async (_u: string, init: RequestInit) => {
      bodies.push(JSON.parse(String(init.body)));
      return new Response(JSON.stringify({ decision_id: null, version: 3, dry_run: true }), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    const tokens = createMemoryTokenStore();
    tokens.set('x'.repeat(40), null);
    const b = new HttpBackend(tokens, fetchImpl);
    await b.previewScope('p1', { op: 'open', entry: '' });
    await b.changeScope('p1', { op: 'close', entry: '' });
    expect(bodies[0]).toEqual({ op: 'open', dry_run: true });
    expect(bodies[1]).toMatchObject({ op: 'close' });
    expect(bodies[1]).not.toHaveProperty('entries');
  });
});
