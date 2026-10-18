// Alle Arten von «Klären» aus der API mit ihren Aktionen (Briefing 5.2, web-api.md 9): Wert
// entscheiden (annehmen, verwerfen, ändern), Widerspruch (Wert wählen, bewusst offen), Kontext
// klären (Kontext-Dialog von ui-verlauf), verwaister Entscheid (widerrufen), Massenfund (Zeitachse).
// Besitzer: ui-karte.
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { Fact, NextItem } from '../../src/lib/api/types';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { MockBackend } from '../../src/lib/mock/backend';
import { hex64, T1, T2 } from '../../src/lib/mock/data/base';
import NextColumn from '../../src/lib/next/NextColumn.svelte';
import { AppState } from '../../src/lib/stores/app.svelte';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { press, settle, until } from '../fundament/helpers';

let apps: AppState[] = [];
beforeAll(() => installKeymap(window));
afterEach(() => {
  cleanup();
  resetKeymapForTests();
  for (const a of apps) a.stop();
  apps = [];
  document.body.replaceChildren();
  url.go('karte', {}, { replace: true, keep: false });
});

const fact: Fact = {
  claim_key: hex64('pw'), subject: 'svc:ip:default/192.168.56.101|tcp/80', subject_label: '192.168.56.101:80', predicate: 'http.login',
  value: 'admin:admin', ctrl: false, is_secret: false, state: 'candidate', lane: 'decide', lane_reason: 'important_heuristic',
  confidence: 'medium', trust: 'heuristic', parser: 'regex.net', from_target: true, suspect: true, verdict: 'in', sources: 1,
  first_seen: null, last_seen: null, conflict_key: null, history: false,
};

const ITEMS: Record<string, NextItem> = {
  value: { kind: 'decide_value', item_key: `claim:${fact.claim_key}`, group_ref: 'g1a2b3c4d', ts: '2026-10-08T14:00:00.000000Z', fact, reason: 'important_heuristic', unit: null },
  conflict: {
    kind: 'conflict', item_key: `conflict:${hex64('c')}`, ts: '2026-10-08T13:10:00.000000Z',
    conflict: {
      conflict_key: hex64('c'), subject: 'svc:ip:default/192.168.56.101|tcp/445', subject_label: '192.168.56.101 tcp/445', predicate: 'service.name', state: 'open', choice: null,
      values: [
        { claim_key: hex64('c1'), value: 'netbios-ssn', ctrl: false, sources: 2, trust: 'structured', state: 'auto' },
        { claim_key: hex64('c2'), value: 'microsoft-ds', ctrl: false, sources: 1, trust: 'tool_text', state: 'auto' },
      ],
    },
  },
  ctx: {
    kind: 'ctx_unknown', item_key: `ctx:${T2}@99`, ts: '2026-10-08T14:30:00.000000Z', terminal_id: T2, from_off: 99, stage_kind: 'ssh', candidate: '10.10.10.5',
    units: 3, unit: null, terminal: { terminal_id: T2, ordinal: 2, label: 'msf' }, from_ts: '2026-10-08T14:30:00.000000Z', excerpt: null,
  },
  orphan: { kind: 'orphan_decision', item_key: 'orphan:x', ts: '2026-10-08T12:00:00.000000Z', decision_id: '0199a3c2-9a09-7000-8000-00000000d009', decision_kind: 'd.claim.confirm', reason: 'Wert nach Reparse nicht mehr da', ref: null },
  mass: {
    kind: 'mass_find', item_key: 'mass:u1', ts: '2026-10-08T12:30:00.000000Z', hosts: 300, candidates: 290,
    unit: { unit_id: `${T1}@100`, kind: 'command', cmd_id: `${T1}@100`, cmd_ref: 'c011@100', title: 'nmap -sn 10.0.0.0/16', ctrl: false, terminal_id: T1, parser: 'nmap.text', ts: null },
  },
};

async function only(item: NextItem) {
  const backend = new MockBackend('normal');
  backend.delay = 0;
  backend.state.next = { ...backend.state.next, clarify: [item], open: 1 };
  const app = new AppState(backend);
  apps.push(app);
  await app.start();
  await until(() => app.project?.next.view != null);
  const project = app.project as ProjectStore;
  const view = render(NextColumn, { props: { app, project } });
  await settle();
  return { app, project, view, backend };
}

describe('Arten von «Klären»', () => {
  it('Wert entscheiden: Kennzeichen, a nimmt an; e ändert inline', async () => {
    const { project, view, backend } = await only(ITEMS.value as NextItem);
    const card = view.container.querySelector('.card') as HTMLElement;
    expect(card.textContent).toContain('Wert entscheiden');
    expect(card.textContent).toContain('admin:admin');
    expect(card.textContent).toContain('wichtige Heuristik');
    expect(card.textContent).toContain('! Injection-Verdacht');
    press('e');
    await settle();
    const input = screen.getByLabelText('Neuer Wert') as HTMLInputElement;
    expect(input.value).toBe('admin:admin');
    await fireEvent.input(input, { target: { value: 'admin:secret' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Speichern' }));
    expect(backend.state.decisions.at(-1)).toMatchObject({ kind: 'd.claim.edit', payload: { claim_key: fact.claim_key, value: 'admin:secret' } });
    await until(() => project.next.done.length === 1);
    expect(project.next.done[0]?.msg?.key).toBe('next.d.edited');
  });

  it('Wert entscheiden: x verwirft (durchgestrichen)', async () => {
    const { project, backend } = await only(ITEMS.value as NextItem);
    press('x');
    await until(() => project.next.done.length === 1);
    expect(backend.state.decisions.at(-1)?.kind).toBe('d.claim.reject');
    expect(project.next.done[0]?.state).toBe('dismissed');
  });

  it('Widerspruch: Werte mit Quellen, einen wählen oder bewusst offen lassen (nie verwerfen)', async () => {
    const { view, backend } = await only(ITEMS.conflict as NextItem);
    const card = view.container.querySelector('.card') as HTMLElement;
    expect(card.textContent).toContain('2 Quellen');
    expect(screen.queryByRole('button', { name: /Verwerfen/ })).toBeNull();
    await fireEvent.click(screen.getAllByRole('button', { name: 'Diesen Wert' })[0] as HTMLElement);
    expect(backend.state.decisions.at(-1)).toMatchObject({ kind: 'd.conflict.resolve', payload: { conflict_key: hex64('c'), choice: hex64('c1') } });
  });

  it('Widerspruch bewusst offen lassen', async () => {
    const { backend } = await only(ITEMS.conflict as NextItem);
    await fireEvent.click(screen.getByRole('button', { name: 'Bewusst offen lassen' }));
    expect(backend.state.decisions.at(-1)).toMatchObject({ kind: 'd.conflict.resolve', payload: { keep_open: true } });
  });

  it('Kontext klären: Terminal, Stufe, Befehle, Kandidat; «Host setzen …» öffnet den Kontext-Dialog', async () => {
    const { app, view } = await only(ITEMS.ctx as NextItem);
    const card = view.container.querySelector('.card') as HTMLElement;
    expect(card.querySelector('.title')?.textContent).toBe('T2 «msf» · SSH');
    expect(card.textContent).toContain('3 Befehle');
    expect(card.textContent).toContain('10.10.10.5');
    press('e');
    expect(app.ui.dialog).toEqual({ kind: 'context', terminalId: T2, itemKey: `ctx:${T2}@99`, fromOff: 99 });
  });

  it('Verwaister Entscheid: Widerrufen schreibt d.revoke', async () => {
    const { backend } = await only(ITEMS.orphan as NextItem);
    await fireEvent.click(screen.getByRole('button', { name: 'Widerrufen' }));
    expect(backend.state.decisions.at(-1)).toMatchObject({ kind: 'd.revoke', payload: { decision_id: '0199a3c2-9a09-7000-8000-00000000d009' } });
  });

  it('Massenfund: ein Eintrag, einzeln in der Zeitachse', async () => {
    const { view } = await only(ITEMS.mass as NextItem);
    expect(view.container.querySelector('.card')?.textContent).toContain('300 Hosts aus einem Befehl, 290 zu entscheiden');
    await fireEvent.click(screen.getByRole('button', { name: 'In der Zeitachse' }));
    expect(url.route).toBe('zeitachse');
    expect(url.get('zeile')).toBe(`${T1}@100`);
  });

  it('ohne Verbindung sind die Aktionen gesperrt und nennen den Grund', async () => {
    const { app } = await only(ITEMS.value as NextItem);
    app.offline = true;
    await settle();
    const btn = screen.getByRole('button', { name: /Annehmen/ });
    expect(btn.hasAttribute('disabled')).toBe(true);
    expect(btn.getAttribute('title')).toBe('Daemon nicht erreichbar');
  });
});
