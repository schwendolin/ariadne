// «Als Nächstes» gegen den Mock (E105, E110, BEHAVIOR «Spalte»): Auswahl, j/k/n, eigene Entscheide
// werden erst mit dem neuen Stand erledigt (kein optimistisches Ausblenden), Cursor springt zur
// nächsten Klärung und im Ruhezustand zum ersten Denkanstoss, «In einem anderen Tab entschieden»,
// Rückgängig, Lernstufen, Belegansicht. Besitzer: ui-karte.
import { afterEach, describe, expect, it } from 'vitest';
import type { NextItem } from '../../src/lib/api/types';
import { T3 } from '../../src/lib/mock/data/base';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, settle, stopAll, until } from '../fundament/helpers';

afterEach(() => {
  stopAll();
  url.go('karte', {}, { replace: true, keep: false });
});

async function ready(scenario: Parameters<typeof makeApp>[0] = 'normal') {
  const h = await makeApp(scenario);
  await until(() => h.app.project?.next.view != null && h.app.project.map.graph != null);
  return { ...h, project: h.app.project as ProjectStore };
}

function clarifyTemplate(p: ProjectStore): NextItem {
  const it = p.next.clarifyItems[0];
  if (!it) throw new Error('keine Klärung');
  return it;
}

function clarify(p: ProjectStore, kind: NextItem['kind']) {
  const it = p.next.clarifyItems.find((i) => i.kind === kind);
  if (!it) throw new Error(`kein ${kind}`);
  return it;
}

describe('Auswahl und Bewegung', () => {
  it('Klären vor Denkanstössen, der erste offene Eintrag ist gewählt, K/D-Nummern, Host markiert', async () => {
    const { project } = await ready();
    const n = project.next;
    expect(n.rows.map((r) => r.type)).toEqual(['clarify', 'clarify', 'suggestion', 'suggestion']);
    expect(n.selectedKey).toBe(`ctx:${T3}@412`);
    // stabile Nummer vom Server (18.12), nicht die Position in der Liste
    expect(n.ordinal(`ctx:${T3}@412`)).toBe('K2');
    expect(n.ordinal(n.suggestionItems[1]?.suggestion_key ?? '')).toBe('D2');
    expect(n.linkedHosts).toEqual(['ip:default/192.168.56.101']);
    expect(n.open).toBe(2);
  });

  it('j/k bewegen in einer Liste, n springt zum nächsten Denkanstoss mit Umlauf, URL folgt', async () => {
    const { project } = await ready();
    const n = project.next;
    n.move(1);
    expect(n.selectedRow?.type === 'clarify' && n.selectedRow.item.kind).toBe('merge_suggestion');
    expect(url.get('sel')).toBe(n.selectedKey);
    n.move(-1);
    n.move(-1);
    expect(n.selectedKey).toBe(`ctx:${T3}@412`);
    n.nextSuggestion();
    expect(n.selectedKey).toBe(n.suggestionItems[0]?.suggestion_key);
    n.nextSuggestion();
    n.nextSuggestion();
    expect(n.selectedKey).toBe(n.suggestionItems[0]?.suggestion_key);
    expect(n.linkedHosts).toEqual([]);
  });
});

describe('eigene Entscheide', () => {
  it('Kontextvorschlag übernehmen: busy bis zum neuen Stand, dann erledigt und Cursor auf K3', async () => {
    const { project } = await ready();
    const n = project.next;
    const k2 = clarify(project, 'ctx_suggestion');
    if (k2.kind !== 'ctx_suggestion') throw new Error();
    const p = n.acceptContext(k2);
    expect(n.isBusy(k2.item_key)).toBe(true);
    expect(await p).toBe(true);
    // kein optimistisches Ausblenden: der Eintrag steht noch da, bis /next ihn nicht mehr liefert
    expect(n.clarifyItems.some((i) => i.item_key === k2.item_key)).toBe(true);
    await until(() => n.done.length === 1);
    const done = n.done[0];
    expect(done?.state).toBe('done');
    expect(done?.msg?.key).toBe('next.d.ctx');
    expect(done?.msg?.params).toEqual({ term: 'T3', host: '192.168.56.101' });
    // ContextResult.decision_id (18.12): «Rückgängig» per d.revoke statt nur «Ändern …»
    expect(done?.decisionId).toMatch(/^[0-9a-f-]{36}$/);
    expect(done?.ctx).toBeNull();
    expect(n.isBusy(k2.item_key)).toBe(false);
    expect(n.selectedRow?.type === 'clarify' && n.selectedRow.item.kind).toBe('merge_suggestion');
    expect(n.rowsOf('clarify').map((r) => r.type)).toEqual(['done', 'clarify']);
  });

  it('Zusammenführen: Ruhezustand mit Cursor auf dem ersten Denkanstoss; Rückgängig holt K3 zurück', async () => {
    const { project, backend } = await ready();
    const n = project.next;
    const k2 = clarify(project, 'ctx_suggestion');
    const k3 = clarify(project, 'merge_suggestion');
    if (k2.kind !== 'ctx_suggestion' || k3.kind !== 'merge_suggestion') throw new Error();
    await n.acceptContext(k2);
    await until(() => n.done.length === 1);
    expect(await n.merge(k3, true)).toBe(true);
    const sent = backend.state.decisions.at(-1);
    expect(sent?.kind).toBe('d.entity.merge');
    expect(sent?.payload).toEqual({ identifiers: ['ip:default/192.168.56.101', 'ip:default/fd00:56::101'] });
    await until(() => n.done.length === 2);
    expect(n.open).toBe(0);
    expect(n.rowsOf('clarify').map((r) => r.key)).toEqual([k2.item_key, k3.item_key]);
    expect(n.selectedKey).toBe(n.suggestionItems[0]?.suggestion_key);
    const merged = n.done.find((d) => d.key === k3.item_key);
    expect(merged?.msg).toEqual({ key: 'next.d.merged', params: { a: 'fd00:56::101', b: '192.168.56.101' }, mono: ['a', 'b'] });
    expect(n.lastUndoable?.key).toBe(k3.item_key);
    expect(await n.undo(merged!)).toBe(true);
    expect(backend.state.decisions.at(-1)?.kind).toBe('d.revoke');
    await until(() => n.clarifyItems.some((i) => i.item_key === k3.item_key));
    expect(n.done.map((d) => d.key)).toEqual([k2.item_key]);
  });

  it('Denkanstoss erledigt (mit basis) und verworfen; der Cursor bleibt in den Denkanstössen', async () => {
    const { project, backend } = await ready('calm');
    const n = project.next;
    const [d1, d2] = n.suggestionItems;
    expect(n.selectedKey).toBe(d1?.suggestion_key);
    expect(await n.suggestionDone(d1!)).toBe(true);
    expect(backend.state.decisions.at(-1)?.payload).toEqual({ suggestion_key: d1?.suggestion_key, basis: d1?.basis });
    await until(() => n.done.length === 1);
    expect(n.selectedKey).toBe(d2?.suggestion_key);
    expect(await n.suggestionDismiss(d2!)).toBe(true);
    expect(backend.state.decisions.at(-1)?.payload).toEqual({ suggestion_key: d2?.suggestion_key });
    await until(() => n.done.length === 2);
    expect(n.done.map((d) => d.state)).toEqual(['done', 'dismissed']);
    expect(n.rows.map((r) => r.type)).toEqual(['done', 'done']);
  });

  it('Fehler: Eintrag schon anders entschieden ergibt eine Meldung ohne Zieldaten, kein Erledigt', async () => {
    const { app, project, backend } = await ready();
    const n = project.next;
    const k3 = clarify(project, 'merge_suggestion');
    if (k3.kind !== 'merge_suggestion') throw new Error();
    backend.state.next = { ...backend.state.next, clarify: backend.state.next.clarify.filter((i) => i.kind !== 'merge_suggestion') };
    expect(await n.merge(k3, true)).toBe(false);
    expect(app.ui.notices.at(-1)?.text).toBe('Entscheid nicht gespeichert: Der Eintrag wurde inzwischen anders entschieden');
    expect(n.isBusy(k3.item_key)).toBe(false);
  });
});

describe('anderer Tab, Rückkehr ins Dashboard, Lernmodus, Beleg', () => {
  it('ohne Entscheid verschwunden (Auswertung): still «erledigt», kein «anderer Tab», der Cursor springt nicht (A5)', async () => {
    const { project, backend } = await ready();
    const n = project.next;
    const k2key = n.selectedKey;
    backend.state.next = { ...backend.state.next, clarify: backend.state.next.clarify.filter((i) => i.kind !== 'ctx_suggestion'), open: 1 };
    backend.inject({ name: 'inbox', id: null, data: { project_id: project.pid, open: 1 } });
    await until(() => n.done.length === 1);
    await settle();
    expect(n.done[0]?.state).toBe('done');
    expect(n.selectedKey).toBe(k2key);
    expect(n.selectedRow?.type).toBe('done');
  });

  it('in einem anderen Tab entschieden: nur mit fremdem Entscheid, Zeile bleibt mit Hinweis stehen (A5)', async () => {
    const { project, backend } = await ready();
    const n = project.next;
    const merge = clarify(project, 'merge_suggestion');
    if (merge.kind !== 'merge_suggestion') throw new Error('merge');
    n.select(merge.item_key);
    // ein anderer Tab entscheidet direkt am Server (nicht über diesen Projekt-Store)
    await backend.decide(project.pid, [{ kind: 'd.entity.merge', payload: { identifiers: merge.identifiers.filter((i) => i.key !== merge.shared).map((i) => i.key) } }]);
    backend.inject({ name: 'inbox', id: null, data: { project_id: project.pid, open: 1 } });
    await until(() => n.done.find((d) => d.key === merge.item_key)?.state === 'other_tab');
    expect(n.selectedKey).toBe(merge.item_key);
  });

  it('im selben Tab anderswo entschieden (Host-Detail, ctx.decide): «erledigt» mit Rückgängig, nie «anderer Tab» (A5)', async () => {
    const { project } = await ready();
    const n = project.next;
    const merge = clarify(project, 'merge_suggestion');
    if (merge.kind !== 'merge_suggestion') throw new Error('merge');
    const res = await project.decide([{ kind: 'd.entity.merge', payload: { identifiers: merge.identifiers.filter((i) => i.key !== merge.shared).map((i) => i.key) } }]);
    expect(res).not.toBeNull();
    await until(() => n.done.some((d) => d.key === merge.item_key));
    await settle();
    const d = n.done.find((x) => x.key === merge.item_key);
    expect(d?.state).toBe('done');
    expect(d?.decisionId).toBe(res?.results[0]?.decision_id);
  });

  it('neue Klärung reisst die Auswahl ohne `sel` nicht weg (A4)', async () => {
    const { project, backend } = await ready();
    const n = project.next;
    const template = clarifyTemplate(project);
    // Ruhezustand: alle Klärungen weg, der Cursor steht ohne `sel` auf dem ersten Denkanstoss
    backend.state.next = { ...backend.state.next, clarify: [], open: 0 };
    backend.inject({ name: 'inbox', id: null, data: { project_id: project.pid, open: 0 } });
    await until(() => n.clarifyItems.length === 0);
    url.set({ sel: null });
    await settle();
    const first = n.suggestionItems[0]?.suggestion_key ?? null;
    n.select(null);
    url.set({ sel: null });
    expect(n.rows.find((r) => r.type === 'suggestion')?.key).toBe(first);
    const extra = { ...template, item_key: 'ctx:neu@1', ordinal: 9 } as NextItem;
    backend.state.next = { ...backend.state.next, clarify: [extra], open: 1 };
    backend.inject({ name: 'inbox', id: null, data: { project_id: project.pid, open: 1 } });
    await until(() => n.clarifyItems.some((i) => i.item_key === 'ctx:neu@1'));
    expect(n.selectedKey).toBe(first);
  });

  it('`sel` nur auf dem Reiter Karte in die URL (A19)', async () => {
    const { project, backend } = await ready();
    const n = project.next;
    const merge = clarify(project, 'merge_suggestion');
    n.select(merge.item_key);
    url.go('zeitachse', {});
    await backend.decide(project.pid, [{ kind: 'd.entity.merge', payload: { identifiers: merge.kind === 'merge_suggestion' ? merge.identifiers.filter((i) => i.key !== merge.shared).map((i) => i.key) : [] } }]);
    backend.inject({ name: 'inbox', id: null, data: { project_id: project.pid, open: 1 } });
    await until(() => n.done.some((d) => d.key === merge.item_key));
    await settle();
    expect(url.route).toBe('zeitachse');
    expect(url.get('sel')).toBeNull();
    expect(n.selectedKey).toBe(merge.item_key);
  });

  it('Denkanstoss in einem anderen Tab verworfen: «In einem anderen Tab entschieden»', async () => {
    const { project, backend } = await ready();
    const n = project.next;
    const key = n.suggestionItems[0]?.suggestion_key ?? '';
    await backend.decide(project.pid, [{ kind: 'd.suggestion.dismiss', payload: { suggestion_key: key } }]);
    await until(() => n.done.some((d) => d.key === key));
    expect(n.done.find((d) => d.key === key)?.state).toBe('other_tab');
  });

  it('Denkanstoss ohne Entscheid verschwunden (Anlass weg): keine Zeile «anderer Tab»', async () => {
    const { project, backend } = await ready();
    const n = project.next;
    const key = n.suggestionItems[1]?.suggestion_key ?? '';
    backend.state.next = { ...backend.state.next, suggestions: backend.state.next.suggestions.filter((x) => x.suggestion_key !== key) };
    backend.inject({ name: 'suggestion', id: null, data: { project_id: project.pid, open: 1 } });
    await until(() => !n.suggestionItems.some((x) => x.suggestion_key === key));
    await settle();
    expect(n.done.some((d) => d.key === key)).toBe(false);
  });

  it('Erledigte verschwinden beim nächsten Wechsel ins Dashboard (Tab wieder sichtbar)', async () => {
    const { project, backend } = await ready();
    const n = project.next;
    backend.state.next = { ...backend.state.next, clarify: [], open: 0 };
    backend.inject({ name: 'inbox', id: null, data: { project_id: project.pid, open: 0 } });
    await until(() => n.done.length === 2);
    const vis = Object.getOwnPropertyDescriptor(Document.prototype, 'visibilityState');
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' });
    document.dispatchEvent(new Event('visibilitychange'));
    expect(n.done.length).toBe(2);
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' });
    document.dispatchEvent(new Event('visibilitychange'));
    expect(n.done).toEqual([]);
    if (vis) Object.defineProperty(document, 'visibilityState', vis);
    delete (document as unknown as Record<string, unknown>).visibilityState;
  });

  it('Lernstufen werden einzeln aufgedeckt (höchstens 3)', async () => {
    const { project } = await ready();
    const key = project.next.suggestionItems[0]?.suggestion_key ?? '';
    expect(project.next.stageOf(key)).toBe(0);
    for (let i = 0; i < 5; i++) project.next.revealStage(key);
    expect(project.next.stageOf(key)).toBe(3);
  });

  it('↵ öffnet die Belegansicht des gewählten Eintrags; Zusammenführen hat keinen Beleg', async () => {
    const { project } = await ready();
    const n = project.next;
    expect(n.openEvidence()).toBe(true);
    expect(url.get('beleg')).toMatch(/^c:[0-9a-f]{64}$/);
    url.set({ beleg: null });
    n.move(1);
    expect(n.openEvidence()).toBe(false);
    n.nextSuggestion();
    expect(n.openEvidence()).toBe(true);
    expect(url.get('beleg')).toMatch(/^u:.*@18432:6-6$/);
  });

  it('Palette: Quelle «next» mit Klärungen und Denkanstössen', async () => {
    const { project } = await ready();
    await settle();
    const { search } = await import('../../src/lib/shell/palette');
    const hits = search('zusammenführen');
    expect(hits.some((h) => h.group === 'next' && h.hint === 'K3')).toBe(true);
    const all = search('denkanstoss').filter((h) => h.group === 'next');
    expect(all.map((h) => h.hint)).toEqual(['D1', 'D2']);
    all[0]?.run();
    expect(url.get('sel')).toBe(project.next.suggestionItems[0]?.suggestion_key);
  });
});
