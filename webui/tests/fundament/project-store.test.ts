// ProjectStore (Integration v0.1-Oberfläche): `changes` während eines laufenden Abrufs geht nicht
// verloren; `decide` mit `onError` gibt den festen Fehlertext zurück statt einer Meldung.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../src/lib/api/client';
import type { ChangeSet } from '../../src/lib/api/types';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import { makeApp, stopAll, until } from './helpers';

afterEach(() => stopAll());

describe('ProjectStore', () => {
  it('ein zweites changes während des Abrufs führt zu einem weiteren Abruf', async () => {
    const { app, backend } = await makeApp('normal');
    await until(() => app.project?.loaded === true);
    const project = app.project as ProjectStore;
    const gen = project.generation ?? 0;
    let release: (() => void) | null = null;
    const calls: number[] = [];
    vi.spyOn(backend, 'changes').mockImplementation(async (_pid: string, since: number): Promise<ChangeSet> => {
      calls.push(since);
      if (calls.length === 1) await new Promise<void>((r) => (release = r));
      return { project_id: project.pid, from: since, to: since + 1, reset: false, changes: [] };
    });
    project.dispatch({ name: 'changes', id: null, data: { project_id: project.pid, generation: gen + 1 } });
    await until(() => calls.length === 1, 3000);
    // zweites Ereignis, solange der erste Abruf hängt
    project.dispatch({ name: 'changes', id: null, data: { project_id: project.pid, generation: gen + 2 } });
    await new Promise((r) => setTimeout(r, 400));
    expect(calls.length).toBe(1);
    (release as (() => void) | null)?.();
    await until(() => calls.length === 2, 3000);
    expect(calls[1]).toBe(gen + 1);
  });

  it('decide mit onError: Text an den Aufrufer, keine Meldung', async () => {
    const { app, backend } = await makeApp('normal');
    await until(() => app.project?.loaded === true);
    const project = app.project as ProjectStore;
    vi.spyOn(backend, 'decide').mockRejectedValue(new ApiError('locked', 423, 'locked'));
    const before = app.ui.notices.length;
    let text: string | null = null;
    const res = await project.decide([{ kind: 'd.revoke', payload: { decision_id: 'nicht-da' } }], {
      errorPrefix: 'err.decisionPrefix',
      onError: (t) => (text = t),
    });
    expect(res).toBeNull();
    expect(text).toMatch(/^Entscheid nicht gespeichert: /);
    expect(app.ui.notices.length).toBe(before);
  });
});
