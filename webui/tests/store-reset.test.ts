import { describe, expect, it, vi } from 'vitest';
import { MockBackend } from '../src/lib/mock/backend';
import { MOCK_PROJECT_ID } from '../src/lib/mock/fixture';
import { AppState } from '../src/lib/stores/app.svelte';

async function until(cond: () => boolean, ms = 3000) {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error('Zeitüberschreitung');
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe('Projekt-Store', () => {
  it('verwirft beim SSE-Ereignis project alle Daten und baut den Store neu auf', async () => {
    const mock = new MockBackend({ latencyMs: 0, scripted: false });
    const app = new AppState(mock);
    await app.start();
    await until(() => !!app.project?.graph && !!app.project.inbox);

    const old = app.project!;
    expect(old.pid).toBe(MOCK_PROJECT_ID);
    expect(old.hosts.length).toBeGreaterThan(0);

    const revoke = vi.spyOn(URL, 'revokeObjectURL');
    const blob = await old.blobUrl('blob-shot-1');
    expect(blob).toMatch(/^blob:/);
    expect(old.blobUrlCount).toBe(1);

    mock.simulateProjectSwitch('0199c3a2-0000-7000-8000-00000000beef');

    // Der alte Store ist sofort leer, abgebrochen und hat seine Blob-URLs freigegeben.
    expect(old.disposed).toBe(true);
    expect(old.signal.aborted).toBe(true);
    expect(old.graph).toBeNull();
    expect(old.inbox).toBeNull();
    expect(old.hosts).toEqual([]);
    expect(old.suggestions).toEqual([]);
    expect(old.blobUrlCount).toBe(0);
    expect(revoke).toHaveBeenCalledWith(blob);

    await until(() => app.project?.pid === '0199c3a2-0000-7000-8000-00000000beef' && !!app.project.graph);
    expect(app.project).not.toBe(old);
    expect(app.project!.graph!.project_id).toBe('0199c3a2-0000-7000-8000-00000000beef');
    expect(app.status?.project?.slug).toBe('metasploitable');
    app.stop();
  });

  it('lädt bei reset alles neu', async () => {
    const mock = new MockBackend({ latencyMs: 0, scripted: false });
    const app = new AppState(mock);
    await app.start();
    await until(() => !!app.project?.graph);
    const store = app.project!;
    const spy = vi.spyOn(mock, 'graph');
    app.handleEvent({ name: 'reset', id: '1', data: { reason: 'reparse', generation: null } });
    await until(() => spy.mock.calls.length > 0 && !store.loading);
    expect(store.generation).not.toBeNull();
    app.stop();
  });

  it('zeigt REC erst nach Bestätigung per SSE', async () => {
    const mock = new MockBackend({ latencyMs: 0, scripted: false });
    const app = new AppState(mock);
    await app.start();
    await until(() => !!app.project);
    expect(app.status?.rec.on).toBe(true);
    await app.toggleRec();
    expect(app.recPending).toBe(false);
    expect(app.status?.rec.on).toBe(true);
    await until(() => app.recPending === null, 2000);
    expect(app.status?.rec.on).toBe(false);
    app.stop();
  });
});
