// Mock-Backend (Vertrag v0.1-Oberfläche, Abschnitt 8): jede Methode der Schnittstelle liefert in
// jedem Szenario eine Antwort oder den Fehler aus web-api.md; die Daten sind in sich stimmig, damit
// ui-karte und ui-verlauf dagegen bauen können, bevor der Daemon fertig ist. Besitzer: ui-fundament.
import { describe, expect, it } from 'vitest';
import { ApiError } from '../../src/lib/api/client';
import type { StreamEvent } from '../../src/lib/api/types';
import { MockBackend } from '../../src/lib/mock/backend';
import * as base from '../../src/lib/mock/data/base';
import { SCENARIOS, type Scenario } from '../../src/lib/mock/state';

function mock(s: Scenario = 'normal'): MockBackend {
  const b = new MockBackend(s);
  b.delay = 0;
  return b;
}

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof ApiError ? e.code : String(e);
  }
}

describe('Szenarien', () => {
  it.each(SCENARIOS.filter((s) => s !== 'login'))('%s: Status, Terminals und Vorlieben', async (s) => {
    const b = mock(s);
    const st = await b.status();
    expect(st.terminals.length).toBeGreaterThan(0);
    await b.terminals();
    expect((await b.prefs()).prefs.theme).toBe('system');
    if (s === 'noproject') expect(st.project).toBeNull();
    if (s === 'locked') expect(st.locked).toBe(true);
  });

  it('login: ohne Anmeldung 401, falscher Code 401, gesperrt 429, gültiger Code meldet an', async () => {
    const b = mock('login');
    expect(b.needsLogin()).toBe(true);
    expect(await code(b.status())).toBe('unauthorized');
    expect(await code(b.login('FALSCH00'))).toBe('unauthorized');
    expect(await code(b.login('SPERRE00'))).toBe('rate_limited');
    await b.login('ABCD2345');
    expect(b.needsLogin()).toBe(false);
    await b.status();
  });

  it('noproject und locked: Projektrouten antworten mit no_project bzw. locked', async () => {
    expect(await code(mock('noproject').graph(base.PID))).toBe('no_project');
    expect(await code(mock('locked').graph(base.PID))).toBe('locked');
    expect(await code(mock('normal').graph('anderes-projekt'))).toBe('project_mismatch');
  });
});

describe('Standbild 16:54 (normal)', () => {
  it('alle Lesemethoden liefern stimmige Daten', async () => {
    const b = mock();
    const pid = base.PID;
    const project = await b.project(pid);
    expect(project.slug).toBe('ms2');
    const graph = await b.graph(pid);
    const hostIds = new Set(graph.nodes.filter((n) => n.kind === 'host').map((n) => n.id));
    expect(hostIds.size).toBeGreaterThanOrEqual(3);
    expect(graph.oos.total).toBe(4);
    for (const id of hostIds) {
      const h = await b.host(pid, id);
      expect(h.id).toBe(id);
    }
    expect(await code(b.host(pid, 'ip:default/203.0.113.9'))).toBe('not_found');
    await b.positions(pid);
    await b.changes(pid, graph.generation);
    await b.hosts(pid);
    await b.services(pid, {});
    const seen = await b.seen(pid);
    expect(seen.new?.count).toBe(3);

    const next = await b.next(pid);
    expect(next.open).toBe(next.clarify.length);
    for (const s of next.suggestions) {
      expect(s.suggestion_key).toMatch(/^sg:[0-9a-f]{24}$/);
      expect(s.basis).toMatch(/^[0-9a-f]{16}$/);
      if (s.host_id) expect(hostIds.has(s.host_id)).toBe(true);
      for (const tpl of s.templates) {
        if (tpl.rendered) expect(tpl.command).toBe(tpl.parts.map((p) => p.text).join(''));
        else expect(tpl.command).toBeNull();
      }
      for (const ev of s.evidence) if (ev.claim_key) await b.factSources(pid, ev.claim_key);
    }
    expect((await b.suggestions(pid, 'all')).suggestions.length).toBeGreaterThanOrEqual(next.suggestions.length);

    const tl = await b.timeline(pid, {});
    expect(tl.items.length).toBeGreaterThan(0);
    for (const it of tl.items) {
      if (it.type === 'command') {
        const unit = await b.unit(pid, it.unit_id);
        expect(unit.unit_id).toBe(it.unit_id);
        const page = await b.lines(pid, it.unit_id, { from: 0, count: 50 });
        expect(page.lines.length).toBeGreaterThan(0);
      }
    }
    await b.inputs(pid, {});
    const findings = await b.findings(pid);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      const d = await b.finding(pid, f.finding_id);
      for (const ev of d.evidence) expect(ev.evidence_id).toMatch(/^ev:[0-9a-f]{16}$/);
    }
    await b.pending(pid);
    const hits = await b.search(pid, 'vsftpd');
    expect(hits.items.length).toBeGreaterThan(0);
  });

  it('Entscheid ändert den Zustand und meldet changes über den Strom', async () => {
    const b = mock();
    const events: StreamEvent[] = [];
    const off = b.subscribe({ onEvent: (e) => events.push(e) });
    const next = await b.next(base.PID);
    const d1 = next.suggestions[0];
    expect(d1).toBeDefined();
    const res = await b.decide(base.PID, [
      { kind: 'd.suggestion.dismiss', payload: { suggestion_key: d1?.suggestion_key, basis: d1?.basis } },
    ]);
    expect(res.results[0]?.decision_id).toBeTruthy();
    await new Promise((r) => setTimeout(r, 0));
    expect(events.some((e) => e.name === 'changes')).toBe(true);
    const after = await b.next(base.PID);
    expect(after.suggestions.some((s) => s.suggestion_key === d1?.suggestion_key)).toBe(false);
    off();
  });

  it('Präsentationsmodus sperrt Aufdecken und Kopieren in die Kali', async () => {
    const b = mock();
    const ref = { ref: 'input' as const, seq: 47001 };
    expect((await b.reveal(base.PID, ref)).value).toBeTruthy();
    expect((await b.copyToKali(base.PID, ref)).target).toBe('kali');
    await b.setPresentation(true);
    expect(await code(b.reveal(base.PID, ref))).toBe('policy');
    expect(await code(b.copyToKali(base.PID, ref))).toBe('policy');
  });

  it('noclip: Kopieren in die Kali meldet clipboard_tool', async () => {
    expect(await code(mock('noclip').copyToKali(base.PID, { ref: 'input', seq: 47001 }))).toBe('clipboard_tool');
  });

  it('hostile: Vorlage mit Shell-Sonderzeichen wird nicht gerendert, nur Einzelwerte', async () => {
    const next = await mock('hostile').next(base.PID);
    const blocked = next.suggestions.flatMap((s) => s.templates).filter((t) => t.blocked_reason !== null);
    expect(blocked.length).toBeGreaterThan(0);
    for (const t of blocked) {
      expect(t.rendered).toBe(false);
      expect(t.command).toBeNull();
      expect(t.values.some((v) => !v.safe)).toBe(true);
    }
  });
});
