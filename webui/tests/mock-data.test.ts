import { describe, expect, it } from 'vitest';
import { progressOf, type GraphLayer } from '../src/lib/api/types';
import { MockBackend } from '../src/lib/mock/backend';
import { createLameFixture, HOSTILE_HOSTNAME, MOCK_PROJECT_ID } from '../src/lib/mock/fixture';
import { buildGraph } from '../src/lib/mock/graph';

const ALL: GraphLayer[] = ['topology', 'services', 'attack', 'oos', 'fog'];
const fx = createLameFixture(Date.parse('2026-10-08T14:00:00Z'));

function unique(values: string[]) {
  return new Set(values).size === values.length;
}

describe('Mock-Daten «lame»', () => {
  it('hat eindeutige Schlüssel', () => {
    expect(unique(fx.hosts.map((h) => h.id))).toBe(true);
    expect(unique(fx.services.map((s) => s.service_id))).toBe(true);
    expect(unique(fx.facts.map((f) => f.fact_id))).toBe(true);
    expect(unique(fx.suggestions.map((s) => s.suggestion_key))).toBe(true);
    expect(unique(fx.timeline.map((t) => t.id))).toBe(true);
    expect(unique(fx.inbox.flatMap((g) => g.items.map((i) => i.item_id)))).toBe(true);
  });

  it('verweist nur auf vorhandene Hosts, Segmente und Terminals', () => {
    const hosts = new Set(fx.hosts.map((h) => h.id));
    const segments = new Set(fx.segments.map((s) => s.id));
    const terminals = new Set(fx.terminals.map((t) => t.terminal_id));
    for (const s of fx.services) expect(hosts.has(s.host_id), s.service_id).toBe(true);
    for (const h of fx.hosts) expect(h.segment && segments.has(h.segment), h.id).toBe(true);
    for (const u of fx.units.values()) expect(terminals.has(u.terminal_id), u.unit_id).toBe(true);
    const nodes = new Set(['kali', ...hosts, ...segments]);
    for (const e of [...fx.thread, ...fx.reach]) {
      expect(nodes.has(e.source), e.id).toBe(true);
      expect(nodes.has(e.target), e.id).toBe(true);
    }
  });

  it('nummeriert den Faden lückenlos ab 1', () => {
    expect(fx.thread.map((e) => e.seq)).toEqual(fx.thread.map((_, i) => i + 1));
  });

  it('leitet progress immer aus knowledge und access ab', () => {
    for (const h of fx.hosts) expect(h.progress, h.id).toBe(progressOf(h.knowledge, h.access));
  });

  it('gibt jedem Fakt eine Quelle, deren Zeilen existieren und den Wert enthalten', () => {
    const literal = new Set(['host.address', 'host.name', 'host.os', 'host.mac', 'service.state', 'service.name', 'service.product', 'service.version', 'url.title']);
    for (const f of fx.facts) {
      const srcs = fx.sources.get(f.fact_id) ?? [];
      expect(srcs.length, f.fact_id).toBeGreaterThan(0);
      expect(f.sources_count).toBe(srcs.length);
      expect(f.fact_id).toBe(f.claim_key);
      for (const s of srcs) {
        if (s.t !== 'stream') continue;
        const unit = fx.units.get(s.unit_id);
        expect(unit, s.unit_id).toBeDefined();
        const [a, b] = s.lines;
        expect(a).toBeGreaterThanOrEqual(0);
        expect(b).toBeLessThan(unit!.lines.length);
        expect(a).toBeLessThanOrEqual(b);
        if (literal.has(f.predicate) && typeof f.value === 'string') {
          const text = unit!.lines.slice(a, b + 1).map((l) => l.text).join('\n');
          expect(text, `${f.predicate} ${f.value}`).toContain(f.value);
        }
      }
    }
  });

  it('verweist in Inbox, Konflikten, Denkanstössen und Findings nur auf vorhandene Fakten', () => {
    const facts = new Set(fx.facts.map((f) => f.fact_id));
    for (const g of fx.inbox) {
      for (const i of g.items) {
        if (i.claim_key) expect(facts.has(i.claim_key), i.item_id).toBe(true);
        if (i.fact_id) expect(facts.has(i.fact_id), i.item_id).toBe(true);
      }
    }
    for (const c of fx.conflicts) for (const v of c.values) expect(facts.has(v.fact_id)).toBe(true);
    for (const s of fx.suggestions) for (const e of s.evidence) if (e.fact_id) expect(facts.has(e.fact_id), s.suggestion_key).toBe(true);
    for (const f of fx.findings) for (const e of f.evidence) if (e.fact_id) expect(facts.has(e.fact_id), f.finding_id).toBe(true);
  });

  it('enthält feindliche Werte für die Sicherheitstests', () => {
    expect(fx.hosts.some((h) => h.label === HOSTILE_HOSTNAME)).toBe(true);
    expect(fx.facts.some((f) => f.injection_suspect)).toBe(true);
    expect(fx.services.some((s) => (s.version ?? '').includes('\u202e'))).toBe(true);
  });

  it('erzeugt einen Graphen ohne lose Kanten, für jede Ebenenwahl', () => {
    for (const layers of [ALL, ['topology'], ['topology', 'attack'], ['topology', 'services', 'fog']] as GraphLayer[][]) {
      const g = buildGraph(fx, layers, 'karte');
      const ids = new Set(g.nodes.map((n) => n.id));
      for (const e of g.edges) {
        expect(ids.has(e.source), `${layers} ${e.id}`).toBe(true);
        expect(ids.has(e.target), `${layers} ${e.id}`).toBe(true);
      }
      expect(g.nodes.some((n) => n.kind === 'host' && n.claim_state === 'candidate')).toBe(layers.includes('fog'));
      expect(g.nodes.some((n) => n.kind === 'service')).toBe(layers.includes('services'));
    }
  });

  it('nimmt Out-of-Scope nicht als Host auf, sondern fasst es zusammen', () => {
    const g = buildGraph(fx, ALL, 'karte');
    expect(g.nodes.some((n) => n.kind === 'host' && n.scope !== 'in')).toBe(false);
    expect(g.oos.excluded + g.oos.out).toBe(fx.oos.length);
  });
});

describe('MockBackend', () => {
  it('ändert den Zustand über Entscheide und meldet es per SSE', async () => {
    const mock = new MockBackend({ latencyMs: 0, scripted: false });
    const events: string[] = [];
    const off = mock.subscribe(MOCK_PROJECT_ID, { onEvent: (e) => events.push(e.name) });
    const before = await mock.inbox(MOCK_PROJECT_ID);
    const item = before.groups[0]!.items[0]!;
    await mock.decide(MOCK_PROJECT_ID, [{ kind: 'd.claim.confirm', payload: { claim_key: item.claim_key! } }]);
    const after = await mock.inbox(MOCK_PROJECT_ID);
    expect(after.open).toBe(before.open - 1);
    await new Promise((r) => setTimeout(r, 300));
    expect(events).toContain('changes');
    expect(events).toContain('inbox');
    const cs = await mock.changes(MOCK_PROJECT_ID, 42);
    expect(cs.reset).toBe(false);
    expect(cs.changes.some((c) => c.entity_key === item.claim_key)).toBe(true);
    off();
  });

  it('lehnt Anfragen für ein anderes Projekt ab', async () => {
    const mock = new MockBackend({ latencyMs: 0, scripted: false });
    await expect(mock.hosts('anderes-projekt')).rejects.toMatchObject({ code: 'project_mismatch' });
  });

  it('maskiert Secrets im Präsentationsmodus ohne Längenangabe', async () => {
    const mock = new MockBackend({ latencyMs: 0, scripted: false });
    mock.fx.status.presentation = true;
    const page = await mock.streamLines(MOCK_PROJECT_ID, mock.fx.units.get('u-john')!.terminal_id, { unit: 'u-john', from: 0, count: 10 });
    expect(page.lines[0]!.text).toContain('••••••••');
    expect(page.lines[0]!.text).not.toContain('msfadmin:msfadmin');
  });
});
