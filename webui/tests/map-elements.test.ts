import { describe, expect, it } from 'vitest';
import type { HostNode } from '../src/lib/api/types';
import { OOS_ID, hostLabel, toElements } from '../src/lib/map/elements';
import { createLameFixture, HOSTILE_HOSTNAME, ip } from '../src/lib/mock/fixture';
import { buildGraph } from '../src/lib/mock/graph';

const fx = createLameFixture(Date.parse('2026-10-08T14:00:00Z'));
const graph = buildGraph(fx, ['topology', 'services', 'attack', 'oos', 'fog'], 'karte');
const host = (id: string) => graph.nodes.find((n) => n.kind === 'host' && n.id === id) as HostNode;

describe('Karten-Elemente', () => {
  it('kennzeichnet Zugriff mit Symbol, nicht nur mit Farbe', () => {
    expect(hostLabel(host(ip('10.10.10.3')), true).startsWith('# ')).toBe(true);
    expect(hostLabel(host(ip('10.10.10.4')), true).startsWith('$ ')).toBe(true);
    expect(hostLabel(host(ip('10.10.10.5')), true).startsWith('10.10.10.5')).toBe(true);
  });

  it('schreibt Arbeitsstand und Konflikte zusätzlich ins Label', () => {
    expect(hostLabel(host(ip('10.10.10.9')), true)).toContain('Sackgasse');
    expect(hostLabel(host(ip('10.10.10.4')), true)).toContain('Konflikt');
  });

  it('nimmt feindliche Namen nur als bereinigten Text ins Label', () => {
    const label = hostLabel(host(ip('10.10.10.9')), true);
    expect(label).toContain(HOSTILE_HOSTNAME);
    const els = toElements(graph, { layers: graph.layers, expanded: new Set([ip('10.10.10.9')]), fresh: new Set() });
    const svcLabels = els.filter((e) => e.data.kind === 'service').map((e) => String(e.data.label));
    expect(svcLabels.some((l) => l.includes('<U+202E>gnp.exe'))).toBe(true);
    expect(svcLabels.some((l) => l.includes('<ESC>'))).toBe(true);
    for (const e of els) {
      // eslint-disable-next-line no-control-regex
      expect(String(e.data.label ?? '')).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/);
    }
  });

  it('zeigt Services als Satelliten nur für ausgeklappte Hosts', () => {
    const none = toElements(graph, { layers: graph.layers, expanded: new Set(), fresh: new Set() });
    expect(none.some((e) => e.data.kind === 'service')).toBe(false);
    const lame = toElements(graph, { layers: graph.layers, expanded: new Set([ip('10.10.10.3')]), fresh: new Set() });
    expect(lame.filter((e) => e.data.kind === 'service')).toHaveLength(5);
  });

  it('markiert Nebel, Faden und Out-of-Scope', () => {
    const els = toElements(graph, { layers: graph.layers, expanded: new Set(), fresh: new Set([ip('10.10.20.8')]) });
    const fog = els.find((e) => e.data.id === ip('10.10.20.8'));
    expect(String(fog?.classes)).toContain('fog');
    expect(String(fog?.classes)).toContain('fresh');
    const thread = els.filter((e) => e.data.kind === 'thread');
    expect(thread.map((e) => String(e.data.label))).toEqual(['1 Foothold', '2 Loot', '3 Foothold', '4 Pivot']);
    expect(els.some((e) => e.data.id === OOS_ID)).toBe(true);
  });
});
