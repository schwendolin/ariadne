// @vitest-environment node
// Reine Hilfen der Karte (karte/model.ts): Ebenen, Modell aus dem Graph, genau ein Hinweis pro Host,
// Kurzform von IPs, Pfeiltasten, Einpassen, Sortierung der Tabelle. Besitzer: ui-karte.
import { describe, expect, it } from 'vitest';
import type { GraphLayer, GraphView, HostNode } from '../../src/lib/api/types';
import {
  buildModel,
  compareHosts,
  compareLabels,
  conflictWhat,
  fitZoom,
  gridPositions,
  hostHint,
  hostOfService,
  hostSymbol,
  ipShortener,
  layersFrom,
  layersParam,
  nearestInDirection,
  STAR_LIMIT,
  zoomPorts,
} from '../../src/lib/karte/model';
import { hostId } from '../../src/lib/mock/data/base';
import { graph, hostNodes } from '../../src/lib/mock/data/map';

const tk = (key: string, p?: Record<string, string | number>) => (p ? `${key}:${JSON.stringify(p)}` : key);
const ALL = layersFrom(null);

describe('Ebenen', () => {
  it('ohne Parameter sind alle an, Topologie immer', () => {
    expect([...ALL].sort()).toEqual(['fog', 'oos', 'services', 'thread', 'topology']);
    expect(layersFrom([]).has('topology')).toBe(true);
    expect([...layersFrom(['thread', 'unbekannt', 'topology'])].sort()).toEqual(['thread', 'topology']);
  });

  it('URL-Wert: null bei allen, sonst die Liste ohne Topologie', () => {
    expect(layersParam(ALL)).toBeNull();
    expect(layersParam(new Set<GraphLayer>(['topology', 'thread', 'oos']))).toBe('thread,oos');
    expect(layersParam(new Set<GraphLayer>(['topology']))).toBe('');
  });
});

describe('Modell aus dem Graph', () => {
  const g = graph(43);

  it('Kali, Segment und alle Hosts im Scope; Nebel nur mit der Ebene', () => {
    const m = buildModel(g, ALL);
    expect(m.cards.map((c) => c.id)).toEqual(['kali', hostId('192.168.56.101'), hostId('192.168.56.103'), hostId('192.168.56.104')]);
    expect(m.segments.map((s) => s.id)).toEqual(['seg:192.168.56.0/24']);
    expect(m.cards.filter((c) => c.kind === 'host').every((c) => c.segment === 'seg:192.168.56.0/24')).toBe(true);
    const noFog = buildModel(g, layersFrom(['thread', 'services', 'oos']));
    expect(noFog.cards.map((c) => c.id)).not.toContain(hostId('192.168.56.103'));
    expect(noFog.edges.some((e) => e.target === hostId('192.168.56.103'))).toBe(false);
  });

  it('Faden nach Reihenfolge, Topologie von Kali zu jedem Host ausser dem Fadenziel, Nebel gepunktet', () => {
    const m = buildModel(g, ALL);
    const thread = m.edges.filter((e) => e.kind === 'thread');
    expect(thread.map((e) => e.thread?.seq)).toEqual([1, 2]);
    expect(thread[1]?.source).toBe(thread[1]?.target);
    const topo = m.edges.filter((e) => e.kind !== 'thread');
    expect(topo.map((e) => [e.kind, e.target])).toEqual([
      ['fog', hostId('192.168.56.103')],
      ['topo', hostId('192.168.56.104')],
    ]);
    const noThread = buildModel(g, layersFrom(['services', 'oos', 'fog']));
    expect(noThread.edges.filter((e) => e.kind === 'thread')).toEqual([]);
    expect(noThread.edges.some((e) => e.target === hostId('192.168.56.101'))).toBe(true);
  });

  it('viele Hosts in einem Segment: eine Kante Kali zum Segment statt eines Sterns', () => {
    const base = hostNodes()[2] as HostNode;
    const many = Array.from({ length: STAR_LIMIT + 1 }, (_, i) => ({ ...base, id: hostId(`192.168.56.${i + 10}`), label: `192.168.56.${i + 10}` }));
    const gv: GraphView = { ...g, nodes: [...g.nodes.filter((n) => n.kind !== 'host'), ...many], edges: [] };
    const m = buildModel(gv, ALL);
    expect(m.edges).toEqual([{ id: 'topo:seg:192.168.56.0/24', kind: 'topo', source: 'kali', target: 'seg:192.168.56.0/24', thread: null }]);
  });

  it('Kanten zeigen nie auf fehlende Knoten; ohne Graph ist das Modell leer', () => {
    const gv: GraphView = { ...g, nodes: g.nodes.filter((n) => n.kind !== 'kali') };
    const m = buildModel(gv, ALL);
    expect(m.cards.some((c) => c.id === 'kali')).toBe(false);
    expect(m.edges.some((e) => e.source === 'kali' || e.target === 'kali')).toBe(false);
    expect(buildModel(null, ALL)).toEqual({ cards: [], edges: [], segments: [] });
  });
});

describe('Hinweis und Symbol auf der Host-Karte (E87: genau einer)', () => {
  const [h101, h103, h104] = hostNodes() as [HostNode, HostNode, HostNode];

  it('Services, Nebel, Sackgasse mit Grund', () => {
    expect(hostHint(h101, ALL, tk)).toEqual({ kind: 'services', text: 'karte.services:{"n":23}', value: null });
    expect(hostHint(h103, ALL, tk).kind).toBe('fog');
    expect(hostHint(h104, ALL, tk)).toEqual({ kind: 'dead', text: 'karte.deadEnd', value: 'nur RDP' });
  });

  it('Konflikt vor KI vor Services; ohne Ebene Services kein Zahl-Hinweis', () => {
    const c = { ...h101, conflicts: 1, hint: 'conflict' as const, conflict_brief: { predicate: 'service.name', port: 445 } };
    expect(hostHint(c, ALL, tk)).toEqual({ kind: 'conflict', text: 'karte.conflict', value: 'table.pred.service.name 445' });
    expect(hostHint({ ...h101, hint: 'ai' }, ALL, tk).kind).toBe('ai');
    expect(hostHint(h101, layersFrom(['thread']), tk).kind).toBe('none');
    expect(conflictWhat({ conflict_brief: { predicate: 'host.os', port: null } }, tk)).toBe('table.pred.other');
    expect(conflictWhat({ conflict_brief: null }, tk)).toBeNull();
  });

  it('Symbole # $ ⊘, im Nebel keines; bis 6 Ports beim Hineinzoomen', () => {
    expect(hostSymbol(h101)).toBe('#');
    expect(hostSymbol({ ...h104, access: 'user' })).toBe('$');
    expect(hostSymbol(h104)).toBe('⊘');
    expect(hostSymbol(h103)).toBe('');
    expect(zoomPorts(h101)).toEqual([21, 22, 23, 25, 53, 80]);
    expect(zoomPorts({ ports: undefined as unknown as number[] })).toEqual([]);
  });
});

describe('Kurzform von IPs im Scope-Netz', () => {
  const short = ipShortener([{ label: '192.168.56.0/24' }, { label: '10.0.0.0/8' }]);

  it('kürzt nur Adressen in /24-Segmenten, auch mit Port', () => {
    expect(short('192.168.56.101:21')).toBe('.101:21');
    expect(short('Zugriff auf 192.168.56.101 und 10.0.0.5')).toBe('Zugriff auf .101 und 10.0.0.5');
    expect(short('192.168.56.1011')).toBe('192.168.56.1011');
    expect(short('1192.168.56.10')).toBe('1192.168.56.10');
    expect(ipShortener([])('192.168.56.101')).toBe('192.168.56.101');
  });
});

describe('Pfeiltasten zum nächstgelegenen Host', () => {
  const pts = [
    { id: 'a', x: 0, y: 0 },
    { id: 'r', x: 200, y: 20 },
    { id: 'rfar', x: 600, y: 0 },
    { id: 'u', x: 10, y: -150 },
    { id: 'diag', x: 100, y: 120 },
  ];
  const from = { x: 0, y: 0 };
  const others = pts.filter((p) => p.id !== 'a');

  it('wählt im 90°-Kegel den nächsten, seitliche Abweichung zählt doppelt', () => {
    expect(nearestInDirection(from, others, 'right')).toBe('r');
    expect(nearestInDirection(from, others, 'up')).toBe('u');
    expect(nearestInDirection(from, others, 'down')).toBe('diag');
    expect(nearestInDirection(from, others, 'left')).toBeNull();
  });
});

describe('Einpassen, Raster, Sortierung, Service-Host', () => {
  it('Zoom zum Einpassen bleibt zwischen 50 und 140 %', () => {
    expect(fitZoom(1000, 800, { w: 100, h: 100 })).toBe(1.4);
    expect(fitZoom(400, 300, { w: 5000, h: 5000 })).toBe(0.5);
    expect(fitZoom(1120, 800, { w: 1000, h: 400 })).toBeCloseTo(1, 5);
    expect(fitZoom(100, 100, { w: 0, h: 0 })).toBe(1);
  });

  it('Rasterlage: Kali links, Hosts rechts, deterministisch', () => {
    const m = buildModel(graph(1), ALL);
    const a = gridPositions(m);
    expect(a).toEqual(gridPositions(m));
    expect(a.kali?.x).toBeLessThan(Math.min(...Object.entries(a).filter(([k]) => k !== 'kali').map(([, p]) => p.x)));
  });

  it('Tabelle: Konflikte zuerst, dann Fortschritt, dann Adresse natürlich', () => {
    const h = (label: string, conflicts = 0, progress: HostNode['progress'] = 1) => ({ label, conflicts, progress });
    const list = [h('192.168.56.10'), h('192.168.56.2'), h('192.168.56.203', 1), h('192.168.56.5', 0, 5), h('name.lab')];
    expect(list.sort(compareHosts).map((x) => x.label)).toEqual(['192.168.56.203', '192.168.56.5', '192.168.56.2', '192.168.56.10', 'name.lab']);
    expect(compareLabels('b', 'a')).toBe(1);
  });

  it('Host eines Services aus der Service-ID', () => {
    expect(hostOfService('svc:ip:default/192.168.56.101|tcp/21')).toBe('ip:default/192.168.56.101');
    expect(hostOfService('ip:default/192.168.56.101')).toBeNull();
  });
});
