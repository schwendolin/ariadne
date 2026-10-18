/**
 * Reine Hilfen der Karte (Besitzer: ui-karte): aus dem GraphView (web-api.md 7) wird das Modell,
 * das MapCanvas zeichnet (HTML-Karten für Kali und Hosts, Kanten für Cytoscape, Segmente als
 * Rahmen). Ohne DOM und ohne Cytoscape, darum in Vitest prüfbar.
 *
 * - Ebenen (Briefing 5.1): Topologie immer, Services (Zahl auf der Karte, beim Hineinzoomen bis 6
 *   Ports), Faden, Out of Scope (Rand), Nebel (Kandidaten). In der URL `ebenen` als Komma-Liste
 *   ohne `topology`; fehlt der Parameter, sind alle an.
 * - Genau ein Hinweis pro Host (E87): Konflikt vor KI vor «N Services»; Nebel und Sackgasse sind
 *   eigene Zustände.
 * - Pfeiltasten springen zum nächstgelegenen Host in der Richtung (BEHAVIOR «Karte»).
 */
import type { GraphLayer, GraphView, HostNode, KaliNode, SegmentNode, ThreadEdge } from '../api/types';

export const LAYERS: GraphLayer[] = ['topology', 'services', 'thread', 'oos', 'fog'];
/** schaltbare Ebenen (Topologie ist immer an) */
export const TOGGLE_LAYERS: Exclude<GraphLayer, 'topology'>[] = ['services', 'thread', 'oos', 'fog'];

/** Ebenen aus dem URL-Parameter (`null` = alle). Unbekannte Werte fallen weg. */
export function layersFrom(param: string[] | null): Set<GraphLayer> {
  if (param === null) return new Set(LAYERS);
  const out = new Set<GraphLayer>(['topology']);
  for (const p of param) if ((TOGGLE_LAYERS as string[]).includes(p)) out.add(p as GraphLayer);
  return out;
}

/** URL-Wert für eine Auswahl von Ebenen: `null`, wenn alle an sind. */
export function layersParam(set: Set<GraphLayer>): string | null {
  const on = TOGGLE_LAYERS.filter((l) => set.has(l));
  return on.length === TOGGLE_LAYERS.length ? null : on.join(',');
}

export type CardKind = 'kali' | 'host';

export interface CardModel {
  id: string;
  kind: CardKind;
  /** Segment (Cytoscape-Elternknoten), `null` ausserhalb */
  segment: string | null;
  host: HostNode | null;
  kali: KaliNode | null;
}

export interface EdgeModel {
  id: string;
  kind: 'topo' | 'fog' | 'thread';
  source: string;
  target: string;
  thread: ThreadEdge | null;
}

export interface SegmentModel {
  id: string;
  label: string;
  origin: SegmentNode['origin'];
}

export interface MapModel {
  cards: CardModel[];
  edges: EdgeModel[];
  segments: SegmentModel[];
}

/** Ab so vielen Hosts in einem Segment zeichnet die Topologie eine Kante Kali → Segment statt eine pro Host. */
export const STAR_LIMIT = 24;

export function hostsOf(g: GraphView | null): HostNode[] {
  return (g?.nodes.filter((n) => n.kind === 'host') as HostNode[] | undefined) ?? [];
}

export function buildModel(g: GraphView | null, layers: Set<GraphLayer>): MapModel {
  if (!g) return { cards: [], edges: [], segments: [] };
  const kali = (g.nodes.find((n) => n.kind === 'kali') as KaliNode | undefined) ?? null;
  // feste Reihenfolge (Tab-Folge der Karten): Adressen natürlich sortiert
  const hosts = hostsOf(g)
    .filter((h) => layers.has('fog') || h.claim_state !== 'candidate')
    .sort((a, b) => compareLabels(a.label, b.label));
  const hostIds = new Set(hosts.map((h) => h.id));
  const segUsed = new Set(hosts.map((h) => h.segment).filter((s): s is string => !!s));
  const segments: SegmentModel[] = (g.nodes.filter((n) => n.kind === 'segment') as SegmentNode[])
    .filter((s) => segUsed.has(s.id) || s.origin === 'scope')
    .map((s) => ({ id: s.id, label: s.label, origin: s.origin }));
  const segIds = new Set(segments.map((s) => s.id));
  const cards: CardModel[] = [];
  if (kali) {
    const scopes = (g.nodes.filter((n) => n.kind === 'segment') as SegmentNode[]).filter((s) => s.origin === 'scope').map((s) => s.label);
    cards.push({ id: 'kali', kind: 'kali', segment: null, host: null, kali: { ...kali, addresses: kaliAddresses(kali.addresses, scopes) } });
  }
  for (const h of hosts) cards.push({ id: h.id, kind: 'host', segment: h.segment && segIds.has(h.segment) ? h.segment : null, host: h, kali: null });

  const edges: EdgeModel[] = [];
  const thread = layers.has('thread')
    ? (g.edges.filter((e) => e.kind === 'thread') as ThreadEdge[]).filter(
        (e) => (e.source === 'kali' ? !!kali : hostIds.has(e.source)) && (e.target === 'kali' ? !!kali : hostIds.has(e.target)),
      )
    : [];
  const threadFromKali = new Set(thread.filter((e) => e.source === 'kali').map((e) => e.target));
  if (kali) {
    const perSeg = new Map<string | null, HostNode[]>();
    for (const h of hosts) {
      const key = h.segment && segIds.has(h.segment) ? h.segment : null;
      perSeg.set(key, [...(perSeg.get(key) ?? []), h]);
    }
    for (const [seg, list] of perSeg) {
      if (seg && list.length > STAR_LIMIT) {
        edges.push({ id: `topo:${seg}`, kind: 'topo', source: 'kali', target: seg, thread: null });
        continue;
      }
      for (const h of list) {
        if (threadFromKali.has(h.id)) continue;
        edges.push({ id: `topo:${h.id}`, kind: h.claim_state === 'candidate' ? 'fog' : 'topo', source: 'kali', target: h.id, thread: null });
      }
    }
  }
  for (const e of [...thread].sort((a, b) => a.seq - b.seq)) {
    edges.push({ id: `thread:${e.id}`, kind: 'thread', source: e.source, target: e.target, thread: e });
  }
  return { cards, edges, segments };
}

/**
 * Adressen von Kali in der Reihenfolge der Anzeige: zuerst Adressen in einem Scope-Segment
 * (192.168.56.102 bei 192.168.56.0/24), dann übrige, Loopback und Link-local zuletzt. Die Karte zeigt
 * die erste; die Kali hat im Lab fast immer auch 127.0.0.1, das als Hauptadresse nichts sagt.
 */
export function kaliAddresses(addresses: string[], scopes: string[]): string[] {
  const rank = (a: string): number => {
    if (scopes.some((c) => inCidr4(a, c))) return 0;
    if (localOnly(a)) return 2;
    return 1;
  };
  return addresses
    .map((a, i) => ({ a, i, r: rank(a) }))
    .sort((x, y) => x.r - y.r || x.i - y.i)
    .map((x) => x.a);
}

/** Loopback und Link-local: nur auf der Kali selbst sinnvoll, zählt auf der Karte nicht als «+N» */
export function localOnly(a: string): boolean {
  return /^127\./.test(a) || a === '::1' || /^fe80:/i.test(a) || /^169\.254\./.test(a);
}

/** IPv4-Adresse in einem IPv4-Netz («192.168.56.0/24»); alles andere ist «nein». */
export function inCidr4(addr: string, cidr: string): boolean {
  const m = /^(.+)\/(\d{1,2})$/.exec(cidr);
  const net = ipv4Num(m ? (m[1] ?? '') : cidr);
  const ip = ipv4Num(addr);
  if (net === null || ip === null) return false;
  const bits = m ? Number(m[2]) : 32;
  if (bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((ip & mask) >>> 0) === ((net & mask) >>> 0);
}

// ---------------------------------------------------------------- Hinweise auf der Host-Karte

export type HintKind = 'conflict' | 'ai' | 'services' | 'fog' | 'dead' | 'none';

export interface HostHint {
  kind: HintKind;
  /** feste Texte; Zielwerte (Grund der Sackgasse) stehen getrennt in `value` */
  text: string;
  value: string | null;
}

/**
 * Genau ein Hinweis (E87): Nebel, Sackgasse (mit Grund), Konflikt, KI, sonst «N Services».
 * `t` ist die Übersetzungsfunktion (hier als Parameter, damit das Modul ohne i18n prüfbar bleibt).
 */
export function hostHint(
  h: HostNode,
  layers: Set<GraphLayer>,
  t: (key: string, p?: Record<string, string | number>) => string,
): HostHint {
  if (h.claim_state === 'candidate') return { kind: 'fog', text: t('karte.fog'), value: null };
  if (h.work === 'dead_end') return { kind: 'dead', text: t('karte.deadEnd'), value: h.work_reason };
  if (h.conflicts > 0 || h.hint === 'conflict') return { kind: 'conflict', text: t('karte.conflict'), value: conflictWhat(h, t) };
  if (h.hint === 'ai') return { kind: 'ai', text: t('karte.ai'), value: null };
  if (!layers.has('services')) return { kind: 'none', text: '', value: null };
  return { kind: 'services', text: h.services_total > 0 ? t('karte.services', { n: h.services_total }) : t('karte.noServices'), value: null };
}

/** «Dienstname 445» aus `conflict_brief` (18.8), sonst null. */
export function conflictWhat(h: Pick<HostNode, 'conflict_brief'>, t: (key: string, p?: Record<string, string | number>) => string): string | null {
  const b = h.conflict_brief;
  if (!b) return null;
  const known = ['service.name', 'service.version', 'service.product', 'service.state'];
  const pred = known.includes(b.predicate) ? t(`table.pred.${b.predicate}`) : t('table.pred.other');
  return b.port !== null && b.port !== undefined ? `${pred} ${b.port}` : pred;
}

/** Zugriffssymbol der Karte: # root, $ user, ⊘ Sackgasse. */
export function hostSymbol(h: Pick<HostNode, 'access' | 'work' | 'claim_state'>): '#' | '$' | '⊘' | '' {
  if (h.claim_state === 'candidate') return '';
  if (h.access === 'admin') return '#';
  if (h.access === 'user') return '$';
  if (h.work === 'dead_end') return '⊘';
  return '';
}

/** bis 6 Ports für die Karte beim Hineinzoomen (Briefing 5.1). */
export function zoomPorts(h: Pick<HostNode, 'ports'>, max = 6): number[] {
  return (Array.isArray(h.ports) ? h.ports : []).slice(0, max);
}

// ---------------------------------------------------------------- Kurzform von IPs

/**
 * Kürzt IPv4-Adressen in /24-Netzen der Segmente auf «.101» (nur Anzeige in engen Stellen, der volle
 * Wert steht im Detail). Gibt eine Funktion zurück, die eine Zeichenkette ersetzt.
 */
export function ipShortener(segments: { label: string }[]): (text: string) => string {
  const prefixes = new Set<string>();
  for (const s of segments) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}\/(\d{1,2})$/.exec(s.label);
    if (m && Number(m[4]) >= 24) prefixes.add(`${m[1]}.${m[2]}.${m[3]}.`);
  }
  if (prefixes.size === 0) return (x) => x;
  return (text: string) =>
    text.replace(/(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d|\.\d)/g, (whole, a, b, c, d) =>
      prefixes.has(`${a}.${b}.${c}.`) ? `.${d}` : whole,
    );
}

// ---------------------------------------------------------------- Geometrie

export interface Pt {
  x: number;
  y: number;
}

export type Direction = 'left' | 'right' | 'up' | 'down';

const DIR: Record<Direction, Pt> = { left: { x: -1, y: 0 }, right: { x: 1, y: 0 }, up: { x: 0, y: -1 }, down: { x: 0, y: 1 } };

/**
 * Nächstgelegener Kandidat in einer Richtung: nur Punkte im 90°-Kegel der Richtung; gewertet wird
 * die Entfernung plus das Doppelte der seitlichen Abweichung. `null`, wenn es keinen gibt.
 */
export function nearestInDirection(from: Pt, candidates: { id: string; x: number; y: number }[], dir: Direction): string | null {
  const d = DIR[dir];
  let best: { id: string; score: number } | null = null;
  for (const c of candidates) {
    const vx = c.x - from.x;
    const vy = c.y - from.y;
    const along = vx * d.x + vy * d.y;
    if (along <= 0.5) continue;
    const across = Math.abs(vx * d.y - vy * d.x);
    if (across > along * 1.0001) continue;
    const score = Math.hypot(vx, vy) + 2 * across;
    if (!best || score < best.score || (score === best.score && c.id < best.id)) best = { id: c.id, score };
  }
  return best?.id ?? null;
}

/** Zoom zum Einpassen: Inhalt skaliert mit der Fläche, 50 bis 140 % (SCREENS «Grundlayout»). */
export function fitZoom(width: number, height: number, box: { w: number; h: number }, pad = 60): number {
  if (box.w <= 0 || box.h <= 0) return 1;
  const z = Math.min((width - 2 * pad) / box.w, (height - 2 * pad) / box.h);
  return Math.max(0.5, Math.min(1.4, Number.isFinite(z) ? z : 1));
}

/** Host-ID eines Services: «svc:ip:default/10.0.0.1|tcp/22» → «ip:default/10.0.0.1». */
export function hostOfService(serviceId: string): string | null {
  const m = /^svc:(.+)\|(tcp|udp)\/\d+$/.exec(serviceId);
  return m?.[1] ?? null;
}

/**
 * Start-Lage ohne gespeicherte Positionen und ohne Layout-Bibliothek: Kali links, die Hosts eines
 * Segments im Raster rechts davon. Deterministisch (Tests, Rückfall ohne Cytoscape).
 */
export function gridPositions(model: MapModel, cell = { w: 280, h: 130 }): Record<string, Pt> {
  const out: Record<string, Pt> = {};
  const hosts = model.cards.filter((c) => c.kind === 'host');
  const cols = Math.max(1, Math.ceil(Math.sqrt(hosts.length)));
  const rows = Math.max(1, Math.ceil(hosts.length / cols));
  if (model.cards.some((c) => c.kind === 'kali')) out.kali = { x: 0, y: ((rows - 1) * cell.h) / 2 };
  hosts.forEach((c, i) => {
    out[c.id] = { x: 300 + (i % cols) * cell.w, y: Math.floor(i / cols) * cell.h };
  });
  return out;
}

/** Sortierung der Tabelle (Screen 12): Konflikte zuerst, dann Fortschritt, dann Adresse. */
export function compareHosts(a: Pick<HostNode, 'conflicts' | 'progress' | 'label'>, b: Pick<HostNode, 'conflicts' | 'progress' | 'label'>): number {
  const ca = a.conflicts > 0 ? 1 : 0;
  const cb = b.conflicts > 0 ? 1 : 0;
  if (ca !== cb) return cb - ca;
  if (a.progress !== b.progress) return b.progress - a.progress;
  return compareLabels(a.label, b.label);
}

/** Natürliche Ordnung für Adressen («192.168.56.2» vor «192.168.56.10»). */
export function compareLabels(a: string, b: string): number {
  const ia = ipv4Num(a);
  const ib = ipv4Num(b);
  if (ia !== null && ib !== null) return ia - ib;
  if (ia !== null) return -1;
  if (ib !== null) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

function ipv4Num(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  return ((Number(m[1]) * 256 + Number(m[2])) * 256 + Number(m[3])) * 256 + Number(m[4]);
}

/** Wert für einen Attribut-Selektor in Anführungszeichen (ohne CSS.escape, das jsdom nicht kennt). */
export function attrValue(v: string): string {
  return v.replace(/["\\]/g, '\\$&');
}
