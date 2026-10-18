/**
 * Cytoscape-Motor der Karte (E108, Vertrag 5.2). Besitzer: ui-karte.
 *
 * Cytoscape mit fcose rechnet die Lage und zeichnet Kanten (Topologie, Nebel, Faden) und die
 * Segmente als gestrichelte Rahmen (Elternknoten). Kali und die Hosts sind in Cytoscape nur
 * unsichtbare Platzhalter in der Grösse der HTML-Karten; die Karten selbst liegen als HTML-Overlay
 * darüber (MapCanvas), damit sie fokussierbar sind und Zieldaten nur als Text erscheinen.
 *
 * CSP: vor der ersten Instanz `ensureCytoscapeCspShim()`, Stile nur über das Stylesheet-Objekt von
 * Cytoscape (CSSOM), Farben aus den Tokens per `getComputedStyle`. Kein `<style>`, kein `style=`.
 *
 * Lage: gespeicherte Positionen gelten (PUT /ui/positions). Neue Knoten legt fcose dazu, höchstens
 * alle 2 s und nie während einer Interaktion (Briefing 8); bekannte Knoten bleiben fest. Bei
 * reduzierter Bewegung springt alles ohne Animation.
 */
import type cytoscapeFn from 'cytoscape';
import type { Core, ElementDefinition, NodeSingular } from 'cytoscape';
import { reducedMotion } from '../util/motion';
import { ensureCytoscapeCspShim } from './csp';
import { gridPositions, type MapModel, type Pt } from './model';

export interface Viewport {
  zoom: number;
  x: number;
  y: number;
}

export interface Frame {
  viewport: Viewport;
  positions: Record<string, Pt>;
  /** Rahmen der Segmente in Modellkoordinaten */
  segments: Record<string, { x1: number; y1: number; x2: number; y2: number }>;
  /** Mitte der Faden-Kanten (Nummern) */
  markers: Record<string, Pt>;
}

export interface EngineCallbacks {
  onFrame(f: Frame): void;
  /** Klick ins Leere (schliesst das Host-Detail) */
  onBackgroundTap(): void;
  /** Positionen haben sich durch Layout oder Ziehen geändert (speichern) */
  onPositionsChanged(p: Record<string, Pt>): void;
}

export interface Insets {
  top: number;
  right: number;
  bottom: number;
  left: number;
}

const LAYOUT_INTERVAL = 2000;
const ZOOM_MIN = 0.2;
const ZOOM_MAX = 2.5;
export const DEFAULT_SIZES = { host: { w: 214, h: 66 }, fog: { w: 190, h: 56 }, kali: { w: 120, h: 64 } };

type Cytoscape = typeof cytoscapeFn;

let libPromise: Promise<Cytoscape> | null = null;

/** Lädt Cytoscape und fcose einmal (eigener Chunk). */
export function loadCytoscape(): Promise<Cytoscape> {
  if (!libPromise) {
    libPromise = (async () => {
      ensureCytoscapeCspShim();
      const [{ default: cytoscape }, { default: fcose }] = await Promise.all([import('cytoscape'), import('cytoscape-fcose')]);
      cytoscape.use(fcose);
      return cytoscape;
    })();
    libPromise.catch(() => {
      libPromise = null;
    });
  }
  return libPromise;
}

function token(name: string, fallback: string): string {
  if (typeof document === 'undefined') return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000;
}

export class MapEngine {
  private cy: Core | null = null;
  private model: MapModel = { cards: [], edges: [], segments: [] };
  private sizes = new Map<string, { w: number; h: number }>();
  private saved: Record<string, Pt> = {};
  private placed = new Set<string>();
  private frameReq = 0;
  private layoutTimer: ReturnType<typeof setTimeout> | null = null;
  private layoutRunning = false;
  private lastLayout = 0;
  private interactingUntil = 0;
  private firstSync = true;
  private userAdjusted = false;
  private insets: Insets = { top: 56, right: 56, bottom: 52, left: 24 };
  private themeObserver: MutationObserver | null = null;
  private media: MediaQueryList | null = null;
  private readonly onMedia = () => this.applyTheme();
  destroyed = false;

  constructor(
    private readonly container: HTMLElement,
    private readonly cb: EngineCallbacks,
  ) {}

  async init(cytoscape: Cytoscape): Promise<void> {
    if (this.destroyed) return;
    const cy = cytoscape({
      container: this.container,
      elements: [],
      style: this.style() as never,
      layout: { name: 'preset' },
      minZoom: ZOOM_MIN,
      maxZoom: ZOOM_MAX,
      boxSelectionEnabled: false,
      autoungrabify: true,
      autounselectify: true,
      selectionType: 'single',
    });
    this.cy = cy;
    cy.on('render', () => this.requestFrame());
    cy.on('tap', (e) => {
      if (e.target === cy) this.cb.onBackgroundTap();
    });
    cy.on('pan zoom', () => {
      this.interactingUntil = Date.now() + 800;
    });
    cy.on('viewport', () => this.requestFrame());
    // Nur Eingaben des Menschen zählen als «selbst verschoben» (kein Einpassen bei Grössenänderung).
    this.container.addEventListener('wheel', this.markUser, { passive: true });
    this.container.addEventListener('pointerdown', this.markUser, { passive: true });
    if (typeof MutationObserver !== 'undefined') {
      this.themeObserver = new MutationObserver(() => this.applyTheme());
      this.themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    }
    if (typeof matchMedia === 'function') {
      this.media = matchMedia('(prefers-color-scheme: dark)');
      this.media.addEventListener?.('change', this.onMedia);
    }
  }

  private readonly markUser = () => {
    this.userAdjusted = true;
    this.interactingUntil = Date.now() + 800;
  };

  get ready(): boolean {
    return this.cy !== null;
  }

  setInsets(i: Insets): void {
    this.insets = i;
  }

  /** Stylesheet aus den Tokens (CSSOM über Cytoscape, nie <style>). */
  private style(): unknown[] {
    const line = token('--line', '#2a3038');
    const thread = token('--thread', '#f0675c');
    const segment = token('--segment-line', '#343b45');
    return [
      {
        selector: 'node',
        style: {
          shape: 'round-rectangle',
          width: 'data(w)',
          height: 'data(h)',
          'background-opacity': 0,
          'border-width': 0,
          label: '',
          events: 'no',
        },
      },
      {
        selector: 'node.segment',
        style: {
          shape: 'round-rectangle',
          'corner-radius': 16,
          'border-width': 1.5,
          'border-style': 'dashed',
          'border-color': segment,
          'background-opacity': 0,
          padding: 48,
          'min-width': 220,
          'min-height': 140,
          events: 'no',
        },
      },
      {
        selector: 'edge',
        style: { width: 1.5, 'line-color': line, 'curve-style': 'straight', events: 'no', 'target-arrow-shape': 'none' },
      },
      { selector: 'edge.fog', style: { 'line-style': 'dashed', 'line-dash-pattern': [2, 5] } },
      {
        selector: 'edge.thread',
        style: {
          width: 3,
          'line-color': thread,
          'curve-style': 'round-taxi',
          'taxi-direction': 'horizontal',
          'taxi-turn': '50%',
          'taxi-radius': 46,
          'radius-type': 'arc-radius',
          'line-cap': 'round',
          'z-index': 10,
        },
      },
      {
        selector: 'edge.loop',
        style: {
          'curve-style': 'bezier',
          'loop-direction': '0deg',
          'loop-sweep': '-70deg',
          'control-point-step-size': 64,
        },
      },
    ];
  }

  applyTheme(): void {
    if (!this.cy) return;
    this.cy.style(this.style() as never);
  }

  sizeOf(id: string): { w: number; h: number } {
    const s = this.sizes.get(id);
    if (s) return s;
    const card = this.model.cards.find((c) => c.id === id);
    if (card?.kind === 'kali') return DEFAULT_SIZES.kali;
    if (card?.host?.claim_state === 'candidate') return DEFAULT_SIZES.fog;
    return DEFAULT_SIZES.host;
  }

  /** Gemessene Grösse einer HTML-Karte (ohne Zoom). */
  setSize(id: string, w: number, h: number): void {
    if (w <= 0 || h <= 0) return;
    const old = this.sizes.get(id);
    if (old && Math.abs(old.w - w) < 0.5 && Math.abs(old.h - h) < 0.5) return;
    this.sizes.set(id, { w, h });
    const n = this.cy?.getElementById(id);
    if (n && n.nonempty()) n.data({ w, h });
  }

  setSaved(p: Record<string, Pt>): void {
    this.saved = { ...p };
  }

  /** Modell übernehmen: Knoten und Kanten hinzufügen, ändern, entfernen. */
  sync(model: MapModel): void {
    this.model = model;
    const cy = this.cy;
    if (!cy) return;
    const seed = gridPositions(model);
    const wanted = new Set<string>([...model.segments.map((s) => s.id), ...model.cards.map((c) => c.id), ...model.edges.map((e) => e.id)]);
    const added: string[] = [];
    cy.batch(() => {
      cy.elements().forEach((ele) => {
        if (!wanted.has(ele.id())) ele.remove();
      });
      for (const s of model.segments) {
        if (cy.getElementById(s.id).empty()) cy.add({ group: 'nodes', data: { id: s.id, w: 1, h: 1 }, classes: 'segment' });
      }
      for (const c of model.cards) {
        const size = this.sizeOf(c.id);
        const existing = cy.getElementById(c.id);
        const parent = c.segment ?? undefined;
        if (existing.nonempty()) {
          if ((existing.data('parent') ?? undefined) !== parent) existing.move({ parent: parent ?? null });
          existing.data({ w: size.w, h: size.h });
          continue;
        }
        const pos = this.saved[c.id] ?? this.nearAnchor(c.segment, seed[c.id]);
        if (this.saved[c.id]) this.placed.add(c.id);
        const def: ElementDefinition = { group: 'nodes', data: { id: c.id, parent, w: size.w, h: size.h }, position: { ...pos }, classes: c.kind };
        cy.add(def);
        added.push(c.id);
      }
      for (const e of model.edges) {
        const existing = cy.getElementById(e.id);
        if (existing.nonempty()) continue;
        if (cy.getElementById(e.source).empty() || cy.getElementById(e.target).empty()) continue;
        const loop = e.source === e.target;
        cy.add({ group: 'edges', data: { id: e.id, source: e.source, target: e.target }, classes: `${e.kind}${loop ? ' loop' : ''}` });
      }
    });
    if (this.firstSync) {
      this.firstSync = false;
      const unplaced = model.cards.filter((c) => !this.placed.has(c.id));
      if (unplaced.length === 0) {
        this.fit();
      } else {
        this.runLayout(this.placed.size > 0 ? 'incremental' : 'full');
      }
      return;
    }
    if (added.some((id) => !this.placed.has(id))) this.requestLayout();
    this.requestFrame();
  }

  private nearAnchor(segment: string | null, seed: Pt | undefined): Pt {
    const cy = this.cy;
    if (cy && segment && this.placed.size > 0) {
      const kids = cy.getElementById(segment).children();
      if (kids.nonempty()) {
        const bb = kids.boundingBox({});
        return { x: bb.x2 + 140, y: (bb.y1 + bb.y2) / 2 + (Math.random() - 0.5) * 60 };
      }
    }
    return seed ? { ...seed } : { x: 0, y: 0 };
  }

  private simpleNodes(): NodeSingular[] {
    if (!this.cy) return [];
    return this.cy.nodes().filter((n) => !n.hasClass('segment')).toArray() as NodeSingular[];
  }

  private requestLayout(): void {
    if (this.layoutTimer) return;
    const tick = () => {
      this.layoutTimer = null;
      const now = Date.now();
      const wait = Math.max(LAYOUT_INTERVAL - (now - this.lastLayout), this.interactingUntil - now);
      if (wait > 0 || this.layoutRunning) {
        this.layoutTimer = setTimeout(tick, Math.max(wait, 200));
        return;
      }
      this.runLayout('incremental');
    };
    this.layoutTimer = setTimeout(tick, 60);
  }

  /** Lage berechnen: `full` ohne gespeicherte Lage, `incremental` mit festen bekannten Knoten. */
  runLayout(mode: 'full' | 'incremental'): void {
    const cy = this.cy;
    if (!cy) return;
    const nodes = this.simpleNodes();
    if (nodes.length === 0) {
      this.requestFrame();
      return;
    }
    const fixed = mode === 'full' ? [] : nodes.filter((n) => this.placed.has(n.id())).map((n) => ({ nodeId: n.id(), position: { ...n.position() } }));
    if (mode === 'incremental' && fixed.length === nodes.length) {
      this.requestFrame();
      return;
    }
    const hostIds = nodes.filter((n) => n.id() !== 'kali').map((n) => n.id());
    const relative =
      mode === 'full' && nodes.some((n) => n.id() === 'kali')
        ? hostIds.slice(0, 12).map((id) => ({ left: 'kali', right: id, gap: 150 }))
        : [];
    const animate = mode !== 'full' && !reducedMotion();
    this.layoutRunning = true;
    const layout = cy.elements().layout({
      name: 'fcose',
      quality: 'proof',
      randomize: false,
      animate,
      animationDuration: 350,
      fit: false,
      padding: 40,
      nodeDimensionsIncludeLabels: false,
      packComponents: true,
      tile: true,
      nodeRepulsion: () => 16000,
      idealEdgeLength: () => 170,
      edgeElasticity: () => 0.45,
      nestingFactor: 0.2,
      gravity: 0.35,
      gravityCompound: 1.4,
      gravityRangeCompound: 1.2,
      numIter: 2500,
      ...(fixed.length ? { fixedNodeConstraint: fixed } : {}),
      ...(relative.length ? { relativePlacementConstraint: relative } : {}),
    } as unknown as Parameters<Core['layout']>[0]);
    layout.one('layoutstop', () => {
      this.layoutRunning = false;
      this.lastLayout = Date.now();
      for (const n of this.simpleNodes()) this.placed.add(n.id());
      if (mode === 'full' || !this.userAdjusted) this.fit();
      this.cb.onPositionsChanged(this.positions());
      this.requestFrame();
    });
    layout.run();
  }

  /** Alle Positionen der Karten (Modellkoordinaten, gerundet). */
  positions(): Record<string, Pt> {
    const out: Record<string, Pt> = {};
    for (const n of this.simpleNodes()) {
      const p = n.position();
      out[n.id()] = { x: Math.round(p.x), y: Math.round(p.y) };
    }
    return out;
  }

  position(id: string): Pt | null {
    const n = this.cy?.getElementById(id);
    if (!n || n.empty()) return null;
    const p = n.position();
    return { x: p.x, y: p.y };
  }

  /** Karte ziehen: neue Modellposition setzen (Overlay folgt über `render`). */
  moveTo(id: string, p: Pt): void {
    const n = this.cy?.getElementById(id);
    if (!n || n.empty()) return;
    this.interactingUntil = Date.now() + 1500;
    n.position({ x: p.x, y: p.y });
    this.placed.add(id);
  }

  endMove(): void {
    this.cb.onPositionsChanged(this.positions());
  }

  get zoomLevel(): number {
    return this.cy?.zoom() ?? 1;
  }

  /** Zoomen um einen Faktor, um einen Punkt in Bildschirmkoordinaten des Containers (sonst Mitte). */
  zoomBy(factor: number, at?: Pt): void {
    const cy = this.cy;
    if (!cy) return;
    this.userAdjusted = true;
    const level = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, cy.zoom() * factor));
    const p = at ?? { x: this.container.clientWidth / 2, y: this.container.clientHeight / 2 };
    cy.zoom({ level, renderedPosition: p });
  }

  /** Einpassen: Inhalt skaliert mit der Fläche (50 bis 140 %), Ränder für Lagebild und Streifen. */
  fit(): void {
    const cy = this.cy;
    if (!cy) return;
    const eles = cy.elements();
    if (eles.empty()) return;
    const bb = eles.boundingBox({});
    const w = this.container.clientWidth;
    const h = this.container.clientHeight;
    if (w <= 0 || h <= 0) return;
    const aw = Math.max(50, w - this.insets.left - this.insets.right);
    const ah = Math.max(50, h - this.insets.top - this.insets.bottom);
    const z = Math.max(0.5, Math.min(1.4, Math.min(aw / Math.max(1, bb.w), ah / Math.max(1, bb.h))));
    const cx = (bb.x1 + bb.x2) / 2;
    const cyy = (bb.y1 + bb.y2) / 2;
    cy.viewport({
      zoom: z,
      pan: { x: this.insets.left + aw / 2 - cx * z, y: this.insets.top + ah / 2 - cyy * z },
    });
    this.userAdjusted = false;
  }

  /** Grösse des Containers hat sich geändert. */
  resize(): void {
    if (!this.cy) return;
    this.cy.resize();
    if (!this.userAdjusted) this.fit();
    this.requestFrame();
  }

  /** Einen Knoten in den sichtbaren Bereich holen (Tastatur). */
  reveal(id: string): void {
    const cy = this.cy;
    const n = cy?.getElementById(id);
    if (!cy || !n || n.empty()) return;
    const rp = n.renderedPosition();
    const w = this.container.clientWidth;
    const h = this.container.clientHeight;
    const m = 40;
    let dx = 0;
    let dy = 0;
    if (rp.x < this.insets.left + m) dx = this.insets.left + m - rp.x;
    else if (rp.x > w - this.insets.right - m) dx = w - this.insets.right - m - rp.x;
    if (rp.y < this.insets.top + m) dy = this.insets.top + m - rp.y;
    else if (rp.y > h - this.insets.bottom - m) dy = h - this.insets.bottom - m - rp.y;
    if (dx || dy) cy.panBy({ x: dx, y: dy });
  }

  private requestFrame(): void {
    if (this.frameReq || this.destroyed) return;
    const raf = typeof requestAnimationFrame === 'function' ? requestAnimationFrame : (f: FrameRequestCallback) => setTimeout(() => f(0), 16) as unknown as number;
    this.frameReq = raf(() => {
      this.frameReq = 0;
      this.emitFrame();
    });
  }

  private emitFrame(): void {
    const cy = this.cy;
    if (!cy || this.destroyed) return;
    const pan = cy.pan();
    const positions: Record<string, Pt> = {};
    for (const n of this.simpleNodes()) {
      const p = n.position();
      positions[n.id()] = { x: round(p.x), y: round(p.y) };
    }
    const segments: Frame['segments'] = {};
    cy.nodes('.segment').forEach((n) => {
      const bb = n.boundingBox({});
      segments[n.id()] = { x1: round(bb.x1), y1: round(bb.y1), x2: round(bb.x2), y2: round(bb.y2) };
    });
    const markers: Record<string, Pt> = {};
    cy.edges('.thread').forEach((e) => {
      const m = e.midpoint();
      if (Number.isFinite(m.x) && Number.isFinite(m.y)) markers[e.id()] = { x: round(m.x), y: round(m.y) };
    });
    this.cb.onFrame({ viewport: { zoom: round(cy.zoom()), x: round(pan.x), y: round(pan.y) }, positions, segments, markers });
  }

  destroy(): void {
    this.destroyed = true;
    if (this.layoutTimer) clearTimeout(this.layoutTimer);
    if (this.frameReq && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(this.frameReq);
    this.container.removeEventListener('wheel', this.markUser);
    this.container.removeEventListener('pointerdown', this.markUser);
    this.themeObserver?.disconnect();
    this.media?.removeEventListener?.('change', this.onMedia);
    this.cy?.destroy();
    this.cy = null;
  }
}

/**
 * Rückfall ohne Cytoscape (Bibliothek fehlt oder Tests ohne Canvas): Karten im Raster, keine Linien
 * (Briefing 5.14 «Kartenbibliothek fehlt: Hosts ohne Linien»).
 */
export function fallbackFrame(model: MapModel, width: number, height: number, saved: Record<string, Pt> = {}): Frame {
  const grid = gridPositions(model);
  const positions: Record<string, Pt> = {};
  for (const c of model.cards) positions[c.id] = saved[c.id] ?? grid[c.id] ?? { x: 0, y: 0 };
  const xs = Object.values(positions).map((p) => p.x);
  const ys = Object.values(positions).map((p) => p.y);
  const minX = Math.min(...xs, 0) - 140;
  const maxX = Math.max(...xs, 0) + 140;
  const minY = Math.min(...ys, 0) - 60;
  const maxY = Math.max(...ys, 0) + 60;
  const z = Math.max(0.5, Math.min(1, Math.min((width - 80) / (maxX - minX), (height - 120) / (maxY - minY))));
  const x = (width - (maxX - minX) * z) / 2 - minX * z;
  const y = 60 + (height - 120 - (maxY - minY) * z) / 2 - minY * z;
  return { viewport: { zoom: round(Number.isFinite(z) ? z : 1), x: round(x), y: round(y) }, positions, segments: {}, markers: {} };
}
