<!--
  Cytoscape-Karte. Darstellung siehe theme.ts und elements.ts.

  - fcose mit fixedNodeConstraint: bekannte Knoten bleiben, wo sie sind; neue
    Knoten werden höchstens alle 2 s eingepasst und nie während einer Interaktion.
  - Positionen pro Projekt und Linse speichern (über das Backend, im Mock lokal).
  - Neue Elemente blenden ein und pulsieren einmal.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import type { Core, ElementDefinition, NodeSingular } from 'cytoscape';
  import type { GraphLayer, GraphView, Positions } from '../api/types';
  import { t } from '../i18n';
  import { ensureCytoscapeCspShim } from './csp';
  import { OOS_ID, toElements } from './elements';
  import { buildStyle, hatchPattern, readMapTheme } from './theme';

  interface Props {
    graph: GraphView;
    layers: GraphLayer[];
    expanded: ReadonlySet<string>;
    fresh: ReadonlySet<string>;
    highlight: string[];
    selected: string | null;
    relayoutToken: number;
    fitToken: number;
    loadPositions: () => Promise<Positions['positions']>;
    savePositions: (p: Positions['positions']) => void;
    onSelectHost: (id: string) => void;
    onToggleHost: (id: string) => void;
    onOpenFact: (factId: string) => void;
  }

  let {
    graph, layers, expanded, fresh, highlight, selected, relayoutToken, fitToken,
    loadPositions, savePositions, onSelectHost, onToggleHost, onOpenFact,
  }: Props = $props();

  let container: HTMLDivElement | undefined = $state();
  let ready = $state(false);
  let cy: Core | null = null;
  let hatchUrl: string | null = null;
  let saved: Positions['positions'] = {};
  const placed = new Set<string>();
  let firstSync = true;
  let lastLayout = 0;
  let interactingUntil = 0;
  let layoutTimer: ReturnType<typeof setTimeout> | null = null;
  let saveTimer: ReturnType<typeof setTimeout> | null = null;
  let layoutRunning = false;

  const LAYOUT_INTERVAL = 2000;

  function simpleNodes(): NodeSingular[] {
    return cy!.nodes().toArray().filter((n) => !n.isParent() && n.id() !== OOS_ID) as NodeSingular[];
  }

  function initialPosition(el: ElementDefinition): { x: number; y: number } {
    const id = String(el.data.id);
    const s = saved[id];
    if (s) return { ...s };
    const anchorId = (el.data.host as string | undefined) ?? (el.data.parent as string | undefined);
    const anchor = anchorId ? cy!.getElementById(anchorId) : null;
    const base = anchor && anchor.nonempty() ? anchor.position() : { x: 0, y: 0 };
    return { x: base.x + (Math.random() - 0.5) * 80, y: base.y + (Math.random() - 0.5) * 80 };
  }

  function sync(g: GraphView): void {
    if (!cy) return;
    const els = toElements(g, { layers, expanded, fresh });
    const wanted = new Set(els.map((e) => String(e.data.id)));
    const added: string[] = [];
    cy.batch(() => {
      cy!.elements().forEach((ele) => {
        if (!wanted.has(ele.id())) ele.remove();
      });
      // Erst Knoten (Eltern vor Kindern), dann Kanten.
      const nodes = els.filter((e) => e.group === 'nodes').sort((a, b) => (a.data.parent ? 1 : 0) - (b.data.parent ? 1 : 0));
      const edges = els.filter((e) => e.group === 'edges');
      for (const el of [...nodes, ...edges]) {
        const id = String(el.data.id);
        const existing = cy!.getElementById(id);
        if (existing.nonempty()) {
          if (existing.isNode() && (existing.data('parent') ?? null) !== (el.data.parent ?? null)) {
            existing.move({ parent: (el.data.parent as string | undefined) ?? null });
          }
          existing.data(el.data);
          existing.classes(el.classes ?? '');
        } else {
          const def: ElementDefinition = el.group === 'nodes' && !isCompound(el, els) ? { ...el, position: initialPosition(el) } : el;
          cy!.add(def);
          if (el.group === 'nodes') added.push(id);
        }
      }
    });
    const addedSimple = added.filter((id) => {
      const n = cy!.getElementById(id);
      return n.nonempty() && !n.isParent() && id !== OOS_ID;
    });
    if (firstSync) {
      firstSync = false;
      for (const id of addedSimple) if (saved[id]) placed.add(id);
      runLayout(placed.size > 0 ? 'incremental' : 'full');
      return;
    }
    for (const id of addedSimple) reveal(cy.getElementById(id) as NodeSingular);
    if (addedSimple.some((id) => !placed.has(id))) requestLayout();
    else placeOos();
  }

  function isCompound(el: ElementDefinition, all: ElementDefinition[]): boolean {
    return all.some((o) => o.data.parent === el.data.id);
  }

  function reveal(n: NodeSingular): void {
    n.style('opacity', 0);
    n.animate({ style: { opacity: 1 } }, { duration: 600, complete: () => n.removeStyle('opacity') });
    n.flashClass('pulse', 1600);
  }

  function requestLayout(): void {
    if (layoutTimer) return;
    const tick = () => {
      layoutTimer = null;
      const now = Date.now();
      const wait = Math.max(LAYOUT_INTERVAL - (now - lastLayout), interactingUntil - now);
      if (wait > 0 || layoutRunning) {
        layoutTimer = setTimeout(tick, Math.max(wait, 200));
        return;
      }
      runLayout('incremental');
    };
    layoutTimer = setTimeout(tick, 50);
  }

  function runLayout(mode: 'full' | 'incremental' | 'reset'): void {
    if (!cy) return;
    const nodes = simpleNodes();
    const fixed = mode === 'reset' ? [] : nodes.filter((n) => placed.has(n.id())).map((n) => ({ nodeId: n.id(), position: { ...n.position() } }));
    if (mode === 'incremental' && fixed.length === nodes.length) {
      placeOos();
      return;
    }
    const eles = cy.elements().difference(cy.getElementById(OOS_ID));
    layoutRunning = true;
    const layout = eles.layout({
      name: 'fcose',
      quality: 'default',
      randomize: fixed.length === 0,
      animate: mode !== 'full',
      animationDuration: 350,
      fit: mode !== 'incremental',
      padding: 50,
      nodeDimensionsIncludeLabels: true,
      packComponents: true,
      tile: true,
      nodeRepulsion: () => 9000,
      idealEdgeLength: (e: { hasClass: (c: string) => boolean }) => (e.hasClass('svc') ? 55 : 120),
      edgeElasticity: () => 0.45,
      nestingFactor: 0.15,
      gravity: 0.3,
      gravityCompound: 1.2,
      numIter: 2500,
      ...(fixed.length ? { fixedNodeConstraint: fixed } : {}),
    } as unknown as Parameters<typeof eles.layout>[0]);
    layout.one('layoutstop', () => {
      layoutRunning = false;
      lastLayout = Date.now();
      for (const n of simpleNodes()) placed.add(n.id());
      placeOos();
      if (mode === 'full') cy?.fit(undefined, 50);
      schedulePositionSave();
    });
    layout.run();
  }

  function placeOos(): void {
    if (!cy) return;
    const oos = cy.getElementById(OOS_ID);
    if (oos.empty()) return;
    const others = cy.elements().difference(oos);
    if (others.empty()) return;
    const bb = others.boundingBox({ includeLabels: true });
    oos.position({ x: bb.x2 + 100, y: bb.y1 + 30 });
  }

  function schedulePositionSave(): void {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      if (!cy) return;
      const out: Positions['positions'] = {};
      for (const n of simpleNodes()) {
        const p = n.position();
        out[n.id()] = { x: Math.round(p.x), y: Math.round(p.y) };
      }
      saved = out;
      savePositions(out);
    }, 1000);
  }

  async function applyTheme(): Promise<void> {
    if (!cy) return;
    const theme = readMapTheme();
    const next = await hatchPattern(theme['oos-fill'], theme['oos-hatch']);
    if (hatchUrl) URL.revokeObjectURL(hatchUrl);
    hatchUrl = next;
    cy.style(buildStyle(theme, hatchUrl));
  }

  onMount(() => {
    let disposed = false;
    const observers: (() => void)[] = [];
    void (async () => {
      ensureCytoscapeCspShim();
      const [{ default: cytoscape }, { default: fcose }] = await Promise.all([import('cytoscape'), import('cytoscape-fcose')]);
      if (disposed || !container) return;
      cytoscape.use(fcose);
      const theme = readMapTheme();
      hatchUrl = await hatchPattern(theme['oos-fill'], theme['oos-hatch']);
      saved = await loadPositions().catch(() => ({}));
      if (disposed || !container) return;
      cy = cytoscape({
        container,
        style: buildStyle(theme, hatchUrl),
        elements: [],
        minZoom: 0.15,
        maxZoom: 3,
        boxSelectionEnabled: false,
        selectionType: 'single',
      });
      cy.on('tap', 'node.host', (e) => onSelectHost(e.target.id()));
      cy.on('tap', 'node.service', (e) => onSelectHost(String(e.target.data('host'))));
      cy.on('dbltap', 'node.host', (e) => onToggleHost(e.target.id()));
      cy.on('tap', 'edge.thread', (e) => {
        const f = e.target.data('fact');
        if (f) onOpenFact(String(f));
      });
      cy.on('grab drag pan zoom', () => {
        interactingUntil = Date.now() + 800;
      });
      cy.on('free', 'node', (e) => {
        placed.add(e.target.id());
        schedulePositionSave();
      });

      const mo = new MutationObserver(() => void applyTheme());
      mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
      observers.push(() => mo.disconnect());
      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      const onMq = () => void applyTheme();
      mq.addEventListener('change', onMq);
      observers.push(() => mq.removeEventListener('change', onMq));
      ready = true;
    })();
    return () => {
      disposed = true;
      observers.forEach((f) => f());
      if (layoutTimer) clearTimeout(layoutTimer);
      if (saveTimer) clearTimeout(saveTimer);
      cy?.destroy();
      cy = null;
      if (hatchUrl) URL.revokeObjectURL(hatchUrl);
    };
  });

  $effect(() => {
    // Abhängigkeiten ausdrücklich lesen, damit der Effekt bei jeder Änderung läuft.
    const g = graph;
    void layers;
    void expanded;
    void fresh;
    if (ready) sync(g);
  });

  $effect(() => {
    const ids = highlight;
    if (!ready || !cy) return;
    cy.nodes('.highlight').removeClass('highlight');
    const eles = cy.collection();
    for (const id of ids) eles.merge(cy.getElementById(id));
    if (eles.nonempty()) {
      eles.addClass('highlight');
      cy.animate({ fit: { eles, padding: 120 } }, { duration: 400 });
    }
  });

  $effect(() => {
    const id = selected;
    if (!ready || !cy) return;
    cy.$(':selected').unselect();
    if (id) cy.getElementById(id).select();
  });

  let lastRelayout = 0;
  $effect(() => {
    const tok = relayoutToken;
    if (!ready || tok === lastRelayout) return;
    lastRelayout = tok;
    placed.clear();
    runLayout('reset');
  });

  let lastFit = 0;
  $effect(() => {
    const tok = fitToken;
    if (!ready || !cy || tok === lastFit) return;
    lastFit = tok;
    cy.animate({ fit: { eles: cy.elements(), padding: 50 } }, { duration: 300 });
  });
</script>

<div class="cy" bind:this={container} role="img" aria-label={`${t('map.label')}. ${t('map.textOnly')}`}></div>

<style>
  .cy {
    position: absolute;
    inset: 0;
    background: var(--map-bg);
  }
</style>
