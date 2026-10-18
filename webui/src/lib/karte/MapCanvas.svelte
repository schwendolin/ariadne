<!--
  Karte mit Cytoscape.js (fcose) und HTML-Overlay der Host-Karten (E108, Vertrag 5.2).

  - Cytoscape (engine.ts) rechnet die Lage und zeichnet Kanten, Faden und Segmentrahmen. Kali und
    Hosts sind HTML-Karten (HostCard) in einer Ebene, die Verschieben und Zoom von Cytoscape über
    CSS-Variablen per CSSOM folgt (`styleProps`, nie `style=`).
  - Faden mit nummerierten Schritten (Marken an der Kantenmitte), Segment-Beschriftung, Auswahlring,
    verknüpfter Host, Puls bei «Neu seit».
  - Bedienung: Klick wählt, Klick ins Leere schliesst das Detail, Ziehen verschiebt einen Host (die
    Lage wird gespeichert), Mausrad und Pinch zoomen, `+ − 0` zoomen und passen ein, `Tab` geht
    durch die Hosts, Pfeiltasten springen zum nächstgelegenen Host in der Richtung.
  - Ohne Kartenbibliothek (Ladefehler, Tests ohne Canvas) stehen die Hosts im Raster ohne Linien.
  Besitzer: ui-karte.
-->
<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import type { GraphLayer } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import { registerKeys } from '../keys/keymap';
  import { pageKeysActive } from '../keys/page';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import { styleProps } from '../ui/actions';
  import { pulse } from '../util/motion';
  import { fallbackFrame, loadCytoscape, MapEngine, type Frame } from './engine';
  import HostCard from './HostCard.svelte';
  import { attrValue, buildModel, hostOfService, nearestInDirection, type Direction } from './model';

  let {
    app,
    project,
    layers,
    selected = null,
    linked = {},
    useLibrary = true,
    onselect,
    onbackground,
  }: {
    app: AppState;
    project: ProjectStore;
    layers: Set<GraphLayer>;
    selected?: string | null;
    /** Host-ID → Nummer des gewählten Eintrags («K2») */
    linked?: Record<string, string>;
    /** false: ohne Cytoscape (Tests ohne Canvas) */
    useLibrary?: boolean;
    onselect: (id: string) => void;
    onbackground: () => void;
  } = $props();

  let wrap: HTMLDivElement | undefined = $state();
  let cyEl: HTMLDivElement | undefined = $state();
  let engine: MapEngine | null = null;
  let libFailed = $state(false);
  let libReady = $state(false);
  let frame = $state.raw<Frame>({ viewport: { zoom: 1, x: 0, y: 0 }, positions: {}, segments: {}, markers: {} });
  let width = $state(0);
  let height = $state(0);
  let suppressClick = false;

  const model = $derived(buildModel(project.map.graph, layers));
  const threadEdges = $derived(model.edges.filter((e) => e.kind === 'thread' && e.thread));
  // Korrektur D3: Ports erst, wenn der Mensch über das Einpassen hinaus zoomt (E87: mehr erst bei
  // Hover, Auswahl oder Zoom); das automatische Einpassen allein zeigt nur «23 Services».
  const zoomed = $derived(frame.viewport.zoom >= Math.max(1.25, (frame.fitZoom ?? frame.viewport.zoom) * 1.25));
  const ui = $derived(app.ui);
  /** Host-Karten, die pulsieren (Hosts, Zugriff, Host neuer Services) */
  const pulsingHosts = $derived.by(() => {
    void ui.pulseToken;
    const out = new Set<string>();
    for (const id of ui.pulseIds) {
      out.add(id);
      const h = hostOfService(id);
      if (h) out.add(h);
    }
    return out;
  });

  let savedApplied = false;

  /** Modell an den Motor geben, sobald Graph und gespeicherte Positionen da sind. */
  function push(): void {
    if (!engine?.ready || !project.map.positionsLoaded) return;
    if (!savedApplied) {
      engine.setSaved(project.map.positions);
      savedApplied = true;
    }
    engine.sync(model);
  }

  $effect(() => {
    void model;
    void project.map.positionsLoaded;
    push();
  });

  /** Misst die HTML-Karte (ohne Zoom) für den Platzhalter in Cytoscape. */
  function measure(node: HTMLElement, id: string) {
    let current = id;
    const report = () => engine?.setSize(current, node.offsetWidth, node.offsetHeight);
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(report) : null;
    ro?.observe(node);
    queueMicrotask(report);
    return {
      update(next: string) {
        current = next;
        report();
      },
      destroy() {
        ro?.disconnect();
      },
    };
  }

  // Rückfall ohne Bibliothek: Raster
  $effect(() => {
    if (libReady || !(libFailed || !useLibrary)) return;
    frame = fallbackFrame(model, width || 900, height || 700, project.map.positions);
  });

  // Korrektur A3: offenes Host-Detail ist eine Interaktion (die Karte springt nicht mehr)
  $effect(() => {
    engine?.setHold('detail', !!selected);
  });

  function focusIn(e: FocusEvent): void {
    engine?.setHold('focus', true);
    // Korrektur A16: Tab auf eine Karte ausserhalb des Bildes holt sie ins Bild
    const id = e.target instanceof HTMLElement ? e.target.closest<HTMLElement>('[data-map-card]')?.dataset.hostId : undefined;
    if (id) engine?.reveal(id);
  }

  function focusOut(e: FocusEvent): void {
    if (!(e.relatedTarget instanceof Node) || !wrap?.contains(e.relatedTarget)) engine?.setHold('focus', false);
  }

  onMount(() => {
    if (!useLibrary || !cyEl) return;
    const e = new MapEngine(cyEl, {
      onFrame: (f) => (frame = f),
      onBackgroundTap: () => onbackground(),
      onPositionsChanged: (p) => project.map.savePositions(p),
    });
    engine = e;
    void (async () => {
      try {
        const lib = await loadCytoscape();
        if (e.destroyed) return;
        await e.init(lib);
        libReady = true;
        e.setHold('detail', !!selected);
        push();
      } catch {
        libFailed = true;
      }
    })();
  });

  onDestroy(() => {
    engine?.destroy();
    engine = null;
  });

  // Grösse: Cytoscape anpassen (Inhalt skaliert mit der Fläche)
  $effect(() => {
    void width;
    void height;
    engine?.resize();
  });

  // Tastatur: + − 0 zoomen und einpassen, Pfeile zwischen den Hosts
  function focusedCard(): string | null {
    const el = document.activeElement;
    if (!(el instanceof HTMLElement) || !wrap?.contains(el)) return null;
    return el.closest<HTMLElement>('[data-map-card]')?.dataset.hostId ?? null;
  }

  function focusCard(id: string): void {
    engine?.reveal(id);
    const el = wrap?.querySelector<HTMLElement>(`[data-map-card][data-host-id="${attrValue(id)}"]`);
    el?.focus({ preventScroll: true });
  }

  const page = () => pageKeysActive('karte');

  function arrow(dir: Direction): boolean {
    const from = focusedCard();
    if (!from) return false;
    const p = frame.positions[from];
    if (!p) return false;
    const others = Object.entries(frame.positions)
      .filter(([id]) => id !== from && model.cards.some((c) => c.id === id))
      .map(([id, q]) => ({ id, x: q.x, y: q.y }));
    const to = nearestInDirection(p, others, dir);
    if (to) focusCard(to);
    return true;
  }

  onMount(() =>
    registerKeys([
      { keys: ['+', '='], help: 'help.k.zoom', when: page, run: () => engine?.zoomBy(1.2) },
      { keys: ['-'], when: page, run: () => engine?.zoomBy(1 / 1.2) },
      { keys: ['0'], when: page, run: () => engine?.fit() },
      // Pfeile zwischen den Host-Karten: auch mit Fokus auf der Karte (einem Knopf), Korrektur A1
      { keys: ['ArrowLeft'], help: 'help.k.hosts', when: page, onControl: true, run: () => arrow('left') },
      { keys: ['ArrowRight'], when: page, onControl: true, run: () => arrow('right') },
      { keys: ['ArrowUp'], when: page, onControl: true, run: () => arrow('up') },
      { keys: ['ArrowDown'], when: page, onControl: true, run: () => arrow('down') },
    ]),
  );

  // Ziehen einer Karte (ab 4 px; ein Klick bleibt ein Klick)
  let drag: { id: string; sx: number; sy: number; start: { x: number; y: number }; moved: boolean; el: HTMLElement; pid: number } | null = null;

  function down(e: PointerEvent, id: string): void {
    if (e.button !== 0 || !engine?.ready) return;
    const start = engine.position(id);
    if (!start) return;
    drag = { id, sx: e.clientX, sy: e.clientY, start, moved: false, el: e.currentTarget as HTMLElement, pid: e.pointerId };
  }

  function move(e: PointerEvent): void {
    if (!drag || !engine) return;
    const dx = e.clientX - drag.sx;
    const dy = e.clientY - drag.sy;
    if (!drag.moved) {
      if (Math.hypot(dx, dy) < 4) return;
      drag.moved = true;
      drag.el.setPointerCapture?.(drag.pid);
    }
    const z = engine.zoomLevel || 1;
    engine.moveTo(drag.id, { x: drag.start.x + dx / z, y: drag.start.y + dy / z });
  }

  function up(): void {
    if (!drag) return;
    if (drag.moved) {
      suppressClick = true;
      setTimeout(() => (suppressClick = false), 0);
      engine?.endMove();
    }
    drag = null;
  }

  function select(id: string): void {
    if (suppressClick) return;
    onselect(id);
  }

  function wheel(e: WheelEvent): void {
    if (!engine?.ready || !wrap) return;
    const r = wrap.getBoundingClientRect();
    engine.zoomBy(Math.exp(-e.deltaY * 0.0015), { x: e.clientX - r.left, y: e.clientY - r.top });
  }

  function stepName(step: string): string {
    return t(`karte.step.${step}` as MessageKey);
  }
</script>

<!-- Maus und Fokus über der Karte halten sie still (Korrektur A3); bedient wird über die Knöpfe darin. -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="canvas"
  bind:this={wrap}
  bind:clientWidth={width}
  bind:clientHeight={height}
  class:nolib={libFailed}
  onpointerenter={() => engine?.setHold('pointer', true)}
  onpointerleave={() => engine?.setHold('pointer', false)}
  onfocusin={focusIn}
  onfocusout={focusOut}
>
  <div class="cy" bind:this={cyEl}></div>
  <div class="layer" role="group" aria-label={t('karte.hostsLabel')} use:styleProps={{ '--tx': frame.viewport.x, '--ty': frame.viewport.y, '--zoom': frame.viewport.zoom }}>
    {#each model.segments as s (s.id)}
      {@const box = frame.segments[s.id]}
      {#if box}
        <span class="seg-label" use:styleProps={{ '--x': box.x1, '--y': box.y1 }}>{s.label}</span>
      {/if}
    {/each}
    {#each threadEdges as e (e.id)}
      {@const m = frame.markers[e.id]}
      {#if m && e.thread}
        <span
          class="marker"
          title={t('karte.marker', { n: e.thread.seq, step: stepName(e.thread.step) })}
          use:styleProps={{ '--x': m.x, '--y': m.y }}
          use:pulse={{ token: ui.pulseToken, active: ui.isPulsing(e.thread.id) }}
          data-thread-id={e.thread.id}>{e.thread.seq}</span
        >
      {/if}
    {/each}
    {#each model.cards as c (c.id)}
      {@const p = frame.positions[c.id]}
      {#if p}
        <!-- Ziehen und Mausrad gehören zur Karte; Klick und Tastatur macht der Knopf darin. -->
        <!-- svelte-ignore a11y_no_static_element_interactions -->
        <div
          class="slot"
          use:styleProps={{ '--x': p.x, '--y': p.y }}
          use:measure={c.id}
          onpointerdown={(e) => down(e, c.id)}
          onpointermove={move}
          onpointerup={up}
          onpointercancel={up}
          onwheel={wheel}
        >
          <HostCard
            card={c}
            {layers}
            selected={selected === c.id}
            linked={linked[c.id] ?? null}
            {zoomed}
            pulseToken={ui.pulseToken}
            pulsing={pulsingHosts.has(c.id)}
            onselect={select}
          />
        </div>
      {/if}
    {/each}
  </div>
  {#if libFailed}<p class="nolib-note">{t('karte.libMissing')}</p>{/if}
</div>


<style>
  .canvas {
    position: absolute;
    inset: 0;
    overflow: hidden;
  }
  .cy {
    position: absolute;
    inset: 0;
  }
  .layer {
    position: absolute;
    left: 0;
    top: 0;
    width: 0;
    height: 0;
    transform: translate(calc(var(--tx, 0) * 1px), calc(var(--ty, 0) * 1px)) scale(var(--zoom, 1));
    transform-origin: 0 0;
    pointer-events: none;
  }
  .slot {
    position: absolute;
    left: calc(var(--x, 0) * 1px);
    top: calc(var(--y, 0) * 1px);
    transform: translate(-50%, -50%);
    pointer-events: auto;
    touch-action: none;
  }
  .seg-label {
    position: absolute;
    left: calc(var(--x, 0) * 1px + 16px);
    top: calc(var(--y, 0) * 1px + 10px);
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--faint);
    white-space: nowrap;
  }
  .marker {
    position: absolute;
    left: calc(var(--x, 0) * 1px);
    top: calc(var(--y, 0) * 1px);
    transform: translate(-50%, -50%);
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: var(--thread);
    color: var(--bg);
    font-size: var(--fs-xs);
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: auto;
    cursor: default;
  }
  .nolib-note {
    position: absolute;
    left: 20px;
    bottom: 52px;
    margin: 0;
    font-size: var(--fs-xs);
    color: var(--attention);
  }
</style>
