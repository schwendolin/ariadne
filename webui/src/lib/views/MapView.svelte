<!--
  Karte: Ebenen-Schalter, Linse, «neu seit …», Legende und die Cytoscape-Fläche.
  Leerer Zustand mit Checkliste für Erstnutzer (Architektur 7.4).
-->
<script lang="ts">
  import type { GraphLayer, HostNode } from '../api/types';
  import { t } from '../i18n';
  import MapCanvas from '../map/MapCanvas.svelte';
  import { router } from '../router.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import { timeLocal } from '../util/time';

  let { project }: { project: ProjectStore } = $props();

  const LAYERS: { id: GraphLayer; enabled: boolean }[] = [
    { id: 'topology', enabled: false },
    { id: 'services', enabled: true },
    { id: 'attack', enabled: true },
    { id: 'fog', enabled: true },
    { id: 'oos', enabled: true },
    { id: 'creds', enabled: false },
    { id: 'web', enabled: false },
    { id: 'ad', enabled: false },
  ];

  let expanded = $state<Set<string>>(new Set());
  let expandedInit = false;
  let highlight = $state<string[]>([]);
  let relayoutToken = $state(0);
  let fitToken = $state(0);
  let legendOpen = $state(false);

  const graph = $derived(project.graph);
  const hosts = $derived((graph?.nodes.filter((n) => n.kind === 'host') ?? []) as HostNode[]);
  const freshSet = $derived(new Set(Object.keys(project.fresh)));
  const freshCounts = $derived.by(() => {
    const c = { host: 0, service: 0, credential: 0 };
    for (const kind of Object.values(project.fresh)) if (kind in c) c[kind as keyof typeof c]++;
    return c;
  });
  const freshSummary = $derived(
    [
      freshCounts.host ? `+${t('inbox.sum.hosts', { n: freshCounts.host })}` : '',
      freshCounts.service ? `+${t('inbox.sum.services', { n: freshCounts.service })}` : '',
      freshCounts.credential ? `+${t('inbox.sum.credentials', { n: freshCounts.credential })}` : '',
    ].filter(Boolean).join(', '),
  );

  // Hosts mit Zugriff und wenigen Services starten ausgeklappt (1-Host-Darstellung).
  $effect(() => {
    if (expandedInit || !hosts.length) return;
    expandedInit = true;
    expanded = new Set(hosts.filter((h) => h.access !== 'none' && h.services_total > 0 && h.services_total <= 6).map((h) => h.id));
  });

  function toggleLayer(id: GraphLayer) {
    const on = project.layers.includes(id);
    project.setLayers(on ? project.layers.filter((l) => l !== id) : [...project.layers, id]);
  }

  function toggleHost(id: string) {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    expanded = next;
  }

  function showFresh() {
    highlight = Object.keys(project.fresh);
  }

  function seen() {
    project.acknowledgeFresh();
    highlight = [];
  }
</script>

<section class="map-view" aria-label={t('map.label')}>
  <div class="toolbar">
    <fieldset class="layers">
      <legend>{t('map.layers')}</legend>
      {#each LAYERS as l (l.id)}
        <label class:disabled={!l.enabled}>
          <input
            type="checkbox"
            checked={l.id === 'topology' || project.layers.includes(l.id)}
            disabled={!l.enabled}
            onchange={() => toggleLayer(l.id)}
          />
          {t(`layer.${l.id}`)}
        </label>
      {/each}
    </fieldset>
    <fieldset class="lens">
      <legend>{t('map.lens')}</legend>
      <label><input type="radio" name="lens" checked disabled={false} /> {t('lens.karte')}</label>
      <label class="disabled"><input type="radio" name="lens" disabled /> {t('lens.faden')}</label>
    </fieldset>
    <div class="spacer"></div>
    {#if freshSummary && project.baselineTs}
      <button type="button" class="fresh" onclick={showFresh}>{t('map.fresh', { time: timeLocal(project.baselineTs), summary: freshSummary })}</button>
      <button type="button" class="small ghost" onclick={seen}>{t('map.freshSeen')}</button>
    {/if}
    <button type="button" onclick={() => (fitToken += 1)}>{t('map.fit')}</button>
    <button type="button" onclick={() => (relayoutToken += 1)}>{t('map.relayout')}</button>
    <button type="button" aria-expanded={legendOpen} onclick={() => (legendOpen = !legendOpen)}>{t('map.legend')}</button>
  </div>

  <div class="stage">
    {#if !graph}
      <p class="center muted">{t('map.loading')}</p>
    {:else}
      <MapCanvas
        {graph}
        layers={project.layers}
        {expanded}
        fresh={freshSet}
        {highlight}
        selected={router.param('host')}
        {relayoutToken}
        {fitToken}
        loadPositions={async () => (await project.backend.positions(project.pid, project.lens, project.signal)).positions}
        savePositions={(p) => void project.backend.savePositions(project.pid, project.lens, p).catch(() => undefined)}
        onSelectHost={(id) => router.setParam('host', id)}
        onToggleHost={toggleHost}
        onOpenFact={(id) => router.setParam('fact', id)}
      />
      {#if hosts.length === 0}
        <div class="empty card">
          <h2>{t('empty.title')}</h2>
          <ol>
            <li>{t('empty.step1')}</li>
            <li>{t('empty.step2')}</li>
            <li>{t('empty.step3')}</li>
          </ol>
        </div>
      {/if}
    {/if}

    {#if legendOpen}
      <aside class="legend card" aria-label={t('map.legend')}>
        <ul>
          <li><span class="sw fog"></span>{t('legend.fog')}</li>
          <li><span class="sw p1"></span>{t('legend.discovered')}</li>
          <li><span class="sw p2"></span>{t('legend.scanned')}</li>
          <li><span class="sw p3"></span>{t('legend.versions')}</li>
          <li><span class="sw p4"></span>{t('legend.user')}</li>
          <li><span class="sw p5"></span>{t('legend.admin')}</li>
          <li><span class="sw inprog"></span>{t('legend.inProgress')}</li>
          <li><span class="sw dead"></span>{t('legend.deadEnd')}</li>
          <li><span class="sw done"></span>{t('legend.done')}</li>
          <li><span class="sw thread"></span>{t('legend.thread')}</li>
          <li><span class="sw conflict"></span>{t('legend.conflict')}</li>
          <li><span class="sw ai"></span>{t('legend.ai')}</li>
          <li><span class="sw oos"></span>{t('legend.oos')}</li>
        </ul>
      </aside>
    {/if}
  </div>
</section>

<style>
  .map-view {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  fieldset {
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
    margin: 0;
    padding: 0;
    border: 0;
  }
  legend {
    float: left;
    margin-right: 6px;
    color: var(--text-muted);
    font-size: 0.85rem;
  }
  label {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 0.9rem;
  }
  label.disabled {
    color: var(--text-muted);
  }
  .fresh {
    border-color: var(--map-fresh);
    color: var(--map-fresh);
    font-weight: 600;
  }
  .stage {
    position: relative;
    flex: 1;
    min-height: 0;
  }
  .center {
    position: absolute;
    inset: 0;
    display: grid;
    place-items: center;
  }
  .empty {
    position: absolute;
    top: 24px;
    left: 24px;
    max-width: 440px;
    box-shadow: var(--shadow);
  }
  .empty ol {
    margin: 0;
    padding-left: 20px;
  }
  .legend {
    position: absolute;
    right: 12px;
    bottom: 12px;
    box-shadow: var(--shadow);
    font-size: 0.85rem;
  }
  .legend ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }
  .legend li {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .sw {
    display: inline-block;
    width: 16px;
    height: 12px;
    border-radius: 3px;
    border: 1.5px solid var(--map-border);
    background: var(--map-discovered);
  }
  .sw.fog {
    background: var(--map-fog-fill);
    border-style: dotted;
    border-color: var(--map-fog-border);
  }
  .sw.p1 { background: var(--map-discovered); }
  .sw.p2 { background: var(--map-scanned); }
  .sw.p3 { background: var(--map-versions); }
  .sw.p4 { background: var(--map-user); }
  .sw.p5 { background: var(--map-admin); }
  .sw.inprog { border: 3px solid var(--map-in-progress); }
  .sw.dead { border: 2px dashed var(--map-dead-end); }
  .sw.done { border: 4px double var(--map-done); }
  .sw.thread {
    height: 4px;
    border: 0;
    background: var(--map-thread);
  }
  .sw.conflict { box-shadow: 0 0 0 3px var(--map-conflict); }
  .sw.ai { background: var(--map-ai); border-color: var(--map-ai); }
  .sw.oos {
    background: repeating-linear-gradient(45deg, var(--map-oos-fill) 0 3px, var(--map-oos-hatch) 3px 5px);
    border: 1.5px dashed var(--map-oos-border);
  }
</style>
