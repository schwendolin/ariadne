<!--
  Reiter Karte (SCREENS 1a, Ruhezustand, 3, 12; E105, E108, BEHAVIOR «Karte» und «Spalte»):
  links die Karte (Lagebild, Cytoscape mit HTML-Overlay, Out-of-Scope-Streifen am rechten Rand,
  Ebenen und Legende unten links) oder die Host-Tabelle (ab 200 Hosts immer, sonst mit `t`),
  rechts die Spalte «Als Nächstes» (27 %, 320 bis 480 px), die bei gewähltem Host (`?host=`) das
  Host-Detail zeigt. `Esc` schliesst das Detail und gibt den Fokus an den Host zurück. Im leeren
  Projekt steht in der Spalte «Erste Schritte». Besitzer: ui-karte.
-->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import HostDetail from '../host/HostDetail.svelte';
  import { t } from '../i18n';
  import { registerKeys } from '../keys/keymap';
  import { pageKeysActive } from '../keys/page';
  import NextColumn from '../next/NextColumn.svelte';
  import FirstSteps from '../shell/FirstSteps.svelte';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import { url } from '../url/state.svelte';
  import HostTable from './HostTable.svelte';
  import Lagebild from './Lagebild.svelte';
  import LayersPopover from './LayersPopover.svelte';
  import MapCanvas from './MapCanvas.svelte';
  import { attrValue, layersFrom } from './model';
  import OutOfScopeStrip from './OutOfScopeStrip.svelte';

  let { app, project, useLibrary = true }: { app: AppState; project: ProjectStore; useLibrary?: boolean } = $props();

  const hostId = $derived(url.get('host'));
  const layers = $derived(layersFrom(url.layers));
  const table = $derived(project.map.tableOnly || url.get('ansicht') === 'tabelle');
  const graph = $derived(project.map.graph);
  const empty = $derived(
    !!graph &&
      graph.summary.hosts === 0 &&
      (project.next.view?.clarify.length ?? 0) === 0 &&
      (project.next.view?.suggestions.length ?? 0) === 0,
  );
  /** gewählter Eintrag → Hosts mit gestricheltem Ring und Nummer («K2») */
  const linked = $derived.by(() => {
    // Korrektur D12: ohne Verbindung zeigt die Spalte keinen Eintrag, also auch keinen Ring
    if (hostId || app.offline) return {};
    const key = project.next.selectedKey;
    const ord = key ? project.next.ordinal(key) : null;
    if (!ord) return {};
    const out: Record<string, string> = {};
    for (const h of project.next.linkedHosts) out[h] = ord;
    return out;
  });

  function select(id: string): void {
    url.set({ host: id }, { push: true });
  }

  async function closeDetail(): Promise<void> {
    const id = url.get('host');
    if (!id) return;
    url.set({ host: null });
    await tick();
    const el = document.querySelector<HTMLElement>(`[data-map-card][data-host-id="${attrValue(id)}"], .table-view [data-host-id="${attrValue(id)}"]`);
    el?.focus({ preventScroll: true });
  }

  function toggleTable(): boolean {
    if (project.map.tableOnly) return false;
    url.set({ ansicht: url.get('ansicht') === 'tabelle' ? null : 'tabelle' });
    return true;
  }

  onMount(() =>
    registerKeys([
      { keys: ['t'], help: 'help.k.table', when: () => pageKeysActive('karte'), run: toggleTable },
      {
        keys: ['Escape'],
        help: 'help.k.close',
        when: () => !!url.get('host') && pageKeysActive('karte'),
        run: () => void closeDetail(),
      },
    ]),
  );
</script>

<div class="karte">
  <section class="map" aria-label={t('karte.label')}>
    {#if table}
      <HostTable {project} selected={hostId} onopen={select} />
    {:else}
      <MapCanvas {app} {project} {layers} selected={hostId} {linked} {useLibrary} onselect={select} onbackground={() => void closeDetail()} />
      <Lagebild {project} offline={app.offline} />
      {#if layers.has('oos')}<OutOfScopeStrip {app} {project} />{/if}
      <LayersPopover {app} {layers} />
    {/if}
  </section>
  <aside class="column">
    {#if hostId}
      <HostDetail {app} {project} {hostId} onback={() => void closeDetail()} />
    {:else if empty}
      <div class="first"><FirstSteps slug={project.slug} scope={project.info?.scope.include ?? []} /></div>
    {:else}
      <NextColumn {app} {project} />
    {/if}
  </aside>
</div>

<style>
  .karte {
    display: flex;
    height: 100%;
    min-height: 0;
  }
  .map {
    position: relative;
    flex: 1 1 auto;
    min-width: 0;
    background: var(--map);
    overflow: hidden;
  }
  .column {
    flex: 0 0 var(--column-w);
    min-width: var(--column-min);
    max-width: var(--column-max);
    background: var(--surface);
    border-left: var(--lw-1) solid var(--line);
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .first {
    overflow: auto;
  }
</style>
