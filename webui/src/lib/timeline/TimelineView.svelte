<!--
  Zeitachse (Screen 6, Briefing 5.5): Filter Typ, Terminal, Host; Lokalzeit CEST, «UTC zeigen»;
  Warteliste als eingeklappter Streifen oben; Zeilen neuestes oben mit allen Typen (Befehl,
  Callback, Lücke, Schlüsselschritt, Entscheid, Remote-Segment, Rückgängig, misstraut, Scope-
  Warnung, Eingaben verdeckt mit Aufdecken), Rückgängig inline mit Grund und Rückmeldung,
  «Wieder vertrauen», j k ↵ u. Besitzer: ui-verlauf. Gerüst aus Phase 1.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import { termShort } from '../util/format';
  import { hhmm } from '../util/time';
  import PendingStrip from './PendingStrip.svelte';

  let { project }: { app: AppState; project: ProjectStore } = $props();
  const items = $derived(project.timeline.items);
</script>

<section class="tl" aria-label={t('tl.title')}>
  <PendingStrip {project} />
  {#if project.timeline.loaded && items.length === 0}<p class="muted">{t('tl.empty')}</p>{/if}
  <ol class="rows">
    {#each items as it (it.id)}
      <li class="row"><span class="time">{hhmm(it.ts, { seconds: true })}</span><span class="term">{termShort(it.terminal)}</span><span>{it.type}</span></li>
    {/each}
  </ol>
</section>

<style>
  .tl {
    height: 100%;
    overflow: auto;
    padding: var(--sp-4) var(--sp-8);
  }
  .rows {
    list-style: none;
    padding: 0;
  }
  .row {
    display: grid;
    grid-template-columns: 90px 50px 1fr;
    padding: 6px 0;
  }
  .time,
  .term {
    font-family: var(--font-mono);
    color: var(--muted);
  }
  .muted {
    color: var(--muted);
  }
</style>
