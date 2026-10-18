<!--
  Warteliste als eingeklappter Streifen oben in der Zeitachse (E114, Screen 6 und 10): «3 Dateien
  nicht übernommen · neueste 16:49», aufgeklappt Pfad, Grund, Grösse, Zeit; Übernehmen in v0.1 nur
  mit `ariadne import`. Besitzer: ui-verlauf. Gerüst aus Phase 1.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { ProjectStore } from '../stores/project.svelte';
  import { hhmm } from '../util/time';

  let { project }: { project: ProjectStore } = $props();
  const files = $derived(project.timeline.pending?.files ?? []);
</script>

{#if files.length > 0}
  <div class="strip">
    <strong>{t('pending.strip')}</strong>
    <span class="muted">{t('pending.summary', { n: files.length, time: hhmm(files[0]?.ts ?? null) })}</span>
  </div>
{/if}

<style>
  .strip {
    display: flex;
    gap: var(--sp-3);
    padding: var(--sp-2) var(--sp-4);
    border: var(--lw-1) solid var(--line);
    border-radius: var(--r-btn);
    background: var(--surface);
  }
  .muted {
    color: var(--muted);
  }
</style>
