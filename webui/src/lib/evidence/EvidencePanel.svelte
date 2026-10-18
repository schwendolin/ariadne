<!--
  Belegansicht als Tafel von rechts (Screen 7, Briefing 5.6): Kopf «Beleg · T2 msf · 16:45:12»,
  Raster Befehl, Kontext, Zeit auf ms, Quelle, Hash-Kette; Log mit Zeilennummern als virtuelle
  Liste, markierter Bereich, «N Zeilen davor ausgeblendet · zeigen»; Knöpfe Als Finding, Zu
  Finding hinzufügen, Als Beleg kopieren · Mac, Ganzes Log. Varianten: Datei mit SHA-256,
  Präsentationsmodus (maskiert), Hash-Kette verletzt (nicht wegklickbar, Kopieren und Finding
  gesperrt). Besitzer: ui-verlauf. Gerüst aus Phase 1.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import LogLine from '../ui/LogLine.svelte';
  import Panel from '../ui/Panel.svelte';
  import { url, type EvidenceTarget } from '../url/state.svelte';

  let { project, target }: { app: AppState; project: ProjectStore; target: EvidenceTarget } = $props();
  $effect(() => {
    void project.evidence.open(target);
  });
  const lines = $derived(project.evidence.lines?.lines ?? []);
  const marked = $derived(target.kind === 'unit' ? target.lines : null);
</script>

<Panel title={t('ev.title')} onclose={() => url.set({ beleg: null })} locked={project.evidence.unit?.chain_ok === false}>
  {#each lines as l (l.n)}
    <LogLine line={l} marked={marked !== null && l.n >= marked[0] && l.n <= marked[1]} />
  {/each}
</Panel>
