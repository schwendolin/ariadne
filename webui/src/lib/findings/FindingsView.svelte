<!--
  Reiter Findings (Screen 8, E113): Liste links (32 %), Formular rechts: Titel, Schwere (5 Stufen,
  setzt nur der Mensch), Status (Entwurf, final), Betroffen, Beschreibung, Massnahme (Markdown
  ohne HTML), ATT&CK, CVE (Hypothese ohne eigenen Beleg markiert), Belege, Speichern; leer:
  «Noch keine Findings. Findings entstehen aus Belegen.»; «Als Finding» aus der Belegansicht
  öffnet dasselbe Formular (`?finding=neu&beleg…`). Besitzer: ui-verlauf. Gerüst aus Phase 1.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Txt from '../ui/Txt.svelte';

  let { project }: { app: AppState; project: ProjectStore } = $props();
  const list = $derived(project.findings.list);
</script>

<section class="findings" aria-label={t('fd.title')}>
  {#if project.findings.loaded && list.length === 0}
    <div class="empty"><strong>{t('fd.empty')}</strong><p>{t('fd.emptyHint')}</p></div>
  {/if}
  <ul>
    {#each list as f (f.finding_id)}
      <li>F{f.ordinal} <Txt value={f.title} ctrl={f.ctrl} /></li>
    {/each}
  </ul>
</section>

<style>
  .findings {
    height: 100%;
    overflow: auto;
    padding: var(--sp-5);
  }
  .empty p {
    color: var(--muted);
  }
</style>
