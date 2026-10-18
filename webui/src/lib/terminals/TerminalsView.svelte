<!--
  Reiter Terminals (SCREENS 5, Briefing 5.4): eine Zeile pro Terminal (Name und pts, Aufnahme,
  Kontext als Brotkrume, letzter Befehl mit Zeit und Exit, Remote-Segment, Aktionen Pause 10 min
  bzw. Fortsetzen, Kontext setzen, Vorschlag übernehmen, Anderer Host), held als gestrichelte
  Zeile ohne Daten, j k ↵. Besitzer: ui-verlauf. Gerüst aus Phase 1.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Breadcrumb from '../ui/Breadcrumb.svelte';
  import Txt from '../ui/Txt.svelte';
  import { termName } from '../util/format';

  let { project }: { app: AppState; project: ProjectStore } = $props();
  const list = $derived(project.terminals.list);
</script>

<section class="terms" aria-label={t('term.title')}>
  {#if project.terminals.loaded && list.length === 0}<p class="muted">{t('term.empty')}</p>{/if}
  {#each list as x (x.terminal_id)}
    <div class="row" class:held={x.state === 'held'}>
      <span class="name">{termName(x)}</span>
      <span class="state">{x.state}</span>
      <span class="ctx">
        {#if x.state !== 'held'}<Breadcrumb stack={x.stack} />{/if}
        {#if x.last_command}<br /><Txt value={x.last_command.text ?? ''} mono max={80} />{/if}
      </span>
    </div>
  {/each}
  <p class="hint">{t('term.hint')}</p>
</section>

<style>
  .terms {
    max-width: 1180px;
    margin: 0 auto;
    padding: var(--sp-8) var(--sp-6);
    overflow: auto;
    height: 100%;
  }
  .row {
    display: grid;
    grid-template-columns: 160px 160px 1fr;
    gap: var(--sp-4);
    padding: var(--sp-3) var(--sp-4);
    margin-bottom: var(--sp-2);
    border: var(--lw-1) solid var(--line);
    border-radius: var(--r-card);
    background: var(--surface);
  }
  .held {
    border-style: dashed;
  }
  .muted,
  .hint {
    color: var(--muted);
  }
  .hint {
    font-size: var(--fs-xs);
  }
</style>
