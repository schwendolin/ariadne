<!--
  Erledigter Eintrag, gedämpft an seinem Platz (Ruhezustand 1a, Screen 4 «Zustände danach»):
  ✓ erledigt mit «Rückgängig u» (d.revoke), ✕ verworfen durchgestrichen, · «In einem anderen Tab
  entschieden». Ein übernommener Kontext lässt sich nicht widerrufen, nur neu setzen («Ändern …»).
  Besitzer: ui-karte.
-->
<script lang="ts">
  import type { AppState } from '../stores/app.svelte';
  import type { DoneEntry } from '../stores/next.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import { t } from '../i18n';
  import Kbd from '../ui/Kbd.svelte';
  import Msg from './Msg.svelte';
  import Parts from './Parts.svelte';

  let {
    app,
    project,
    entry,
    selected,
    short = (s: string) => s,
  }: { app: AppState; project: ProjectStore; entry: DoneEntry; selected: boolean; short?: (s: string) => string } = $props();
  const next = $derived(project.next);
  const busy = $derived(next.isBusy(entry.key));
  const params = $derived(
    entry.msg ? Object.fromEntries(Object.entries(entry.msg.params).map(([k, v]) => [k, entry.msg?.mono.includes(k) ? short(v) : v])) : {},
  );
  const lineText = $derived(`${entry.line.kind} ${entry.line.parts.map((p) => p.text).join('')}`);

  function change(): void {
    if (!entry.ctx) return;
    app.ui.openDialog({ kind: 'context', terminalId: entry.ctx.terminalId, fromOff: entry.ctx.fromOff });
  }
</script>

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="done s-{entry.state}" class:selected data-done-key={entry.key} aria-current={selected ? 'true' : undefined} onclick={() => next.select(entry.key)}>
  <span class="mark" aria-hidden="true">{entry.state === 'done' ? '✓' : entry.state === 'dismissed' ? '✕' : '·'}</span>
  {#if entry.state === 'other_tab'}
    <span class="text" title={lineText}>{t('next.otherTab')}<span class="sr-only"> ({lineText})</span></span>
    <span class="right">{t('next.d.otherTabState')}</span>
  {:else}
    <span class="text" class:strike={entry.state === 'dismissed'}>
      {#if entry.state === 'dismissed' || !entry.msg}
        <Parts parts={entry.line.parts} />
      {:else}
        <Msg key={entry.msg.key} {params} mono={entry.msg.mono} />
      {/if}
    </span>
    {#if entry.decisionId}
      <button type="button" class="right link" disabled={busy || app.offline} onclick={(e) => { e.stopPropagation(); void next.undo(entry); }}>
        {t('next.a.undo')} <Kbd keys="u" subtle />
      </button>
    {:else if entry.ctx}
      <button type="button" class="right link" disabled={app.offline} onclick={(e) => { e.stopPropagation(); change(); }}>{t('next.a.change')}</button>
    {:else if entry.state === 'dismissed'}
      <span class="right">{t('next.d.sugDismissed')}</span>
    {/if}
  {/if}
</div>

<style>
  .done {
    display: flex;
    align-items: baseline;
    gap: 10px;
    padding: 8px;
    border-radius: 8px;
    color: var(--faint);
    cursor: default;
  }
  .done.s-other_tab {
    color: var(--muted);
  }
  .selected {
    box-shadow: 0 0 0 2px var(--focus);
  }
  .mark {
    flex: none;
  }
  .text {
    flex: 1;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .strike {
    text-decoration: line-through;
  }
  .right {
    flex: none;
    margin-left: auto;
    color: var(--muted);
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    font: inherit;
    cursor: pointer;
  }
  .link:hover:not(:disabled) {
    color: var(--fg);
  }
  .link:disabled {
    cursor: not-allowed;
    opacity: 0.6;
  }
</style>
