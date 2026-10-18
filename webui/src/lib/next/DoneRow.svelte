<!--
  Erledigter Eintrag, gedämpft an seinem Platz (Ruhezustand 1a, Screen 4 «Zustände danach»):
  ✓ erledigt mit «Rückgängig» (d.revoke; das `u` steht an dem Eintrag, auf den die Taste wirkt),
  ✕ verworfen durchgestrichen mit «verworfen» (gewählt: «Rückgängig»), · «In einem anderen Tab
  entschieden». Eine Zeile, zu lange Meldungen gekürzt, voller Text im title. Ein übernommener
  Kontext lässt sich nicht widerrufen, nur neu setzen («Ändern …»). Besitzer: ui-karte.
-->
<script lang="ts">
  import { SP } from '../karte/sep';
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
  const fullText = $derived(entry.msg ? t(entry.msg.key, entry.msg.params) : entry.line.parts.map((p) => p.text).join(''));
  /**
   * Tastenhinweis `u` nur am gewählten Eintrag (Korrektur D7): an jeder erledigten Zeile kostete er
   * Platz und kürzte den Text; die Fusszeile nennt `u` ohnehin.
   */
  const uTarget = $derived(selected);
  const showUndo = $derived(!!entry.decisionId && (entry.state !== 'dismissed' || selected));

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
    <span class="text" title={lineText}>{t('next.otherTab')}<span class="sr-only">{SP}({lineText})</span></span>
    <span class="right">{t('next.d.otherTabState')}</span>
  {:else}
    <span class="text" class:strike={entry.state === 'dismissed'} title={fullText}>
      {#if entry.state === 'dismissed'}
        <Parts parts={entry.line.parts} />
      {:else if !entry.msg}
        <!-- erledigt ohne eigene Meldung (anderswo im Tab entschieden oder durch die Auswertung) -->
        {entry.line.kind}{SP}<Parts parts={entry.line.parts} />
      {:else}
        <Msg key={entry.msg.key} {params} mono={entry.msg.mono} />
      {/if}
    </span>
    {#if showUndo}
      <button type="button" class="right link" disabled={busy || app.offline} onclick={(e) => { e.stopPropagation(); void next.undo(entry); }}>
        {t('next.a.undo')}{#if uTarget}{SP}<Kbd keys="u" subtle />{/if}
      </button>
    {:else if entry.ctx}
      <button type="button" class="right link" disabled={app.offline} onclick={(e) => { e.stopPropagation(); change(); }}>{t('next.a.change')}</button>
    {:else if entry.state === 'dismissed'}
      <span class="right">{t('next.d.sugDismissed')}</span>
    {:else if !entry.msg}
      <span class="right">{t('next.d.otherTabState')}</span>
    {/if}
  {/if}
</div>

<style>
  .done {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 4px 8px;
    min-height: 26px;
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
  /* Korrektur D7: der Text hat Vorrang; lieber umbrechen als mitten im Wert kürzen */
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
