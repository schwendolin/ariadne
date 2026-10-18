<!--
  Log einer Einheit in der Belegansicht (Screen 7): virtuelle Liste mit fester Zeilenhöhe (lange
  Ausgaben wie linpeas), Zeilennummern ab 1, markierter Bereich; liegt die Markierung weiter unten,
  beginnt die Ansicht kurz davor mit «N Zeilen davor ausgeblendet · zeigen». «verdeckte Teile
  zeigen» lädt mit reveal_hidden (nur Profil lab, nie im Präsentationsmodus). Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { EvidenceStore } from '../stores/evidence.svelte';
  import VirtualList from '../ui/VirtualList.svelte';
  import { errorText } from '../util/errors';
  import LogRow from './LogRow.svelte';

  let {
    store,
    marked,
    chainBreak = null,
    canReveal = false,
  }: { store: EvidenceStore; marked: [number, number] | null; chainBreak?: number | null; canReveal?: boolean } = $props();

  const CONTEXT = 3;
  let showAll = $state(false);
  let scrollTo = $state<number | null>(null);
  let scrollKey = $state(0);

  const total = $derived(store.total);
  const start = $derived(!showAll && marked && marked[0] > CONTEXT + 2 ? Math.min(marked[0] - CONTEXT, Math.max(0, total - 1)) : 0);
  const count = $derived(Math.max(0, total - start));
  const anyHidden = $derived(
    Object.values(store.chunks).some((c) => c.some((l) => l.concealed || l.overwritten || l.masked.some((m) => m.kind === 'concealed'))),
  );

  function expand(): void {
    showAll = true;
    scrollTo = marked ? Math.max(0, marked[0]) : 0;
    scrollKey++;
  }

  function inMark(n: number): boolean {
    return marked !== null && n >= marked[0] && n <= marked[1];
  }
</script>

<div class="log">
  {#if start > 0 || anyHidden || store.revealHidden}
    <div class="bar">
      {#if start > 0}
        <span>{t('ev.hiddenBefore', { n: start })} · <button type="button" class="link" onclick={expand}>{t('ev.showAll')}</button></span>
      {/if}
      {#if anyHidden || store.revealHidden}
        <button
          type="button"
          class="link right"
          disabled={!canReveal && !store.revealHidden}
          title={!canReveal ? t('ev.revealBlocked') : undefined}
          aria-pressed={store.revealHidden}
          onclick={() => store.setRevealHidden(!store.revealHidden)}>{store.revealHidden ? t('ev.hideHidden') : t('ev.revealHidden')}</button
        >
      {/if}
    </div>
  {/if}
  {#if store.linesError}
    <p class="err" role="alert">{errorText(store.linesError, 'ev.logFailed')}</p>
  {:else if total === 0}
    <p class="empty">{t('ev.noLines')}</p>
  {:else}
    <div class="vl">
      <VirtualList {count} rowHeight={22} {scrollTo} {scrollKey} label={t('ev.logLabel')}>
        {#snippet row(i: number)}
          <LogRow {store} n={start + i} marked={inMark(start + i)} broken={chainBreak !== null && start + i >= chainBreak} showHidden={store.revealHidden} />
        {/snippet}
      </VirtualList>
    </div>
  {/if}
</div>

<style>
  .log {
    flex: 1;
    min-height: 180px;
    display: flex;
    flex-direction: column;
    border-radius: 8px;
    background: var(--log-bg);
    border: var(--lw-1) solid var(--line);
    padding: 10px 0;
    overflow: hidden;
  }
  .bar {
    display: flex;
    gap: var(--sp-3);
    padding: 0 14px 6px;
    color: var(--faint);
    font-size: var(--fs-xs);
    flex: none;
  }
  .right {
    margin-left: auto;
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    cursor: pointer;
    font-size: var(--fs-xs);
  }
  .link:hover:not(:disabled) {
    color: var(--fg);
    text-decoration: underline;
  }
  .link:disabled {
    cursor: not-allowed;
    opacity: 0.6;
  }
  .vl {
    flex: 1;
    min-height: 0;
    padding-right: 14px;
  }
  .err,
  .empty {
    margin: 0;
    padding: 0 14px;
  }
  .err {
    color: var(--error);
  }
  .empty {
    color: var(--muted);
  }
</style>
