<!--
  Eine Zeile der virtuellen Logliste in der Belegansicht: lädt ihren Block nach, sobald sie
  sichtbar wird (EvidenceStore.ensure), zeigt bis dahin nur die Nummer. Markierter Bereich im
  --focus-Ton, Zeilen ab einer Bruchstelle der Hash-Kette mit Rand in --error. Besitzer: ui-verlauf.
-->
<script lang="ts">
  import type { EvidenceStore } from '../stores/evidence.svelte';
  import LogLine from '../ui/LogLine.svelte';

  let {
    store,
    n,
    marked = false,
    broken = false,
    showHidden = false,
  }: { store: EvidenceStore; n: number; marked?: boolean; broken?: boolean; showHidden?: boolean } = $props();

  const line = $derived(store.line(n));

  $effect(() => {
    if (!line) store.ensure(n);
  });
</script>

<div class="lr" class:broken data-n={n}>
  {#if line}
    <LogLine {line} {marked} {showHidden} />
  {:else}
    <div class="ph" class:marked><span class="ln">{n + 1}</span><span class="dots">…</span></div>
  {/if}
</div>

<style>
  .lr {
    border-left: 2px solid transparent;
  }
  .broken {
    border-left-color: var(--error);
  }
  .ph {
    display: flex;
    font-family: var(--font-mono);
    font-size: var(--fs-s);
    line-height: 22px;
    color: var(--faint);
  }
  .ph.marked {
    background: var(--log-mark);
  }
  .ln {
    flex: none;
    width: 5ch;
    padding-right: 1.5ch;
    text-align: right;
  }
</style>
