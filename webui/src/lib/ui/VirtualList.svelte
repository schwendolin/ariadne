<!--
  Virtuelle Liste mit fester Zeilenhöhe für lange Logs (linpeas: tausende Zeilen).
  Positionen nur über CSS-Variablen per CSSOM (styleProps), keine Style-Attribute.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { styleProps } from './actions';

  let {
    count,
    rowHeight = 20,
    overscan = 12,
    row,
    scrollTo = null,
    scrollKey = 0,
    label,
  }: {
    count: number;
    rowHeight?: number;
    overscan?: number;
    row: Snippet<[number]>;
    scrollTo?: number | null;
    /** erhöhen, um erneut zu scrollTo zu springen */
    scrollKey?: number;
    label?: string;
  } = $props();

  let viewport: HTMLDivElement | undefined = $state();
  let scrollTop = $state(0);
  let height = $state(400);

  const start = $derived(Math.max(0, Math.floor(scrollTop / rowHeight) - overscan));
  const end = $derived(Math.min(count, Math.ceil((scrollTop + height) / rowHeight) + overscan));
  const indices = $derived(Array.from({ length: Math.max(0, end - start) }, (_, i) => start + i));

  $effect(() => {
    void scrollKey;
    void count;
    if (scrollTo === null || !viewport) return;
    const target = Math.max(0, scrollTo * rowHeight - viewport.clientHeight / 3);
    viewport.scrollTop = target;
    scrollTop = target;
  });
</script>

<div
  class="vl"
  bind:this={viewport}
  bind:clientHeight={height}
  onscroll={() => (scrollTop = viewport?.scrollTop ?? 0)}
  role="list"
  aria-label={label}
  tabindex="0"
>
  <div class="spacer" use:styleProps={{ '--vl-height': `${count * rowHeight}px` }}>
    <div class="window" use:styleProps={{ '--vl-offset': `${start * rowHeight}px`, '--vl-row': `${rowHeight}px` }}>
      {#each indices as i (i)}
        <div class="vl-row" role="listitem">{@render row(i)}</div>
      {/each}
    </div>
  </div>
</div>

<style>
  .vl {
    position: relative;
    height: 100%;
    overflow: auto;
  }
  .spacer {
    position: relative;
    height: var(--vl-height);
  }
  .window {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    transform: translateY(var(--vl-offset));
  }
  .vl-row {
    height: var(--vl-row);
    overflow: hidden;
  }
</style>
