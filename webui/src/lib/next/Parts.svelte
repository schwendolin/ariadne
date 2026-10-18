<!--
  Titel in Teilen (TextPart[]) für Liste und Karten der Spalte: Teile aus Zieldaten in Mono (über
  Txt), ohne Unterstreichung (gepunktet nur in Befehlsvorlagen, TemplateBlock). Besitzer: ui-karte.
-->
<script lang="ts">
  import type { TextPart } from '../api/types';
  import Txt from '../ui/Txt.svelte';

  let { parts, max = 120 }: { parts: TextPart[]; max?: number } = $props();
</script>

{#each parts as p, i (i)}{#if p.target}<span class="m"><Txt value={p.text} mono {max} /></span>{:else}<Txt value={p.text} {max} flag={false} />{/if}{/each}

<style>
  .m {
    font-family: var(--font-mono);
    font-size: 0.93em;
  }
</style>
