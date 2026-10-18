<!--
  Text in Teilen (TextPart[]): Teile aus Zieldaten gepunktet unterstrichen (Vorlagen, Titel der
  Denkanstösse, Briefing 9.5). Jeder Teil geht durch Txt. Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { TextPart } from '../api/types';
  import Txt from './Txt.svelte';

  let { parts, mono = false, max = 0 }: { parts: TextPart[]; mono?: boolean; max?: number } = $props();
</script>

<span class="parts" class:mono>{#each parts as p, i (i)}<Txt value={p.text} target={p.target} {mono} max={max > 0 ? max : 100000} flag={false} />{/each}</span>

<style>
  .mono {
    font-family: var(--font-mono);
  }
</style>
