<!--
  Fester Text mit eingesetzten Werten (`{name}`), Werte aus Zieldaten in Mono über Txt
  («Kontext T3 = <mono>.101</mono>, rückwirkend»). Nie HTML aus dem Text. Besitzer: ui-karte.
-->
<script lang="ts">
  import { t, type MessageKey } from '../i18n';
  import Txt from '../ui/Txt.svelte';

  let { key, params = {}, mono = [] }: { key: MessageKey; params?: Record<string, string>; mono?: string[] } = $props();

  /** Teile der Vorlage: Text oder Platzhalter */
  const parts = $derived.by(() => {
    const raw = t(key);
    const out: { text: string; param: string | null }[] = [];
    let last = 0;
    for (const m of raw.matchAll(/\{(\w+)\}/g)) {
      const at = m.index ?? 0;
      if (at > last) out.push({ text: raw.slice(last, at), param: null });
      out.push({ text: '', param: m[1] ?? null });
      last = at + m[0].length;
    }
    if (last < raw.length) out.push({ text: raw.slice(last), param: null });
    return out;
  });
</script>

{#each parts as p, i (i)}{#if p.param !== null}{#if mono.includes(p.param)}<span class="m"><Txt value={params[p.param] ?? ''} mono max={60} /></span>{:else}<Txt value={params[p.param] ?? ''} max={60} />{/if}{:else}{p.text}{/if}{/each}

<style>
  .m {
    font-size: var(--fs-s);
  }
</style>
