<!-- Leerer Zustand mit Titel, Text und optionaler Befehlszeile zum Kopieren. Besitzer: ui-fundament. -->
<script lang="ts">
  import type { Snippet } from 'svelte';
  let { title, text = '', children }: { title: string; text?: string; children?: Snippet } = $props();
</script>

<div class="empty">
  <h2>{title}</h2>
  {#if text}<p>{text}</p>{/if}
  {@render children?.()}
</div>

<style>
  .empty {
    max-width: 520px;
    margin: 0 auto;
    padding-top: 30vh;
  }
  h2 {
    margin: 0 0 var(--sp-2);
    font-size: var(--fs-xl);
  }
  p {
    color: var(--muted);
    margin: 0 0 var(--sp-4);
  }
</style>
