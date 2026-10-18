<!--
  Kennzeichen (Radius 4): neutral, attention (Handlungsbedarf, Pause, held), error, ai («KI»),
  solid (Präsentation). Status nie nur über Farbe: immer mit Text. Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  let { tone = 'neutral', children }: { tone?: 'neutral' | 'attention' | 'error' | 'ai' | 'solid'; children: Snippet } = $props();
</script>

<span class="badge {tone}">{@render children()}</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-1);
    padding: 1px 6px;
    border-radius: var(--r-badge);
    border: var(--lw-1) solid var(--line-strong);
    font-size: var(--fs-xs);
    color: var(--muted);
    white-space: nowrap;
  }
  .attention {
    border-color: var(--attention);
    color: var(--attention);
  }
  .error {
    border-color: var(--error);
    color: var(--error);
  }
  .ai {
    border-color: var(--fg-2);
    color: var(--fg);
    font-weight: 700;
  }
  .solid {
    background: var(--fg);
    border-color: var(--fg);
    color: var(--bg);
    font-weight: 600;
  }
</style>
