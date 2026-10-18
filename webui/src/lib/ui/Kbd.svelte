<!-- Tastenhinweis (Mono, --kbd-bg), z. B. «a», «↵», «⌘K». Besitzer: ui-fundament. -->
<script lang="ts">
  let { keys, subtle = false }: { keys: string; subtle?: boolean } = $props();
</script>

<kbd class:subtle>{keys}</kbd>

<style>
  kbd {
    font-family: var(--font-mono);
    font-size: 11.5px;
    padding: 1px 5px;
    border-radius: var(--r-badge);
    background: var(--kbd-bg);
    color: var(--muted);
  }
  .subtle {
    background: transparent;
    padding: 0;
  }
</style>
