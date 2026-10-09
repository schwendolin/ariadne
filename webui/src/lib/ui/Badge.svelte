<script lang="ts">
  import type { Snippet } from 'svelte';

  type Tone = 'muted' | 'ok' | 'warn' | 'danger' | 'ai' | 'info';
  let { tone = 'muted', title, children }: { tone?: Tone; title?: string; children: Snippet } = $props();
</script>

<span class="badge {tone}" {title}>{@render children()}</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0 6px;
    border-radius: 999px;
    font-size: 0.78rem;
    line-height: 1.6;
    white-space: nowrap;
    font-weight: 600;
  }
  .muted {
    background: var(--badge-muted-bg);
    color: var(--badge-muted-text);
  }
  .ok {
    background: var(--badge-ok-bg);
    color: var(--badge-ok-text);
  }
  .warn {
    background: var(--badge-warn-bg);
    color: var(--badge-warn-text);
  }
  .danger {
    background: var(--badge-danger-bg);
    color: var(--badge-danger-text);
  }
  .ai {
    background: var(--badge-ai-bg);
    color: var(--badge-ai-text);
  }
  .info {
    background: var(--badge-info-bg);
    color: var(--badge-info-text);
  }
</style>
