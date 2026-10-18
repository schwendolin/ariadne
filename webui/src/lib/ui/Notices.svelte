<!--
  Meldungen oben in der Mitte unter der Kopfzeile (Fehlertexte aus 5.14, nie Zieldaten), damit
  sie weder die Scope-Warnung oben rechts noch die Spalte verdecken. role="status" bzw. "alert".
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { UiStore } from '../stores/ui.svelte';
  import { fadeIn } from '../util/motion';

  let { ui }: { ui: UiStore } = $props();
</script>

<div class="notices" aria-live="polite">
  {#each ui.notices as n (n.id)}
    <div class="notice {n.kind}" role={n.kind === 'error' ? 'alert' : 'status'} use:fadeIn>
      <span>{n.text}</span>
      <button type="button" aria-label={t('notice.close')} onclick={() => ui.dismiss(n.id)}>×</button>
    </div>
  {/each}
</div>

<style>
  .notices {
    position: fixed;
    top: calc(var(--header-h) + 8px);
    left: 50%;
    transform: translateX(-50%);
    z-index: 60;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-2);
    width: max-content;
    max-width: min(520px, calc(100vw - 32px));
    pointer-events: none;
  }
  .notice {
    pointer-events: auto;
  }
  .notice {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-3);
    padding: var(--sp-3) var(--sp-4);
    background: var(--surface-2);
    border: var(--lw-1) solid var(--line-strong);
    border-radius: var(--r-card);
    box-shadow: var(--shadow);
  }
  .error {
    border-color: var(--error);
    color: var(--fg);
  }
  button {
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
  }
</style>
