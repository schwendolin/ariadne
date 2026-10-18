<!--
  Befehl in Mono mit «Kopieren · Mac» (Kein Projekt, Gesperrt, Erste Schritte; Screen 9). Der
  Befehl ist fester Text oder eine Vorlage vom Server, nie ein Secret. `short` zeigt nur «Mac».
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import CopyButton from './CopyButton.svelte';
  let { command, copy = true, short = false, size = 'm' }: { command: string; copy?: boolean; short?: boolean; size?: 's' | 'm' } = $props();
</script>

<div class="cmd {size}">
  <code>{command}</code>
  {#if copy}<CopyButton target="mac" text={command} {short} />{/if}
</div>

<style>
  .cmd {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: 9px 9px 9px 12px;
    border: var(--lw-1) solid var(--line);
    border-radius: 8px;
    background: var(--log-bg);
    min-width: 0;
  }
  .cmd.s {
    padding: 7px 7px 7px 10px;
    border-radius: 7px;
  }
  code {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono);
    font-size: 13px;
    overflow-wrap: anywhere;
  }
  .s code {
    font-size: var(--fs-xs);
  }
</style>
