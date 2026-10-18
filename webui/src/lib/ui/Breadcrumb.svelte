<!--
  Kontext-Stapel als Brotkrume (Briefing 5.4): «Kali › 192.168.56.101 [msf] (auto)», unten immer
  Kali, eine unbekannte Stufe auffällig als «?», «auto» unauffällig (E110). Hosts sind Zieldaten
  (Txt). Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { StageKind, StageView } from '../api/types';
  import { t } from '../i18n';
  import Txt from './Txt.svelte';

  let { stack, suggestion = null }: { stack: StageView[]; suggestion?: string | null } = $props();

  const KIND: Record<StageKind, string> = {
    local: '',
    su: 'su',
    ssh: 'ssh',
    winrm: 'winrm',
    remote: 'remote',
    revshell: 'Reverse Shell',
    msf: 'msf',
    meterpreter: 'meterpreter',
    db: 'Datenbank',
    unknown: 'unbekannt',
  };
  const rest = $derived(stack.filter((s) => s.depth > 0));
</script>

<span class="crumb">
  <span class="kali">Kali</span>
  {#each rest as s (s.depth)}
    <span class="sep" aria-hidden="true">›</span>
    {#if s.host_label}
      <Txt value={s.host_label} mono max={48} />
    {:else}
      <span class="unknown" title={suggestion ?? undefined}>?</span>
    {/if}
    {#if KIND[s.kind]}<span class="kind">[{KIND[s.kind]}]</span>{/if}
    {#if s.user}<span class="user">(<Txt value={s.user} max={32} />)</span>{/if}
    {#if s.auto}<span class="auto">({t('common.auto')})</span>{/if}
  {/each}
</span>

<style>
  .crumb {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
    min-width: 0;
  }
  .sep,
  .auto {
    color: var(--muted);
  }
  .unknown {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    padding: 0 4px;
    border: var(--lw-1) solid var(--attention);
    border-radius: var(--r-badge);
    color: var(--attention);
    font-weight: 700;
  }
</style>
