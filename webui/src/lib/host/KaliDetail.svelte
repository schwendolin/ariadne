<!--
  Kali-Detail (Briefing 5.3 «Sonderfälle»): «Eingang. Ariadne schickt von Kali aus nie selbst Pakete
  an Ziele», eigene Adressen (nie ein Host, E42) und die Terminals mit Zustand und Kontext.
  Besitzer: ui-karte.
-->
<script lang="ts">
  import type { KaliNode } from '../api/types';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Txt from '../ui/Txt.svelte';
  import { termName } from '../util/format';

  let { app, project }: { app: AppState; project: ProjectStore } = $props();
  const kali = $derived((project.map.graph?.nodes.find((n) => n.kind === 'kali') as KaliNode | undefined) ?? null);
  const terms = $derived(app.status?.terminals ?? []);
</script>

<div class="id">
  <span class="sym" aria-hidden="true"></span>
  <div class="idtext"><h2 class="label">{t('host.kali.title')}</h2></div>
</div>
<p class="text">{t('host.kali.text')}</p>
<div class="grid">
  <span class="k">{t('host.kali.addrs')}</span>
  <span class="list">
    {#each kali?.addresses ?? [] as a (a)}<span class="mono"><Txt value={a} mono max={60} /></span>{/each}
    <span class="muted small">{t('host.kali.never')}</span>
  </span>
  <span class="k">{t('host.kali.terminals')}</span>
  <span class="list">
    {#each terms as tm (tm.terminal_id)}
      <span>{termName(tm)} · <span class="muted">{tm.state}</span>{#if tm.context_label}{' · '}<Txt value={tm.context_label} ctrl={tm.ctrl} max={60} />{/if}</span>
    {/each}
  </span>
</div>

<style>
  .id {
    display: flex;
    gap: 12px;
    align-items: center;
    padding: 16px 20px 12px;
  }
  .sym {
    width: 36px;
    height: 36px;
    border-radius: 8px;
    border: var(--lw-node) solid var(--line-hover);
    background: var(--surface-2);
  }
  .label {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
  }
  .text {
    margin: 0;
    padding: 0 20px 14px;
    color: var(--fg-2);
  }
  .grid {
    display: grid;
    grid-template-columns: 96px minmax(0, 1fr);
    gap: 8px 12px;
    padding: 0 20px 14px;
    font-size: 13px;
  }
  .k,
  .muted {
    color: var(--muted);
  }
  .small {
    font-size: var(--fs-xs);
  }
  .list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .mono {
    font-family: var(--font-mono);
  }
</style>
