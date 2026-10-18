<!--
  Lagebild oben links auf der Karte (SCREENS 1a, Briefing 5.1): «Stand 16:54 · 3 Hosts, 1 im Nebel ·
  1 mit Zugriff», dazu die Marke «+3 seit 16:40» (E106, web-api.md 18.3), wenn seit dem letzten
  Unsichtbarwerden des Tabs etwas neu ist. Ein Klick lässt genau das Neue einmal pulsieren.
  Besitzer: ui-karte.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { ProjectStore } from '../stores/project.svelte';
  import { hhmm } from '../util/time';

  /** `offline`: ohne Verbindung keine Marke «+N seit» (Korrektur D12, Screen 9) */
  let { project, offline = false }: { project: ProjectStore; offline?: boolean } = $props();
  const g = $derived(project.map.graph);
  const seen = $derived(project.seen.view);
  /** «Stand»: Zeit der Generation (18.8), sonst Zeit des letzten Ladens */
  const asOf = $derived(g?.as_of ?? project.map.loadedAt);
  const summary = $derived.by(() => {
    if (!g) return '';
    const s = g.summary;
    if (s.hosts === 0) return `${t('lage.stand', { time: hhmm(asOf) })} · ${t('lage.noHosts')}`;
    let text = `${t('lage.stand', { time: hhmm(asOf) })} · ${t('lage.hosts', { n: s.hosts })}`;
    if (s.fog > 0) text += `, ${t('lage.fog', { n: s.fog })}`;
    text += ` · ${t('lage.access', { n: s.with_access })}`;
    return text;
  });
</script>

<div class="lage">
  {#if g}<span class="sum">{summary}</span>{/if}
  {#if !offline && seen?.new && seen.new.count > 0}
    <button
      type="button"
      class="new"
      title={t('lage.newSinceTitle', { time: hhmm(seen.new.since) })}
      onclick={() => project.seen.pulse()}
    >
      {t('lage.newSince', { n: seen.new.count, time: hhmm(seen.new.since) })}
    </button>
  {/if}
</div>

<style>
  .lage {
    position: absolute;
    left: 20px;
    top: 16px;
    z-index: 3;
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    font-size: 13px;
    color: var(--muted);
    pointer-events: none;
  }
  .sum {
    white-space: nowrap;
  }
  .new {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 3px 9px;
    border-radius: var(--r-pill);
    border: var(--lw-1) solid var(--line-strong);
    background: var(--map);
    color: var(--fg);
    font-size: 13px;
    cursor: pointer;
    pointer-events: auto;
  }
  .new:hover {
    border-color: var(--muted);
  }
</style>
