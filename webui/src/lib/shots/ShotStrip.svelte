<!--
  Screenshots in der Zeitachse und im Host-Detail: Reihe kleiner Bilder, neueste zuerst, mit Zeit
  und Auslöser; ein Klick öffnet die Belegansicht des Bildes (`beleg=s:<id>`). Im
  Präsentationsmodus verdeckt. Besitzer: ui.
-->
<script lang="ts">
  import type { Screenshot } from '../api/types';
  import { t } from '../i18n';
  import type { ProjectStore } from '../stores/project.svelte';
  import { url } from '../url/state.svelte';
  import { hhmm } from '../util/time';
  import ShotImage from './ShotImage.svelte';

  let { project, shots, presentation, label = t('shot.strip') }: { project: ProjectStore; shots: Screenshot[]; presentation: boolean; label?: string } = $props();
</script>

{#if shots.length > 0}
  <section class="strip" aria-label={label}>
    <h3>{label} <span class="n">{shots.length}</span></h3>
    <ul>
      {#each shots.slice(0, 12) as s (s.id)}
        <li>
          <button type="button" class="item" onclick={() => url.set({ beleg: `s:${s.id}`, tafel: null })} aria-label={t('shot.evTitle', { time: hhmm(s.ts, { seconds: true }) })}>
            <ShotImage {project} shot={s} {presentation} />
            <span class="meta">{hhmm(s.ts, { seconds: true })} · {t(`shot.trigger.${s.trigger}`)}</span>
          </button>
        </li>
      {/each}
    </ul>
  </section>
{/if}

<style>
  .strip {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  h3 {
    margin: 0;
    font-size: var(--fs-xs);
    font-weight: 500;
    color: var(--muted);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .n {
    font-family: var(--font-mono);
  }
  ul {
    display: flex;
    gap: 10px;
    margin: 0;
    padding: 0 0 4px;
    list-style: none;
    overflow-x: auto;
  }
  .item {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 4px;
    border: var(--lw-1) solid transparent;
    border-radius: 8px;
    background: none;
    color: var(--fg-2);
    font: inherit;
    cursor: pointer;
    text-align: left;
  }
  .item:hover {
    border-color: var(--line-strong);
  }
  .meta {
    font-size: var(--fs-xs);
    font-family: var(--font-mono);
    color: var(--muted);
  }
</style>
