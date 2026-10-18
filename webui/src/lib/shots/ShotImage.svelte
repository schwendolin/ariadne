<!--
  Bild eines Screenshots (Entwurf api-screenshots): holt die Bytes über `GET /blobs/{id}` mit Token
  und zeigt sie als `blob:`-URL (CSP `img-src 'self' blob:`). Im Präsentationsmodus kein Abruf,
  sondern die Fläche «Im Präsentationsmodus verdeckt». Der Alternativtext nennt nur die Zeit, nie
  Zieldaten (Fenstertitel). Besitzer: ui.
-->
<script lang="ts">
  import type { Screenshot } from '../api/types';
  import { t } from '../i18n';
  import type { ProjectStore } from '../stores/project.svelte';
  import { hhmm } from '../util/time';

  let { project, shot, size = 'thumb', presentation }: { project: ProjectStore; shot: Screenshot; size?: 'thumb' | 'full'; presentation: boolean } = $props();

  let src = $state<string | null>(null);
  let failed = $state(false);

  $effect(() => {
    const id = shot.blob_id;
    const hidden = presentation;
    src = null;
    failed = false;
    if (hidden) return;
    let live = true;
    void project.shots.image(id).then((u) => {
      if (!live) return;
      src = u;
      failed = u === null;
    });
    return () => {
      live = false;
    };
  });
</script>

<span class="shot {size}" data-shot={shot.id}>
  {#if presentation}
    <span class="cover" data-shot-hidden>{t('shot.hidden')}</span>
  {:else if src}
    <img {src} alt={t('shot.alt', { time: hhmm(shot.ts, { seconds: true }) })} width={shot.width} height={shot.height} draggable="false" />
  {:else}
    <span class="cover muted">{failed ? t('shot.noImage') : t('shot.loading')}</span>
  {/if}
</span>

<style>
  .shot {
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    border-radius: 6px;
    border: var(--lw-1) solid var(--line);
    background: var(--surface-2);
  }
  .thumb {
    width: 132px;
    aspect-ratio: 16 / 10;
    flex: none;
  }
  .full {
    width: 100%;
    min-height: 120px;
  }
  img {
    display: block;
    width: 100%;
    height: 100%;
    object-fit: contain;
  }
  .cover {
    padding: 6px;
    font-size: var(--fs-xs);
    color: var(--fg-2);
    text-align: center;
  }
  .muted {
    color: var(--muted);
  }
</style>
