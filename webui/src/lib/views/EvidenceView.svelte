<!--
  Belegansicht (Architektur 7.6): zu jedem Fakt die Stelle, aus der er stammt.
  Terminal: Befehl, Kontext, Zeit, Zeilen mit markiertem Bereich (virtuelle Liste).
  Datei: Pfad, SHA-256, Pfad im Dokument. Bild: Region als SVG-Rahmen.
-->
<script lang="ts">
  import type { FactSources, SourceView } from '../api/types';
  import { t } from '../i18n';
  import { router } from '../router.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import ConfBadge from '../ui/ConfBadge.svelte';
  import FactBadges from '../ui/FactBadges.svelte';
  import ScopeBadge from '../ui/ScopeBadge.svelte';
  import Txt from '../ui/Txt.svelte';
  import { errText } from '../util/errors';
  import { predLabel, shortId } from '../util/labels';
  import { dateTimeLocal, utcTooltip } from '../util/time';
  import StreamSource from './StreamSource.svelte';

  let { project, factId, presentation }: { project: ProjectStore; factId: string; presentation: boolean } = $props();

  let data = $state<FactSources | null>(null);
  let error = $state<string | null>(null);
  let images = $state<Record<string, string>>({});

  $effect(() => {
    const id = factId;
    void project.version;
    const ctrl = new AbortController();
    error = null;
    project.backend
      .factSources(project.pid, id, ctrl.signal)
      .then((d) => {
        data = d;
        for (const s of d.sources) {
          if (s.t === 'image') project.blobUrl(s.blob_id).then((u) => (images = { ...images, [s.blob_id]: u })).catch(() => undefined);
        }
      })
      .catch((e) => {
        if (!ctrl.signal.aborted) error = errText(e);
      });
    return () => ctrl.abort();
  });

  function close() {
    router.setParam('fact', null);
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'Escape') close();
  }
</script>

<svelte:window onkeydown={onKey} />

{#snippet source(s: SourceView)}
  {#if s.t === 'stream'}
    <StreamSource {project} src={s} {presentation} />
  {:else if s.t === 'file'}
    <dl class="kv">
      <dt>{t('ev.file')}</dt><dd><code><Txt value={s.path} max={160} /></code></dd>
      <dt>{t('ev.sha')}</dt><dd class="mono small">{s.sha256}</dd>
      {#if s.xpath}<dt>{t('ev.xpath')}</dt><dd><code><Txt value={s.xpath} max={160} /></code></dd>{/if}
      <dt>{t('col.source')}</dt><dd>{t('ev.parser', { p: s.parser, trust: t(`trust.${s.trust}`) })}</dd>
    </dl>
  {:else if s.t === 'image'}
    <figure class="shot">
      {#if images[s.blob_id]}
        <img src={images[s.blob_id]} alt={t('ev.image')} class:blur={presentation} />
        <svg class="overlay" viewBox="0 0 {s.width} {s.height}" preserveAspectRatio="none" aria-hidden="true">
          <rect x={s.bbox[0]} y={s.bbox[1]} width={s.bbox[2]} height={s.bbox[3]} class="region" />
        </svg>
      {/if}
      <figcaption class="small muted"><time title={utcTooltip(s.taken_at)}>{dateTimeLocal(s.taken_at)}</time> · <Txt value={s.window_title ?? ''} /></figcaption>
    </figure>
  {:else if s.t === 'ai'}
    <p><Badge tone="ai">{t('badge.ai')}</Badge> {t('ev.ai', { model: s.model })}</p>
    {#if s.quote_in}{@render source(s.quote_in)}{/if}
  {:else if s.t === 'user'}
    <p>{t('ev.user')} · <time title={utcTooltip(s.ts)}>{dateTimeLocal(s.ts)}</time> · <span class="mono">{s.decision_id}</span></p>
  {/if}
{/snippet}

<button type="button" class="backdrop" tabindex="-1" aria-label={t('common.close')} onclick={close}></button>
<aside class="evidence" role="dialog" aria-modal="true" aria-labelledby="ev-title">
  <header class="head">
    <div class="stack grow">
      <span class="small muted">{t('ev.title')}</span>
      {#if data}
        <h2 id="ev-title">
          <Txt value={data.fact.subject_label} max={60} /> · {predLabel(data.fact.predicate)}:
          <code><Txt value={data.fact.value} max={80} /></code>
        </h2>
        <div class="row">
          <Badge tone={data.fact.state === 'candidate' ? 'warn' : 'muted'}>{t(`claim.${data.fact.state}`)}</Badge>
          <ConfBadge level={data.fact.confidence_level} />
          <ScopeBadge verdict={data.fact.scope} />
          <FactBadges ai={data.fact.ai} offered={data.fact.offered_by_target} injection={data.fact.injection_suspect} conflict={!!data.fact.conflict_key} />
          <span class="small muted">{shortId(data.fact.subject)} · {t('ev.sources', { n: data.sources.length })}</span>
        </div>
      {:else}
        <h2 id="ev-title">{t('common.loading')}</h2>
      {/if}
    </div>
    <button type="button" class="ghost" onclick={close}>{t('common.close')}</button>
  </header>

  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if data}
    {#if data.sources.length === 0}
      <p class="muted">{t('ev.none')}</p>
    {/if}
    {#each data.sources as s, i (i)}
      <section class="card">
        {@render source(s)}
      </section>
    {/each}
  {/if}
</aside>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    width: 100%;
    border: 0;
    border-radius: 0;
    background: rgba(0, 0, 0, 0.25);
    z-index: 30;
    cursor: default;
  }
  .backdrop:hover {
    background: rgba(0, 0, 0, 0.25);
  }
  .evidence {
    position: fixed;
    top: 4vh;
    left: 50%;
    transform: translateX(-50%);
    width: min(1000px, 96vw);
    max-height: 92vh;
    overflow: auto;
    padding: 14px 16px 20px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    z-index: 31;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .head {
    display: flex;
    gap: 8px;
    align-items: flex-start;
  }
  .head h2 {
    margin: 0 0 4px;
    overflow-wrap: anywhere;
  }
  .grow {
    flex: 1;
    gap: 2px;
  }
  .kv {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 3px 12px;
    margin: 0;
  }
  .kv dt {
    color: var(--text-muted);
  }
  .kv dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .shot {
    position: relative;
    margin: 0;
    max-width: 640px;
  }
  .shot img {
    display: block;
    width: 100%;
  }
  .shot img.blur {
    filter: blur(8px);
  }
  .overlay {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: calc(100% - 22px);
  }
  .region {
    fill: none;
    stroke: var(--map-thread);
    stroke-width: 3;
  }
</style>
