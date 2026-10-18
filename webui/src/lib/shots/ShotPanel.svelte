<!--
  Belegansicht eines Screenshots (Tafel, URL `beleg=s:<id>`): Bild in voller Breite, Zeit,
  Auslöser, Modus, Grösse, Host, Terminal, Fenstertitel (Zieldaten möglich, nur als Text), Notiz,
  SHA-256. Im Präsentationsmodus ist das Bild verdeckt und der Server liefert keinen Fenstertitel.
  Besitzer: ui.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import Panel from '../ui/Panel.svelte';
  import Txt from '../ui/Txt.svelte';
  import { url } from '../url/state.svelte';
  import { termShort } from '../util/format';
  import { hhmm } from '../util/time';
  import ShotImage from './ShotImage.svelte';

  let { app, project, id }: { app: AppState; project: ProjectStore; id: string } = $props();
  const shot = $derived(project.shots.byId(id));
  const term = $derived(shot?.terminal_id ? (project.terminals.all.find((r) => r.term.terminal_id === shot.terminal_id)?.term ?? null) : null);
  const title = $derived(shot ? t('shot.evTitle', { time: hhmm(shot.ts, { seconds: true }) }) : t('shot.evTitle', { time: '' }));

  function close(): void {
    url.set({ beleg: null });
  }
</script>

<Panel {title} onclose={close}>
  {#snippet header()}
    <div class="head">
      <h2>{title}</h2>
      {#if app.presentation}<Badge tone="solid">{t('ev.presentation')}</Badge>{/if}
    </div>
  {/snippet}
  {#if !shot}
    <p class="muted">{project.shots.loaded ? t('shot.missing') : t('shot.loading')}</p>
  {:else}
    <div class="body">
      <ShotImage {project} {shot} size="full" presentation={app.presentation} />
      <dl class="facts">
        <dt>{t('shot.trigger')}</dt>
        <dd>{t(`shot.trigger.${shot.trigger}`)} · {t(shot.mode === 'region' ? 'shot.mode.area' : `shot.mode.${shot.mode}`)}</dd>
        <dt>{t('shot.size')}</dt>
        <dd class="mono">{shot.width} × {shot.height}</dd>
        {#if shot.host}
          <dt>{t('shot.host')}</dt>
          <dd><Txt value={shot.host} mono max={80} /></dd>
        {/if}
        {#if shot.terminal_id}
          <dt>{t('shot.terminal')}</dt>
          <dd>{term ? termShort(term) : termShort({ terminal_id: shot.terminal_id, ordinal: null })}</dd>
        {/if}
        {#if shot.window_title}
          <dt>{t('shot.window')}</dt>
          <dd><Txt value={shot.window_title} max={200} /></dd>
        {/if}
        {#if shot.note}
          <dt>{t('shot.noteLabel')}</dt>
          <dd><Txt value={shot.note} max={500} /></dd>
        {/if}
        <dt>SHA-256</dt>
        <dd class="mono hash"><Txt value={shot.sha256} max={64} flag={false} /></dd>
      </dl>
    </div>
  {/if}
</Panel>

<style>
  .head {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  h2 {
    margin: 0;
    font-size: var(--fs-l);
    font-weight: 600;
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }
  .facts {
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    gap: 6px var(--sp-4);
    margin: 0;
    font-size: var(--fs-s);
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .mono {
    font-family: var(--font-mono);
  }
  .hash {
    font-size: var(--fs-xs);
  }
  .muted {
    color: var(--muted);
  }
</style>
