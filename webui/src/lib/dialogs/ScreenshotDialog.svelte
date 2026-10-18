<!--
  Dialog «Screenshot der Kali» (Screen 10, Briefing 5.7, Entwurf api-screenshots): Modus Fenster,
  Monitor oder Bereich (mit X, Y, Breite, Höhe), Countdown 0, 3, 5 oder 10 s, Notiz. Auslösen
  schickt `POST /screenshots`; der Server wartet den Countdown ab und nimmt im Daemon auf (nur
  X11). Während die Anfrage läuft, zählt der Dialog sichtbar herunter. Danach: Vorschau mit
  «Ansehen» (Belegansicht) oder der feste Fehlertext (keine grafische Sitzung, Wayland, kein
  Fenster, Bereich ausserhalb). Hinweis «Beleg ohne Host-Identifikation». Besitzer: ui.
-->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { Screenshot, ShotMode, ShotRequest } from '../api/types';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import ShotImage from '../shots/ShotImage.svelte';
  import { url } from '../url/state.svelte';
  import { errorText } from '../util/errors';

  let { app, project, onclose }: { app: AppState; project: ProjectStore; onclose: () => void } = $props();

  let mode = $state<ShotMode>('window');
  let delay = $state<'0' | '3' | '5' | '10'>('3');
  let note = $state('');
  let region = $state({ x: '0', y: '0', w: '800', h: '600' });
  let phase = $state<'form' | 'counting' | 'done' | 'error'>('form');
  let left = $state(0);
  let shot = $state.raw<Screenshot | null>(null);
  let error = $state<string | null>(null);
  let timer: ReturnType<typeof setInterval> | null = null;

  const modes = $derived([
    { value: 'window' as const, label: t('shot.mode.window') },
    { value: 'monitor' as const, label: t('shot.mode.monitor') },
    { value: 'region' as const, label: t('shot.mode.area') },
  ]);
  const delays = [
    { value: '0' as const, label: t('shot.delayS', { n: 0 }) },
    { value: '3' as const, label: t('shot.delayS', { n: 3 }) },
    { value: '5' as const, label: t('shot.delayS', { n: 5 }) },
    { value: '10' as const, label: t('shot.delayS', { n: 10 }) },
  ];

  function int(v: string, min: number, max: number): number | null {
    if (!/^\d{1,5}$/.test(v.trim())) return null;
    const n = Number(v);
    return n >= min && n <= max ? n : null;
  }

  const regionValue = $derived.by(() => {
    const x = int(region.x, 0, 16384);
    const y = int(region.y, 0, 16384);
    const w = int(region.w, 1, 16384);
    const h = int(region.h, 1, 16384);
    return x === null || y === null || w === null || h === null ? null : { x, y, width: w, height: h };
  });
  const formOk = $derived(mode !== 'region' || regionValue !== null);

  function stopTimer(): void {
    if (timer) clearInterval(timer);
    timer = null;
  }
  onDestroy(stopTimer);

  async function run(): Promise<void> {
    if (!formOk || app.offline || phase === 'counting') return;
    const d = Number(delay);
    const req: ShotRequest = { mode, delay_s: d };
    if (mode === 'region' && regionValue) req.region = regionValue;
    if (note.trim()) req.note = note.trim().slice(0, 500);
    phase = 'counting';
    error = null;
    left = d;
    stopTimer();
    timer = setInterval(() => {
      left = Math.max(0, left - 1);
    }, 1000);
    try {
      shot = await project.backend.takeScreenshot(project.pid, req);
      phase = 'done';
      void project.shots.load();
    } catch (e) {
      error = errorText(e, 'shot.failedPrefix');
      phase = 'error';
    } finally {
      stopTimer();
    }
  }

  function open(): void {
    if (!shot) return;
    const id = shot.id;
    onclose();
    url.set({ beleg: `s:${id}`, tafel: null });
  }

  function again(): void {
    phase = 'form';
    shot = null;
    error = null;
  }
</script>

<Dialog title={t('shot.title')} {onclose} size="s">
  <div class="body">
    {#if phase === 'form' || phase === 'error'}
      <div class="field">
        <span class="lbl">{t('shot.mode')}</span>
        <Segmented options={modes} value={mode} onchange={(v) => (mode = v)} label={t('shot.mode')} />
        <span class="muted small">{t(mode === 'region' ? 'shot.modeHint.area' : `shot.modeHint.${mode}`)}</span>
      </div>
      {#if mode === 'region'}
        <div class="region">
          <label>{t('shot.region.x')}<input inputmode="numeric" bind:value={region.x} maxlength="5" /></label>
          <label>{t('shot.region.y')}<input inputmode="numeric" bind:value={region.y} maxlength="5" /></label>
          <label>{t('shot.region.w')}<input inputmode="numeric" bind:value={region.w} maxlength="5" /></label>
          <label>{t('shot.region.h')}<input inputmode="numeric" bind:value={region.h} maxlength="5" /></label>
        </div>
      {/if}
      <div class="field">
        <span class="lbl">{t('shot.delay')}</span>
        <Segmented options={delays} value={delay} onchange={(v) => (delay = v)} label={t('shot.delay')} />
      </div>
      <label class="field">
        <span class="lbl">{t('shot.note')}</span>
        <input class="note" bind:value={note} maxlength="500" />
      </label>
      {#if error}<p class="err" role="alert">{error}</p>{/if}
    {:else if phase === 'counting'}
      <div class="count" role="status" aria-live="polite" data-shot-counting>
        <span class="n">{left}</span>
        <span class="muted">{left > 0 ? t('shot.countdown') : t('shot.taking')}</span>
      </div>
    {:else if phase === 'done' && shot}
      <div class="done" role="status" data-shot-done>
        <strong>{t('shot.done')}</strong>
        <ShotImage {project} {shot} size="full" presentation={app.presentation} />
      </div>
    {/if}
    <p class="hint">{t('shot.hint')}</p>
  </div>
  {#snippet footer()}
    <Button onclick={onclose}>{t('shot.close')}</Button>
    {#if phase === 'done'}
      <Button onclick={again}>{t('shot.again')}</Button>
      <Button variant="primary" onclick={open}>{t('shot.open')}</Button>
    {:else}
      <Button variant="primary" disabled={!formOk || phase === 'counting' || app.offline} reason={app.offline ? t('err.network') : null} onclick={() => void run()}>{t('shot.run')}</Button>
    {/if}
  {/snippet}
</Dialog>

<style>
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .field {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
  }
  .lbl {
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .small {
    font-size: var(--fs-xs);
  }
  .muted {
    color: var(--muted);
  }
  .region {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 8px;
  }
  .region label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  input {
    width: 100%;
    padding: 6px 8px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: var(--surface);
    color: var(--fg);
    font: inherit;
    font-family: var(--font-mono);
    font-size: var(--fs-s);
  }
  .note {
    font-family: inherit;
  }
  .count {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 64px;
  }
  .n {
    font-size: 44px;
    font-weight: 700;
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }
  .done {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .hint {
    margin: 0;
    color: var(--attention);
    font-size: var(--fs-s);
  }
  .err {
    margin: 0;
    color: var(--error);
    font-size: var(--fs-s);
  }
</style>
