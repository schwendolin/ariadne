<!--
  Rückgängig pro Befehl inline in der Zeitachsenzeile (Screen 6, E42, web-api.md 12): «Werte aus
  diesem Befehl verwerfen?», Erklärung, Grund (optional), «Rückgängig machen» (d.unit.distrust,
  allein in der Anfrage) und «Abbrechen»; danach die Rückmeldung «18 verworfen, 0 geschwächt» mit
  «Wieder vertrauen» (d.revoke). Fehler stehen hier, nicht als Meldung («Rückgängig nicht
  gespeichert: Das Projekt ist gesperrt»). Enter bestätigt, Esc bricht ab. Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import type { TimelineItem } from '../api/types';
  import { t } from '../i18n';
  import type { TimelineStore, UndoState } from '../stores/timeline.svelte';
  import Button from '../ui/Button.svelte';
  import Txt from '../ui/Txt.svelte';
  import { fadeIn } from '../util/motion';

  let {
    store,
    undo,
    item,
    offline = false,
    onclose,
  }: { store: TimelineStore; undo: UndoState; item: TimelineItem; offline?: boolean; onclose: () => void } = $props();

  let reason = $state('');
  let input: HTMLInputElement | undefined = $state();
  const asking = $derived(undo.phase === 'ask' || undo.phase === 'busy' || undo.phase === 'error');
  const tooLong = $derived(reason.length > 500);

  let box: HTMLElement | undefined = $state();

  // Der Kasten öffnet unter der Zeile; steht sie unten im Bild, rückt er ins Bild (ohne Sprung,
  // nur so weit wie nötig), dann bekommt der Grund den Fokus.
  onMount(() => {
    queueMicrotask(() => {
      box?.scrollIntoView?.({ block: 'nearest' });
      if (asking) input?.focus({ preventScroll: true });
    });
  });

  function submit(e: SubmitEvent): void {
    e.preventDefault();
    if (tooLong || undo.phase === 'busy') return;
    void store.distrust(reason);
  }

  function cancel(): void {
    store.cancelUndo();
    onclose();
  }

  function trust(): void {
    if (undo.decisionId) void store.trustAgain(item, undo.decisionId);
  }
</script>

{#if asking}
  <form class="box" bind:this={box} onsubmit={submit} use:fadeIn aria-label={t('tl.undo.title')}>
    <strong>{t('tl.undo.title')}</strong>
    <p class="text">{t('tl.undo.text.pre')} <Txt value={undo.short} mono max={40} /> {t('tl.undo.text.post')}</p>
    <label class="sr-only" for="undo-reason-{undo.rowId}">{t('tl.undo.reason')}</label>
    <input
      id="undo-reason-{undo.rowId}"
      bind:this={input}
      bind:value={reason}
      placeholder={t('tl.undo.reason')}
      maxlength="500"
      autocomplete="off"
      disabled={undo.phase === 'busy'}
    />
    {#if tooLong}<p class="err">{t('tl.undo.reasonTooLong')}</p>{/if}
    <div class="buttons">
      <Button variant="primary" type="submit" disabled={undo.phase === 'busy' || offline} reason={offline ? t('term.offline') : t('tl.undo.busy')}>
        {undo.phase === 'busy' ? t('tl.undo.busy') : t('tl.undo.confirm')}
      </Button>
      <Button onclick={cancel} disabled={undo.phase === 'busy'} reason={t('tl.undo.busy')}>{t('tl.undo.cancel')}</Button>
    </div>
    {#if undo.phase === 'error' && undo.error}<p class="error-box" role="alert">{undo.error}</p>{/if}
  </form>
{:else}
  <div class="feedback" class:bad={undo.phase === 'trust_error'} role="status" use:fadeIn>
    {#if undo.phase === 'done'}
      <span>{t('tl.undo.done', { rejected: undo.effect?.rejected ?? 0, weakened: undo.effect?.weakened ?? 0 })}</span>
      {#if undo.decisionId}
        <button type="button" class="link" disabled={offline} onclick={trust}>{t('tl.trustAgain')}</button>
      {/if}
    {:else if undo.phase === 'trusting'}
      <span>{t('tl.undo.trustBusy')}</span>
    {:else if undo.phase === 'trusted'}
      <span>{t('tl.undo.trusted')}</span>
      <button type="button" class="link" onclick={cancel}>{t('common.close')}</button>
    {:else}
      <span>{undo.error ?? t('tl.undo.trustFailed')}</span>
      <button type="button" class="link" onclick={trust}>{t('common.retry')}</button>
    {/if}
  </div>
{/if}

<style>
  .box {
    border-radius: var(--r-card);
    background: var(--surface-2);
    border: var(--lw-1) solid var(--line-strong);
    padding: var(--sp-4);
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    max-width: 560px;
    font-size: var(--fs-m);
  }
  .text {
    margin: 0;
    color: var(--fg-2);
    line-height: 1.5;
  }
  input {
    padding: 8px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: var(--bg);
    color: var(--fg);
    font-size: 13px;
  }
  input:focus {
    border-color: var(--focus);
    outline: none;
  }
  .buttons {
    display: flex;
    gap: var(--sp-2);
  }
  .err {
    margin: 0;
    color: var(--error);
    font-size: var(--fs-xs);
  }
  .error-box {
    margin: 0;
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--error);
    padding: var(--sp-3) 14px;
  }
  .feedback {
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--line);
    padding: var(--sp-3) 14px;
    display: flex;
    justify-content: space-between;
    gap: var(--sp-4);
    max-width: 560px;
  }
  .feedback.bad {
    border-color: var(--error);
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    cursor: pointer;
  }
  .link:hover:not(:disabled) {
    color: var(--fg);
    text-decoration: underline;
  }
  .link:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }
</style>
