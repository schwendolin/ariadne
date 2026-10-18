<!--
  Dialog «Screenshot der Kali» (Screen 10, Briefing 5.7): Fenster, Monitor oder Bereich, Countdown
  3 s, Hinweis «Beleg ohne Host-Identifikation». In v0.1 gibt es Screenshots aus dem Dashboard noch
  nicht (POST /screenshots antwortet 501): Der Dialog zeigt den klaren Hinweis, Auswahl und
  Auslösen sind gesperrt. Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { t } from '../i18n';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Segmented from '../ui/Segmented.svelte';

  let { onclose }: { onclose: () => void } = $props();

  const modes = $derived([
    { value: 'window' as const, label: t('shot.mode.window') },
    { value: 'monitor' as const, label: t('shot.mode.monitor') },
    { value: 'area' as const, label: t('shot.mode.area') },
  ]);
</script>

<Dialog title={t('shot.title')} {onclose} size="s">
  <div class="body">
    <p class="later" role="note">{t('shot.later')}</p>
    <div class="field">
      <span class="lbl">{t('shot.mode')}</span>
      <Segmented options={modes} value="window" onchange={() => undefined} label={t('shot.mode')} disabled />
    </div>
    <div class="count" aria-hidden="true"><span class="n">3</span><span class="muted">{t('shot.countdown')}</span></div>
    <p class="hint">{t('shot.hint')}</p>
  </div>
  {#snippet footer()}
    <Button onclick={onclose}>{t('shot.close')}</Button>
    <Button variant="primary" disabled reason={t('shot.disabled')}>{t('shot.run')}</Button>
  {/snippet}
</Dialog>

<style>
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .later {
    margin: 0;
    padding: var(--sp-3) 14px;
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--attention);
    color: var(--fg-2);
    line-height: 1.5;
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
  .count {
    display: flex;
    align-items: center;
    gap: 14px;
    opacity: 0.5;
  }
  .n {
    font-size: 44px;
    font-weight: 700;
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }
  .muted {
    color: var(--muted);
  }
  .hint {
    margin: 0;
    color: var(--attention);
    font-size: var(--fs-s);
  }
</style>
