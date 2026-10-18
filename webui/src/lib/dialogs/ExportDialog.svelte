<!--
  Dialog «Bericht exportieren» (Screen 10, Briefing 5.12): Vorlage cys/htb, «Phasen geprüft · in
  der Zeitachse ›», Credentials verdeckt, Liste der Exporte. In v0.1 gibt es den Export noch nicht
  (POST /exports antwortet 501): Der Dialog zeigt, was er später kann, mit klarem Hinweis; alle
  Bedienelemente ausser Schliessen und dem Sprung in die Zeitachse sind gesperrt.
  Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { t } from '../i18n';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import { url } from '../url/state.svelte';

  let { onclose }: { onclose: () => void } = $props();

  const templates = [
    { value: 'cys' as const, label: 'cys' },
    { value: 'htb' as const, label: 'htb' },
  ];

  function toTimeline(): void {
    onclose();
    url.go('zeitachse');
  }
</script>

<Dialog title={t('export.title')} {onclose} size="m">
  <div class="body">
    <p class="later" role="note">{t('export.later')}</p>
    <div class="field">
      <span class="lbl">{t('export.template')}</span>
      <Segmented options={templates} value="cys" onchange={() => undefined} label={t('export.template')} disabled />
    </div>
    <dl class="facts">
      <dt>{t('export.phases')}</dt>
      <dd><button type="button" class="link" onclick={toTimeline}>{t('export.phasesLink')}</button></dd>
      <dt>{t('export.creds')}</dt>
      <dd class="muted">{t('export.credsValue')}</dd>
    </dl>
    <div>
      <Button variant="primary" disabled reason={t('export.disabled')}>{t('export.run')}</Button>
    </div>
    <div class="list">
      <span class="lbl">{t('export.list')}</span>
      <span class="muted">{t('export.listEmpty')}</span>
    </div>
  </div>
  {#snippet footer()}
    <Button onclick={onclose}>{t('export.close')}</Button>
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
  .facts {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 6px var(--sp-3);
    margin: 0;
  }
  dd {
    margin: 0;
    text-align: right;
  }
  .muted {
    color: var(--muted);
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    cursor: pointer;
  }
  .link:hover {
    color: var(--fg);
  }
  .list {
    border-top: var(--lw-1) solid var(--line);
    padding-top: 10px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: var(--fs-s);
  }
</style>
