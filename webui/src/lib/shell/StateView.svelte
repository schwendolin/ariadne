<!--
  Zustände ohne Projektdaten (SCREENS 9, Briefing 4.1):
    no_project  «Kein aktives Projekt», Startbefehl mit «Kopieren · Mac» (Vorlauf steht in der Kopfzeile)
    locked      «Projekt ms2 ist gesperrt»: Projektdaten verschwinden, kein Passphrase-Feld,
                Hinweis `ariadne start` (ohne Kopierknopf, wie im Design)
    sonst       Laden
  «Entsperrt, nicht geöffnet» sieht aus wie «kein Projekt». Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import CommandLine from '../ui/CommandLine.svelte';

  let { app }: { app: AppState } = $props();
  const phase = $derived(app.phase);
  const slug = $derived(app.status?.active?.slug ?? '');
</script>

<div class="state" data-state={phase}>
  {#if phase === 'locked'}
    <section class="box" aria-labelledby="state-title">
      <h2 id="state-title">{t('state.locked.pre')} <code>{slug}</code> {t('state.locked.post')}</h2>
      <p>{t('state.locked.text')}</p>
      <CommandLine command={t('state.locked.cmd')} copy={false} />
    </section>
  {:else if phase === 'no_project'}
    <section class="box" aria-labelledby="state-title">
      <h2 id="state-title">{t('state.noProject.title')}</h2>
      <p>{t('state.noProject.text')}</p>
      <CommandLine command={t('state.noProject.cmd')} />
    </section>
  {:else}
    <p class="loading" role="status">{t('state.loading')}</p>
  {/if}
</div>

<style>
  .state {
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--sp-6);
  }
  .box {
    width: 520px;
    max-width: 100%;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  h2 {
    margin: 0;
    font-size: var(--fs-xl);
    font-weight: 600;
  }
  h2 code {
    font-family: var(--font-mono);
  }
  p {
    margin: 0;
    color: var(--muted);
    line-height: 1.5;
  }
  .loading {
    color: var(--muted);
  }
</style>
