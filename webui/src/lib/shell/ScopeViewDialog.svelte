<!--
  «Scope ansehen» aus dem Menü (Screen 11): Ziele und Ausschlüsse aus GET /project (Eingaben des
  Nutzers, trotzdem als Text über Txt), Version. Ändern in den Einstellungen (E129) oder im
  Terminal mit `ariadne scope`; im Profil customer nur im Terminal. Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Txt from '../ui/Txt.svelte';

  let { app, onclose }: { app: AppState; onclose: () => void } = $props();
  const info = $derived(app.project?.info ?? null);
</script>

<Dialog title={t('scope.view.title')} {onclose} size="m">
  <h3>{t('scope.view.include')}</h3>
  {#if info && info.scope.include.length > 0}
    <ul>{#each info.scope.include as s, i (`${i}:${s}`)}<li><Txt value={s} mono /></li>{/each}</ul>
  {:else}
    <p class="none">{t('scope.view.empty')}</p>
  {/if}
  <h3>{t('scope.view.exclude')}</h3>
  {#if info && info.scope.exclude.length > 0}
    <ul>{#each info.scope.exclude as s, i (`${i}:${s}`)}<li><Txt value={s} mono /></li>{/each}</ul>
  {:else}
    <p class="none">{t('scope.view.empty')}</p>
  {/if}
  <p class="hint">{app.profile === 'customer' ? `${t('scope.view.hintCustomer')} ${t('scope.view.cli')}` : t('scope.view.hint')}</p>
</Dialog>

<style>
  h3 {
    margin: var(--sp-3) 0 var(--sp-1);
    font-size: 11.5px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-weight: 400;
    color: var(--faint);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .none {
    margin: 0;
    color: var(--muted);
  }
  .hint {
    margin: var(--sp-4) 0 0;
    padding-top: var(--sp-2);
    border-top: var(--lw-1) solid var(--line);
    color: var(--faint);
    font-size: var(--fs-xs);
  }
</style>
