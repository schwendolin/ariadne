<!--
  Einstellungen als Tafel wie der Beleg (Screen 11, E112): Darstellung (System, Hell, Dunkel),
  Dichte, Lernmodus, KI, Profil, eigene Secrets (nur verdeckt mit Zahl, nie Werte, nie über HTTP),
  Projekt mit Scope. Theme, Dichte und Lernmodus speichert der Server (PUT /ui/prefs); die Anzeige
  folgt sofort, bei Fehler zurück mit Meldung. Kein Browser-Speicher. Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import Panel from '../ui/Panel.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import Toggle from '../ui/Toggle.svelte';
  import { url } from '../url/state.svelte';

  let { app }: { app: AppState } = $props();
  const p = $derived(app.prefs.prefs);
  const s = $derived(app.status);
  const info = $derived(app.project?.info ?? null);
  const own = $derived(s?.operator?.own_secrets);
  const disabled = $derived(app.offline);

  function aiText(): string {
    if (!s || s.llm.mode === 'off') return t('settings.ai.off');
    return t('settings.ai.value', {
      mode: s.llm.mode === 'cloud' ? t('rec.ai.cloud') : t('rec.ai.local'),
      limit: s.llm.budget?.month_limit_usd ?? 0,
      used: (s.llm.budget?.month_used_usd ?? 0).toFixed(2),
    });
  }
</script>

<Panel title={t('settings.title')} onclose={() => url.set({ tafel: null })}>
  <dl class="grid">
    <dt id="set-theme">{t('settings.theme')}</dt>
    <dd>
      <Segmented
        label={t('settings.theme')}
        value={p.theme}
        {disabled}
        options={[
          { value: 'system', label: t('settings.theme.system') },
          { value: 'light', label: t('settings.theme.light') },
          { value: 'dark', label: t('settings.theme.dark') },
        ]}
        onchange={(v) => void app.prefs.set({ theme: v })}
      />
    </dd>
    <dt>{t('settings.density')}</dt>
    <dd>
      <Segmented
        label={t('settings.density')}
        value={p.density}
        {disabled}
        options={[
          { value: 'comfortable', label: t('settings.density.comfortable') },
          { value: 'compact', label: t('settings.density.compact') },
        ]}
        onchange={(v) => void app.prefs.set({ density: v })}
      />
    </dd>
    <dt>{t('settings.learning')}</dt>
    <dd>
      <Toggle
        label={t('settings.learning')}
        checked={p.learning}
        {disabled}
        text={p.learning ? t('settings.learning.on') : t('settings.learning.off')}
        onchange={(v) => void app.prefs.set({ learning: v })}
      />
    </dd>
    <dt>{t('settings.ai')}</dt>
    <dd>{aiText()}</dd>
    <dt>{t('settings.profile')}</dt>
    <dd>{s?.project?.profile ?? '–'} <span class="faint">· {t('settings.profile.hint')}</span></dd>
    <dt>{t('settings.ownSecrets')}</dt>
    <dd data-testid="own-secrets">
      <span class="mono">{t('secret.mask')}</span>
      {#if typeof own === 'number'}
        <span class="faint">· {t('settings.ownSecrets.value', { n: own })}</span>
      {:else if own === null || s?.operator?.unlocked === false}
        <span class="faint">· {t('settings.ownSecrets.locked')}</span>
      {/if}
    </dd>
    <dt>{t('settings.project')}</dt>
    <dd>
      {#if info}<span class="mono">{info.slug}</span> · {t('settings.scope', { scope: info.scope.include.join(', ') || '–' })}{:else}–{/if}
      <span class="faint">· {t('settings.project.hint')}</span>
    </dd>
  </dl>
</Panel>

<style>
  .grid {
    display: grid;
    grid-template-columns: 130px minmax(0, 1fr);
    gap: 14px var(--sp-4);
    align-items: center;
    margin: 0;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    min-width: 0;
  }
  .faint {
    color: var(--faint);
  }
  .mono {
    font-family: var(--font-mono);
  }
</style>
