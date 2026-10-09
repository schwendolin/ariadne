<!--
  Kopfzeile: Projekt mit Profilfarbe, REC-Knopf mit Laufzeit, Sperrzustand, KI-Modus,
  Verbindung, Präsentationsmodus und Theme (Architektur 7.4).
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import Badge from '../ui/Badge.svelte';
  import Txt from '../ui/Txt.svelte';
  import { applyTheme, initTheme, type ThemeChoice } from '../util/theme';
  import RecButton from './RecButton.svelte';

  let { app }: { app: AppState } = $props();

  let theme = $state<ThemeChoice>(initTheme());
  const s = $derived(app.status);
  const project = $derived(s?.project ?? null);
  const llm = $derived(s?.llm ?? null);
  const budget = $derived(
    llm?.budget ? t('llm.budget', { used: llm.budget.month_used_usd.toFixed(2), limit: llm.budget.month_limit_usd.toFixed(0) }) : '',
  );
  const connTone = $derived(app.connection === 'open' ? 'ok' : app.connection === 'retrying' ? 'warn' : 'muted');
</script>

<header class="top">
  <div class="brand" aria-hidden="true">
    <svg viewBox="0 0 32 32" width="22" height="22"><path d="M6 24 C10 8, 16 26, 20 12 S 26 8, 27 7" class="thread" /><circle cx="6" cy="24" r="2.5" class="end" /><circle cx="27" cy="7" r="2.5" class="end" /></svg>
    <span>Ariadne</span>
  </div>

  {#if project}
    <div class="project">
      <span class="profile {project.profile}" title={t('header.profile')}>{t(`profile.${project.profile}`)}</span>
      <strong><Txt value={project.name} max={40} /></strong>
      <span class="muted small mono">{project.slug}</span>
    </div>
  {:else}
    <span class="muted">{t('header.noProject')}</span>
  {/if}

  <RecButton {app} />

  {#if s}
    <Badge tone={s.locked ? 'danger' : 'muted'}>{s.locked ? t('lock.locked') : t('lock.unlocked')}</Badge>
    {#if llm}
      <Badge tone={llm.mode === 'off' ? 'muted' : llm.available ? 'ai' : 'warn'} title={[llm.model ?? '', budget, llm.available ? '' : t('llm.unavailable')].filter(Boolean).join(' · ')}>
        {t(`llm.${llm.mode}`)}
      </Badge>
    {/if}
  {/if}
  <Badge tone={connTone}>{t(`conn.${app.connection}`)}</Badge>
  {#if app.backend.kind === 'mock'}<Badge tone="info" title={t('mock.hint')}>{t('mock.badge')}</Badge>{/if}

  <div class="spacer"></div>

  <button
    type="button"
    class="small"
    class:active={s?.presentation}
    aria-pressed={s?.presentation ?? false}
    disabled={!s}
    title={s?.presentation ? t('presentation.toggleOff') : t('presentation.toggleOn')}
    onclick={() => app.togglePresentation()}
  >
    {t('presentation.label')}
  </button>
  <label class="row small theme">
    <span class="sr-only">{t('theme.label')}</span>
    <select bind:value={theme} onchange={() => applyTheme(theme)} aria-label={t('theme.label')}>
      <option value="system">{t('theme.system')}</option>
      <option value="light">{t('theme.light')}</option>
      <option value="dark">{t('theme.dark')}</option>
    </select>
  </label>
</header>

<style>
  .top {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    padding: 8px 14px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .brand {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 800;
    letter-spacing: 0.02em;
  }
  .brand .thread {
    fill: none;
    stroke: var(--map-thread);
    stroke-width: 3;
    stroke-linecap: round;
  }
  .brand .end {
    fill: var(--text);
  }
  .project {
    display: inline-flex;
    align-items: baseline;
    gap: 8px;
  }
  .profile {
    padding: 0 8px;
    border-radius: 4px;
    color: var(--profile-text);
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
  }
  .profile.lab {
    background: var(--profile-lab);
  }
  .profile.customer {
    background: var(--profile-customer);
  }
  button.active {
    background: var(--badge-info-bg);
    border-color: var(--badge-info-text);
    color: var(--badge-info-text);
  }
</style>
