<!--
  App-Gerüst: Kopfzeile, Banner, Navigation, Ansichten, Host-Schublade, Belegansicht.
  Alle Ansichten hängen am Store des aktiven Projekts und werden bei einem
  Projektwechsel neu aufgebaut ({#key}).
-->
<script lang="ts">
  import { t } from './lib/i18n';
  import { router } from './lib/router.svelte';
  import Header from './lib/shell/Header.svelte';
  import Lagebild from './lib/shell/Lagebild.svelte';
  import LoginView from './lib/shell/LoginView.svelte';
  import Nav from './lib/shell/Nav.svelte';
  import type { AppState } from './lib/stores/app.svelte';
  import { codeText } from './lib/util/errors';
  import EvidenceView from './lib/views/EvidenceView.svelte';
  import FindingsView from './lib/views/FindingsView.svelte';
  import HostDrawer from './lib/views/HostDrawer.svelte';
  import InboxView from './lib/views/InboxView.svelte';
  import MapView from './lib/views/MapView.svelte';
  import SuggestionsView from './lib/views/SuggestionsView.svelte';
  import TerminalsView from './lib/views/TerminalsView.svelte';
  import TimelineView from './lib/views/TimelineView.svelte';

  let { app }: { app: AppState } = $props();

  const route = $derived(router.route);
  const hostParam = $derived(router.param('host'));
  const factParam = $derived(router.param('fact'));
  const status = $derived(app.status);
</script>

{#if app.auth === 'init'}
  <p class="boot muted">{t('app.loading')}</p>
{:else if app.auth === 'login'}
  <LoginView {app} />
{:else}
  <div class="shell">
    <a class="skip" href="#main">{t('app.skip')}</a>
    <Header {app} />

    {#if status?.locked}
      <div class="banner danger" role="alert">
        {t('lock.banner')}
        {#if status.rec.mode === 'waiting'}<br />{t('lock.waiting')}{/if}
      </div>
    {/if}
    {#if status?.presentation}
      <div class="banner info" role="status">{t('presentation.banner')}</div>
    {/if}
    {#if app.error}
      <div class="banner danger" role="alert">{codeText(app.error)}</div>
    {/if}

    <div class="subbar">
      <Nav project={app.project} />
      <div class="spacer"></div>
      {#if app.project}<Lagebild project={app.project} />{/if}
    </div>

    <main id="main" tabindex="-1">
      {#if !app.project}
        <div class="view">
          <h1>{t('noProject.title')}</h1>
          <p class="muted">{t('noProject.text')}</p>
        </div>
      {:else}
        {#key app.project.pid}
          {#if route === 'karte'}
            <MapView project={app.project} />
          {:else if route === 'inbox'}
            <InboxView project={app.project} />
          {:else if route === 'terminals'}
            <TerminalsView project={app.project} />
          {:else if route === 'zeitachse'}
            <TimelineView project={app.project} />
          {:else if route === 'denkanstoesse'}
            <SuggestionsView project={app.project} {status} jobs={app.jobs} />
          {:else if route === 'findings'}
            <FindingsView project={app.project} />
          {/if}
          {#if hostParam}
            <HostDrawer project={app.project} hostId={hostParam} />
          {/if}
        {/key}
      {/if}
    </main>

    {#if factParam && app.project}
      {#key app.project.pid + factParam}
        <EvidenceView project={app.project} factId={factParam} presentation={status?.presentation ?? false} />
      {/key}
    {/if}
  </div>
{/if}

<style>
  .boot {
    padding: 24px;
  }
  .shell {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .skip {
    position: absolute;
    left: -9999px;
  }
  .skip:focus {
    left: 8px;
    top: 8px;
    z-index: 100;
    padding: 6px 10px;
    background: var(--surface);
  }
  .banner {
    padding: 6px 14px;
    font-weight: 600;
  }
  .banner.danger {
    background: var(--banner-danger-bg);
    color: var(--banner-danger-text);
  }
  .banner.info {
    background: var(--banner-info-bg);
    color: var(--banner-info-text);
  }
  .subbar {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    padding: 0 14px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  main {
    position: relative;
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }
  main:focus {
    outline: none;
  }
</style>
