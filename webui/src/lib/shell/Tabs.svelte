<!--
  Reiter Karte, Terminals, Zeitachse, Findings (aktiv mit 2 px Unterstrich --fg). Links mit echter
  Adresse (History-Router), Tasten 1 bis 4 (in App.svelte registriert). Ohne Projekt stehen sie
  wie im Design da, wechseln aber nichts (`aria-disabled`). Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t, type MessageKey } from '../i18n';
  import { ROUTES, url, type RouteId } from '../url/state.svelte';

  let { disabled = false }: { disabled?: boolean } = $props();

  const LABEL: Record<RouteId, MessageKey> = {
    karte: 'nav.karte',
    terminals: 'nav.terminals',
    zeitachse: 'nav.zeitachse',
    findings: 'nav.findings',
  };

  function go(e: MouseEvent, r: RouteId): void {
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    if (!disabled) url.go(r);
  }
</script>

<nav class="tabs" aria-label={t('nav.label')}>
  {#each ROUTES as r (r)}
    <a
      href={url.href(r, {}, true)}
      class:active={url.route === r}
      aria-current={url.route === r ? 'page' : undefined}
      aria-disabled={disabled ? 'true' : undefined}
      onclick={(e) => go(e, r)}>{t(LABEL[r])}</a
    >
  {/each}
</nav>

<style>
  .tabs {
    display: flex;
    align-items: stretch;
    gap: 2px;
    height: var(--header-h);
  }
  a {
    display: flex;
    align-items: center;
    padding: 0 12px;
    color: var(--muted);
    text-decoration: none;
    white-space: nowrap;
  }
  a:focus-visible {
    outline-offset: -4px;
  }
  a:hover {
    color: var(--fg);
  }
  a.active {
    color: var(--fg);
    font-weight: 600;
    box-shadow: inset 0 -2px 0 var(--fg);
  }
  a[aria-disabled='true'] {
    cursor: default;
  }
  a[aria-disabled='true']:hover:not(.active) {
    color: var(--muted);
  }
</style>
