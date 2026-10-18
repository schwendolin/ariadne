<!--
  Kopfzeile (SCREENS 5, AriadneKopfzeile.dc.html, E107): 52 px. Links Logo-Zeichen, Slug (Mono),
  Aufnahme-Knopf mit Popover, Ausnahme-Badges, Herkunft der Sitzung (immer). Mitte Reiter. Rechts
  Suche (⌘K) und Menü (⋯). Varianten (data-variant, auch für Tests):
    normal, waiting, pause, held   Projekt offen: Aufnahme-Knopf und Ausnahmen
    locked                         «Gesperrt · im Terminal ariadne start», «Aufnahme puffert …»
    noproject                      Slug «kein Projekt», «Vorlauf: 3 Terminals, 15 Minuten …»
    offline                        «Keine Verbindung · Stand 16:54 · verbindet neu …» statt Aufnahme
  Präsentation ist ein Kennzeichen in jeder Variante. Keine Zahlen von Klärungen oder
  Denkanstössen (E87, E107). Unter 1280 px kompakt (nur CSS): kurze Aufnahme, Suche nur als ⌘K;
  die Herkunft bleibt immer sichtbar. Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t } from '../i18n';
  import { modLabel } from '../keys/keymap';
  import type { AppState } from '../stores/app.svelte';
  import LogoMark from '../ui/LogoMark.svelte';
  import { minutesText } from '../util/format';
  import { hhmm } from '../util/time';
  import HeaderBadges from './HeaderBadges.svelte';
  import MainMenu from './MainMenu.svelte';
  import RecordingButton from './RecordingButton.svelte';
  import Tabs from './Tabs.svelte';

  let { app }: { app: AppState } = $props();

  const s = $derived(app.status);
  const phase = $derived(app.phase);
  const slug = $derived(s?.project?.slug ?? (phase === 'locked' ? (s?.active?.slug ?? null) : null));
  const origin = $derived(s?.session?.origin === 'local' ? t('header.origin.local') : t('header.origin.sshd'));
  const offlineSince = $derived(app.lastGoodAt ? hhmm(new Date(app.lastGoodAt)) : '–');
  const preroll = $derived(
    s && s.preroll.terminals > 0
      ? t('header.preroll', { n: s.preroll.terminals, minutes: minutesText(s.preroll.seconds) })
      : t('header.prerollNone'),
  );
  const variant = $derived(
    app.offline
      ? 'offline'
      : phase === 'locked'
        ? 'locked'
        : phase === 'no_project'
          ? 'noproject'
          : Object.values(app.pendingPause).length > 0
            ? 'waiting'
            : s?.terminals.some((x) => x.state === 'held')
              ? 'held'
              : s?.terminals.some((x) => x.state === 'paused')
                ? 'pause'
                : 'normal',
  );
  const palette = modLabel('K');
</script>

<header class="header" data-variant={variant} data-presentation={app.presentation ? 'on' : undefined}>
  <div class="left">
    <LogoMark size={20} />
    <span class="divider" aria-hidden="true"></span>
    <span class="slug" class:none={!slug}>{slug ?? t('header.noProject')}</span>
    {#if app.offline}
      <span class="badge attention" role="status">{t('header.offline', { time: offlineSince })}</span>
    {:else if phase === 'locked'}
      <span class="badge attention">{t('header.locked')} <code>ariadne start</code></span>
      <span class="muted">{t('header.lockedBuffer')}</span>
    {:else if phase === 'no_project'}
      <span class="muted">{preroll}</span>
    {:else if phase === 'project'}
      <RecordingButton {app} />
      <HeaderBadges {app} />
    {/if}
    {#if app.presentation && (app.offline || phase !== 'project')}
      <span class="badge solid">{t('header.presentation')}</span>
    {/if}
    <span class="origin">{origin}</span>
  </div>
  <Tabs disabled={phase !== 'project'} />
  <div class="right">
    <button type="button" class="search" onclick={() => app.ui.openDialog({ kind: 'palette' })} aria-label={t('palette.title')} aria-keyshortcuts="Control+K Meta+K">
      <span class="long">{t('header.search')}</span><kbd>{palette}</kbd>
    </button>
    <MainMenu {app} />
  </div>
</header>

<style>
  .header {
    height: var(--header-h);
    flex: none;
    display: flex;
    align-items: center;
    gap: var(--sp-4);
    padding: 0 var(--sp-4);
    background: var(--bg);
    border-bottom: var(--lw-1) solid var(--line);
    position: relative;
    z-index: 20;
    font-size: var(--fs-m);
    color: var(--fg);
  }
  .left {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    min-width: 0;
    flex: 1 1 auto;
  }
  .divider {
    flex: none;
    width: 1px;
    height: 18px;
    background: var(--line);
  }
  .slug {
    font-family: var(--font-mono);
    font-weight: 600;
    font-size: 14px;
    letter-spacing: 0.01em;
    white-space: nowrap;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    padding: 5px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line);
    white-space: nowrap;
  }
  .badge code {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
  }
  .attention {
    border-color: var(--attention);
    color: var(--attention);
  }
  .solid {
    background: var(--fg);
    border-color: var(--fg);
    color: var(--bg);
    font-weight: 600;
  }
  .muted,
  .origin {
    color: var(--muted);
    white-space: nowrap;
  }
  .muted {
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }
  .origin {
    flex: none;
  }
  .right {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex: 1 1 auto;
    justify-content: flex-end;
  }
  .search {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-6);
    min-width: 180px;
    padding: 5px 6px 5px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line);
    background: transparent;
    color: var(--muted);
    cursor: pointer;
  }
  .search:hover {
    border-color: var(--line-hover);
  }
  kbd {
    font-family: var(--font-mono);
    font-size: 11.5px;
    padding: 2px 5px;
    border-radius: var(--r-badge);
    background: var(--surface-3);
    color: var(--muted);
  }
  @media (max-width: 1279px) {
    .search {
      min-width: 0;
      padding: 5px 6px;
    }
    .search .long {
      display: none;
    }
  }
</style>
