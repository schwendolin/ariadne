<!--
  Ausnahme-Badges der Kopfzeile (Briefing 4.2, SCREENS 5): Pause mit Restzeit bzw. «wartet auf
  Bestätigung», held («hier geht Aufnahme verloren»), Scope-Warnung bis zum Quittieren, Platte fast
  voll, Präsentation. Nur, wenn sie gelten; nie Zahlen von Klärungen (E87).
  Platz (Korrekturen D2, A12): Die Kennzeichen sind Kinder der linken Gruppe der Kopfzeile und
  kürzen sich dort statt in die Reiter zu laufen. Zuerst kürzt die Pause; held behält mindestens
  «… nicht gespeichert» (unter 1280 px als Kurzform «! pts/4 nicht gespeichert»), nie nur «!».
  Unter 1440 px stehen Pause, Scope und Präsentation in Kurzform (voller Text im title).
  E131: «Scope offen» als Kennzeichen, solange der Scope des Projekts offen ist (führt zu den
  Einstellungen). Besitzer: ui-fundament, «Scope offen»: ui.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import { termShort } from '../util/format';
  import { hhmm } from '../util/time';
  import { url } from '../url/state.svelte';
  import { scopeOpen } from '../scope/open';

  let { app }: { app: AppState } = $props();
  const s = $derived(app.status);
  const terms = $derived(s?.terminals ?? []);
  const waiting = $derived(Object.entries(app.pendingPause)[0] ?? null);
  const waitingTerm = $derived(waiting ? (terms.find((x) => x.terminal_id === waiting[0]) ?? null) : null);
  const paused = $derived(terms.filter((x) => x.state === 'paused'));
  const held = $derived(terms.filter((x) => x.state === 'held'));
  const scope = $derived(s?.scope_warning && s.scope_warning.acked !== true ? s.scope_warning : null);
  const open = $derived(!!s?.project && scopeOpen(app));
</script>

{#if waitingTerm && waiting}
  <span class="badge attention" role="status" data-badge="waiting">
    <span class="bar" aria-hidden="true">‖</span><span class="txt"
      >{waiting[1].kind === 'pause'
        ? t('header.pauseWaiting', { term: termShort(waitingTerm) })
        : t('header.resumeWaiting', { term: termShort(waitingTerm) })}</span
    >
  </span>
{:else if paused[0]}
  {@const full = t('header.pauseUntil', { term: termShort(paused[0]), time: hhmm(paused[0].pause_until) })}
  <span class="badge attention" class:compact={held.length > 0} data-badge="pause" title={full}>
    <span class="bar" aria-hidden="true">‖</span><span class="txt"
      ><span class="long">{full}</span><span class="short">{t('header.pauseShort', { time: hhmm(paused[0].pause_until) })}</span>{#if paused.length > 1}<span class="more"
          >{t('header.pauseMore', { n: paused.length - 1 })}</span
        >{/if}</span
    >
  </span>
{/if}
{#if held[0]}
  <!-- wie die Pause: ein Kennzeichen für das erste Terminal, weitere als «+N weitere» (alle im title) -->
  {@const h = held[0]}
  <span class="badge attention" data-badge="held" title={held.map((x) => t('header.held', { term: termShort(x), slug: x.held_slug ?? '?' })).join('\n')}>
    <span class="bang" aria-hidden="true">!</span><span class="txt"
      ><span class="long">{t('header.heldPre', { term: termShort(h) })} <code>{h.held_slug ?? '?'}</code>{t('header.heldPost')}</span><span class="short"
        >{t('header.heldShort', { term: termShort(h) })}</span
      >{#if held.length > 1}<span class="more">{t('header.pauseMore', { n: held.length - 1 })}</span>{/if}</span
    >
  </span>
{/if}
{#if scope}
  <button
    type="button"
    class="badge attention"
    data-badge="scope"
    title={t('header.scopeWarningTitle')}
    aria-label={t('header.scopeWarning')}
    onclick={() => {
      url.go('karte', { host: null });
      app.ui.openDialog({ kind: 'scope-warning' });
    }}
  >
    <span class="bang" aria-hidden="true">!</span><span class="txt"><span class="long">{t('header.scopeWarning')}</span><span class="short">{t('header.scopeShort')}</span></span>
  </button>
{/if}
{#if open}
  <button type="button" class="badge attention" data-badge="scope-open" title={t('header.scopeOpenTitle')} onclick={() => url.set({ tafel: 'einstellungen' }, { push: true })}>
    <span class="txt">{t('header.scopeOpen')}</span>
  </button>
{/if}
{#if s?.disk_low}
  <span class="badge attention" data-badge="disk">{t('header.diskLow')}</span>
{/if}
{#if app.presentation}
  <span class="badge solid" data-badge="presentation" title={t('header.presentation')}
    ><span class="pdot" aria-hidden="true"></span><span class="ptxt">{t('header.presentation')}</span></span
  >
{/if}

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 5px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line);
    background: transparent;
    white-space: nowrap;
    font: inherit;
    flex: 0 1 auto;
    min-width: 0;
  }
  /* Kürzen nach Wichtigkeit (Korrektur D2, A12): held ist die Warnung «hier geht Aufnahme verloren»
     und kürzt sich nie (unter 1440 px in der Kurzform «! pts/4 nicht gespeichert»); zuerst kürzen
     Pause und Warten (Faktor 8), dann der Aufnahme-Text; Scope und Präsentation sind kurz genug. */
  .badge[data-badge='pause'],
  .badge[data-badge='waiting'] {
    flex: 0 8 auto;
    min-width: 6.5em;
  }
  .badge[data-badge='held'],
  .badge[data-badge='scope'],
  .badge[data-badge='scope-open'],
  .badge[data-badge='presentation'] {
    flex: none;
  }
  .badge[data-badge='disk'] {
    flex: 0 1 auto;
    min-width: 6em;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .txt {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .short {
    display: none;
  }
  /* neben held steht die Pause immer kurz («Pause bis 17:00», voller Text im title) */
  .compact .long {
    display: none;
  }
  .compact .short {
    display: inline;
  }
  .pdot {
    display: none;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: currentColor;
  }
  @media (max-width: 1439px) {
    .badge .long {
      display: none;
    }
    .badge .short {
      display: inline;
    }
    /* Präsentation als Punkt (Text im title und für Bildschirmleser) */
    .badge[data-badge='presentation'] {
      padding: 5px 8px;
    }
    .pdot {
      display: inline-block;
    }
    .ptxt {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip-path: inset(50%);
      white-space: nowrap;
    }
  }
  /* Rückfall unter 1000 px: auch held darf sich kürzen, nie unter «! pts/4 …» */
  @media (max-width: 999px) {
    .badge[data-badge='held'] {
      flex: 0 1 auto;
      min-width: 6em;
    }
    .badge[data-badge='pause'],
    .badge[data-badge='waiting'] {
      min-width: 4.5em;
    }
  }
  .bar,
  .bang {
    flex: none;
  }
  button.badge {
    cursor: pointer;
  }
  button.badge:hover {
    background: var(--attention-bg);
  }
  .attention {
    border-color: var(--attention);
    color: var(--attention);
  }
  .solid {
    position: relative;
    background: var(--fg);
    border-color: var(--fg);
    color: var(--bg);
    font-weight: 600;
  }
  .bar {
    font-weight: 700;
    letter-spacing: -1px;
  }
  .bang {
    font-weight: 700;
  }
  code {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
  }
  .more {
    margin-left: var(--sp-1);
    opacity: 0.8;
  }
</style>
