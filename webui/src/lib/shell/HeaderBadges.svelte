<!--
  Ausnahme-Badges der Kopfzeile (Briefing 4.2, SCREENS 5): Pause mit Restzeit bzw. «wartet auf
  Bestätigung», held («hier geht Aufnahme verloren»), Scope-Warnung bis zum Quittieren, Platte fast
  voll, Präsentation. Nur, wenn sie gelten; nie Zahlen von Klärungen (E87).
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import { termShort } from '../util/format';
  import { hhmm } from '../util/time';

  let { app }: { app: AppState } = $props();
  const s = $derived(app.status);
  const terms = $derived(s?.terminals ?? []);
  const waiting = $derived(Object.entries(app.pendingPause)[0] ?? null);
  const waitingTerm = $derived(waiting ? (terms.find((x) => x.terminal_id === waiting[0]) ?? null) : null);
  const paused = $derived(terms.filter((x) => x.state === 'paused'));
  const held = $derived(terms.filter((x) => x.state === 'held'));
  const scope = $derived(s?.scope_warning && s.scope_warning.acked !== true ? s.scope_warning : null);
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
  <span class="badge attention" data-badge="pause" title={full}>
    <span class="bar" aria-hidden="true">‖</span><span class="txt">{full}{#if paused.length > 1}<span class="more">{t('header.pauseMore', { n: paused.length - 1 })}</span>{/if}</span>
  </span>
{/if}
{#each held as h (h.terminal_id)}
  <span class="badge attention" data-badge="held" title={t('header.held', { term: termShort(h), slug: h.held_slug ?? '?' })}>
    <span class="bang" aria-hidden="true">!</span><span class="txt">{t('header.heldPre', { term: termShort(h) })} <code>{h.held_slug ?? '?'}</code>{t('header.heldPost')}</span>
  </span>
{/each}
{#if scope}
  <button type="button" class="badge attention" data-badge="scope" title={t('header.scopeWarningTitle')} onclick={() => app.ui.openDialog({ kind: 'scope-warning' })}>
    <span class="bang" aria-hidden="true">!</span>{t('header.scopeWarning')}
  </button>
{/if}
{#if s?.disk_low}
  <span class="badge attention" data-badge="disk">{t('header.diskLow')}</span>
{/if}
{#if app.presentation}
  <span class="badge solid" data-badge="presentation">{t('header.presentation')}</span>
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
  /* Pause und Warten bleiben ganz lesbar; lange Ausnahmen (held) kürzen sich zuerst. */
  .badge[data-badge='pause'],
  .badge[data-badge='waiting'],
  .badge[data-badge='scope'] {
    flex: none;
  }
  .txt {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
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
    flex: none;
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
