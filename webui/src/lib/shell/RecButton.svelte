<!--
  Grosser REC-Knopf mit Laufzeit. Der Zustand wechselt erst, wenn der Daemon ihn per
  SSE bestätigt (auch Hotkey und CLI schalten REC). Solange REC läuft, beginnt der
  Tab-Titel mit «REC».
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import { duration, timeLocal, utcTooltip } from '../util/time';

  let { app }: { app: AppState } = $props();

  let now = $state(Date.now());
  const rec = $derived(app.status?.rec ?? null);
  const mode = $derived(rec?.mode ?? 'offline');
  const pending = $derived(app.recPending !== null);
  const elapsed = $derived(rec?.on && rec.since ? duration(now - Date.parse(rec.since)) : null);
  const label = $derived(
    mode === 'on' ? t('rec.on') : mode === 'waiting' ? t('rec.waiting') : mode === 'offline' ? t('rec.offline') : t('rec.off'),
  );
  const title = $derived(
    [rec?.on ? t('rec.stop') : t('rec.start'), rec ? t('rec.terminals', { n: rec.terminals_recording }) : '', rec?.since ? utcTooltip(rec.since) : '']
      .filter(Boolean)
      .join(' · '),
  );

  $effect(() => {
    if (!rec?.on) return;
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });

  $effect(() => {
    const name = app.status?.project?.slug ?? 'Ariadne';
    document.title = rec?.on ? `REC ${name} · Ariadne` : `${name} · Ariadne`;
  });
</script>

<button
  type="button"
  class="rec {mode}"
  class:pending
  aria-pressed={rec?.on ?? false}
  aria-busy={pending}
  disabled={!app.project || pending}
  {title}
  onclick={() => app.toggleRec()}
>
  <span class="dot" aria-hidden="true"></span>
  <span class="label">{label}</span>
  {#if elapsed}<span class="time">{elapsed}</span>{/if}
  {#if pending}<span class="pend">{t('rec.pending')}</span>{/if}
</button>
{#if rec?.since && rec.on}<span class="sr-only">{timeLocal(rec.since)}</span>{/if}

<style>
  .rec {
    min-height: 36px;
    padding: 4px 14px;
    border-radius: 999px;
    font-weight: 700;
    letter-spacing: 0.02em;
    gap: 8px;
    border-width: 2px;
  }
  .rec.on {
    background: var(--rec);
    border-color: var(--rec);
    color: var(--rec-text);
  }
  .rec.on:hover:not(:disabled) {
    background: var(--rec);
    filter: brightness(1.1);
  }
  .rec.off {
    color: var(--rec-off);
    border-color: var(--rec-off);
  }
  .rec.waiting {
    background: var(--banner-danger-bg);
    color: var(--banner-danger-text);
    border-color: var(--rec);
  }
  .rec.offline {
    color: var(--text-muted);
    border-style: dashed;
  }
  .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: currentColor;
  }
  .rec.off .dot,
  .rec.offline .dot {
    background: transparent;
    border: 2px solid currentColor;
  }
  .time {
    font-variant-numeric: tabular-nums;
    font-weight: 600;
  }
  .pend {
    font-weight: 400;
    font-size: 0.8rem;
  }
</style>
