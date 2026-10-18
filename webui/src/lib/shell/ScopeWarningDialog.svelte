<!--
  Scope-Warnung beim Eintreffen (Briefing 4.5, Screen 10): keine modale Ebene, sondern eine Meldung
  oben rechts mit Rand --attention, die einen offenen Dialog nicht verdrängt und den Fokus nicht
  stiehlt. Inhalt: Terminal, Befehl (Zieldaten, über Txt), Ziel mit Urteil, Zeit. Quittieren
  (PUT /ui/scope-ack, danach nur noch der Vermerk in der Zeitachse) oder «In der Zeitachse» (Zeile
  des Befehls). Schliessen ohne Quittieren lässt das Kennzeichen in der Kopfzeile stehen.
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { ScopeWarning, Verdict } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import { registerKeys } from '../keys/keymap';
  import type { AppState } from '../stores/app.svelte';
  import Txt from '../ui/Txt.svelte';
  import { url } from '../url/state.svelte';
  import { termShort } from '../util/format';
  import { fadeIn } from '../util/motion';
  import { hhmm } from '../util/time';

  let { app, onclose }: { app: AppState; onclose: () => void } = $props();
  const w = $derived<ScopeWarning | null>(app.status?.scope_warning ?? null);
  const term = $derived(w ? termShort(w.terminal ?? { terminal_id: w.terminal_id, ordinal: null }) : '–');
  let busy = $state(false);
  let node: HTMLElement | undefined = $state();

  const VERDICT: Record<Verdict, MessageKey> = {
    out: 'scope.notIn',
    excluded: 'scope.excluded',
    outside_window: 'scope.outsideWindow',
    unknown: 'scope.unknown',
    in: 'scope.unknown',
  };

  const off = registerKeys([
    {
      keys: ['Escape'],
      when: () => !!node && node.contains(document.activeElement),
      run: () => onclose(),
    },
  ]);
  onDestroy(off);

  function toTimeline(): void {
    const id = w?.cmd_id ?? null;
    onclose();
    url.go('zeitachse', { zeile: id });
  }

  async function ack(): Promise<void> {
    busy = true;
    await app.ackScopeWarning();
    busy = false;
  }
</script>

{#if w}
  <div class="card" role="alertdialog" aria-modal="false" aria-labelledby="scope-title" aria-describedby="scope-body" tabindex="-1" bind:this={node} use:fadeIn>
    <div class="top">
      <h2 id="scope-title"><span aria-hidden="true">!</span> {t('scope.title')}</h2>
      <button type="button" class="x" aria-label={t('scope.close')} onclick={onclose}>×</button>
    </div>
    <div id="scope-body" class="body">
      <p class="cmd">{term}: <Txt value={w.text ?? w.cmd_ref} mono ctrl={w.ctrl ?? false} max={160} /></p>
      {#each w.targets ?? [] as tg, i (`${i}:${tg.value}`)}
        <p class="muted">
          <Txt value={tg.value} mono ctrl={tg.ctrl} max={80} />
          {t(VERDICT[tg.verdict] ?? 'scope.unknown', { scope: (w.scope ?? []).join(', ') || '–', time: hhmm(w.ts, { seconds: true }) })}
        </p>
      {/each}
    </div>
    <div class="actions">
      {#if w.acked === true}
        <span class="muted">{t('scope.acked')}</span>
      {:else}
        <button type="button" class="primary" disabled={busy || app.offline} onclick={ack}>{t('scope.ack')}</button>
      {/if}
      <button type="button" class="secondary" onclick={toTimeline}>{t('scope.toTimeline')}</button>
    </div>
  </div>
{/if}

<style>
  .card {
    position: fixed;
    top: calc(var(--header-h) + 12px);
    right: var(--sp-4);
    z-index: 45;
    width: 440px;
    max-width: calc(100vw - 32px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: 14px var(--sp-4);
    border-radius: var(--r-card);
    background: var(--surface-2);
    border: 1.5px solid var(--attention);
    box-shadow: var(--shadow);
    color: var(--fg);
  }
  .top {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  h2 {
    margin: 0;
    font-size: var(--fs-m);
    font-weight: 600;
    color: var(--attention);
  }
  .x {
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 16px;
    line-height: 1;
    padding: 2px 4px;
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  p {
    margin: 0;
  }
  .muted {
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .actions {
    display: flex;
    gap: var(--sp-2);
    align-items: center;
  }
  .primary,
  .secondary {
    padding: 7px 12px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    cursor: pointer;
    font-size: 13px;
    line-height: 1;
  }
  .primary {
    background: var(--fg);
    color: var(--bg);
    border-color: var(--fg);
    font-weight: 600;
  }
  .primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
