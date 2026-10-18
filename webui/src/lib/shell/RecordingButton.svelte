<!--
  Aufnahme-Knopf mit Popover (SCREENS 5, «Popover nach Klick auf die Aufnahme»): «2 von 3 Terminals
  nehmen auf ▾» (kompakt «2 von 3 nehmen auf»). Im Popover pro Terminal «T1 scan · Pause bis 17:00»
  mit Fortsetzen bzw. «Pause 10 min»; bis der Daemon bestätigt «wartet auf Bestätigung» (E107).
  E117: das restliche Web-Pausenbudget der gleitenden Stunde steht am Terminal, sobald davon
  etwas verbraucht ist; reicht es nicht für 10 min, bietet der Knopf den Rest an; lehnt der Server
  ab (403 policy), bleibt die Grenze sichtbar. Dazu Projekt mit Name und Profil, Sitzung
  (Herkunft), Leerlauf, KI und der Hinweis F12 r. Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { TerminalState } from '../api/types';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import Popover from '../ui/Popover.svelte';
  import Txt from '../ui/Txt.svelte';
  import { endAfterText, recSummary, termShort } from '../util/format';
  import { hhmm, hoursMinutes } from '../util/time';

  let { app }: { app: AppState } = $props();
  const ID = 'recording';
  const PAUSE_MIN = 10;
  const s = $derived(app.status);
  const open = $derived(app.ui.popover === ID);
  const rec = $derived(s?.recording ?? { connected: 0, on: 0, paused: 0, held: 0, mux: 0 });
  const long = $derived(recSummary(rec.on, rec.connected));
  const short = $derived(recSummary(rec.on, rec.connected, true));

  function stateText(x: TerminalState): string {
    switch (x.state) {
      case 'on':
        return t('rec.state.on');
      case 'paused':
        return t('rec.state.paused', { time: hhmm(x.pause_until) });
      case 'held':
        return t('rec.state.held', { slug: x.held_slug ?? '?' });
      case 'locked':
        return t('rec.state.locked');
      case 'preroll':
        return t('rec.state.preroll');
      default:
        return t('rec.state.off');
    }
  }

  /** Budget in Minuten (E117); null = unbekannt (älterer Daemon) */
  function budgetMin(x: TerminalState): number | null {
    return typeof x.web_pause_left_s === 'number' ? Math.floor(x.web_pause_left_s / 60) : null;
  }

  /** Minuten, die der Knopf anbietet: 10, oder der Rest des Budgets; 0 = gesperrt */
  function offer(x: TerminalState): number {
    const b = budgetMin(x);
    return b === null ? PAUSE_MIN : Math.max(0, Math.min(PAUSE_MIN, b));
  }

  function aiText(): string {
    if (!s || s.llm.mode === 'off') return t('rec.ai.off');
    const mode = s.llm.mode === 'cloud' ? t('rec.ai.cloud') : t('rec.ai.local');
    return t('rec.ai.value', {
      mode,
      used: (s.llm.budget?.month_used_usd ?? 0).toFixed(2),
      limit: s.llm.budget?.month_limit_usd ?? 0,
    });
  }
</script>

<span class="wrap">
  <button
    type="button"
    class="rec"
    class:open
    aria-haspopup="dialog"
    aria-expanded={open}
    aria-label={t('header.recLabel', { text: long })}
    onclick={() => app.ui.togglePopover(ID)}
  >
    <span class="dot" aria-hidden="true"></span>
    <span class="long">{long}</span>
    <span class="short">{short}</span>
    <span class="caret" aria-hidden="true">▾</span>
  </button>
  <Popover {open} onclose={() => app.ui.closePopover(ID)} label={t('rec.label')} wide flush>
    <div class="cap">{t('rec.terminals')}</div>
    <div class="terms">
      {#if !s || s.terminals.length === 0}
        <p class="none">{t('rec.none')}</p>
      {:else}
        {#each s.terminals as x (x.terminal_id)}
          {@const pending = app.pendingPause[x.terminal_id]}
          {@const refused = x.terminal_id in app.pauseRefused}
          {@const minutes = offer(x)}
          {@const budget = budgetMin(x)}
          <div class="term" data-terminal={x.terminal_id}>
            <span class="tn">{termShort(x)}</span>
            <span class="name">
              {#if x.label}<Txt value={x.label} max={24} />{/if}
              <span class="st" class:attention={x.state !== 'on' || !!pending}
                >{x.label ? '· ' : ''}{pending ? t('rec.waiting') : stateText(x)}</span
              >
              {#if refused || (x.state === 'on' && minutes === 0)}
                <span class="limit" role="note">{t('rec.budgetEmpty')}</span>
              {:else if x.state === 'on' && budget !== null && budget < 30}
                <span class="budget">{t('rec.budget', { minutes: budget })}</span>
              {/if}
            </span>
            {#if x.state === 'paused'}
              <button
                type="button"
                class="small"
                disabled={!!pending || app.offline}
                aria-label={t('rec.resumeFor', { term: termShort(x) })}
                onclick={() => app.resume(x.terminal_id)}>{t('rec.resume')}</button
              >
            {:else if x.state === 'on'}
              <button
                type="button"
                class="small"
                disabled={!!pending || app.offline || refused || minutes === 0}
                title={refused || minutes === 0 ? t('rec.budgetEmpty') : undefined}
                aria-label={t('rec.pauseFor', { term: termShort(x), minutes: minutes || PAUSE_MIN })}
                onclick={() => app.pause(x.terminal_id, minutes)}>{t('rec.pause', { minutes: minutes || PAUSE_MIN })}</button
              >
            {/if}
          </div>
        {/each}
      {/if}
    </div>
    <dl class="facts">
      {#if s?.project}
        <dt>{t('rec.project')}</dt>
        <dd><code>{s.project.slug}</code> · <Txt value={s.project.name} max={40} /> · {s.project.profile}</dd>
      {/if}
      {#if s}
        <dt>{t('rec.session')}</dt>
        <dd>{s.session.origin === 'local' ? t('rec.session.local') : t('rec.session.sshd')}</dd>
      {/if}
      {#if s?.idle}
        <dt>{t('rec.idle')}</dt>
        <dd>
          {s.idle.end_after_s
            ? t('rec.idleValue', { time: hoursMinutes(s.idle.idle_s), end: endAfterText(s.idle.end_after_s) })
            : t('rec.idleNoEnd', { time: hoursMinutes(s.idle.idle_s) })}
        </dd>
      {/if}
      {#if s}
        <dt>{t('rec.ai')}</dt>
        <dd>{aiText()}</dd>
      {/if}
    </dl>
    <p class="hint">{t('rec.hint.pre')} <code>F12 r</code> {t('rec.hint.post')}</p>
  </Popover>
</span>

<style>
  .wrap {
    position: relative;
    flex: none;
  }
  .rec {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: 5px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line);
    background: var(--rec-bg);
    color: var(--fg);
    cursor: pointer;
    white-space: nowrap;
  }
  .rec:hover {
    border-color: var(--line-hover);
  }
  .rec.open {
    background: var(--surface-3);
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--fg);
    box-shadow: 0 0 0 3px var(--dot-ring);
  }
  .caret {
    color: var(--muted);
    font-size: 10px;
  }
  .short {
    display: none;
  }
  @media (max-width: 1279px) {
    .long {
      display: none;
    }
    .short {
      display: inline;
    }
  }
  .cap {
    padding: var(--sp-3) var(--sp-4) 6px;
    color: var(--muted);
    font-size: var(--fs-xs);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .terms {
    display: flex;
    flex-direction: column;
    padding: 0 var(--sp-2) var(--sp-2);
  }
  .term {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: var(--sp-2);
  }
  .tn {
    flex: none;
    width: 22px;
    font-family: var(--font-mono);
    font-size: var(--fs-s);
    color: var(--muted);
  }
  .name {
    flex: 1;
    min-width: 0;
  }
  .st {
    color: var(--muted);
  }
  .st.attention {
    color: var(--attention);
  }
  .budget,
  .limit {
    display: block;
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .limit {
    color: var(--attention);
  }
  .small {
    flex: none;
    padding: 5px 9px;
    border-radius: 5px;
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    cursor: pointer;
    font-size: var(--fs-xs);
    line-height: 1;
  }
  .small:hover:not(:disabled) {
    border-color: var(--line-hover);
  }
  .small:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .none {
    margin: 0;
    padding: var(--sp-2);
    color: var(--muted);
  }
  .facts {
    display: grid;
    grid-template-columns: 84px minmax(0, 1fr);
    gap: 7px 10px;
    margin: 0;
    padding: var(--sp-3) var(--sp-4);
    border-top: var(--lw-1) solid var(--line);
    font-size: 13px;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    min-width: 0;
  }
  code {
    font-family: var(--font-mono);
  }
  .hint {
    margin: 0;
    padding: 10px var(--sp-4);
    border-top: var(--lw-1) solid var(--line);
    color: var(--faint);
    font-size: var(--fs-xs);
  }
</style>
