<!--
  Fuss der Spalte: «Denkanstoss anfordern (KI)» und der Zustand des Auftrags (Briefing 5.2, D3,
  Entwurf api-ki). Aktiv, wenn die KI eingerichtet ist (`/ai/status` ready); sonst gesperrt mit
  Grund («KI ist aus …», «Cloud-KI nicht freigegeben …»). Während des Auftrags: Schritt («Lagebild
  wird gesendet»), Tokens, Maskierung, Kosten. Danach: neue Denkanstösse, keine neuen, verworfene
  Einträge, Injection-Verdacht, Ablehnung wörtlich (nur als Text), Anbieter weg. Budget: Hinweis ab
  80 %, bei 100 % fragt der Fuss vor dem Senden nach. Ariadne sendet nur das Lagebild nach dem
  Redaktor (E72); keine Zieldaten in diesen festen Texten. Besitzer: ui.
-->
<script lang="ts">
  import { aiButton, aiFacts, aiPhase, aiResultText, aiStepText, budgetText } from '../ai/view';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Button from '../ui/Button.svelte';
  import Txt from '../ui/Txt.svelte';

  let { app, project }: { app: AppState; project: ProjectStore } = $props();
  const ai = $derived(project.ai);
  const job = $derived(ai.job);
  const phase = $derived(aiPhase(job));
  const btn = $derived(aiButton(ai.status, job, { offline: app.offline, presentation: app.presentation, starting: ai.starting }));
  const budget = $derived(budgetText(ai.status));
  const facts = $derived(job ? aiFacts(job) : []);
</script>

<div class="ai" data-ai-phase={phase}>
  {#if ai.confirm}
    <div class="confirm" role="alertdialog" aria-labelledby="ai-confirm-text">
      <p id="ai-confirm-text">{t('next.ai.confirmText')}</p>
      {#if budget}<p class="small over">{budget.text}</p>{/if}
      <div class="row">
        <Button variant="primary" onclick={() => void ai.request(true)} disabled={ai.starting}>{t('next.ai.confirmSend')}</Button>
        <Button onclick={() => ai.cancelConfirm()}>{t('next.ai.confirmCancel')}</Button>
      </div>
    </div>
  {:else}
    <Button disabled={!btn.enabled} reason={btn.reason} onclick={() => void ai.request(false)}>{t('next.askAi')}</Button>
  {/if}

  {#if !btn.enabled && btn.reason && phase !== 'running' && !ai.confirm}
    <p class="small muted" data-ai-reason>{btn.reason}</p>
  {/if}

  {#if job && phase === 'running'}
    <div class="state" role="status" aria-live="polite">
      <p class="step"><span class="dot" aria-hidden="true"></span>{aiStepText(job)}</p>
      <p class="small muted">{facts.join(' · ')}</p>
    </div>
  {:else if job && phase !== 'idle'}
    <div class="state" class:bad={phase === 'failed' || phase === 'refused'} role="status" aria-live="polite">
      <div class="top">
        <p class="step">{aiResultText(job)}</p>
        <button type="button" class="hide" onclick={() => ai.dismissResult()}>{t('next.ai.hide')}</button>
      </div>
      {#if job.dropped > 0}<p class="small muted">{t('next.ai.dropped', { n: job.dropped })}</p>{/if}
      {#if job.injection_suspect > 0}<p class="small attention" data-ai-injection>! {t('next.ai.injection', { n: job.injection_suspect })}</p>{/if}
      {#if job.refusal}
        <p class="small muted">{t('next.ai.refusal')}</p>
        <blockquote class="refusal" data-ai-refusal><Txt value={job.refusal.text} max={600} /></blockquote>
      {/if}
      {#if facts.length > 0 && phase === 'done'}<p class="small muted">{facts.join(' · ')}</p>{/if}
    </div>
  {/if}

  {#if ai.error}
    <p class="small err" role="alert">{ai.error}</p>
  {/if}

  {#if budget && budget.level !== 'ok' && !ai.confirm}
    <p class="small" class:warn={budget.level === 'warn'} class:over={budget.level === 'over'} data-ai-budget={budget.level}>{budget.text}</p>
  {/if}
  {#if ai.status?.model && ai.status.provider !== 'off'}
    <p class="small faint">{t('next.ai.model')} <Txt value={ai.status.model} mono max={60} /> · {ai.status.provider}</p>
  {/if}
</div>

<style>
  .ai {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .ai :global(.btn) {
    justify-content: center;
    padding: 9px 12px;
    font-size: 13px;
  }
  p {
    margin: 0;
  }
  .small {
    font-size: var(--fs-xs);
    line-height: 1.4;
  }
  .muted {
    color: var(--muted);
  }
  .faint {
    color: var(--faint);
  }
  .warn,
  .attention {
    color: var(--attention);
  }
  .over,
  .err {
    color: var(--error);
  }
  .state {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 10px;
    border-radius: 8px;
    border: var(--lw-1) solid var(--line);
    background: var(--surface-2);
  }
  .state.bad {
    border-color: var(--attention);
  }
  .top {
    display: flex;
    justify-content: space-between;
    gap: 8px;
  }
  .step {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--fs-s);
    font-weight: 600;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--focus);
    animation: blink 1.2s ease-in-out infinite;
  }
  @media (prefers-reduced-motion: reduce) {
    .dot {
      animation: none;
    }
  }
  @keyframes blink {
    50% {
      opacity: 0.3;
    }
  }
  .hide {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    font: inherit;
    font-size: var(--fs-xs);
    cursor: pointer;
  }
  .refusal {
    margin: 0;
    padding: 6px 8px;
    border-left: 2px solid var(--line-strong);
    font-size: var(--fs-xs);
    color: var(--fg-2);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 120px;
    overflow: auto;
  }
  .confirm {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px;
    border-radius: 8px;
    border: 1.5px solid var(--error);
  }
  .confirm p {
    font-size: var(--fs-s);
  }
  .row {
    display: flex;
    gap: 8px;
  }
</style>
