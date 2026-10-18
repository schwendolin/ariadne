<!--
  Denkanstoss (Briefing 5.2, Screen 4 D1/D2, Ruhezustand 1a, A 6.1, 6.3, web-api.md 18.6).
  - Einzeilig: Quelle «Regel» und Titel; Zieldaten in Mono, IPs im Scope-Netz gekürzt («.101:21»).
  - Aufgeklappt: «Prüfziel · Regel R-ANON-ZUGRIFF», Titel, Grund, Beleg (öffnet die Belegansicht),
    Kennzeichen (Injection-Verdacht, vom Ziel angeboten), Vorlagen (TemplateBlock, «Kopieren · Mac»),
    «Erledigt» (mit `basis`, kommt bei neuem Anlass wieder) und «Verwerfen» (bleibt verworfen).
  - Lernmodus (Vorlieben): Stufen 1 Frage, 2 Richtung, 3 Vorlage, jede erst auf Klick.
  Ariadne führt nichts davon aus (E10): es gibt keinen Ausführen-Knopf. Besitzer: ui-karte.
-->
<script lang="ts">
  import { tick } from 'svelte';
  import type { Suggestion, TextPart } from '../api/types';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import { evidenceLabel, suggestionEvidence } from '../stores/next.svelte';
  import Badge from '../ui/Badge.svelte';
  import Button from '../ui/Button.svelte';
  import Txt from '../ui/Txt.svelte';
  import { pulse } from '../util/motion';
  import { displaySafe } from '../safe/displaySafe';
  import Parts from './Parts.svelte';
  import TemplateBlock from './TemplateBlock.svelte';
  import { collapsedParts, titleParts } from './title';

  let {
    app,
    project,
    suggestion,
    selected,
    short = (s: string) => s,
  }: { app: AppState; project: ProjectStore; suggestion: Suggestion; selected: boolean; short?: (s: string) => string } = $props();

  const s = $derived(suggestion);
  const next = $derived(project.next);
  const learning = $derived(app.prefs.prefs.learning);
  const stage = $derived(next.stageOf(s.suggestion_key));
  const busy = $derived(next.isBusy(s.suggestion_key));
  const evidence = $derived(suggestionEvidence(s));
  const title = $derived(titleParts(s));
  const shortParts = $derived<TextPart[]>(collapsedParts(title).map((p) => (p.target ? { ...p, text: short(p.text) } : p)));
  const showTemplates = $derived(!learning || stage >= 3);
  const offline = $derived(app.offline);

  function openEvidence(): void {
    next.openEvidence({ type: 'suggestion', key: s.suggestion_key, index: 0, s });
  }

  // Korrektur A13: Der Knopf der Zeile wird beim Aufklappen durch die Karte ersetzt; der Fokus geht
  // auf die Karte statt auf body. Ebenso nach der letzten Lernstufe (ihr Knopf verschwindet).
  let card: HTMLDivElement | undefined = $state();
  let focusCard = false;

  function openLine(): void {
    focusCard = true;
    next.select(s.suggestion_key);
  }

  $effect(() => {
    if (selected && card && focusCard) {
      focusCard = false;
      card.focus({ preventScroll: true });
    }
  });

  async function reveal(): Promise<void> {
    const last = stage === 2;
    next.revealStage(s.suggestion_key);
    if (!last) return;
    await tick();
    card?.focus({ preventScroll: true });
  }
</script>

{#if !selected}
  <button
    type="button"
    class="line"
    data-suggestion-key={s.suggestion_key}
    use:pulse={{ token: app.ui.pulseToken, active: app.ui.isPulsing(s.suggestion_key) }}
    onclick={openLine}
    title={displaySafe(s.title, 400)}
  >
    <span class="src">{t('sug.rule')}</span>
    <span class="title"><Parts parts={shortParts} /></span>
  </button>
{:else}
  <div class="card" data-suggestion-key={s.suggestion_key} aria-current="true" aria-busy={busy} tabindex="-1" bind:this={card}>
    <div class="head">
      {t(`sug.kind.${s.kind}`)} · {t('sug.rule')} <span class="mono"><Txt value={s.rule_id} max={40} /></span>
      {#if s.flags.includes('injection_suspect')}<Badge tone="attention">{t('sug.flag.injection_suspect')}</Badge>{/if}
      {#if s.flags.includes('from_target')}<Badge>{t('sug.flag.from_target')}</Badge>{/if}
    </div>
    <h3 class="title-l"><Parts parts={title} max={200} /></h3>
    {#if !learning}
      <p class="reason"><Txt value={s.reason} ctrl={s.ctrl_reason} max={240} /></p>
      {#if s.evidence[0]}
        <button type="button" class="ev" disabled={!evidence} onclick={openEvidence}>{t('sug.evidence', { label: '' })}<Txt value={evidenceLabel(s.evidence[0])} max={80} /></button>
      {/if}
    {:else}
      {#if stage >= 1}
        <div class="stage"><span class="st">{t('sug.stage1')}</span><span><Txt value={s.stages.question} max={400} /></span></div>
      {/if}
      {#if stage >= 2}
        <div class="stage"><span class="st">{t('sug.stage2')}</span><span><Txt value={s.stages.direction} max={400} /></span></div>
      {/if}
      {#if stage >= 3}
        <div class="stage"><span class="st">{t('sug.stage3')}</span></div>
        {#if s.evidence[0]}
          <button type="button" class="ev" disabled={!evidence} onclick={openEvidence}>{t('sug.evidence', { label: '' })}<Txt value={evidenceLabel(s.evidence[0])} max={80} /></button>
        {/if}
      {/if}
      {#if stage < 3}
        <button type="button" class="reveal" onclick={() => void reveal()}>
          <span>{t(stage === 0 ? 'sug.show1' : stage === 1 ? 'sug.show2' : 'sug.show3')}</span><span aria-hidden="true">›</span>
        </button>
      {/if}
    {/if}
    {#if showTemplates}
      {#each s.templates as tpl (tpl.template_id)}
        <TemplateBlock template={tpl} showLabel={s.templates.length > 1} />
      {/each}
    {/if}
    <div class="actions">
      <Button variant="primary" disabled={busy || offline} reason={busy ? t('next.loading') : offline ? t('err.network') : null} onclick={() => next.suggestionDone(s)}>{t('sug.done')}</Button>
      <Button disabled={busy || offline} reason={busy ? t('next.loading') : offline ? t('err.network') : null} onclick={() => next.suggestionDismiss(s)}>{t('sug.dismiss')}</Button>
    </div>
  </div>
{/if}

<style>
  .line {
    display: flex;
    gap: 10px;
    width: 100%;
    padding: 9px 8px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: var(--fg);
    text-align: left;
    font: inherit;
    /* Raster 34 px wie im Design (Runde 1, 1a), Korrektur D5: feste Zeilenhöhe, auch für Mono-Teile */
    line-height: 16px;
    cursor: pointer;
  }
  .line:hover {
    background: var(--surface-2);
  }
  .src {
    width: 34px;
    flex: none;
    padding-top: 1px;
    font-size: var(--fs-xs);
    color: var(--faint);
  }
  .title {
    flex: 1;
    min-width: 0;
    /* eingeklappt einzeilig wie im Design (1a); der volle Titel steht in der Karte und im title */
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 14px;
    border-radius: var(--r-card);
    background: var(--surface-2);
    border: var(--lw-1) solid var(--line-strong);
    box-shadow: 0 0 0 2px var(--focus);
    outline: none;
  }
  .head {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .mono {
    font-family: var(--font-mono);
  }
  .title-l {
    margin: 0;
    font-size: 14.5px;
    font-weight: 600;
    line-height: 1.35;
  }
  .reason {
    margin: 0;
    font-size: var(--fs-s);
    color: var(--fg-2);
  }
  .ev {
    align-self: flex-start;
    padding: 0;
    border: none;
    background: none;
    font: inherit;
    font-size: var(--fs-s);
    color: var(--muted);
    text-align: left;
    cursor: pointer;
  }
  .ev:hover:not(:disabled) {
    color: var(--fg);
    text-decoration: underline;
  }
  .ev:disabled {
    cursor: default;
  }
  .stage {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .st {
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .reveal {
    display: flex;
    justify-content: space-between;
    padding: 9px 10px;
    border-radius: 7px;
    border: var(--lw-1) dashed var(--line-strong);
    background: transparent;
    color: var(--muted);
    font: inherit;
    cursor: pointer;
  }
  .reveal:hover {
    border-color: var(--muted);
    color: var(--fg);
  }
  .actions :global(.btn) {
    gap: 6px;
    padding: 7px 11px;
    font-size: 13px;
    line-height: 1;
  }
  .actions {
    display: flex;
    gap: 8px;
  }
</style>
