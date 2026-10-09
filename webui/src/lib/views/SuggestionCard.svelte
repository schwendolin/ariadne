<!--
  Ein Denkanstoss: Begründung, Belege, Herkunft (Regel oder KI mit Modell) und Stufen.
  Im Lernmodus erscheinen die Stufen einzeln auf Klick: Frage, Richtung, Befehle.
  Es gibt keinen Ausführen-Knopf. Befehle kommen fertig vom Server; Anteile aus
  Zieldaten sind markiert, kopiert wird ohne Zeilenumbruch (Architektur 6.1).
-->
<script lang="ts">
  import type { CommandTemplateView, Suggestion } from '../api/types';
  import { t } from '../i18n';
  import { router } from '../router.svelte';
  import Badge from '../ui/Badge.svelte';
  import Txt from '../ui/Txt.svelte';
  import { copyText } from '../ui/actions';

  let {
    s,
    learning,
    onDone,
    onDismiss,
  }: { s: Suggestion; learning: boolean; onDone: () => void; onDismiss: () => void } = $props();

  let level = $state(1);
  let copied = $state<string | null>(null);
  const stages = $derived(learning ? s.stages.filter((st) => st.level <= level) : s.stages);
  const more = $derived(learning && s.stages.some((st) => st.level > level));

  async function copy(key: string, text: string) {
    if (await copyText(text)) {
      copied = key;
      setTimeout(() => (copied = null), 1500);
    }
  }

  function openSubject(sub: Suggestion['subjects'][number]) {
    const id = sub.kind === 'service' ? sub.id.replace(/^svc:(.+)\|[a-z]+\/\d+$/, '$1') : sub.id;
    if (sub.kind !== 'credential') router.navigate(router.href('karte', { host: id }));
  }

  function cmdKey(c: CommandTemplateView) {
    return `${s.suggestion_key}:${c.template_id}`;
  }
</script>

<article class="card sg" class:closed={s.status !== 'open'} class:injection={s.injection_suspect}>
  <header class="row">
    <Badge tone="info">{t(`sg.kind.${s.kind}`)}</Badge>
    {#if s.origin.type === 'ai'}
      <Badge tone="ai" title={t('badge.aiTitle')}>{t('sg.origin.ai', { model: s.origin.model })}</Badge>
    {:else}
      <Badge tone="muted">{t('sg.origin.rule', { id: s.origin.rule_id })}</Badge>
    {/if}
    {#if s.goal_id}<span class="small muted mono">{s.goal_id}</span>{/if}
    {#if s.injection_suspect}<Badge tone="danger">{t('badge.injection')}</Badge>{/if}
    {#if s.status !== 'open'}<Badge tone="muted">{t(`sg.status.${s.status}`)}</Badge>{/if}
  </header>
  <h2><Txt value={s.title} max={200} /></h2>
  <p><Txt value={s.reasoning} max={1200} /></p>

  {#if s.subjects.length}
    <div class="row small">
      {#each s.subjects as sub (sub.id)}
        <button type="button" class="chip" onclick={() => openSubject(sub)}><Txt value={sub.label} max={48} /></button>
      {/each}
    </div>
  {/if}

  {#if s.evidence.length}
    <div class="row small">
      <span class="muted">{t('sg.evidence')}:</span>
      {#each s.evidence as e, i (i)}
        {#if e.fact_id}
          <button type="button" class="small ghost" onclick={() => router.setParam('fact', e.fact_id)}><Txt value={e.label} max={60} /></button>
        {:else}
          <Txt value={e.label} max={60} />
        {/if}
      {/each}
    </div>
  {/if}

  {#if s.criteria}
    <dl class="criteria small">
      <dt>{t('sg.criteria.confirmed')}</dt><dd><Txt value={s.criteria.confirmed} max={400} /></dd>
      <dt>{t('sg.criteria.refuted')}</dt><dd><Txt value={s.criteria.refuted} max={400} /></dd>
    </dl>
  {/if}

  <ol class="stages">
    {#each stages as st (st.level)}
      <li>
        <span class="small muted">{t(`sg.stage.${st.kind}`)}</span>
        {#if st.text}<p><Txt value={st.text} max={800} /></p>{/if}
        {#each st.commands as c (c.template_id)}
          <div class="cmd">
            <div class="small muted">{c.title}</div>
            {#if c.renderable && c.copy_text !== null}
              <div class="row">
                <code class="cmdline">{#each c.parts as p, i (i)}<span class:from-target={p.from_target}><Txt value={p.text} max={0} /></span>{/each}</code>
                <button type="button" class="small" onclick={() => copy(cmdKey(c), c.copy_text ?? '')}>
                  {copied === cmdKey(c) ? t('sg.copied') : t('sg.copy')}
                </button>
              </div>
              {#if c.parts.some((p) => p.from_target)}<div class="small muted">{t('sg.fromTarget')}</div>{/if}
            {:else}
              <p class="warn small">{t('sg.unsafe')}</p>
              {#each c.values as v (v.name)}
                <div class="row">
                  <code><Txt value={v.value} max={120} /></code>
                  <button type="button" class="small" onclick={() => copy(`${cmdKey(c)}:${v.name}`, v.value)}>
                    {copied === `${cmdKey(c)}:${v.name}` ? t('sg.copied') : t('sg.copyValue', { name: v.name })}
                  </button>
                </div>
              {/each}
            {/if}
          </div>
        {/each}
      </li>
    {/each}
  </ol>

  <footer class="row">
    {#if more}<button type="button" class="small" onclick={() => (level += 1)}>{t('sg.nextStage')}</button>{/if}
    <div class="spacer"></div>
    {#if s.status === 'open'}
      <button type="button" class="small ghost" onclick={onDismiss}>{t('sg.dismiss')}</button>
      <button type="button" class="small primary" onclick={onDone}>{t('sg.done')}</button>
    {/if}
  </footer>
</article>

<style>
  .sg h2 {
    margin: 8px 0 4px;
    font-size: 1rem;
  }
  .sg.closed {
    opacity: 0.6;
  }
  .sg.injection {
    border-color: var(--badge-danger-text);
  }
  .chip {
    min-height: 22px;
    padding: 0 8px;
    border-radius: 999px;
    font-size: 0.85rem;
  }
  .criteria {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 2px 10px;
    margin: 6px 0;
  }
  .criteria dt {
    color: var(--text-muted);
  }
  .criteria dd {
    margin: 0;
  }
  .stages {
    margin: 8px 0;
    padding-left: 20px;
  }
  .stages li {
    margin-bottom: 6px;
  }
  .stages p {
    margin: 2px 0;
  }
  .cmd {
    margin: 6px 0;
  }
  .cmdline {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    background: var(--surface-2);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .warn {
    color: var(--badge-warn-text);
    margin: 2px 0;
  }
  footer {
    margin-top: 6px;
  }
</style>
