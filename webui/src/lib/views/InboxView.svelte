<!--
  Inbox: gruppiert nach auslösender Einheit, Sammelbestätigung, Tastatur-Triage
  (j/k wählen, a bestätigen, x verwerfen, e bearbeiten, Enter öffnet den Beleg),
  Automodus-Schalter, Scope-Urteil und KI-Kennzeichen pro Wert (Architektur 5.7, 7.4).
-->
<script lang="ts">
  import { tick } from 'svelte';
  import type { DecisionInput, InboxGroup, InboxItem } from '../api/types';
  import { t } from '../i18n';
  import { router } from '../router.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import ConfBadge from '../ui/ConfBadge.svelte';
  import FactBadges from '../ui/FactBadges.svelte';
  import ScopeBadge from '../ui/ScopeBadge.svelte';
  import Txt from '../ui/Txt.svelte';
  import { errText } from '../util/errors';
  import { predLabel } from '../util/labels';
  import { timeLocal, utcTooltip } from '../util/time';

  let { project }: { project: ProjectStore } = $props();

  const inbox = $derived(project.inbox);
  const groups = $derived(inbox?.groups ?? []);
  const flat = $derived(groups.flatMap((g) => g.items.map((i) => ({ g, i }))));
  let cursor = $state(0);
  let pending = $state<Set<string>>(new Set());
  let editing = $state<string | null>(null);
  let editValue = $state('');
  let ctxHost = $state<Record<string, string>>({});
  let error = $state<string | null>(null);
  let listEl: HTMLElement | undefined = $state();

  const current = $derived(flat[Math.min(cursor, Math.max(0, flat.length - 1))]?.i ?? null);

  $effect(() => {
    if (cursor >= flat.length) cursor = Math.max(0, flat.length - 1);
  });

  // Neue Inbox vom Server: erledigte Einträge sind verschwunden, Markierungen zurücksetzen.
  $effect(() => {
    void inbox;
    pending = new Set();
  });

  function summaryText(g: InboxGroup): string {
    const s = g.summary;
    const parts = [
      s.hosts ? t('inbox.sum.hosts', { n: s.hosts }) : '',
      s.services ? t('inbox.sum.services', { n: s.services }) : '',
      s.credentials ? t('inbox.sum.credentials', { n: s.credentials }) : '',
      s.other ? t('inbox.sum.other', { n: s.other }) : '',
    ].filter(Boolean);
    return parts.join(', ');
  }

  function bulkCandidates(g: InboxGroup): InboxItem[] {
    return g.items.filter((i) => i.type === 'claim' && i.claim_key && i.scope === 'in' && i.confidence_level !== 'low');
  }

  async function decide(items: InboxItem[], decisions: DecisionInput[]) {
    if (!decisions.length) return;
    error = null;
    pending = new Set([...pending, ...items.map((i) => i.item_id)]);
    try {
      await project.backend.decide(project.pid, decisions);
    } catch (e) {
      error = errText(e);
      pending = new Set([...pending].filter((id) => !items.some((i) => i.item_id === id)));
      project.refresh('inbox');
    }
  }

  function confirm(i: InboxItem) {
    if (i.type !== 'claim' || !i.claim_key) return;
    void decide([i], [{ kind: 'd.claim.confirm', payload: { claim_key: i.claim_key } }]);
  }

  function reject(i: InboxItem) {
    if (!i.claim_key) return;
    void decide([i], [{ kind: 'd.claim.reject', payload: { claim_key: i.claim_key } }]);
  }

  function confirmGroup(g: InboxGroup) {
    const items = bulkCandidates(g);
    void decide(items, items.map((i) => ({ kind: 'd.claim.confirm', payload: { claim_key: i.claim_key! } })));
  }

  async function startEdit(i: InboxItem) {
    if (i.type !== 'claim' || !i.claim_key) return;
    editing = i.item_id;
    editValue = i.value === null ? '' : String(i.value);
    await tick();
    listEl?.querySelector<HTMLInputElement>('input.edit')?.focus();
  }

  function saveEdit(i: InboxItem) {
    if (!i.claim_key) return;
    editing = null;
    void decide([i], [{ kind: 'd.claim.edit', payload: { claim_key: i.claim_key, value: editValue } }]);
  }

  function resolveConflict(i: InboxItem, choice: string | null) {
    if (!i.conflict) return;
    void decide([i], [{ kind: 'd.conflict.resolve', payload: { conflict_key: i.conflict.conflict_key, choice, keep_open: choice === null } }]);
  }

  async function setContext(i: InboxItem) {
    if (!i.context) return;
    const host = (ctxHost[i.item_id] ?? i.context.candidate ?? '').trim();
    if (!host) return;
    error = null;
    pending = new Set([...pending, i.item_id]);
    try {
      await project.backend.setContext(i.context.terminal_id, { op: 'set', host });
    } catch (e) {
      error = errText(e);
      pending = new Set([...pending].filter((id) => id !== i.item_id));
    }
  }

  function toggleAutomode() {
    const a = inbox?.automode;
    if (!a) return;
    void project.backend
      .decide(project.pid, [{ kind: 'd.automode.set', payload: { enabled: !a.enabled, parsers: a.parsers, auto_ctx: a.auto_ctx } }])
      .catch((e) => (error = errText(e)));
  }

  function openSource(i: InboxItem) {
    if (i.fact_id) router.setParam('fact', i.fact_id);
  }

  async function onKey(e: KeyboardEvent) {
    const target = e.target as HTMLElement | null;
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return;
    if (router.param('fact') || router.param('host')) return;
    const item = current;
    switch (e.key) {
      case 'j':
        cursor = Math.min(flat.length - 1, cursor + 1);
        break;
      case 'k':
        cursor = Math.max(0, cursor - 1);
        break;
      case 'a':
        if (item) confirm(item);
        break;
      case 'x':
        if (item) reject(item);
        break;
      case 'e':
        if (item) await startEdit(item);
        break;
      case 'Enter':
        if (item) openSource(item);
        break;
      default:
        return;
    }
    e.preventDefault();
    await tick();
    listEl?.querySelector('.item.current')?.scrollIntoView({ block: 'nearest' });
  }
</script>

<svelte:window onkeydown={onKey} />

<section class="view" aria-labelledby="inbox-title">
  <div class="view-head">
    <h1 id="inbox-title">{t('inbox.title')}</h1>
    {#if inbox}<Badge tone={inbox.open ? 'info' : 'muted'}>{t('inbox.open', { n: inbox.open })}</Badge>{/if}
    <div class="spacer"></div>
    {#if inbox}
      <label class="row automode" title={t('inbox.automodeHint')}>
        <input type="checkbox" checked={inbox.automode.enabled} onchange={toggleAutomode} />
        {t('inbox.automode')}
      </label>
    {/if}
  </div>
  <p class="muted small">{t('inbox.keys')}</p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#if !inbox}
    <p class="muted">{t('common.loading')}</p>
  {:else if groups.length === 0}
    <p class="muted">{t('inbox.empty')}</p>
  {:else}
    <div class="groups" bind:this={listEl}>
      {#each groups as g (g.group_id)}
        {@const bulk = bulkCandidates(g)}
        <article class="group card">
          <header class="group-head">
            <div class="stack grow">
              <h2 class="mono"><Txt value={g.title} max={140} /></h2>
              <div class="row small muted">
                <time title={utcTooltip(g.ts)}>{timeLocal(g.ts)}</time>
                {#if g.unit?.parser}<span>{g.unit.parser}</span>{/if}
                <span>{summaryText(g)}</span>
              </div>
            </div>
            {#if bulk.length > 1}
              <div class="stack bulk">
                <button type="button" class="primary small" onclick={() => confirmGroup(g)}>{t('inbox.confirmAll', { n: bulk.length })}</button>
                {#if g.summary.out_of_scope || g.summary.low_confidence}
                  <span class="small muted">{t('inbox.confirmAllHint', { oos: g.summary.out_of_scope, low: g.summary.low_confidence })}</span>
                {/if}
              </div>
            {/if}
          </header>

          <ul class="items">
            {#each g.items as i (i.item_id)}
              {@const idx = flat.findIndex((f) => f.i.item_id === i.item_id)}
              <li class="item" class:current={idx === cursor} class:pending={pending.has(i.item_id)} aria-current={idx === cursor ? 'true' : undefined}>
                {#if i.type === 'context' && i.context}
                  <div class="main">
                    <strong>{t('pred.ctx.host')}</strong>
                    <span class="muted">{t('inbox.contextHint', { term: i.context.terminal_label ?? i.context.terminal_id, cand: i.context.candidate ?? '–' })}</span>
                  </div>
                  <form class="row" onsubmit={(e) => { e.preventDefault(); void setContext(i); }}>
                    <input
                      type="text"
                      aria-label={t('term.hostPlaceholder')}
                      placeholder={t('term.hostPlaceholder')}
                      value={ctxHost[i.item_id] ?? i.context.candidate ?? ''}
                      oninput={(e) => (ctxHost = { ...ctxHost, [i.item_id]: (e.currentTarget as HTMLInputElement).value })}
                    />
                    <button type="submit" class="small">{t('inbox.setContext')}</button>
                  </form>
                {:else if i.type === 'conflict' && i.conflict}
                  <div class="main">
                    <strong><Txt value={i.subject_label} max={60} /></strong>
                    <span>{predLabel(i.predicate)}</span>
                    <Badge tone="warn">{t('badge.conflict')}</Badge>
                    <p class="small muted">{t('inbox.conflictHint')}</p>
                    <ul class="conflict">
                      {#each i.conflict.values as v (v.claim_key)}
                        <li class="row">
                          <code><Txt value={v.value} max={80} /></code>
                          <span class="small muted">{t(`trust.${v.trust}`)}, {t('ev.sources', { n: v.sources_count })}</span>
                          <button type="button" class="small ghost" onclick={() => router.setParam('fact', v.fact_id)}>{t('inbox.source')}</button>
                          <button type="button" class="small" onclick={() => resolveConflict(i, v.value)}>{t('inbox.choose')}</button>
                        </li>
                      {/each}
                    </ul>
                    <button type="button" class="small ghost" onclick={() => resolveConflict(i, null)}>{t('inbox.keepOpen')}</button>
                  </div>
                {:else}
                  <div class="main">
                    <strong><Txt value={i.subject_label} max={60} /></strong>
                    <span class="muted">{predLabel(i.predicate)}</span>
                    {#if editing === i.item_id}
                      <form class="row" onsubmit={(e) => { e.preventDefault(); saveEdit(i); }}>
                        <input class="edit" type="text" bind:value={editValue} aria-label={t('col.value')} />
                        <button type="submit" class="small">{t('common.save')}</button>
                        <button type="button" class="small ghost" onclick={() => (editing = null)}>{t('common.cancel')}</button>
                      </form>
                    {:else}
                      <code class="value"><Txt value={i.value} max={100} /></code>
                    {/if}
                    <span class="badges">
                      <ConfBadge level={i.confidence_level} />
                      <ScopeBadge verdict={i.scope} />
                      <FactBadges ai={i.ai} offered={i.offered_by_target} />
                      {#if i.parser}<span class="small muted">{i.parser}</span>{/if}
                    </span>
                  </div>
                  <div class="actions row">
                    {#if i.fact_id}<button type="button" class="small ghost" onclick={() => openSource(i)}>{t('inbox.source')}</button>{/if}
                    <button type="button" class="small" onclick={() => startEdit(i)}>{t('inbox.edit')}</button>
                    <button type="button" class="small" onclick={() => reject(i)}>{t('inbox.reject')}</button>
                    <button type="button" class="small primary" onclick={() => confirm(i)}>{t('inbox.confirm')}</button>
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        </article>
      {/each}
    </div>
  {/if}
</section>

<style>
  .groups {
    display: flex;
    flex-direction: column;
    gap: 12px;
    max-width: 1100px;
  }
  .group-head {
    display: flex;
    gap: 12px;
    align-items: flex-start;
    margin-bottom: 8px;
  }
  .group-head h2 {
    font-size: 0.95rem;
    margin: 0;
  }
  .grow {
    flex: 1;
    gap: 2px;
  }
  .bulk {
    align-items: flex-end;
    max-width: 320px;
    text-align: right;
    gap: 4px;
  }
  .items {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .item {
    display: flex;
    gap: 12px;
    align-items: flex-start;
    justify-content: space-between;
    padding: 6px 8px;
    border-top: 1px solid var(--border);
    border-radius: 4px;
  }
  .item.current {
    background: var(--row-selected);
    box-shadow: inset 3px 0 0 var(--accent);
  }
  .item.pending {
    opacity: 0.5;
  }
  .main {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 10px;
    align-items: baseline;
    min-width: 0;
  }
  .value {
    max-width: 420px;
  }
  .badges {
    display: inline-flex;
    gap: 4px;
    align-items: center;
    flex-wrap: wrap;
  }
  .actions {
    flex: none;
  }
  .conflict {
    list-style: none;
    margin: 4px 0;
    padding: 0;
    width: 100%;
  }
  .automode {
    font-size: 0.9rem;
  }
</style>
