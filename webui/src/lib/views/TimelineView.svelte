<!--
  Zeitachse als einfache, filterbare Liste: Befehle, REC-Marken, Kontextwechsel,
  Screenshots, Entscheide und Schlüsselschritte. Lokalzeit, UTC im Tooltip.
-->
<script lang="ts">
  import type { TimelineItem, TimelineType } from '../api/types';
  import { t } from '../i18n';
  import { router } from '../router.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import Txt from '../ui/Txt.svelte';
  import { dayKey, timeLocal, utcTooltip } from '../util/time';

  let { project }: { project: ProjectStore } = $props();

  const TYPES: TimelineType[] = ['command', 'segment', 'keystep', 'context', 'screenshot', 'decision', 'rec', 'gap', 'ai', 'file'];
  let type = $state<TimelineType | ''>('');
  let terminal = $state('');

  const termLabels = $derived(Object.fromEntries(project.terminals.map((x) => [x.terminal_id, x.label ?? x.tty ?? x.terminal_id])));
  const items = $derived(project.timeline.filter((i) => (!type || i.type === type) && (!terminal || i.terminal_id === terminal)));
  const days = $derived.by(() => {
    const out: { day: string; items: TimelineItem[] }[] = [];
    for (const i of items) {
      const d = dayKey(i.ts);
      const last = out[out.length - 1];
      if (last && last.day === d) last.items.push(i);
      else out.push({ day: d, items: [i] });
    }
    return out;
  });

  function tone(ty: TimelineType) {
    if (ty === 'keystep') return 'danger';
    if (ty === 'gap') return 'warn';
    if (ty === 'ai') return 'ai';
    if (ty === 'decision') return 'ok';
    return 'muted';
  }
</script>

<section class="view" aria-labelledby="tl-title">
  <div class="view-head">
    <h1 id="tl-title">{t('tl.title')}</h1>
    <label class="row small">
      {t('tl.type')}
      <select bind:value={type}>
        <option value="">{t('tl.all')}</option>
        {#each TYPES as ty (ty)}<option value={ty}>{t(`tlType.${ty}`)}</option>{/each}
      </select>
    </label>
    <label class="row small">
      {t('tl.terminal')}
      <select bind:value={terminal}>
        <option value="">{t('tl.all')}</option>
        {#each project.terminals as term (term.terminal_id)}<option value={term.terminal_id}>{term.label ?? term.terminal_id}</option>{/each}
      </select>
    </label>
  </div>

  {#if items.length === 0}
    <p class="muted">{t('tl.empty')}</p>
  {/if}
  {#each days as d (d.day)}
    <h2 class="day">{d.day}</h2>
    <ol class="tl">
      {#each d.items as i (i.id)}
        <li class="item {i.type}">
          <time title={utcTooltip(i.ts)}>{timeLocal(i.ts, true)}</time>
          <span><Badge tone={tone(i.type)}>{t(`tlType.${i.type}`)}</Badge></span>
          <div class="body">
            <div class:mono={i.type === 'command' || i.type === 'segment'}><Txt value={i.title} max={160} /></div>
            <div class="small muted row">
              {#if i.host_label && i.host_id}
                <button type="button" class="linkish" onclick={() => router.navigate(router.href('karte', { host: i.host_id }))}><Txt value={i.host_label} max={40} /></button>
              {/if}
              {#if i.terminal_id}<span>{termLabels[i.terminal_id] ?? i.terminal_id}</span>{/if}
              {#if i.exit !== null}<span>{t('tl.exit', { n: i.exit })}</span>{/if}
              {#if i.facts}<span>{t('tl.facts', { n: i.facts })}</span>{/if}
              {#if i.detail}<span><Txt value={i.detail} max={160} /></span>{/if}
              {#if i.evidence?.fact_id}
                <button type="button" class="linkish" onclick={() => router.setParam('fact', i.evidence!.fact_id)}>{t('inbox.source')}</button>
              {/if}
            </div>
          </div>
        </li>
      {/each}
    </ol>
  {/each}
</section>

<style>
  .day {
    margin: 16px 0 6px;
    font-size: 0.95rem;
    color: var(--text-muted);
  }
  .tl {
    list-style: none;
    margin: 0;
    padding: 0;
    max-width: 1100px;
    border-left: 2px solid var(--border);
  }
  .item {
    display: grid;
    grid-template-columns: 76px 130px 1fr;
    gap: 8px;
    align-items: baseline;
    padding: 5px 0 5px 10px;
  }
  .item.keystep {
    border-left: 3px solid var(--map-thread);
    margin-left: -2px;
  }
  time {
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }
  .body {
    min-width: 0;
  }
</style>
