<!-- Beleg aus einem Terminal-Strom: Befehl, Kontext, Zeit, Exit-Code, Quell-IP und die bereinigten Zeilen. -->
<script lang="ts">
  import type { SourceView } from '../api/types';
  import { t } from '../i18n';
  import { visible } from '../safe/displaySafe';
  import { LinesCache, PAGE } from '../stores/lines.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import Breadcrumbs from '../ui/Breadcrumbs.svelte';
  import LogLineView from '../ui/LogLineView.svelte';
  import Txt from '../ui/Txt.svelte';
  import VirtualList from '../ui/VirtualList.svelte';
  import { copyText } from '../ui/actions';
  import { evidenceMarkdown } from '../util/evidence';
  import { dateTimeLocal, utcTooltip } from '../util/time';

  let { project, src, presentation }: { project: ProjectStore; src: Extract<SourceView, { t: 'stream' }>; presentation: boolean } = $props();

  let showHidden = $state(false);
  let revealed = $state(false);
  let copied = $state(false);
  let scrollTo = $state<number | null>(null);
  let scrollKey = $state(0);

  const cache = $derived(new LinesCache(project, src.terminal_id, src.unit_id, showHidden));
  const [a, b] = $derived(src.lines);

  $effect(() => {
    void cache.ensure(Math.floor(src.lines[0] / PAGE)).then(() => (scrollTo = src.lines[0]));
  });

  async function copyEvidence() {
    const lines = await cache.range(a, b);
    copied = await copyText(evidenceMarkdown(src, lines));
    setTimeout(() => (copied = false), 2000);
  }

  async function downloadLog() {
    const total = cache.total ?? 0;
    if (!total) return;
    const all = await cache.range(0, total - 1);
    const text = all.map((l) => visible(l.text)).join('\n') + '\n';
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `${src.unit_id.replace(/[^A-Za-z0-9_-]/g, '_')}.txt`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
</script>

<div class="src">
  <dl class="kv">
    {#if src.cmd}
      <dt>{t('ev.command')}</dt>
      <dd><code><Txt value={src.cmd.text ?? '–'} max={200} /></code></dd>
    {/if}
    <dt>{t('ev.terminal')}</dt>
    <dd><Txt value={src.terminal_label ?? src.terminal_id} /></dd>
    <dt>{t('ev.context')}</dt>
    <dd><Breadcrumbs stack={src.context} /></dd>
    {#if src.cmd}
      <dt>{t('ev.time')}</dt>
      <dd><time title={utcTooltip(src.cmd.started_at)}>{dateTimeLocal(src.cmd.started_at)}</time></dd>
      {#if src.cmd.exit !== null}<dt>{t('ev.exit')}</dt><dd>{src.cmd.exit}</dd>{/if}
      {#if src.cmd.src_ip}<dt>{t('ev.srcIp')}</dt><dd class="mono">{src.cmd.src_ip}</dd>{/if}
    {/if}
    <dt>{t('col.source')}</dt>
    <dd>
      {t('ev.parser', { p: src.parser, trust: t(`trust.${src.trust}`) })} · {t('ev.lines', { a: a + 1, b: b + 1 })}
      {#if !src.cmd}<Badge tone="warn">{t('ev.remoteRec')}</Badge>{/if}
      {#if src.truncated}<Badge tone="warn">{t('ev.truncated')}</Badge>{/if}
      {#if src.partial}<Badge tone="warn">{t('ev.partial')}</Badge>{/if}
    </dd>
  </dl>

  <div class="row tools">
    <button type="button" class="small" onclick={() => {
        scrollTo = a;
        scrollKey += 1;
      }}>{t('ev.jump')}</button>
    <label class="row small"><input type="checkbox" bind:checked={showHidden} /> {t('ev.showHidden')}</label>
    <div class="spacer"></div>
    <button type="button" class="small" onclick={copyEvidence}>{copied ? t('ev.copied') : t('ev.copy')}</button>
    <button type="button" class="small" onclick={downloadLog}>{t('ev.fullLog')}</button>
    <button type="button" class="small" disabled>{t('ev.toFinding')}</button>
  </div>

  {#if presentation && !revealed}
    <div class="collapsed card">
      <span class="muted">{t('ev.collapsed')}</span>
      <button type="button" class="small" onclick={() => (revealed = true)}>{t('ev.reveal')}</button>
    </div>
  {:else}
    <div class="log">
      <VirtualList count={cache.total ?? 0} rowHeight={20} {scrollTo} {scrollKey} label={t('ev.title')}>
        {#snippet row(i: number)}
          {@const l = cache.line(i)}
          {#if l}
            <LogLineView line={l} marked={i >= a && i <= b} {showHidden} />
          {:else}
            <div class="ph">…</div>
          {/if}
        {/snippet}
      </VirtualList>
    </div>
  {/if}
</div>

<style>
  .src {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .kv {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 3px 12px;
    margin: 0;
  }
  .kv dt {
    color: var(--text-muted);
  }
  .kv dd {
    margin: 0;
    min-width: 0;
  }
  .tools {
    gap: 6px;
  }
  .log {
    height: min(52vh, 560px);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--log-bg);
  }
  .ph {
    height: 20px;
    color: var(--text-muted);
    font-family: var(--font-mono);
    padding-left: 6ch;
  }
  .collapsed {
    display: flex;
    gap: 12px;
    align-items: center;
  }
</style>
