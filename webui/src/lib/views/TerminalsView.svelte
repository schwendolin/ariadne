<!--
  Terminals: Name, Status, letzter Befehl, Quell-IP, Kontextstapel als Brotkrumen.
  Die Stufe «unbekannt» ist auffällig und lässt sich direkt setzen (Architektur 3.5, 7.4).
  Kontext-Änderungen gehen über POST /terminals/{tid}/context (intern d.ctx.*).
-->
<script lang="ts">
  import type { ContextOp, ContextResult, Terminal } from '../api/types';
  import { t } from '../i18n';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import Breadcrumbs from '../ui/Breadcrumbs.svelte';
  import Txt from '../ui/Txt.svelte';
  import { errText } from '../util/errors';
  import { timeLocal, utcTooltip } from '../util/time';

  let { project }: { project: ProjectStore } = $props();

  let hostDraft = $state<Record<string, string>>({});
  let userDraft = $state<Record<string, string>>({});
  let labelDraft = $state<Record<string, string>>({});
  let renaming = $state<string | null>(null);
  let warnings = $state<Record<string, ContextResult['warnings']>>({});
  let error = $state<string | null>(null);

  const terminals = $derived([...project.terminals].sort((a, b) => Number(b.alive) - Number(a.alive)));
  const hostOptions = $derived(project.hosts.map((h) => ({ id: h.id, label: h.label, addr: h.addresses[0] ?? h.id })));

  function top(term: Terminal) {
    return term.stack[term.stack.length - 1];
  }

  async function context(term: Terminal, op: ContextOp) {
    error = null;
    try {
      const res = await project.backend.setContext(term.terminal_id, op);
      warnings = { ...warnings, [term.terminal_id]: res.warnings };
    } catch (e) {
      error = errText(e);
    }
  }

  function setHost(term: Terminal, e: SubmitEvent) {
    e.preventDefault();
    const st = top(term);
    const host = (hostDraft[term.terminal_id] ?? st?.candidate ?? '').trim();
    if (!host) return;
    const user = (userDraft[term.terminal_id] ?? st?.user ?? '').trim() || null;
    void context(term, { op: 'set', host, user });
  }

  async function rename(term: Terminal, e: SubmitEvent) {
    e.preventDefault();
    const label = (labelDraft[term.terminal_id] ?? '').trim().slice(0, 64);
    renaming = null;
    if (!label) return;
    try {
      await project.backend.decide(project.pid, [{ kind: 'd.terminal.label', payload: { terminal_id: term.terminal_id, label } }]);
    } catch (err) {
      error = errText(err);
    }
  }

  function warnText(w: ContextResult['warnings'][number]): string {
    return t(`term.warn.${w.code}`, { id: w.identifier });
  }
</script>

<section class="view" aria-labelledby="term-title">
  <div class="view-head">
    <h1 id="term-title">{t('term.title')}</h1>
  </div>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if terminals.length === 0}
    <p class="muted">{t('term.none')}</p>
  {/if}

  <datalist id="known-hosts">
    {#each hostOptions as h (h.id)}<option value={h.addr}>{h.label}</option>{/each}
  </datalist>

  <div class="list">
    {#each terminals as term (term.terminal_id)}
      {@const st = top(term)}
      <article class="card term" class:closed={!term.alive} class:unknown={st?.kind === 'unknown'}>
        <header class="row">
          {#if renaming === term.terminal_id}
            <form class="row" onsubmit={(e) => rename(term, e)}>
              <input
                type="text"
                maxlength="64"
                aria-label={t('term.renamePlaceholder')}
                value={labelDraft[term.terminal_id] ?? term.label ?? ''}
                oninput={(e) => (labelDraft = { ...labelDraft, [term.terminal_id]: (e.currentTarget as HTMLInputElement).value })}
              />
              <button type="submit" class="small">{t('common.save')}</button>
            </form>
          {:else}
            <h2><Txt value={term.label ?? term.tty ?? term.terminal_id} max={48} /></h2>
            <button type="button" class="small ghost" onclick={() => (renaming = term.terminal_id)}>{t('term.rename')}</button>
          {/if}
          <div class="spacer"></div>
          <Badge tone={term.alive ? 'ok' : 'muted'}>{term.alive ? t('term.alive') : t('term.closed')}</Badge>
          {#if term.recording}
            <Badge tone="danger">{t('term.recording')}</Badge>
          {:else if term.paused_reason}
            <Badge tone="muted">{t('term.paused', { reason: t(`gap.${term.paused_reason}`) })}</Badge>
          {:else}
            <Badge tone="muted">{t('term.notRecording')}</Badge>
          {/if}
          <span class="small muted">{t('term.shell')}: {term.shell}{term.tty ? ` · ${term.tty}` : ''}</span>
        </header>

        <div class="ctx">
          <span class="muted small">{t('term.context')}</span>
          <Breadcrumbs stack={term.stack} />
        </div>

        {#if term.last_command}
          <div class="last">
            <span class="muted small">{t('term.lastCmd')}</span>
            <code><Txt value={term.last_command.text ?? '–'} max={160} /></code>
            <span class="small muted">
              <time title={utcTooltip(term.last_command.started_at)}>{timeLocal(term.last_command.started_at)}</time>
              {#if term.last_command.exit !== null} · {t('tl.exit', { n: term.last_command.exit })}{/if}
              {#if term.last_command.src_ip} · {t('term.srcIp')} <span class="mono">{term.last_command.src_ip}</span>{/if}
            </span>
          </div>
        {/if}

        {#if term.alive}
          {#if st?.kind === 'unknown'}
            <p class="hint small">{t('term.unknownHint')}</p>
          {/if}
          <form class="row setctx" onsubmit={(e) => setHost(term, e)}>
            <input
              type="text"
              list="known-hosts"
              placeholder={t('term.hostPlaceholder')}
              aria-label={t('term.setHost')}
              value={hostDraft[term.terminal_id] ?? (st?.kind === 'unknown' ? (st.candidate ?? '') : '')}
              oninput={(e) => (hostDraft = { ...hostDraft, [term.terminal_id]: (e.currentTarget as HTMLInputElement).value })}
            />
            <input
              type="text"
              class="user"
              placeholder={t('term.user')}
              aria-label={t('term.user')}
              value={userDraft[term.terminal_id] ?? st?.user ?? ''}
              oninput={(e) => (userDraft = { ...userDraft, [term.terminal_id]: (e.currentTarget as HTMLInputElement).value })}
            />
            <button type="submit" class:primary={st?.kind === 'unknown'} class="small">{t('term.setHost')}</button>
            <button type="button" class="small ghost" onclick={() => context(term, { op: 'push', kind: 'unknown' })}>{t('term.push')}</button>
            {#if term.stack.length > 1}
              <button type="button" class="small ghost" onclick={() => context(term, { op: 'pop' })}>{t('term.pop')}</button>
            {/if}
          </form>
          {#each warnings[term.terminal_id] ?? [] as w (w.code + w.identifier)}
            <p class="warn small" role="status"><Txt value={warnText(w)} max={200} /></p>
          {/each}
        {/if}
      </article>
    {/each}
  </div>
</section>

<style>
  .list {
    display: grid;
    gap: 12px;
    max-width: 1100px;
  }
  .term header h2 {
    margin: 0;
    font-size: 1rem;
  }
  .term.closed {
    opacity: 0.65;
  }
  .term.unknown {
    border-color: var(--badge-warn-text);
    box-shadow: inset 4px 0 0 var(--badge-warn-text);
  }
  .ctx,
  .last {
    display: flex;
    gap: 8px;
    align-items: baseline;
    flex-wrap: wrap;
    margin-top: 6px;
  }
  .setctx {
    margin-top: 8px;
  }
  .setctx .user {
    width: 140px;
  }
  .hint {
    margin: 8px 0 0;
    color: var(--badge-warn-text);
  }
  .warn {
    margin: 6px 0 0;
    color: var(--badge-warn-text);
  }
</style>
