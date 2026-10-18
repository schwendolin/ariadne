<!--
  Eine Zeile im Reiter Terminals (SCREENS 5, Briefing 5.4): Name und pts · Shell (Name ändern mit
  d.terminal.label), Aufnahme (nimmt auf, Pause bis, held, gesperrt, Vorlauf, aus, wartet auf
  Bestätigung, E117-Grenze), Kontext als Brotkrume mit Vorschlag, letzter Befehl mit Zeit, Exit
  und Quell-IP, Remote-Segment, Eingaben ohne Echo verdeckt (Aufdecken einzeln, «In die Kali»),
  Aktionen Pause 10 min bzw. Fortsetzen, Kontext setzen, Vorschlag übernehmen, Anderer Host,
  Zeitachse. held als gestrichelte Zeile ohne Daten (E70), geschlossene gedämpft ohne Aktionen.
  Besitzer: ui-verlauf.
-->
<script lang="ts">
  import type { Terminal } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Breadcrumb from '../ui/Breadcrumb.svelte';
  import Button from '../ui/Button.svelte';
  import SecretValue from '../ui/SecretValue.svelte';
  import Txt from '../ui/Txt.svelte';
  import { url } from '../url/state.svelte';
  import { errorText } from '../util/errors';
  import { termShort } from '../util/format';
  import { hhmm } from '../util/time';

  let {
    app,
    project,
    term,
    closed = false,
    selected = false,
    onselect,
  }: {
    app: AppState;
    project: ProjectStore;
    term: Terminal;
    closed?: boolean;
    selected?: boolean;
    onselect: () => void;
  } = $props();
  const SEP = ' · ';

  const PAUSE_MIN = 10;
  const tid = $derived(term.terminal_id);
  const short = $derived(termShort(term));
  const tty = $derived(typeof term.tty === 'string' ? (/^\/dev\/(pts\/\d{1,5}|tty\w{1,8})$/.exec(term.tty)?.[1] ?? null) : null);
  const held = $derived(term.state === 'held');
  const pending = $derived(app.pendingPause[tid]);
  const refused = $derived(tid in app.pauseRefused);
  const budget = $derived(typeof term.web_pause_left_s === 'number' ? Math.floor(term.web_pause_left_s / 60) : null);
  const minutes = $derived(budget === null ? PAUSE_MIN : Math.max(0, Math.min(PAUSE_MIN, budget)));
  const top = $derived(term.stack[term.stack.length - 1] ?? null);
  const unknownTop = $derived(!!top && top.depth > 0 && !top.host_label);
  const inputs = $derived(project.terminals.hiddenInputs(tid));
  const cmd = $derived(term.last_command);
  const canAct = $derived(!closed && !held && !app.offline);

  let renaming = $state(false);
  let name = $state('');
  let renameError = $state<string | null>(null);
  let busy = $state(false);
  let nameInput: HTMLInputElement | undefined = $state();

  function startRename(): void {
    name = term.label ?? '';
    renameError = null;
    renaming = true;
    queueMicrotask(() => nameInput?.focus());
  }

  async function saveName(): Promise<void> {
    const v = name.trim();
    if (!v) {
      renaming = false;
      return;
    }
    if ([...v].length > 64) {
      renameError = t('term.renameTooLong');
      return;
    }
    busy = true;
    const err = await project.terminals.rename(tid, v);
    busy = false;
    if (err) {
      renameError = err;
      return;
    }
    renaming = false;
    app.ui.notify('info', t('term.renamed'), 2500);
  }

  function nameKey(e: KeyboardEvent): void {
    if (e.key === 'Enter') {
      e.preventDefault();
      void saveName();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      renaming = false;
    }
  }

  export async function accept(): Promise<void> {
    const s = term.suggestion;
    if (!s || !canAct || busy) return;
    busy = true;
    try {
      const res = await app.backend.setContext(tid, { op: 'accept', item_key: s.item_key });
      for (const w of res.warnings) app.ui.notify('info', `${t('ctx.host')} ${t(`ctx.warn.${w.code}` as MessageKey)}`);
      app.ui.notify('info', t('term.accepted'), 2500);
    } catch (e) {
      app.ui.notify('error', errorText(e, 'term.acceptFailed'));
    } finally {
      busy = false;
    }
  }

  export function openContext(): void {
    if (closed && !term.stack.length) return;
    app.ui.openDialog({ kind: 'context', terminalId: tid, itemKey: term.suggestion?.item_key, fromOff: term.suggestion?.from_off });
  }
</script>

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<li
  class="row"
  class:held
  class:closed
  class:sel={selected}
  class:suggest={!!term.suggestion && !closed}
  tabindex={selected ? 0 : -1}
  data-terminal={tid}
  aria-label={short}
  aria-current={selected ? 'true' : undefined}
  onfocus={onselect}
  onclick={onselect}
>
  <div class="who">
    <span class="name">
      {#if term.ordinal !== null}T{term.ordinal}{:else}{short}{/if}
      {#if term.label}<Txt value={term.label} max={32} />{/if}
    </span>
    <span class="tty">{tty ?? short}{#if term.shell}{SEP}<Txt value={term.shell} max={16} />{/if}</span>
    {#if renaming}
      <span class="rename">
        <label class="sr-only" for="term-name-{tid}">{t('term.renameLabel')}</label>
        <input id="term-name-{tid}" bind:this={nameInput} bind:value={name} maxlength="64" autocomplete="off" spellcheck="false" onkeydown={nameKey} />
        <span class="rename-actions">
          <Button size="s" variant="primary" disabled={busy} reason={t('term.renameSave')} onclick={() => void saveName()}>{t('term.renameSave')}</Button>
          <Button size="s" variant="ghost" onclick={() => (renaming = false)}>{t('common.cancel')}</Button>
        </span>
        {#if renameError}<span class="err" role="alert">{renameError}</span>{/if}
      </span>
    {:else if !held}
      <span class="links reveal">
        {#if !closed && term.ordinal !== null}
          <button type="button" class="link" aria-label={t('term.renameFor', { term: short })} disabled={app.offline} onclick={startRename}>{t('term.rename')}</button>
        {/if}
        <a class="link" href={url.href('zeitachse', { terminal: tid })} aria-label={t('term.toTimelineFor', { term: short })} onclick={(e) => {
          e.preventDefault();
          url.go('zeitachse', { terminal: tid, typ: null, hostf: null, zeile: null });
        }}>{t('term.toTimeline')}</a>
      </span>
    {/if}
  </div>

  <div class="rec">
    {#if closed}
      <span class="muted">{t('term.closed')}</span>
    {:else if pending}
      <span class="attention">{t('term.state.waiting')}</span>
    {:else if term.state === 'on'}
      <span class="on"><span class="dot" aria-hidden="true"></span>{t('term.state.on')}</span>
    {:else if term.state === 'paused'}
      <span class="attention"><b class="bars" aria-hidden="true">‖</b>{t('term.state.paused', { time: hhmm(term.pause_until) })}</span>
    {:else if held}
      <span class="attention">{t('term.state.held')} <code><Txt value={term.held_slug ?? '?'} max={32} /></code></span>
    {:else if term.state === 'locked'}
      <span class="attention">{t('term.state.locked')}</span>
    {:else if term.state === 'preroll'}
      <span class="muted">{t('term.state.preroll')}</span>
    {:else}
      <span class="muted">{t('term.state.off')}</span>
    {/if}
    {#if term.mux && !closed}<span class="note">{t('term.mux')}</span>{/if}
    {#if !closed && (refused || (term.state === 'on' && budget !== null && minutes === 0))}
      <span class="limit" role="note">{t('term.budgetEmpty')}</span>
    {:else if !closed && term.state === 'on' && budget !== null && budget < 30}
      <span class="note">{t('term.budget', { minutes: budget })}</span>
    {/if}
  </div>

  <div class="ctx">
    {#if held}
      <span>{t('term.held')} <code><Txt value={term.held_slug ?? '?'} max={32} /></code>{t('term.heldPost')}</span>
    {:else}
      <span class="crumb">
        <Breadcrumb stack={term.stack} suggestion={term.suggestion?.host_label ?? null} />
        {#if term.suggestion && unknownTop}
          <span class="sugg">· {t('term.suggestion')} <code><Txt value={term.suggestion.host_label} max={48} /></code></span>
        {/if}
      </span>
      {#if cmd}
        <span class="cmd"
          ><Txt value={cmd.text ?? ''} mono max={90} />
          <span class="meta"
            >· {hhmm(cmd.started_at)}{#if cmd.ended_at === null}{SEP}{t('term.running')}{:else if cmd.exit !== null}{SEP}{t('term.exit', { code: cmd.exit })}{/if}{#if cmd.src_ip}{SEP}{t('term.srcIp')} <Txt value={cmd.src_ip} mono max={45} />{/if}</span
          ></span
        >
      {:else}
        <span class="meta">{t('term.noCommand')}</span>
      {/if}
      {#if term.remote_segment && !closed}
        <span class="remote">{t('term.remote', { time: hhmm(term.remote_segment.since, { seconds: true }), n: term.remote_segment.lines })}</span>
      {/if}
      {#if closed}<span class="meta">{t('term.closedHint')}</span>{/if}
      {#each inputs.slice(0, 2) as inp (inp.seq)}
        <span class="input">
          <span class="meta">{t('term.inputs')} · {hhmm(inp.ts, { seconds: true })}</span>
          <SecretValue secret={{ ref: 'input', seq: inp.seq }} pid={project.pid} backend={app.backend} presentation={app.presentation} profile={app.profile} />
        </span>
      {/each}
      {#if inputs.length > 2}<span class="meta">{t('term.inputsMore', { n: inputs.length - 2 })}</span>{/if}
    {/if}
  </div>

  <div class="actions">
    {#if !held && !closed}
      {#if term.suggestion}
        <Button size="s" variant="primary" kbd="a" disabled={!canAct || busy} reason={app.offline ? t('term.offline') : t('common.loading')} onclick={() => void accept()}>{t('term.accept')}</Button>
        <Button size="s" kbd="e" disabled={!canAct} reason={t('term.offline')} onclick={openContext}>{t('term.otherHost')}</Button>
      {/if}
      {#if term.state === 'paused'}
        <Button
          size="s"
          disabled={!!pending || app.offline}
          reason={app.offline ? t('term.offline') : t('term.state.waiting')}
          label={t('term.resumeFor', { term: short })}
          onclick={() => void app.resume(tid)}>{t('term.resume')}</Button
        >
      {:else if term.state === 'on'}
        <Button
          size="s"
          disabled={!!pending || app.offline || refused || minutes === 0}
          reason={app.offline ? t('term.offline') : refused || minutes === 0 ? t('term.budgetEmpty') : t('term.state.waiting')}
          label={t('term.pauseFor', { term: short, minutes: minutes || PAUSE_MIN })}
          onclick={() => void app.pause(tid, minutes)}>{t('term.pause', { minutes: minutes || PAUSE_MIN })}</Button
        >
      {/if}
      {#if !term.suggestion}
        <Button size="s" disabled={!canAct} reason={t('term.offline')} onclick={openContext}>{t('term.setContext')}</Button>
      {/if}
    {/if}
  </div>
</li>

<style>
  .row {
    display: grid;
    grid-template-columns: 150px 150px minmax(0, 1fr) 270px;
    gap: var(--sp-4);
    align-items: start;
    padding: var(--sp-4) var(--sp-5);
    border-radius: var(--r-card);
    background: var(--rec-bg);
    border: var(--lw-1) solid var(--line);
    list-style: none;
    outline: none;
  }
  .row.suggest {
    border-color: var(--line-strong);
  }
  .row.sel {
    box-shadow: 0 0 0 var(--lw-focus) var(--focus);
  }
  .row:focus-visible {
    box-shadow: 0 0 0 var(--lw-focus) var(--focus);
  }
  .held {
    background: transparent;
    border-style: dashed;
    color: var(--muted);
  }
  .closed {
    opacity: 0.7;
    border-style: dashed;
  }
  .who,
  .rec,
  .ctx {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }
  .who {
    gap: 3px;
  }
  .name {
    font-weight: 600;
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
  }
  .tty {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .reveal {
    opacity: 0;
  }
  .row:hover .reveal,
  .row:focus-within .reveal,
  .row.sel .reveal {
    opacity: 1;
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    font-size: var(--fs-xs);
    cursor: pointer;
    text-decoration: underline dotted;
    text-underline-offset: 3px;
  }
  .link:disabled {
    cursor: not-allowed;
  }
  .rename {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-top: 4px;
  }
  .rename input {
    width: 100%;
    padding: 5px 8px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--focus);
    background: var(--bg);
    color: var(--fg);
    font-size: var(--fs-s);
  }
  .rename-actions {
    display: flex;
    gap: 6px;
  }
  .on {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--fg);
    flex: none;
  }
  .attention {
    color: var(--attention);
    display: flex;
    gap: 6px;
    align-items: baseline;
    flex-wrap: wrap;
  }
  .bars {
    letter-spacing: -1px;
  }
  .muted,
  .meta {
    color: var(--muted);
  }
  .meta {
    font-family: var(--font-ui);
  }
  .note {
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .limit {
    color: var(--attention);
    font-size: var(--fs-xs);
  }
  .crumb {
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
    align-items: center;
  }
  .sugg {
    color: var(--muted);
  }
  code {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
  }
  .cmd {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
    color: var(--fg-2);
    overflow-wrap: anywhere;
  }
  .cmd .meta {
    color: var(--faint);
  }
  .remote {
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .input {
    display: flex;
    gap: var(--sp-2);
    align-items: center;
    flex-wrap: wrap;
    font-size: var(--fs-s);
  }
  .actions {
    display: flex;
    gap: var(--sp-2);
    justify-content: flex-end;
    flex-wrap: wrap;
    align-items: center;
  }
  .links {
    display: flex;
    gap: var(--sp-3);
    margin-top: 2px;
  }
  .err {
    color: var(--error);
    font-size: var(--fs-xs);
  }
</style>
