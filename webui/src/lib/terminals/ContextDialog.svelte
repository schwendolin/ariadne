<!--
  Dialog «Kontext für T3 «listener»» (Screen 10, Briefing 5.4, web-api.md 5): Host als Freitext mit
  Vorschlägen (Vorschlag aus dem Callback, bekannte Hosts der Karte, sonst «unbekannter Host»),
  Benutzer (optional), «Gilt ab» (rückwirkend ab dem Vorschlag bzw. ab Beginn der Stufe, oder ab
  jetzt), Wirkung (Stufe setzen oder neue Stufe öffnen mit Art). Setzen über
  POST /terminals/{tid}/context; ist der gewählte Host genau der Vorschlag, geht es als `accept`.
  Danach Warnungen (ausserhalb, ausgeschlossen, ohne Urteil, unbekannt) im Dialog. «Stufe
  schliessen» (pop, nie Kali). Ein beendetes Terminal geht nur rückwirkend. Fokus gefangen,
  Einzeltasten aus (Dialog). Geöffnet von der Spalte (ui-karte) und vom Reiter Terminals.
  Besitzer: ui-verlauf.
-->
<script lang="ts">
  import type { ContextOp, ContextResult, HostNode, StageKind } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import { displaySafe } from '../safe/displaySafe';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Txt from '../ui/Txt.svelte';
  import { errorText } from '../util/errors';
  import { termShort } from '../util/format';
  import { hhmm } from '../util/time';

  let {
    app,
    project,
    terminalId,
    itemKey = undefined,
    fromOff = undefined,
    onclose,
  }: {
    app: AppState;
    project: ProjectStore;
    terminalId: string;
    itemKey?: string | undefined;
    fromOff?: number | undefined;
    onclose: () => void;
  } = $props();

  const KINDS: StageKind[] = ['remote', 'ssh', 'su', 'winrm', 'revshell', 'msf', 'meterpreter', 'db', 'local', 'unknown'];
  const HOST_RE = /^[^\s\p{Cc}\p{Cf}]{1,253}$/u;
  const USER_RE = /^[^\s\p{Cc}\p{Cf}]{1,64}$/u;

  const term = $derived(project.terminals.byId(terminalId));
  const closed = $derived(project.terminals.isClosed(terminalId) || term?.connected === false);
  const stack = $derived(term?.stack ?? []);
  const top = $derived(stack[stack.length - 1] ?? null);
  const item = $derived(itemKey ? (project.next.clarifyItems.find((i) => i.item_key === itemKey) ?? null) : null);

  /** Vorschlag aus dem Callback: aus «Als Nächstes» oder aus dem Terminal */
  const sugg = $derived.by(() => {
    if (item && item.kind === 'ctx_suggestion') {
      return { itemKey: item.item_key, label: item.suggested_label, fromOff: item.from_off, fromTs: item.from_ts };
    }
    const s = term?.suggestion;
    if (s && (!itemKey || s.item_key === itemKey)) return { itemKey: s.item_key, label: s.host_label, fromOff: s.from_off, fromTs: null as string | null };
    return null;
  });

  /** Offset «wie der Vorschlag» (aus der Spalte oder dem Vorschlag) */
  const offset = $derived(fromOff ?? sugg?.fromOff ?? (item && 'from_off' in item ? (item.from_off ?? null) : null));
  const offsetTs = $derived(sugg?.fromTs ?? (item && 'from_ts' in item ? item.from_ts : null));
  const stageOff = $derived(top && top.depth > 0 ? top.opened_at : null);

  const termTitle = $derived.by(() => {
    if (!term) return termShort({ ordinal: null, terminal_id: terminalId });
    const base = termShort(term);
    return term.label ? `${base} «${displaySafe(term.label, 40)}»` : base;
  });

  let host = $state('');
  let user = $state('');
  let from = $state<'offset' | 'stage' | 'now'>('now');
  let mode = $state<'set' | 'push'>('set');
  let kind = $state<StageKind>('remote');
  let error = $state<string | null>(null);
  let busy = $state(false);
  let result = $state.raw<ContextResult | null>(null);
  let inited = false;

  $effect(() => {
    if (inited) return;
    inited = true;
    host = sugg?.label ?? (top && top.depth > 0 ? (top.host_label ?? '') : '');
    user = top && top.depth > 0 ? (top.user ?? '') : '';
    from = offset !== null ? 'offset' : stageOff !== null && top && !top.host_label ? 'stage' : closed ? 'stage' : 'now';
    kind = top && top.depth > 0 ? top.kind : 'remote';
  });

  const known = $derived((project.map.graph?.nodes.filter((n) => n.kind === 'host') ?? []) as HostNode[]);

  interface Option {
    value: string;
    note: MessageKey;
    tone: 'muted' | 'attention';
  }

  const options = $derived.by(() => {
    const q = host.trim().toLowerCase();
    const out: Option[] = [];
    const seen = new Set<string>();
    if (sugg) {
      out.push({ value: sugg.label, note: 'ctx.opt.suggestion', tone: 'muted' });
      seen.add(sugg.label.toLowerCase());
    }
    for (const h of known) {
      if (out.length >= 7) break;
      const label = h.label;
      if (seen.has(label.toLowerCase())) continue;
      if (q && !label.toLowerCase().includes(q) && !h.addresses.some((a) => a.includes(q))) continue;
      out.push({ value: label, note: h.claim_state === 'candidate' ? 'ctx.opt.fog' : 'ctx.opt.known', tone: 'muted' });
      seen.add(label.toLowerCase());
    }
    const typed = host.trim();
    if (typed && !seen.has(typed.toLowerCase()) && !known.some((h) => h.addresses.includes(typed) || h.names.includes(typed))) {
      out.push({ value: typed, note: 'ctx.opt.unknown', tone: 'attention' });
    }
    return out;
  });

  function fromOffValue(): number | undefined {
    if (from === 'offset' && offset !== null) return offset;
    if (from === 'stage' && stageOff !== null) return stageOff;
    return undefined;
  }

  function check(): string | null {
    const h = host.trim();
    const u = user.trim();
    if (mode === 'set' && !h) return t('ctx.err.host');
    if (h && [...h].length > 253) return t('ctx.err.tooLong');
    if (h && !HOST_RE.test(h)) return t('ctx.err.chars');
    if (u && !USER_RE.test(u)) return t('ctx.err.user');
    if (closed && (mode === 'push' || fromOffValue() === undefined)) return t('ctx.closedTerm');
    return null;
  }

  function buildOp(): ContextOp {
    const h = host.trim();
    const u = user.trim();
    if (mode === 'push') return { op: 'push', kind, host: h || null, ...(u ? { user: u } : {}) };
    const off = fromOffValue();
    if (sugg && h === sugg.label && !u && from === 'offset' && off === sugg.fromOff) return { op: 'accept', item_key: sugg.itemKey };
    return { op: 'set', host: h, ...(u ? { user: u } : {}), ...(off !== undefined ? { from_off: off } : {}) };
  }

  async function send(op: ContextOp): Promise<void> {
    if (busy || app.offline) return;
    busy = true;
    error = null;
    try {
      const res = await app.backend.setContext(terminalId, op);
      if (!res.stored) app.ui.notify('info', t('ctx.doneStack'), 4000);
      if (res.warnings.length > 0) {
        result = res;
      } else {
        app.ui.notify('info', t('ctx.done'), 2500);
        onclose();
      }
    } catch (e) {
      error = errorText(e, 'ctx.failed');
    } finally {
      busy = false;
    }
  }

  function submit(e: SubmitEvent): void {
    e.preventDefault();
    const err = check();
    if (err) {
      error = err;
      return;
    }
    void send(buildOp());
  }

  const fromLabel = $derived(offsetTs ? t('ctx.from.suggestion', { time: hhmm(offsetTs, { seconds: true }) }) : t('ctx.from.asSuggestion'));
</script>

<Dialog title={t('ctx.title', { term: termTitle })} {onclose} size="m">
  {#if result}
    <div class="warn" role="status">
      <strong>{t('ctx.warnTitle')}</strong>
      <ul>
        {#each result.warnings as w, i (i)}
          <li><code><Txt value={w.host} mono max={80} /></code> {t(`ctx.warn.${w.code}` as MessageKey)}</li>
        {/each}
      </ul>
    </div>
    <div class="buttons">
      <Button variant="primary" onclick={onclose}>{t('ctx.close')}</Button>
    </div>
  {:else}
    <form class="form" onsubmit={submit} novalidate>
      <div class="field">
        <label for="ctx-host">{t('ctx.host')}</label>
        <input
          id="ctx-host"
          class="mono"
          bind:value={host}
          placeholder={t('ctx.hostPlaceholder')}
          autocomplete="off"
          spellcheck="false"
          maxlength="253"
          data-autofocus
          aria-describedby="ctx-options"
        />
        {#if options.length > 0}
          <ul class="options" id="ctx-options" aria-label={t('ctx.options')}>
            {#each options as o (o.value)}
              <li>
                <button type="button" class="opt" class:chosen={o.value === host.trim()} onclick={() => (host = o.value)}>
                  <span class="mono"><Txt value={o.value} max={60} /></span>
                  <span class="note {o.tone}">{t(o.note)}</span>
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>
      <div class="grid">
        <div class="field">
          <label for="ctx-user">{t('ctx.user')}</label>
          <input id="ctx-user" bind:value={user} placeholder={t('ctx.userPlaceholder')} autocomplete="off" spellcheck="false" maxlength="64" />
        </div>
        <div class="field">
          <label for="ctx-from">{t('ctx.from')}</label>
          <select id="ctx-from" class="mono" bind:value={from} disabled={mode === 'push'}>
            {#if offset !== null}<option value="offset">{fromLabel}</option>{/if}
            {#if stageOff !== null}<option value="stage">{t('ctx.from.stage')}</option>{/if}
            <option value="now" disabled={closed}>{t('ctx.from.now')}</option>
          </select>
        </div>
      </div>
      <div class="grid">
        <div class="field">
          <label for="ctx-mode">{t('ctx.mode')}</label>
          <select id="ctx-mode" bind:value={mode}>
            <option value="set">{t('ctx.mode.set')}</option>
            <option value="push" disabled={closed}>{t('ctx.mode.push')}</option>
          </select>
        </div>
        {#if mode === 'push'}
          <div class="field">
            <label for="ctx-kind">{t('ctx.kind')}</label>
            <select id="ctx-kind" bind:value={kind}>
              {#each KINDS as k (k)}<option value={k}>{t(`ctx.kind.${k}` as MessageKey)}</option>{/each}
            </select>
          </div>
        {/if}
      </div>
      {#if closed}<p class="note attention">{t('ctx.closedTerm')}</p>{/if}
      {#if error}<p class="err" role="alert">{error}</p>{/if}
      <div class="buttons">
        {#if top && top.depth > 0 && !closed}
          <Button variant="ghost" disabled={busy || app.offline} reason={t('ctx.popHint')} onclick={() => void send({ op: 'pop' })}>{t('ctx.pop')}</Button>
        {/if}
        <span class="spacer"></span>
        <Button onclick={onclose}>{t('ctx.cancel')}</Button>
        <Button variant="primary" type="submit" disabled={busy || app.offline} reason={app.offline ? t('term.offline') : t('common.loading')}>{t('ctx.set')}</Button>
      </div>
      <p class="hint">{t('ctx.hint')} <code>F12 h</code></p>
    </form>
  {/if}
</Dialog>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }
  label {
    color: var(--muted);
    font-size: var(--fs-s);
  }
  input,
  select {
    padding: 9px 12px;
    border-radius: 7px;
    border: var(--lw-1) solid var(--line-strong);
    background: var(--bg);
    color: var(--fg);
    min-width: 0;
  }
  input:focus {
    border-color: var(--focus);
    outline: none;
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
  }
  .options {
    list-style: none;
    margin: 0;
    padding: 4px;
    border-radius: 7px;
    border: var(--lw-1) solid var(--line-strong);
    background: var(--bg);
    display: flex;
    flex-direction: column;
  }
  .opt {
    width: 100%;
    display: flex;
    justify-content: space-between;
    gap: var(--sp-3);
    padding: 6px 8px;
    border: none;
    border-radius: 5px;
    background: transparent;
    color: var(--fg);
    cursor: pointer;
    text-align: left;
  }
  .opt:hover,
  .opt.chosen {
    background: var(--surface-3);
  }
  .note {
    font-size: var(--fs-xs);
    flex: none;
  }
  .note.muted {
    color: var(--muted);
  }
  .note.attention,
  .attention {
    color: var(--attention);
  }
  .grid {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: var(--sp-3);
  }
  .buttons {
    display: flex;
    gap: var(--sp-2);
    justify-content: flex-end;
    align-items: center;
  }
  .spacer {
    flex: 1;
  }
  .hint {
    margin: 0;
    color: var(--faint);
    font-size: var(--fs-xs);
  }
  .hint code {
    font-family: var(--font-mono);
  }
  .err {
    margin: 0;
    color: var(--error);
    font-size: var(--fs-s);
  }
  p.note {
    margin: 0;
    font-size: var(--fs-s);
  }
  .warn {
    border: var(--lw-1) solid var(--attention);
    border-radius: var(--r-card);
    padding: var(--sp-3) var(--sp-4);
    margin-bottom: var(--sp-4);
  }
  .warn strong {
    color: var(--attention);
  }
  .warn ul {
    margin: 6px 0 0;
    padding-left: 18px;
  }
  code {
    font-family: var(--font-mono);
  }
</style>
