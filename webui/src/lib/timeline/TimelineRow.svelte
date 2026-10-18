<!--
  Eine Zeile der Zeitachse (Screen 6, Briefing 5.5, web-api.md 10 und 18.8): Zeit, Terminal,
  Ereignis, Ergebnis, Aktion. Typen: Befehl (mit Exit, Datei, Hinweisen, Scope-Warnung, Ergebnis,
  «Kontext unklar»), misstraut (durchgestrichen, «Wieder vertrauen»), Remote-Segment
  («rekonstruiert», «wird frühestens … ausgewertet»), Datei, Schlüsselschritt (Faden-Nummer),
  Kontext (auto, gesetzt, Stufe), Entscheid (auch «Rückgängig» mit Wirkung), Lücke (schraffiert),
  Projekt, Eingabe (verdeckt mit Aufdecken und «In die Kali»). Zieldaten nur über Txt.
  Rückgängig pro Befehl erscheint bei Hover, Fokus und auf der gewählten Zeile. Besitzer: ui-verlauf.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { TimelineItem } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import SecretValue from '../ui/SecretValue.svelte';
  import Txt from '../ui/Txt.svelte';
  import { displaySafe } from '../safe/displaySafe';
  import { encodeEvidence, url } from '../url/state.svelte';
  import { termShort } from '../util/format';
  import { hhmm, utcTooltip } from '../util/time';
  import { canUndo, resultText, shortCommand } from './model';

  let {
    app,
    project,
    item,
    selected = false,
    utc = false,
    now,
    onselect,
    onopen,
    onundo,
    below,
  }: {
    app: AppState;
    project: ProjectStore;
    item: TimelineItem;
    selected?: boolean;
    utc?: boolean;
    /** Serverzeit jetzt (ms), für «läuft noch» und «wird frühestens … ausgewertet» */
    now: number;
    onselect: () => void;
    onopen: () => void;
    onundo: () => void;
    /** Inhalt unter der Zeile (Rückgängig inline) */
    below?: Snippet<[TimelineItem]>;
  } = $props();
  const SEP = ' · ';
  const SP = ' ';

  const GAPS = new Set(['pause', 'no_project', 'daemon_down', 'project_switch', 'sensitive_output', 'locked', 'disk_low', 'shim_error', 'multiplexer', 'buffer_overflow', 'rec_off']);
  const KEYSTEPS = new Set(['foothold', 'privesc', 'pivot', 'loot']);

  const time = $derived(hhmm(item.ts, { seconds: true, utc }));
  const term = $derived(item.terminal ? termShort(item.terminal) : item.terminal_id ? termShort({ ordinal: null, terminal_id: item.terminal_id }) : '');
  const hasEvidence = $derived(item.type === 'command' || item.type === 'segment' || item.type === 'file' || item.type === 'callback');
  const distrusted = $derived(item.type === 'command' && item.distrusted !== null);
  const undoable = $derived(canUndo(item));

  /** offene Kontextklärung zum Terminal eines laufenden Befehls («Kontext unklar · K2») */
  const unclear = $derived.by(() => {
    if (item.type !== 'command' || item.cmd.ended_at !== null || !item.terminal_id) return null;
    // steht der Callback als eigene Zeile da (D15), trägt sie den Hinweis, nicht der Listener
    if (project.timeline.rows.some((r) => r.type === 'callback' && r.unit_id === item.unit_id)) return null;
    const it = project.next.clarifyItems.find((x) => (x.kind === 'ctx_suggestion' || x.kind === 'ctx_unknown') && x.terminal_id === item.terminal_id);
    return it ? { key: it.item_key, ordinal: project.next.ordinal(it.item_key) } : null;
  });

  /** offene Kontextklärung zum Terminal eines Callbacks («Kontext unklar · K2», Korrektur D15) */
  const cbUnclear = $derived.by(() => {
    if (item.type !== 'callback' || !item.terminal_id) return null;
    const it = project.next.clarifyItems.find((x) => (x.kind === 'ctx_suggestion' || x.kind === 'ctx_unknown') && x.terminal_id === item.terminal_id);
    return it ? { key: it.item_key, ordinal: project.next.ordinal(it.item_key) } : null;
  });

  const scope = $derived(app.status?.scope_warning ?? null);

  /** Unterzeile (Exit, Dateien, Hinweise) wie im Design nur, wenn sie etwas sagt: gewählt, läuft, Hinweise, Exit ungleich 0 */
  const subLine = $derived(
    item.type === 'command' &&
      (selected || item.cmd.ended_at === null || item.flags.length > 0 || (item.cmd.exit !== null && item.cmd.exit !== 0)),
  );

  /** Dateien des Befehls: die XML-Ausgabe zuerst (wie im Design «Datei scans/ms2.xml erkannt»), weitere als «+2» */
  const files = $derived(
    item.type === 'command' ? [...item.files].sort((a, b) => Number(!a.path.endsWith('.xml')) - Number(!b.path.endsWith('.xml'))) : [],
  );

  function openFile(unitId: string): void {
    url.set({ beleg: encodeEvidence({ kind: 'unit', unit_id: unitId, lines: null }) }, { push: true });
  }

  function fileOwner(cmdId: string | null): string | null {
    const c = project.timeline.findByCmd(cmdId);
    return c ? shortCommand(c.cmd.text, hhmm(c.ts, { utc })) : null;
  }

  function verdictText(v: string): string {
    if (v === 'excluded') return t('tl.scopeWarnExcluded');
    if (v === 'unknown') return t('tl.scopeWarnUnknown');
    if (v === 'outside_window') return t('tl.scopeWarnWindow');
    return t('tl.scopeWarnOut');
  }

  function decisionLabel(it: Extract<TimelineItem, { type: 'decision' }>): string {
    if (it.kind === 'd.status.access' && it.detail) return it.detail;
    // Korrektur K3: nie die Kennung des Entscheids («d.finding.update») zeigen
    if (it.summary === 'Entscheid' || !it.summary) return it.detail ?? t('tl.decisionOther');
    return it.detail ? `${it.summary} · ${it.detail}` : it.summary;
  }

  function gapText(it: Extract<TimelineItem, { type: 'gap' }>): string {
    const why = GAPS.has(it.reason) ? t(`tl.gap.${it.reason}` as MessageKey) : it.reason;
    const range = it.until ? t('tl.gap.range', { from: hhmm(it.ts, { utc }), until: hhmm(it.until, { utc }) }) : t('tl.gap.since', { from: hhmm(it.ts, { utc }) });
    return `${t('tl.gap')} ${why} ${range}`;
  }

  function sourceText(s: string): string {
    return t((['auto', 'hotkey', 'webui', 'cli', 'suggestion'].includes(s) ? `tl.source.${s}` : 'tl.source.auto') as MessageKey);
  }

  function noteMono(note: string): boolean {
    return /^[/~]/.test(note);
  }

  function click(e: MouseEvent): void {
    if (e.target instanceof Element && e.target.closest('button, a, input, form')) return;
    onselect();
  }

  function dbl(e: MouseEvent): void {
    if (e.target instanceof Element && e.target.closest('button, a, input, form')) return;
    if (hasEvidence) onopen();
  }
</script>

<!-- Zeile: Klick wählt, Doppelklick und ↵ öffnen den Beleg (Tastatur in TimelineView). -->
<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<li
  class="item t-{item.type}"
  class:sel={selected}
  class:distrusted
  tabindex={selected ? 0 : -1}
  data-row={item.id}
  aria-current={selected ? 'true' : undefined}
  onclick={click}
  ondblclick={dbl}
>
  <div class="row">
    <span class="time" title={utcTooltip(item.ts)}>{time}</span>
    <span class="term">{term}</span>

    <span class="event">
      {#if item.type === 'command'}
        <span class="stack">
          <span class="cmdtext" class:strike={distrusted}><Txt value={item.cmd.text ?? ''} mono max={160} ctrl={item.ctrl} /></span>
          {#if !distrusted}
            {#if subLine}
              <span class="sub">
                {#if item.cmd.ended_at === null}{t('tl.running')}{:else if item.cmd.exit !== null}{t('tl.exit', { code: item.cmd.exit })}{/if}{#if files[0]}{@const first = files[0]}{SEP}{t('tl.file')}
                  <button type="button" class="file" title={t('tl.fileEvidence')} onclick={() => openFile(first.unit_id)}><Txt value={first.path} mono max={60} /></button>
                  {t('tl.fileSeen')}{#if files.length > 1}<span class="muted" title={files.slice(1).map((f) => displaySafe(f.path, 120)).join('\n')}>{SP}{t('tl.filesMore', { n: files.length - 1 })}</span>{/if}{/if}{#each item.flags as fl (fl)}{SEP}<span class="flag">{t(`tl.flag.${fl}` as MessageKey)}</span>{/each}
                {#if selected}<button type="button" class="mini" onclick={onopen}>{t('tl.openEvidence')} <kbd>↵</kbd></button>{/if}
              </span>
            {/if}
          {/if}
          {#if item.scope_warning}
            <span class="scope">
              {t('tl.scopeWarn')}{#each item.scope_warning.targets as tg, i (i)}{i > 0 ? ',' : ''}{SP}<Txt value={tg.value} mono max={60} />{SP}{verdictText(tg.verdict)}{/each}{#if scope && scope.cmd_id === item.cmd.cmd_id}{SEP}{#if scope.acked}{t(
                    'tl.scopeAcked',
                  )}{:else}<button type="button" class="mini attention" disabled={app.offline} onclick={() => void app.ackScopeWarning()}>{t('tl.scopeAck')}</button>{/if}{/if}
            </span>
          {/if}
        </span>
      {:else if item.type === 'segment'}
        <span>{t('tl.segment')} <span class="muted">{t('tl.segmentMeta', { n: item.lines })}</span></span>
      {:else if item.type === 'file'}
        <span>{t('tl.file')} <Txt value={item.path} mono max={120} ctrl={item.ctrl} /></span>
      {:else if item.type === 'keystep'}
        <span class="with-icon">
          <span class="step" aria-hidden="true">{item.ordinal}</span>
          <span
            >{KEYSTEPS.has(item.step) ? t(`tl.keystep.${item.step}` as MessageKey) : item.step}{#if item.note}{#if noteMono(item.note)}{SP}<Txt
                  value={item.note}
                  mono
                  max={80}
                />{:else}{SEP}<Txt value={item.note} max={80} />{/if}{/if}</span
          >
        </span>
      {:else if item.type === 'context'}
        <span>
          {#if item.change === 'auto'}{t('tl.ctx.auto')}{:else if item.change === 'push'}{t('tl.ctx.push')}{:else if item.change === 'pop'}{t('tl.ctx.pop')}{:else}{t('tl.ctx.set')}{/if}
          {#if item.change !== 'pop' && item.host_label}
            <Txt value={item.host_label} mono max={100} ctrl={item.ctrl} />{#if item.user}<span class="muted">{SP}(<Txt value={item.user} max={40} />)</span>{/if}{#if item.source === 'auto'}<span class="faint">{SP}{t('tl.ctx.autoMark')}</span>{/if}
          {:else}
            <Txt value={item.stack_label} mono max={100} ctrl={item.ctrl} />
          {/if}
        </span>
      {:else if item.type === 'callback'}
        <span>{t('tl.callback')}{SP}<Txt value={item.remote ?? '?'} mono max={80} ctrl={item.ctrl} /></span>
      {:else if item.type === 'decision'}
        {#if item.kind === 'd.unit.distrust'}
          <span>
            {t('tl.decision.undo')} <span class="ref"><Txt value={item.ref ?? ''} mono max={40} /></span>{#if item.reason}{SEP}«<Txt value={item.reason} max={120} />»{/if}
          </span>
        {:else}
          <span class="with-icon">
            {#if item.kind === 'd.status.access'}<span class="acc" aria-hidden="true">#</span>{/if}
            <span>{t('tl.decision')} <Txt value={decisionLabel(item)} max={140} ctrl={item.ctrl} />{#if item.reason}{SEP}«<Txt value={item.reason} max={120} />»{/if}</span>
          </span>
        {/if}
      {:else if item.type === 'gap'}
        <span>{gapText(item)}</span>
      {:else if item.type === 'project'}
        <span>
          {#if item.change === 'start'}{t('tl.project.start', { slug: project.slug })}{:else if item.change === 'end'}{t('tl.project.end')}{#if item.reason}{SEP}<Txt value={item.reason} max={80} />{/if}{:else}{t('tl.project.preroll')}{/if}
        </span>
      {:else if item.type === 'input'}
        {#if item.input.hidden}
          <span class="with-icon input">
            <span>{t('tl.input.hidden')}</span>
            <SecretValue
              secret={{ ref: 'input', seq: item.input.seq }}
              pid={project.pid}
              backend={app.backend}
              presentation={app.presentation}
              profile={app.profile}
              hint={null}
            />
          </span>
        {:else}
          <span>{t('tl.input')} <Txt value={item.input.text} mono max={120} ctrl={item.ctrl} />{#if item.input.paste}{SEP}{t('tl.input.paste')}{/if}{#if item.input.redacted}{SEP}{t('tl.input.redacted')}{/if}</span>
        {/if}
      {/if}
    </span>

    <span class="result">
      {#if item.type === 'command'}
        {#if item.distrusted}
          <span class="dist"><span class="badge">{t('tl.distrusted')}</span>{t('tl.distrustedValues', { n: item.distrusted.rejected })}</span>
        {:else if unclear}
          <button type="button" class="unclear" onclick={() => url.go('karte', { sel: unclear.key, host: null })}>
            <span class="dot" aria-hidden="true"></span>{t('tl.res.ctxUnclear')}{#if unclear.ordinal}{SEP}{unclear.ordinal}{/if}
          </button>
        {:else}
          {resultText(item)}
        {/if}
      {:else if item.type === 'callback'}
        {#if cbUnclear}
          <button type="button" class="unclear" onclick={() => url.go('karte', { sel: cbUnclear.key, host: null })}>
            <span class="dot" aria-hidden="true"></span>{t('tl.res.ctxUnclear')}{#if cbUnclear.ordinal}{SEP}{cbUnclear.ordinal}{/if}
          </button>
        {:else}
          <span class="muted">{#if item.listener}<Txt value={item.listener} mono max={40} />{/if}{#if item.session}{SEP}{t('tl.ctx.session', { n: item.session })}{/if}</span>
        {/if}
      {:else if item.type === 'segment'}
        <span class="muted"
          >{#if item.state === 'final'}{t('tl.segment.final')}{:else if item.evaluate_after}{t('tl.segment.evaluateAfter', {
              time: hhmm(item.evaluate_after, { seconds: true, utc }),
            })}{:else if item.state === 'provisional'}{t('tl.segment.provisional')}{:else}{t('tl.segment.open')}{/if}</span
        >
      {:else if item.type === 'file'}
        {@const by = fileOwner(item.cmd_id)}
        <span class="muted">{#if by}{t('tl.fileOf', { cmd: by })}{/if}</span>
      {:else if item.type === 'keystep'}
        <span class="muted">{t('tl.keystep')}</span>
      {:else if item.type === 'context'}
        <span class="muted"
          >{#if item.stage_kind && item.stage_kind !== 'local' && item.change !== 'pop'}{t(`next.stage.${item.stage_kind}` as MessageKey)}{#if item.session}{SP}{t('tl.ctx.session', { n: item.session })}{/if}{SEP}{/if}{sourceText(item.source)}</span
        >
      {:else if item.type === 'decision'}
        {#if item.kind === 'd.unit.distrust' && item.effect}
          {t('tl.decision.effect', { rejected: item.effect.rejected, weakened: item.effect.weakened })}
        {:else}
          <span class="muted">{t('tl.decision.byYou')}</span>
        {/if}
      {:else if item.type === 'gap'}
        {#if item.reason === 'pause' && item.until && Date.parse(item.until) > now}
          <span class="muted">{t('tl.gap.running')} <code>F12 r</code></span>
        {:else if item.bytes_lost > 0}
          <span class="muted">{t('tl.gap.lost', { n: item.bytes_lost })}</span>
        {/if}
      {:else if item.type === 'project'}
        <span class="muted">{#if item.detail}<Txt value={item.detail} max={80} />{/if}</span>
      {:else if item.type === 'input'}
        <span class="muted">{#if item.input.reason}{t(`tl.input.reason.${item.input.reason}` as MessageKey)}{/if}</span>
      {/if}
    </span>

    <span class="action">
      {#if item.type === 'command' && item.distrusted}
        <button type="button" class="link" disabled={app.offline} aria-label={t('tl.trustAgainFor', { ref: item.cmd.cmd_ref })} onclick={() => {
          if (item.type === 'command' && item.distrusted) void project.timeline.trustAgain(item, item.distrusted.decision_id);
        }}>{t('tl.trustAgain')}</button>
      {:else if undoable}
        <button type="button" class="undo" disabled={app.offline} aria-label={t('tl.undoFor', { ref: item.type === 'command' ? item.cmd.cmd_ref : '' })} onclick={onundo}
          >{t('tl.undo')} <kbd>u</kbd></button
        >
      {/if}
    </span>
  </div>
  {#if below}<div class="below">{@render below(item)}</div>{/if}
</li>

<style>
  .item {
    list-style: none;
    border-radius: 8px;
    outline: none;
    margin: 2px 0;
  }
  .row {
    display: grid;
    grid-template-columns: 76px 34px minmax(0, 1fr) minmax(0, 300px) 110px;
    gap: 14px;
    align-items: center;
    padding: var(--row-pad-y, 9px) 12px;
    border-radius: 8px;
    min-height: var(--row-h);
  }
  .item.sel .row,
  .item:focus-visible .row {
    background: var(--surface-2);
    box-shadow: 0 0 0 var(--lw-focus) var(--focus);
  }
  .item:hover:not(.sel) .row {
    background: var(--rec-bg);
  }
  .t-gap .row {
    background: repeating-linear-gradient(135deg, var(--rec-bg) 0 6px, var(--map) 6px 12px);
    color: var(--muted);
  }
  .t-gap .event {
    color: var(--fg);
  }
  .time,
  .term {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--muted);
    white-space: nowrap;
  }
  .event {
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .cmdtext {
    font-size: var(--fs-s);
  }
  .strike :global(.txt) {
    text-decoration: line-through;
    text-decoration-color: var(--faint);
  }
  .distrusted .row {
    color: var(--faint);
  }
  .sub {
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .flag {
    color: var(--attention);
  }
  .scope {
    color: var(--attention);
    font-size: var(--fs-xs);
  }
  .with-icon {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .step {
    width: 19px;
    height: 19px;
    border-radius: 50%;
    background: var(--thread);
    color: var(--bg);
    font-size: 11px;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
  }
  .acc {
    width: 19px;
    height: 19px;
    border-radius: 5px;
    background: var(--access-root);
    color: var(--bg);
    font-size: var(--fs-xs);
    font-weight: 700;
    font-family: var(--font-mono);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
  }
  .ref {
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .result {
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .muted {
    color: var(--muted);
  }
  .faint {
    color: var(--faint);
  }
  .dist {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .badge {
    padding: 1px 6px;
    border-radius: var(--r-badge);
    border: var(--lw-1) solid var(--faint);
    font-size: 11.5px;
    color: var(--muted);
  }
  .unclear {
    display: inline-flex;
    gap: 6px;
    align-items: center;
    border: none;
    background: none;
    padding: 0;
    color: var(--attention);
    cursor: pointer;
    text-align: left;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--attention);
  }
  .action {
    display: flex;
    justify-content: flex-end;
    text-align: right;
  }
  .undo {
    padding: 5px 9px;
    border-radius: 5px;
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    font-size: var(--fs-xs);
    line-height: 1;
    cursor: pointer;
    opacity: 0;
    white-space: nowrap;
  }
  .item:hover .undo,
  .item:focus-within .undo,
  .item.sel .undo {
    opacity: 1;
  }
  .undo:disabled {
    cursor: not-allowed;
  }
  .undo kbd,
  .mini kbd {
    font-family: var(--font-mono);
    color: var(--muted);
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    cursor: pointer;
    text-align: right;
  }
  .link:hover:not(:disabled) {
    color: var(--fg);
    text-decoration: underline;
  }
  .mini {
    border: none;
    background: none;
    padding: 0 0 0 6px;
    color: var(--muted);
    font-size: var(--fs-xs);
    cursor: pointer;
    text-decoration: underline dotted;
    text-underline-offset: 3px;
  }
  .mini.attention {
    color: var(--attention);
  }
  .file {
    border: none;
    background: none;
    padding: 0;
    color: inherit;
    font: inherit;
    cursor: pointer;
  }
  .file:hover,
  .file:focus-visible {
    color: var(--fg);
    text-decoration: underline dotted;
    text-underline-offset: 3px;
  }
  code {
    font-family: var(--font-mono);
  }
  .below {
    padding: 6px 12px 10px 150px;
  }
</style>
