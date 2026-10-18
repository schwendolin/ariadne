<!--
  Belegansicht als Tafel von rechts (Screen 7, Briefing 5.6, web-api.md 11 und 18.8): Kopf
  «Beleg · T2 msf · 16:45:12», Raster Wert (bei Belegen eines Werts), Befehl, Kontext, Zeit auf ms,
  Quelle (Terminal, Quell-IP, Exit, Dauer), Auswertung, Hinweise, Hash-Kette; Quellen eines Werts
  zum Umschalten (Terminal, Datei mit SHA-256, Entscheid); Log mit Zeilennummern als virtuelle
  Liste mit markiertem Bereich und «N Zeilen davor ausgeblendet · zeigen», verdeckte Teile auf
  Wunsch. Knöpfe Als Finding, Zu Finding hinzufügen, Als Beleg kopieren · Mac, Ganzes Log.
  Varianten: Datei, Präsentationsmodus (Kennzeichen, kopiert maskiert, nichts aufdecken), Hash-Kette
  verletzt (Meldung nicht wegklickbar, Kopieren und Finding gesperrt), Beleg nicht mehr vorhanden,
  Log nicht verfügbar. Esc schliesst, der Fokus geht zurück zum Auslöser (Panel). Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import type { FindingSummary } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import Breadcrumb from '../ui/Breadcrumb.svelte';
  import Button from '../ui/Button.svelte';
  import Panel from '../ui/Panel.svelte';
  import Popover from '../ui/Popover.svelte';
  import SecretValue from '../ui/SecretValue.svelte';
  import Txt from '../ui/Txt.svelte';
  import { url, type EvidenceTarget } from '../url/state.svelte';
  import { copyText } from '../util/clipboard';
  import { errorCode, errorText } from '../util/errors';
  import { termName } from '../util/format';
  import { duration, exactTime, hhmm } from '../util/time';
  import { shortCommand } from '../timeline/model';
  import LogView from './LogView.svelte';
  import { evidenceLabel, evidenceMarkdown, logFileName, refFor, stackText } from './text';

  let { app, project, target }: { app: AppState; project: ProjectStore; target: EvidenceTarget } = $props();
  const SEP = ' · ';

  const ev = $derived(project.evidence);
  const unit = $derived(ev.unit);
  const source = $derived(ev.source);
  const fact = $derived(ev.sources?.fact ?? null);
  const marked = $derived(ev.marked);
  const utc = $derived(url.get('utc') === '1');
  const broken = $derived(unit?.chain_ok === false);
  const missing = $derived(ev.error !== null && errorCode(ev.error) === 'not_found');
  const isFile = $derived(unit?.kind === 'file' || source?.t === 'file');
  const canReveal = $derived(app.profile === 'lab' && !app.presentation);
  const POP = 'ev-add-finding';

  // nur vom Ziel abhängig: open() liest den Zustand des Stores, der sich beim Laden ändert
  $effect(() => {
    const tg = target;
    untrack(() => void project.evidence.open(tg));
  });

  onDestroy(() => {
    project.evidence.close();
  });

  function close(): void {
    url.set({ beleg: null });
  }

  const realSources = $derived((ev.sources?.sources ?? []).map((s, i) => ({ s, i })));

  const headText = $derived.by(() => {
    if (source?.t === 'user') return `${t('ev.title')} · ${t('ev.sourceUser')}`;
    if (!unit) return t('ev.title');
    if (unit.kind === 'file') return `${t('ev.titleFile')} · ${unit.title}`;
    const parts = [t('ev.title')];
    if (unit.terminal) parts.push(termName(unit.terminal));
    parts.push(hhmm(unit.ts ?? unit.started_at, { seconds: true, utc }));
    return parts.join(' · ');
  });

  const producedBy = $derived.by(() => {
    const cmdId = source?.t === 'file' ? source.produced_by_cmd : unit?.kind === 'file' ? unit.cmd_id : null;
    if (!cmdId) return null;
    const c = project.timeline.findByCmd(cmdId);
    if (!c) return unit?.cmd_ref ?? cmdId;
    const term = c.terminal ? termName({ ...c.terminal, label: null }) : '';
    return `${shortCommand(c.cmd.text, hhmm(c.ts, { utc }))}${term ? ` · ${term}` : ''}`;
  });

  const sha = $derived(source?.t === 'file' ? source.sha256 : unit?.kind === 'file' ? (unit.sha256 ?? null) : null);
  const runText = $derived.by(() => {
    if (!unit) return '';
    const parts: string[] = [];
    const running = unit.kind === 'segment' ? unit.state !== undefined && unit.state !== 'final' : unit.ended_at === null;
    if (running && unit.kind !== 'file') parts.push(t('ev.running'));
    else if (unit.exit !== null) parts.push(t('ev.exit', { code: unit.exit }));
    if (unit.duration_ms !== null && unit.duration_ms >= 1000) parts.push(t('ev.duration', { d: duration(unit.duration_ms) }));
    return parts.join(SEP);
  });
  const flags = $derived([...new Set([...(unit?.flags ?? []), ...(unit?.kind === 'segment' ? ['remote_reconstructed'] : []), ...(source?.t === 'stream' ? source.flags : []), ...(source?.t === 'stream' && source.distrusted ? ['distrusted'] : [])])]);

  function flagText(f: string): string {
    const key = `ev.flag.${f}`;
    return ['truncated', 'partial', 'remote_reconstructed', 'distrusted', 'gap', 'altscreen', 'marker_forged'].includes(f) ? t(key as MessageKey) : f;
  }

  // ------------------------------------------------------------------ Aktionen
  const ref = $derived(refFor(target, target.kind === 'unit' ? marked : null));
  const label = $derived(evidenceLabel(unit, marked, fact && !fact.is_secret ? fact.value : null));
  const findings = $derived(project.findings.list);
  let addError = $state<string | null>(null);
  let copyState = $state<'idle' | 'done' | 'manual' | 'error'>('idle');
  let manualText = $state('');
  let manualEl: HTMLTextAreaElement | undefined = $state();
  let busy = $state(false);

  function asFinding(): void {
    if (broken) return;
    project.findings.startFromEvidence(ref, label);
  }

  async function addTo(f: FindingSummary): Promise<void> {
    addError = null;
    busy = true;
    const err = await project.findings.addEvidence(f.finding_id, ref);
    busy = false;
    if (err) {
      addError = err;
      return;
    }
    app.ui.closePopover(POP);
    app.ui.notify('info', t('ev.added', { ordinal: `F${f.ordinal}` }), 3000);
  }

  /** Zeilen für «Als Beleg kopieren»: markierter Bereich, sonst die ersten 40 Zeilen */
  function copyRange(): [number, number] | null {
    if (ev.total <= 0) return null;
    if (marked) return [marked[0], Math.min(marked[1], ev.total - 1, marked[0] + 199)];
    return [0, Math.min(ev.total - 1, 39)];
  }

  async function copyEvidence(): Promise<void> {
    if (broken || !unit) return;
    const range = copyRange();
    const lines = [];
    if (range) {
      const ok = await ev.ensureRange(range[0], range[1]);
      if (!ok) {
        copyState = 'error';
        return;
      }
      for (let n = range[0]; n <= range[1]; n++) {
        const l = ev.line(n);
        if (l) lines.push(l);
      }
    }
    const text = evidenceMarkdown({
      head: label,
      time: exactTime(unit.ts ?? unit.started_at, utc),
      context: unit.kind === 'file' ? null : stackText(unit.context),
      chainOk: unit.chain_ok,
      lines,
    });
    const ok = await copyText(text);
    if (ok) {
      copyState = 'done';
      setTimeout(() => (copyState = 'idle'), 2500);
    } else {
      manualText = text;
      copyState = 'manual';
      queueMicrotask(() => manualEl?.select());
    }
  }

  async function fullLog(): Promise<void> {
    const unitId = ev.unitId;
    if (!unitId) return;
    try {
      const blob = await ev.fullLog();
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = logFileName(unitId);
      a.rel = 'noopener';
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(href), 2000);
    } catch (e) {
      app.ui.notify('error', errorText(e, 'ev.fullLogFailed'));
    }
  }
</script>

<Panel title={t('ev.title')} onclose={close}>
  {#snippet header()}
    <div class="head">
      <h2><Txt value={headText} max={140} flag={false} /></h2>
      {#if app.presentation}<Badge tone="solid">{t('ev.presentation')}</Badge>{/if}
    </div>
  {/snippet}

  <div class="wrap">
    {#if broken}
      <div class="chain" role="alert">
        <div class="chain-title"><span class="bang" aria-hidden="true">!</span>{t('ev.chainBroken')}</div>
        <p>
          {#if unit?.chain_break_line !== null && unit?.chain_break_line !== undefined}
            {t('ev.chainBrokenText', { n: unit.chain_break_line + 1 })}
          {:else}
            {t('ev.chainBrokenTextNoLine')}
          {/if}
        </p>
        <p class="small">{t('ev.chainBrokenLocked')}</p>
      </div>
    {/if}

    {#if missing}
      <div class="missing" role="alert">
        <strong>{t('ev.missing')}</strong>
        <p>{t('ev.missingHint')}</p>
      </div>
    {:else if ev.error}
      <div class="missing" role="alert"><strong>{errorText(ev.error, 'ev.logFailed')}</strong></div>
    {:else if !unit && !fact && ev.loading}
      <p class="muted">{t('ev.loading')}</p>
    {/if}

    {#if !missing && (unit || fact)}
      <dl class="meta">
        {#if fact}
          <dt>{t('ev.k.value')}</dt>
          <dd>
            <Txt value={fact.subject_label} mono max={80} /> · <span class="muted">{fact.predicate}</span> =
            {#if fact.is_secret}
              <SecretValue secret={{ ref: 'claim', claim_key: fact.claim_key }} pid={project.pid} backend={app.backend} presentation={app.presentation} profile={app.profile} />
            {:else}
              <Txt value={fact.value} mono max={200} ctrl={fact.ctrl} />
            {/if}
          </dd>
        {/if}
        {#if realSources.length > 1}
          <dt>{t('ev.sources')}</dt>
          <dd><div class="sources" role="radiogroup" aria-label={t('ev.sources')}>
            {#each realSources as { s, i } (i)}
              <button type="button" role="radio" aria-checked={i === ev.sourceIndex} class:on={i === ev.sourceIndex} onclick={() => void ev.selectSource(i)}>
                {#if s.t === 'file'}{t('ev.sourceFile')} <Txt value={s.path} mono max={40} />{:else if s.t === 'user'}{t('ev.sourceUser')}{:else}{t('ev.sourceN', { n: i + 1 })}{#if s.cmd}{SEP}<Txt value={shortCommand(s.cmd.text, hhmm(s.cmd.started_at, { utc }))} max={40} />{/if}{/if}
              </button>
            {/each}
          </div></dd>
        {/if}
        {#if source?.t === 'user'}
          <dt>{t('ev.k.decision')}</dt>
          <dd>{t('ev.userDecision', { kind: source.kind, time: hhmm(source.ts, { seconds: true, utc }) })}</dd>
        {/if}
        {#if unit}
          {#if isFile}
            <dt>{t('ev.k.path')}</dt>
            <dd><Txt value={source?.t === 'file' ? source.path : unit.title} mono max={160} ctrl={unit.ctrl} /></dd>
            {#if sha}
              <dt>{t('ev.k.sha')}</dt>
              <dd class="sha" title={sha}>{sha.slice(0, 8)}…{sha.slice(-8)}</dd>
            {/if}
            {#if producedBy}
              <dt>{t('ev.k.producedBy')}</dt>
              <dd><Txt value={producedBy} max={80} /></dd>
            {/if}
          {:else}
            <dt>{t('ev.k.command')}</dt>
            <dd><Txt value={unit.title} mono max={400} ctrl={unit.ctrl} /></dd>
            <dt>{t('ev.k.context')}</dt>
            <dd><Breadcrumb stack={unit.context} /></dd>
          {/if}
          <dt>{t('ev.k.time')}</dt>
          <dd class="mono">{exactTime(unit.ts ?? unit.started_at, utc)}</dd>
          {#if !isFile}
            <dt>{t('ev.k.source')}</dt>
            <dd>
              {#if unit.tty}<span class="mono">{unit.tty.replace(/^\/dev\//, '')}</span>{:else if unit.terminal}<Txt value={termName(unit.terminal)} max={40} />{/if}{#if unit.src_ip}{#if unit.tty || unit.terminal}{SEP}{/if}{t('ev.srcIp')}
                <Txt value={unit.src_ip} mono max={45} />{/if}{#if runText}{#if unit.tty || unit.terminal || unit.src_ip}{SEP}{/if}{runText}{/if}
            </dd>
          {/if}
          {#if source && source.t !== 'user'}
            <dt>{t('ev.k.parser')}</dt>
            <dd>
              <code>{source.parser}</code>{#if source.t === 'stream'}{SEP}{t(`ev.confidence.${source.confidence}` as MessageKey)}{/if}
            </dd>
          {/if}
          {#if flags.length > 0}
            <dt>{t('ev.k.notes')}</dt>
            <dd class="flags">{flags.map(flagText).join(' · ')}</dd>
          {/if}
          <dt>{t('ev.k.chain')}</dt>
          <dd class:bad={broken}>
            {#if !broken}{t('ev.chainOk')}{:else if unit.chain_break_line !== null}{t('ev.chainBad', { n: unit.chain_break_line + 1 })}{:else}{t('ev.chainBadNoLine')}{/if}
          </dd>
        {/if}
      </dl>
    {/if}

    {#if unit && !missing}
      <LogView store={ev} {marked} chainBreak={broken ? unit.chain_break_line : null} {canReveal} />
      {#if app.presentation}<p class="note">{t('ev.presentationNote')}</p>{/if}
      {#if copyState === 'manual'}
        <textarea class="manual" readonly rows="4" bind:this={manualEl}>{manualText}</textarea>
      {/if}
    {/if}
  </div>

  {#snippet footer()}
    <div class="foot">
      <Button variant="primary" disabled={broken || !unit || app.offline} reason={broken ? t('ev.chainBrokenLocked') : t('ev.loading')} onclick={asFinding}>{t('ev.asFinding')}</Button>
      <span class="pop">
        <Button
          disabled={broken || !unit || app.offline}
          reason={broken ? t('ev.chainBrokenLocked') : t('ev.loading')}
          onclick={() => {
            addError = null;
            app.ui.togglePopover(POP);
          }}>{t('ev.addToFinding')}</Button
        >
        <Popover open={app.ui.popover === POP} onclose={() => app.ui.closePopover(POP)} label={t('ev.addToFinding')} placement="above">
          <div class="menu">
            {#each findings as f (f.finding_id)}
              <button type="button" class="opt" disabled={busy} onclick={() => void addTo(f)}>
                <span class="mono">F{f.ordinal}</span>
                <Txt value={f.title} max={60} ctrl={f.ctrl} />
              </button>
            {/each}
            {#if findings.length === 0}<span class="none">{t('ev.addNone')}</span>{/if}
            {#if addError}<span class="err" role="alert">{addError}</span>{/if}
          </div>
        </Popover>
      </span>
      <Button disabled={broken || !unit} reason={broken ? t('ev.chainBrokenLocked') : t('ev.loading')} onclick={() => void copyEvidence()}>{t('ev.copy')}</Button>
      <span class="copied" role="status" aria-live="polite"
        >{copyState === 'done' ? t('copy.done.mac') : copyState === 'error' ? t('ev.logFailed') : copyState === 'manual' ? t('copy.failed') : ''}</span
      >
      <span class="spacer"></span>
      <Button disabled={!ev.unitId} reason={t('ev.loading')} onclick={() => void fullLog()}>{t('ev.fullLog')}</Button>
    </div>
  {/snippet}
</Panel>

<style>
  .head {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    min-width: 0;
  }
  .head h2 {
    margin: 0;
    font-size: var(--fs-l);
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .wrap {
    height: 100%;
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
    min-height: 0;
  }
  .meta {
    display: grid;
    grid-template-columns: 110px minmax(0, 1fr);
    gap: 7px 14px;
    margin: 0;
    font-size: 13px;
    flex: none;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .mono,
  code,
  .sha {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
  }
  .sha {
    font-size: 11.5px;
    color: var(--fg-2);
  }
  .muted {
    color: var(--muted);
  }
  .flags {
    color: var(--attention);
  }
  .bad {
    color: var(--error);
  }
  .sources {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .sources button {
    padding: 3px 9px;
    border-radius: var(--r-pill);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    font-size: var(--fs-s);
    cursor: pointer;
  }
  .sources button.on {
    background: var(--fg);
    color: var(--bg);
    border-color: var(--fg);
  }
  .chain {
    border-radius: var(--r-card);
    border: var(--lw-focus) solid var(--error);
    padding: var(--sp-4);
    display: flex;
    flex-direction: column;
    gap: 10px;
    flex: none;
  }
  .chain p {
    margin: 0;
    color: var(--fg-2);
    line-height: 1.5;
  }
  .chain .small {
    color: var(--faint);
    font-size: var(--fs-xs);
  }
  .chain-title {
    display: flex;
    gap: 10px;
    align-items: center;
    color: var(--error);
    font-weight: 600;
  }
  .bang {
    width: 20px;
    height: 20px;
    border-radius: 50%;
    border: 2px solid var(--error);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: var(--fs-xs);
  }
  .missing {
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--line);
    padding: var(--sp-4);
  }
  .missing p {
    margin: 6px 0 0;
    color: var(--muted);
  }
  .note {
    margin: 0;
    color: var(--faint);
    font-size: var(--fs-xs);
    flex: none;
  }
  .manual {
    width: 100%;
    font-family: var(--font-mono);
    font-size: var(--fs-s);
    background: var(--log-bg);
    border: var(--lw-1) solid var(--focus);
    border-radius: var(--r-badge);
    color: var(--fg);
    resize: vertical;
    flex: none;
  }
  .foot {
    display: flex;
    gap: var(--sp-2);
    flex-wrap: wrap;
    align-items: center;
    width: 100%;
  }
  .pop {
    position: relative;
  }
  .menu {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 4px;
    max-height: 40vh;
    overflow: auto;
  }
  .opt {
    display: flex;
    gap: var(--sp-2);
    align-items: baseline;
    padding: 7px 9px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--fg);
    text-align: left;
    cursor: pointer;
  }
  .opt:hover:not(:disabled) {
    background: var(--surface-3);
  }
  .none {
    color: var(--muted);
    padding: 7px 9px;
  }
  .err {
    color: var(--error);
    font-size: var(--fs-xs);
    padding: 4px 9px;
  }
  .copied {
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .copied:empty {
    display: none;
  }
  .spacer {
    flex: 1;
  }
</style>
