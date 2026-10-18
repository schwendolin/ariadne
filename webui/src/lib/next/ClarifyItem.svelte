<!--
  Ein Eintrag «Klären» (Briefing 5.2, SCREENS 1a und 4, web-api.md 9 und 18.8), einzeilig oder
  aufgeklappt, mit den Aktionen jeder Art:
  - ctx_suggestion (K2): Vorschlag, Grund, «Wirkt rückwirkend ab», Logauszug «Darum mehrdeutig»;
    Übernehmen `a`, Anderer Host … `e` (Kontext-Dialog von ui-verlauf), Beleg `↵`.
  - ctx_unknown: Terminal, Stufe, Befehle, Kandidat; Host setzen … `e`, Beleg.
  - merge_suggestion (K3): zwei Kacheln (im Scope, ausserhalb), gemeinsame Kennung; Zusammenführen
    `a`, Getrennt lassen `x`.
  - decide_value: Wert mit Grund und Kennzeichen; Annehmen `a`, Verwerfen `x`, Ändern `e`, Beleg.
  - conflict: Werte mit Quellen; einen Wert wählen oder bewusst offen lassen (nie verwerfen).
  - orphan_decision: Widerrufen. mass_find: in der Zeitachse einzeln entscheiden.
  - scope_name (E130): «<Name> gehört laut nmap zu <IP>. In den Scope aufnehmen?», Wahl nur
    Name oder Domain-Wildcard, Warnhinweis bei öffentlicher Endung; «Aufnehmen …» öffnet den
    Bestätigungsdialog (E129) mit dem gewählten Eintrag, «Verwerfen» `x`. Nie automatisch.
  Zieldaten nur über Txt. Besitzer: ui-karte, E130: ui.
-->
<script lang="ts">
  import { DOT, SP } from '../karte/sep';
  import { untrack } from 'svelte';
  import type { CtxExcerpt, NextItem, StageKind } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import { itemEvidence, itemLine, scopeChoices } from '../stores/next.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import Button from '../ui/Button.svelte';
  import TextField from '../ui/TextField.svelte';
  import Txt from '../ui/Txt.svelte';
  import { url } from '../url/state.svelte';
  import { termShort } from '../util/format';
  import { pulse } from '../util/motion';
  import { hhmm } from '../util/time';
  import Parts from './Parts.svelte';

  let {
    app,
    project,
    item,
    selected,
    short = (s: string) => s,
  }: { app: AppState; project: ProjectStore; item: NextItem; selected: boolean; short?: (s: string) => string } = $props();

  const next = $derived(project.next);
  const busy = $derived(next.isBusy(item.item_key));
  const offline = $derived(app.offline);
  const blockReason = $derived(busy ? t('next.loading') : offline ? t('err.network') : null);
  const line = $derived(itemLine(item, short));
  const evidence = $derived(itemEvidence(item));
  let editing = $state(false);
  let editValue = $state('');
  let editError = $state<string | null>(null);

  function stageName(k: StageKind | null): string {
    return k ? t(`next.stage.${k}` as MessageKey) : '';
  }

  function termTitle(tr: { ordinal: number | null; label: string | null; terminal_id?: string } | null, tid: string | null): string {
    const base = termShort(tr ?? (tid ? { ordinal: null, terminal_id: tid } : null));
    return tr?.label ? `${base} «${tr.label}»` : base;
  }

  /** Kopf des Logauszugs (18.8): «Darum mehrdeutig: zweiter Callback im Output, 16:53:02». */
  function excerptNote(ex: CtxExcerpt): string {
    const time = ex.ts ? hhmm(ex.ts, { seconds: true }) : null;
    if (ex.note === 'second_callback') return t('next.ambiguous', { note: time ? t('next.ex.second', { time }) : t('next.ex.secondPlain') });
    if (ex.note === 'callback') return time ? t('next.ex.callback', { time }) : t('next.ex.callbackPlain');
    return t('next.ambiguousPlain');
  }

  function verdictText(v: string | null): string {
    return v === 'in' ? t('next.inScope') : v === null || v === 'unknown' ? t('next.verdictUnknown') : t('next.outScope');
  }

  function sharedLabel(shared: string): { kind: string; value: string } {
    const ident = item.kind === 'merge_suggestion' ? item.identifiers.find((i) => i.key === shared) : undefined;
    const value = ident?.label || shared.replace(/^[a-z]+:/, '');
    const mac = shared.startsWith('mac:') || /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(shared);
    return { kind: mac ? t('next.sharedMac') : t('next.sharedId'), value };
  }

  function startEdit(): void {
    if (item.kind !== 'decide_value') return;
    editValue = item.fact.is_secret ? '' : item.fact.value;
    editError = null;
    editing = true;
  }

  async function saveEdit(): Promise<void> {
    if (item.kind !== 'decide_value') return;
    if (!editValue.trim()) {
      editError = t('next.edit.empty');
      return;
    }
    if (await next.decideValue(item, 'edit', editValue)) editing = false;
  }

  function openEvidence(): void {
    next.openEvidence({ type: 'clarify', key: item.item_key, index: 0, item });
  }

  // `e` aus der Tastatur der Spalte (NextStore.requestEdit)
  let lastEdit = untrack(() => project.next.editToken);
  $effect(() => {
    const tok = next.editToken;
    if (tok === lastEdit) return;
    lastEdit = tok;
    if (selected) startEdit();
  });

  // Aktionen: Prüfung der Art im Rumpf (Typen bleiben eng)
  function accept(): void {
    if (item.kind === 'ctx_suggestion') void next.acceptContext(item);
  }
  function mergeIt(together: boolean): void {
    if (item.kind === 'merge_suggestion') void next.merge(item, together);
  }
  function value(action: 'confirm' | 'reject'): void {
    if (item.kind === 'decide_value') void next.decideValue(item, action);
  }
  function resolve(choice: string | null): void {
    if (item.kind === 'conflict') void next.resolveConflict(item, choice);
  }
  function revoke(): void {
    if (item.kind === 'orphan_decision') void next.revokeOrphan(item);
  }
  // E130: gewählter Vorschlag (Name oder Wildcard), Standard der erste (genauer Name)
  let scopeChoice = $state<string | null>(null);
  const scopeOpts = $derived(item.kind === 'scope_name' ? scopeChoices(item) : []);
  const scopeSel = $derived(scopeOpts.find((o) => o.entry === scopeChoice) ?? scopeOpts[0] ?? null);
  const scopeEditable = $derived(project.scope.editable && (item.kind !== 'scope_name' || item.change_allowed !== false));
  // Ausserhalb der Lab-Allowlist ohne «kein Kundenauftrag»: nur im Terminal (web-api.md 20.5)
  const scopeNeedsNc = $derived(!!scopeSel?.outside_lab && app.profile === 'lab' && project.scope.view?.not_customer !== true);
  function scopeAdd(): void {
    if (item.kind === 'scope_name') next.openScopeAdd(item, scopeSel?.entry ?? null);
  }
  function scopeDismiss(): void {
    if (item.kind === 'scope_name') void next.scopeDismiss(item);
  }
  function massGo(): void {
    if (item.kind === 'mass_find') url.go('zeitachse', { zeile: item.unit.cmd_id ?? item.unit.unit_id });
  }

  // Korrektur A13: Beim Aufklappen ersetzt die Karte den Knopf der Zeile; der Fokus geht auf die
  // Karte statt auf body.
  let card: HTMLDivElement | undefined = $state();
  let focusCard = false;

  function openLine(): void {
    focusCard = true;
    next.select(item.item_key);
  }

  $effect(() => {
    if (selected && card && focusCard) {
      focusCard = false;
      card.focus({ preventScroll: true });
    }
  });
</script>

{#if !selected}
  <button
    type="button"
    class="line"
    data-item-key={item.item_key}
    use:pulse={{ token: app.ui.pulseToken, active: app.ui.isPulsing(item.item_key) }}
    onclick={openLine}
  >
    <span class="dot" aria-hidden="true"></span>
    <span class="kind">{line.kind}</span>
    {#if line.parts.length}<span class="parts"><Parts parts={line.parts} max={60} /></span>{/if}
  </button>
{:else}
  <div class="card" data-item-key={item.item_key} aria-current="true" aria-busy={busy} tabindex="-1" bind:this={card}>
    <div class="head"><span class="dot" aria-hidden="true"></span>{t(`next.kind.${item.kind}` as MessageKey)}</div>

    {#if item.kind === 'ctx_suggestion'}
      <h3 class="title">{termTitle(item.terminal, item.terminal_id)}{#if item.stage_kind}{DOT}{stageName(item.stage_kind)}{/if}</h3>
      <div class="grid">
        <span class="k">{t('next.f.suggestion')}</span><span class="mono"><Txt value={item.suggested_label} mono max={80} /></span>
        <span class="k">{t('next.f.reason')}</span><span><Txt value={item.reason} ctrl={item.ctrl ?? false} max={240} />{#if item.reason_ts}{SP}{t('next.reasonAt', { time: hhmm(item.reason_ts, { seconds: true }) })}{/if}</span>
        {#if item.from_ts}<span class="k">{t('next.f.effect')}</span><span>{t('next.retroFrom', { time: hhmm(item.from_ts, { seconds: true }) })}</span>{/if}
      </div>
      {#if item.excerpt}
        <div class="excerpt">
          <span class="ex-note">{excerptNote(item.excerpt)}</span>
          {#each item.excerpt.text as l, i (i)}<span class="ex-line"><Txt value={l} mono ctrl={item.excerpt.ctrl} max={240} /></span>{/each}
        </div>
      {/if}
      <div class="actions">
        <Button variant="primary" kbd="a" disabled={!!blockReason} reason={blockReason} onclick={accept}>{t('next.a.accept')}</Button>
        <Button disabled={!!blockReason} reason={blockReason} onclick={() => next.openContextDialog(item)}>{t('next.a.otherHost')}</Button>
        {#if evidence}<Button kbd="↵" onclick={openEvidence}>{t('next.a.evidence')}</Button>{/if}
      </div>
    {:else if item.kind === 'ctx_unknown'}
      <h3 class="title">
        {#if item.terminal_id}{termTitle(item.terminal, item.terminal_id)}{#if item.stage_kind}{DOT}{stageName(item.stage_kind)}{/if}{:else if item.unit}<Txt value={item.unit.title} mono ctrl={item.unit.ctrl} max={80} />{/if}
      </h3>
      <div class="grid">
        {#if item.from_ts}<span class="k">{t('next.f.effect')}</span><span>{t('next.retroFrom', { time: hhmm(item.from_ts, { seconds: true }) })}</span>{/if}
        <span class="k">{t('next.f.commands')}</span><span>{t('next.units', { n: item.units })}</span>
        {#if item.candidate}<span class="k">{t('next.f.candidate')}</span><span class="mono"><Txt value={item.candidate} mono max={80} /></span>{/if}
        {#if !item.terminal_id && item.unit}<span class="k">{t('next.f.file')}</span><span class="mono"><Txt value={item.unit.title} mono ctrl={item.unit.ctrl} max={120} /></span>{/if}
      </div>
      {#if item.excerpt}
        <div class="excerpt">
          <span class="ex-note">{excerptNote(item.excerpt)}</span>
          {#each item.excerpt.text as l, i (i)}<span class="ex-line"><Txt value={l} mono ctrl={item.excerpt.ctrl} max={240} /></span>{/each}
        </div>
      {/if}
      <div class="actions">
        <Button
          variant="primary"
          kbd="e"
          disabled={!!blockReason || !item.terminal_id}
          reason={blockReason ?? (!item.terminal_id ? t('next.a.noTerminal') : null)}
          onclick={() => next.openContextDialog(item)}>{t('next.a.setHost')}</Button
        >
        {#if evidence}<Button kbd="↵" onclick={openEvidence}>{t('next.a.evidence')}</Button>{/if}
      </div>
    {:else if item.kind === 'merge_suggestion'}
      {@const ids = item.identifiers.filter((i) => i.key !== item.shared)}
      {@const sh = sharedLabel(item.shared)}
      <div class="tiles">
        {#each ids as i (i.key)}
          <div class="tile"><span class="mono"><Txt value={i.label} mono max={60} /></span><span class="muted">{verdictText(i.verdict)}</span></div>
        {/each}
      </div>
      <p class="shared" title={item.reason}>{sh.kind} <span class="mono s"><Txt value={sh.value} mono max={80} /></span></p>
      <div class="actions">
        <Button variant="primary" kbd="a" disabled={!!blockReason} reason={blockReason} onclick={() => mergeIt(true)}>{t('next.a.merge')}</Button>
        <Button disabled={!!blockReason} reason={blockReason} onclick={() => mergeIt(false)}>{t('next.a.separate')}</Button>
      </div>
    {:else if item.kind === 'decide_value'}
      <h3 class="title"><span class="mono"><Txt value={item.fact.subject_label} mono max={80} /></span> <span class="pred">{item.fact.predicate}</span></h3>
      <div class="grid">
        <span class="k">{t('next.f.value')}</span><span class="mono"><Txt value={item.fact.value} mono ctrl={item.fact.ctrl} max={200} /></span>
        <span class="k">{t('next.f.reason')}</span><span>{t(`next.reason.${['important_heuristic', 'offered', 'suspect', 'ai', 'ocr'].includes(item.reason) ? item.reason : 'other'}` as MessageKey)}</span>
        {#if item.unit}<span class="k">{t('next.f.source')}</span><span><Txt value={item.unit.title} mono ctrl={item.unit.ctrl} max={80} />{#if item.unit.ts}{DOT}{hhmm(item.unit.ts)}{/if}</span>{/if}
      </div>
      {#if item.fact.suspect || item.fact.from_target}
        <p class="flags">
          {#if item.fact.suspect}<Badge tone="attention">! {t('common.injection')}</Badge>{/if}
          {#if item.fact.from_target}<Badge>{t('common.fromTarget')}</Badge>{/if}
        </p>
      {/if}
      {#if editing}
        <div class="edit">
          <TextField id="next-edit-{item.item_key}" label={t('next.edit.label')} mono bind:value={editValue} error={editError} autofocus />
          <div class="actions">
            <Button variant="primary" disabled={!!blockReason} reason={blockReason} onclick={saveEdit}>{t('next.edit.save')}</Button>
            <Button onclick={() => (editing = false)}>{t('next.edit.cancel')}</Button>
          </div>
        </div>
      {:else}
        <div class="actions">
          <Button variant="primary" kbd="a" disabled={!!blockReason} reason={blockReason} onclick={() => value('confirm')}>{t('next.a.confirm')}</Button>
          <Button kbd="x" disabled={!!blockReason} reason={blockReason} onclick={() => value('reject')}>{t('next.a.reject')}</Button>
          <Button kbd="e" disabled={!!blockReason || item.fact.is_secret} reason={blockReason ?? (item.fact.is_secret ? t('secret.revealBlocked') : null)} onclick={startEdit}>{t('next.a.edit')}</Button>
          {#if evidence}<Button kbd="↵" onclick={openEvidence}>{t('next.a.evidence')}</Button>{/if}
        </div>
      {/if}
    {:else if item.kind === 'conflict'}
      <h3 class="title"><span class="mono"><Txt value={item.conflict.subject_label} mono max={80} /></span> <span class="pred">{item.conflict.predicate}</span></h3>
      <ul class="values">
        {#each item.conflict.values as v (v.claim_key)}
          <li>
            <span class="mono"><Txt value={v.value} mono ctrl={v.ctrl} max={120} /></span>
            <span class="muted">{t('next.sources', { n: v.sources })}</span>
            <Button size="s" disabled={!!blockReason} reason={blockReason} onclick={() => resolve(v.claim_key)}>{t('next.a.choose')}</Button>
          </li>
        {/each}
      </ul>
      <div class="actions">
        <Button disabled={!!blockReason} reason={blockReason} onclick={() => resolve(null)}>{t('next.a.keepOpen')}</Button>
        {#if evidence}<Button kbd="↵" onclick={openEvidence}>{t('next.a.evidence')}</Button>{/if}
      </div>
    {:else if item.kind === 'orphan_decision'}
      <p class="text">{t('next.orphanText')}</p>
      <div class="grid">
        <span class="k">{t('next.f.decision')}</span><span class="mono"><Txt value={item.decision_kind} mono max={60} /></span>
        <span class="k">{t('next.f.reason')}</span><span><Txt value={item.reason} max={200} /></span>
      </div>
      <div class="actions">
        <Button variant="primary" disabled={!!blockReason} reason={blockReason} onclick={revoke}>{t('next.a.revoke')}</Button>
      </div>
    {:else if item.kind === 'scope_name'}
      <h3 class="title scope-q">
        <span class="mono"><Txt value={item.name} mono ctrl={item.ctrl ?? false} max={120} /></span>
        <span class="pred">{t('next.scopeSug.belongs')}</span>
        <span class="mono"><Txt value={item.ip} mono max={60} /></span>.
        {t('next.scopeSug.question')}
      </h3>
      {#if scopeOpts.length > 0}
        <fieldset class="choice">
          <legend class="k">{t('next.scopeSug.choose')}</legend>
          {#each scopeOpts as o, oi (`${oi}:${o.entry}`)}
            <label class="opt">
              <input type="radio" name="scope-sug-{item.item_key}" value={o.entry} checked={scopeSel?.entry === o.entry} onchange={() => (scopeChoice = o.entry)} />
              <span class="mono s"><Txt value={o.entry} mono ctrl={o.ctrl ?? false} max={120} /></span>
              <span class="muted s">{t(o.kind === 'wildcard' ? 'scope.add.kind.wildcard' : 'scope.add.kind.name')}</span>
            </label>
          {/each}
        </fieldset>
      {/if}
      {#if scopeSel?.public || item.public}<p class="warn" role="note"><span aria-hidden="true">!</span> {t('scope.add.public')}</p>{/if}
      {#if scopeNeedsNc}<p class="warn" role="note"><span aria-hidden="true">!</span> {t('scope.add.outsideLab')}</p>{/if}
      <p class="note">{t('next.scopeSug.never')} {t('scope.add.dns')}</p>
      <div class="grid">
        <span class="k">{t('next.f.source')}</span>
        <span>{item.source === 'ptr' ? t('next.scopeSug.ptr') : t('next.scopeSug.nmap')}{#if item.unit}{DOT}<Txt value={item.unit.title} mono ctrl={item.unit.ctrl} max={120} />{#if item.unit.ts}{DOT}{hhmm(item.unit.ts)}{/if}{/if}</span>
      </div>
      <div class="actions">
        <Button
          variant="primary"
          kbd="a"
          disabled={!!blockReason || !scopeSel || !scopeEditable || scopeNeedsNc}
          reason={blockReason ?? (!scopeEditable ? t('scope.edit.err.policy') : !scopeSel ? t('scope.add.none') : scopeNeedsNc ? t('scope.edit.err.guardrail') : null)}
          onclick={scopeAdd}>{t('next.a.scopeAdd')}</Button
        >
        <Button kbd="x" disabled={!!blockReason} reason={blockReason} onclick={scopeDismiss}>{t('next.a.scopeDismiss')}</Button>
        {#if evidence}<Button kbd="↵" onclick={openEvidence}>{t('next.a.evidence')}</Button>{/if}
      </div>
    {:else if item.kind === 'mass_find'}
      <p class="text">{t('next.massText', { hosts: item.hosts, candidates: item.candidates })}</p>
      <div class="grid">
        <span class="k">{t('next.f.source')}</span><span><Txt value={item.unit.title} mono ctrl={item.unit.ctrl} max={120} /></span>
      </div>
      <div class="actions">
        <Button variant="primary" onclick={massGo}>{t('next.a.single')}</Button>
        {#if evidence}<Button kbd="↵" onclick={openEvidence}>{t('next.a.evidence')}</Button>{/if}
      </div>
    {/if}
  </div>
{/if}

<style>
  .line {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    min-width: 0;
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
  .dot {
    width: 7px;
    height: 7px;
    flex: none;
    border-radius: 50%;
    background: var(--attention);
  }
  .kind {
    flex: none;
    color: var(--muted);
  }
  .parts {
    min-width: 0;
    font-size: var(--fs-s);
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
    gap: 8px;
    font-size: var(--fs-xs);
    color: var(--attention);
  }
  .title {
    margin: 0;
    font-size: 14.5px;
    font-weight: 600;
    line-height: 1.35;
    overflow-wrap: anywhere;
  }
  .pred {
    font-weight: 400;
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .grid {
    display: grid;
    grid-template-columns: 76px minmax(0, 1fr);
    gap: 6px 10px;
    font-size: 13px;
  }
  .k,
  .muted {
    color: var(--muted);
  }
  .mono {
    font-family: var(--font-mono);
  }
  .s {
    font-size: var(--fs-s);
  }
  .excerpt {
    display: flex;
    flex-direction: column;
    gap: 5px;
    padding: 9px 10px;
    border-radius: 7px;
    background: var(--log-bg);
    border: var(--lw-1) solid var(--line);
  }
  .ex-note {
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .ex-line {
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--fg-2);
    overflow-wrap: anywhere;
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
    flex-wrap: wrap;
  }
  .tiles {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 8px;
  }
  .tile {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 9px 10px;
    border-radius: 7px;
    background: var(--log-bg);
    font-size: var(--fs-s);
    min-width: 0;
  }
  .tile .muted {
    font-size: var(--fs-xs);
  }
  .shared,
  .text {
    margin: 0;
    color: var(--fg-2);
  }
  .flags {
    margin: 0;
    display: flex;
    gap: 6px;
  }
  .values {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .values li {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .values li .mono {
    flex: 1;
    min-width: 0;
    font-size: var(--fs-s);
  }
  .choice {
    margin: 0;
    padding: 0;
    border: none;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .choice legend {
    padding: 0;
    margin-bottom: 4px;
    font-size: 13px;
  }
  .opt {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    column-gap: 8px;
    align-items: baseline;
    cursor: pointer;
  }
  .opt .muted {
    grid-column: 2;
    font-size: var(--fs-xs);
  }
  .warn {
    margin: 0;
    color: var(--attention);
    font-size: var(--fs-s);
  }
  .note {
    margin: 0;
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .edit {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
</style>
