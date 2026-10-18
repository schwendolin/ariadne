<!--
  «In den Scope aufnehmen» (E129, E130): Bestätigungsdialog mit den Vorschlägen des Servers
  (genauer Name, Domain-Wildcard, IP) pro Ziel, dem gewählten Eintrag gross, dem Hinweis «Ariadne
  prüft keine Namen per DNS», einem Warnhinweis bei öffentlicher Endung und «Aufnehmen»/«Abbrechen».
  Vor dem Aufnehmen fragt der Dialog den Server mit `dry_run` (web-api.md 20.2) und zeigt, was neu
  in den Scope kommt; braucht es «kein Kundenauftrag» (`needs_not_customer`), bleibt «Aufnehmen»
  gesperrt mit Hinweis aufs Terminal.
  Danach Rückmeldung im Dialog: «Aufgenommen», «Ariadne wertet neu aus …», sobald per SSE
  `changes` kommt «Neu ausgewertet.», mit «Rückgängig» (`op: 'revert'`, nie d.revoke) und «Schliessen».
  Im Profil customer nur der Hinweis auf `ariadne scope`. Ziele und Einträge nur über Txt.
  Besitzer: ui.
-->
<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import type { ScopeChangeResult, ScopeEntryKind, ScopeOption } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import type { ScopeAddRequest } from '../stores/ui.svelte';
  import Button from '../ui/Button.svelte';
  import CommandLine from '../ui/CommandLine.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Txt from '../ui/Txt.svelte';
  import { isApiError } from '../api/client';
  import { errorText, isAbort } from '../util/errors';

  let { app, project, req, onclose }: { app: AppState; project: ProjectStore; req: ScopeAddRequest; onclose: () => void } = $props();

  interface Group {
    value: string;
    ctrl: boolean;
    inScope: boolean;
    excluded: boolean;
    options: ScopeOption[];
    error: string | null;
  }

  const scope = $derived(project.scope);
  const editable = $derived(scope.editable);
  let groups = $state.raw<Group[]>([]);
  let loading = $state(true);
  let selected = $state<string | null>(null);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let done = $state.raw<{ entry: string; result: ScopeChangeResult } | null>(null);
  let undone = $state(false);
  const abort = new AbortController();

  const all = $derived(groups.flatMap((g) => g.options));
  const chosen = $derived(all.find((o) => o.entry === selected) ?? null);
  // Vorschau per dry_run für den gewählten Eintrag
  let preview = $state.raw<{ entry: string; result: ScopeChangeResult | null; error: string | null } | null>(null);
  let previewSeq = 0;
  $effect(() => {
    const entry = chosen?.entry ?? null;
    if (!entry || done || !editable) return;
    const seq = ++previewSeq;
    void scope.preview({ op: 'add', entry }).then((r) => {
      if (seq !== previewSeq) return;
      preview = r.ok ? { entry, result: r.result, error: null } : { entry, result: null, error: r.error };
    });
  });
  const current = $derived(preview && chosen && preview.entry === chosen.entry ? preview : null);
  const needsNc = $derived(!!current?.result?.needs_not_customer || (!!chosen?.outside_lab && app.profile === 'lab' && scope.view?.not_customer === false));
  const blockReason = $derived(
    busy ? t('next.loading') : app.offline ? t('err.network') : !chosen ? t('scope.edit.empty') : needsNc ? t('scope.edit.err.guardrail') : current?.error ? current.error : null,
  );

  const KINDS = new Set<string>(['name', 'url_host', 'wildcard', 'ip', 'cidr', 'range', 'url', 'other']);
  function kindText(k: ScopeEntryKind | string): string {
    return t(`scope.add.kind.${KINDS.has(k) ? k : 'other'}` as MessageKey);
  }

  onMount(async () => {
    const out: Group[] = [];
    for (const v of req.values.slice(0, 20)) {
      if (v.proposals && v.proposals.length > 0) {
        out.push({ value: v.value, ctrl: v.ctrl ?? false, inScope: false, excluded: false, options: v.proposals.slice(0, 8), error: null });
        continue;
      }
      // ausgeschlossene Ziele bekommen keinen Vorschlag (20.4): Ausschluss entfernen statt aufnehmen
      if (v.verdict === 'excluded') {
        out.push({ value: v.value, ctrl: v.ctrl ?? false, inScope: false, excluded: true, options: [], error: null });
        continue;
      }
      try {
        const r = await scope.options(v.value, abort.signal);
        out.push({ value: r.value, ctrl: r.ctrl, inScope: r.verdict === 'in', excluded: r.verdict === 'excluded', options: r.options.slice(0, 8), error: null });
      } catch (e) {
        if (isAbort(e)) return;
        // Server ohne Vorschläge zu diesem Ziel: keine eigene Zerlegung in der UI, Hinweis aufs Terminal
        const missing = isApiError(e, 'not_found') || isApiError(e, 'method') || isApiError(e, 'not_implemented');
        out.push({ value: v.value, ctrl: v.ctrl ?? false, inScope: false, excluded: false, options: [], error: missing ? null : errorText(e, 'scope.add.loadFailed') });
      }
    }
    groups = out;
    loading = false;
    const first = groups.flatMap((g) => g.options);
    selected = (req.selected && first.some((o) => o.entry === req.selected) ? req.selected : first[0]?.entry) ?? null;
  });

  onDestroy(() => abort.abort());

  async function submit(): Promise<void> {
    if (!chosen || busy || blockReason) return;
    busy = true;
    error = null;
    const res = await scope.change({ op: 'add', entry: chosen.entry, source: req.source });
    busy = false;
    if (!res.ok) {
      error = res.error;
      return;
    }
    done = { entry: chosen.entry, result: res.result };
    app.ui.notify('info', t('scope.add.notice'));
    // E130: die Klärung steht danach als erledigt da (mit Rückgängig), der Server wertet neu aus
    if (req.source.item_key) project.next.scopeAccepted(req.source.item_key, chosen.entry, res.result.decision_id);
    void project.next.load();
    void app.refreshStatus();
  }

  async function undo(): Promise<void> {
    if (!done?.result.decision_id || busy) return;
    busy = true;
    const ok = await scope.undo(done.result.decision_id);
    busy = false;
    if (ok) {
      undone = true;
      app.ui.notify('info', t('scope.add.undone'));
      void project.next.load();
      void app.refreshStatus();
    }
  }
</script>

<Dialog title={t('scope.add.title')} {onclose} size="m" tone={chosen?.public && !done ? 'attention' : 'neutral'}>
  {#if !editable}
    <p class="text">{t('scope.add.customer')}</p>
    <CommandLine command="ariadne scope" size="s" />
  {:else if done}
    <div class="done" data-testid="scope-add-done">
      <p class="kicker">{undone ? t('scope.add.undo') : t('scope.add.done')}</p>
      <p class="entry big"><Txt value={done.entry} mono max={200} /></p>
      <p class="status" role="status">
        {#if undone}{t('scope.add.undone')}{:else if scope.reevaluated > 0}{t('scope.add.reevaluated')}{:else}{t('scope.add.reevaluating')}{/if}
      </p>
    </div>
  {:else if loading}
    <p class="muted" role="status">{t('scope.add.loading')}</p>
  {:else}
    <p class="label">{t('scope.add.choose')}</p>
    <div class="groups" role="radiogroup" aria-label={t('scope.add.choose')}>
      {#each groups as g, gi (`${gi}:${g.value}`)}
        <div class="group">
          <p class="target"><span class="k">{t('scope.add.target')}</span> <Txt value={g.value} mono ctrl={g.ctrl} max={120} />{#if g.inScope}<span class="muted"> · {t('scope.add.inScope')}</span>{/if}</p>
          {#if g.error}<p class="error">{g.error}</p>{:else if g.excluded}<p class="muted">{t('scope.add.excluded')}</p>{:else if g.options.length === 0}<p class="muted">{t('scope.add.none')}</p>{/if}
          {#each g.options as o, oi (`${oi}:${o.entry}`)}
            <label class="option" class:on={selected === o.entry}>
              <input type="radio" name="scope-add-option" value={o.entry} checked={selected === o.entry} onchange={() => (selected = o.entry)} />
              <span class="o-entry"><Txt value={o.entry} mono ctrl={o.ctrl ?? false} max={120} /></span>
              <span class="o-kind">{kindText(o.kind)}</span>
            </label>
          {/each}
        </div>
      {/each}
    </div>
    {#if chosen}
      <div class="chosen">
        <p class="kicker">{t('scope.add.entry')}</p>
        <p class="entry big" data-testid="scope-add-entry"><Txt value={chosen.entry} mono ctrl={chosen.ctrl ?? false} max={200} /></p>
        {#if chosen.public}<p class="warn" role="note"><span aria-hidden="true">!</span> {t('scope.add.public')}</p>{/if}
        {#if needsNc}<p class="warn" role="note"><span aria-hidden="true">!</span> {t('scope.add.outsideLab')}</p>{/if}
        {#if current?.result}
          {@const r = current.result}
          {#if (r.exclude_removed ?? []).length > 0}<p class="effect">{t('scope.add.fromExclude')} {#each r.exclude_removed ?? [] as e, i (i)}{#if i > 0}, {/if}<Txt value={e} mono max={120} />{/each}</p>{/if}
        {:else if current?.error}
          <p class="warn" role="note">{current.error}</p>
        {/if}
      </div>
    {/if}
    <p class="hint">{t('scope.add.dns')}</p>
    <p class="hint">{t('scope.add.decision')}</p>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
  {/if}

  {#snippet footer()}
    {#if !editable}
      <Button variant="primary" onclick={onclose}>{t('scope.add.close')}</Button>
    {:else if done}
      {#if done.result.decision_id && !undone}
        <Button disabled={busy || app.offline} reason={busy ? t('next.loading') : app.offline ? t('err.network') : null} onclick={undo}>{t('scope.add.undo')}</Button>
      {/if}
      <Button variant="primary" onclick={onclose}>{t('scope.add.close')}</Button>
    {:else}
      <Button onclick={onclose}>{t('scope.add.cancel')}</Button>
      <Button variant="primary" disabled={!!blockReason || loading} reason={blockReason ?? (loading ? t('scope.add.loading') : null)} onclick={submit}>{t('scope.add.submit')}</Button>
    {/if}
  {/snippet}
</Dialog>

<style>
  .label,
  .kicker {
    margin: 0 0 var(--sp-2);
    font-size: 11.5px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--faint);
  }
  .groups {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .group {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .target {
    margin: 0 0 2px;
    overflow-wrap: anywhere;
  }
  .k,
  .muted {
    color: var(--muted);
  }
  .option {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    grid-template-rows: auto auto;
    column-gap: 10px;
    padding: 8px 10px;
    border-radius: 8px;
    border: var(--lw-1) solid var(--line);
    cursor: pointer;
  }
  .option.on {
    border-color: var(--focus);
    background: var(--surface-3);
  }
  .option input {
    grid-row: 1 / span 2;
    margin: 2px 0 0;
  }
  .o-entry {
    font-family: var(--font-mono);
    overflow-wrap: anywhere;
  }
  .o-kind {
    grid-column: 2;
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .chosen,
  .done {
    margin-top: var(--sp-4);
    padding: 12px 14px;
    border-radius: var(--r-card);
    background: var(--log-bg);
    border: var(--lw-1) solid var(--line);
  }
  .entry {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .big {
    font-family: var(--font-mono);
    font-size: 20px;
    font-weight: 600;
    line-height: 1.3;
  }
  .warn {
    margin: var(--sp-2) 0 0;
    color: var(--attention);
    font-size: var(--fs-s);
  }
  .status,
  .effect {
    margin: var(--sp-2) 0 0;
    color: var(--muted);
    font-size: var(--fs-s);
    overflow-wrap: anywhere;
  }
  .hint {
    margin: var(--sp-3) 0 0;
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .text {
    margin: 0 0 var(--sp-2);
  }
  .error {
    margin: var(--sp-2) 0 0;
    color: var(--error);
  }
</style>
