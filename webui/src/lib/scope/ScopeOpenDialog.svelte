<!--
  Scope öffnen bzw. schliessen (E131) aus den Einstellungen. Vorher fragt der Dialog den Server mit
  `dry_run` (web-api.md 20.2):
  - Öffnen: Wirkung im Klartext. Braucht es «kein Kundenauftrag» (`needs_not_customer` bzw. 403
    guardrail), bleibt der Knopf gesperrt mit dem Hinweis auf `ariadne scope open` (nur im Terminal).
  - Schliessen: die Einschlüsse, die danach allein gelten; ohne Einschluss (409 no_include) gesperrt
    mit «Zuerst einen Eintrag hinzufügen».
  Danach Rückmeldung mit Neuauswertung und «Rückgängig» erst nach einer Bestätigung mit Wirkung
  (`op: 'revert'`). Im Profil customer nur der Hinweis auf `ariadne scope`. Einträge nur über Txt.
  Besitzer: ui.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import type { ScopeChangeResult } from '../api/types';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Button from '../ui/Button.svelte';
  import CommandLine from '../ui/CommandLine.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Txt from '../ui/Txt.svelte';

  let { app, project, op, onclose }: { app: AppState; project: ProjectStore; op: 'open' | 'close'; onclose: () => void } = $props();

  const scope = $derived(project.scope);
  const include = $derived(scope.view?.include ?? project.info?.scope.include ?? []);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state<string | null>(null);
  /** Ergebnis der Vorschau: gesperrt mit Grund (guardrail, no_include, noop) oder frei */
  let blocked = $state<'guardrail' | 'no_include' | 'other' | null>(null);
  let previewError = $state<string | null>(null);
  let done = $state.raw<ScopeChangeResult | null>(null);
  let undone = $state(false);
  let confirmUndo = $state(false);

  onMount(async () => {
    if (!scope.editable) {
      loading = false;
      return;
    }
    const r = await scope.preview({ op, entry: '' });
    loading = false;
    if (r.ok) {
      if (op === 'open' && r.result.needs_not_customer) blocked = 'guardrail';
      return;
    }
    blocked = r.code === 'guardrail' ? 'guardrail' : r.code === 'no_include' ? 'no_include' : 'other';
    previewError = blocked === 'other' ? r.error : null;
  });

  const blockReason = $derived(
    busy
      ? t('next.loading')
      : app.offline
        ? t('err.network')
        : loading
          ? t('scope.add.loading')
          : blocked === 'guardrail'
            ? t('scope.open.needsNc')
            : blocked === 'no_include'
              ? t('scope.close.noInclude')
              : blocked === 'other'
                ? previewError
                : null,
  );

  async function submit(): Promise<void> {
    if (busy || blockReason) return;
    busy = true;
    error = null;
    const res = await scope.change({ op, entry: '', source: null });
    busy = false;
    if (!res.ok) {
      error = res.error;
      if (res.code === 'guardrail') blocked = 'guardrail';
      if (res.code === 'no_include') blocked = 'no_include';
      return;
    }
    done = res.result;
    app.ui.notify('info', op === 'open' ? t('scope.open.notice') : t('scope.close.notice'));
    void project.next.load();
    void app.refreshStatus();
  }

  async function undo(): Promise<void> {
    if (!done?.decision_id || busy) return;
    busy = true;
    const ok = await scope.undo(done.decision_id);
    busy = false;
    confirmUndo = false;
    if (ok) {
      undone = true;
      void project.next.load();
      void app.refreshStatus();
    }
  }
</script>

<Dialog title={op === 'open' ? t('scope.open.title') : t('scope.close.title')} {onclose} size="m" tone={op === 'open' && !done ? 'attention' : 'neutral'}>
  {#if !scope.editable}
    <p class="text">{t('scope.add.customer')}</p>
    <CommandLine command="ariadne scope" size="s" />
  {:else if done}
    <div class="box" data-testid="scope-open-done">
      <p class="state">{op === 'open' ? t('scope.open.done') : t('scope.close.done')}{done.version ? ` · Version ${done.version}` : ''}</p>
      <p class="status" role="status">
        {#if undone}{t('scope.add.undone')}{:else if scope.reevaluated > 0}{t('scope.add.reevaluated')}{:else}{t('scope.add.reevaluating')}{/if}
      </p>
    </div>
    {#if confirmUndo && !undone}
      <p class="hint undo-confirm" data-testid="scope-open-undo-confirm">{op === 'open' ? t('scope.open.undoText') : t('scope.close.undoText')}</p>
    {/if}
  {:else if op === 'open'}
    <p class="text" data-testid="scope-open-text">{t('scope.open.text')}</p>
    {#if blocked === 'guardrail'}
      <p class="warn" role="note" data-testid="scope-open-blocked"><span aria-hidden="true">!</span> {t('scope.open.needsNc')}</p>
      <CommandLine command={t('scope.open.cli')} size="s" />
    {/if}
    <p class="hint">{t('scope.add.decision')}</p>
  {:else}
    <p class="text">{t('scope.close.text')}</p>
    <div class="box">
      {#if include.length === 0}
        <p class="none">{t('scope.view.empty')}</p>
      {:else}
        <ul data-testid="scope-close-include">
          {#each include as e, i (`${i}:${e}`)}<li><Txt value={e} mono max={160} /></li>{/each}
        </ul>
      {/if}
    </div>
    {#if blocked === 'no_include'}
      <p class="warn" role="note" data-testid="scope-close-blocked"><span aria-hidden="true">!</span> {t('scope.close.noInclude')}</p>
      <p class="hint">{t('scope.close.noIncludeHint')}</p>
      <CommandLine command={t('scope.close.cli')} size="s" copy={false} />
    {/if}
    <p class="hint">{t('scope.close.excludes')}</p>
    <p class="hint">{t('scope.add.decision')}</p>
  {/if}
  {#if previewError && !error}<p class="error" data-testid="scope-open-preview-error">{previewError}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#snippet footer()}
    {#if !scope.editable}
      <Button variant="primary" onclick={onclose}>{t('scope.add.close')}</Button>
    {:else if done && confirmUndo && !undone}
      <Button onclick={() => (confirmUndo = false)}>{t('scope.add.cancel')}</Button>
      <Button variant="primary" disabled={busy || app.offline} reason={busy ? t('next.loading') : app.offline ? t('err.network') : null} onclick={undo}>{t('scope.edit.undoConfirm')}</Button>
    {:else if done}
      {#if done.decision_id && !undone}<Button disabled={busy || app.offline} reason={busy ? t('next.loading') : app.offline ? t('err.network') : null} onclick={() => (confirmUndo = true)}>{t('scope.add.undo')}</Button>{/if}
      <Button variant="primary" onclick={onclose}>{t('scope.add.close')}</Button>
    {:else}
      <Button onclick={onclose}>{t('scope.add.cancel')}</Button>
      <Button variant="primary" disabled={!!blockReason} reason={blockReason} onclick={submit}>{op === 'open' ? t('scope.open.submit') : t('scope.close.submit')}</Button>
    {/if}
  {/snippet}
</Dialog>

<style>
  .text {
    margin: 0 0 var(--sp-2);
  }
  .box {
    margin-top: var(--sp-3);
    padding: 12px 14px;
    border-radius: var(--r-card);
    background: var(--log-bg);
    border: var(--lw-1) solid var(--line);
  }
  .box ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-family: var(--font-mono);
    overflow-wrap: anywhere;
  }
  .state {
    margin: 0;
    font-size: var(--fs-l, 18px);
    font-weight: 600;
  }
  .none {
    margin: 0;
    color: var(--muted);
  }
  .status {
    margin: var(--sp-2) 0 0;
    color: var(--muted);
  }
  .hint {
    margin: var(--sp-3) 0 0;
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .warn {
    margin: var(--sp-3) 0 var(--sp-2);
    color: var(--attention);
    font-weight: 600;
  }
  .error {
    margin: var(--sp-2) 0 0;
    color: var(--error);
  }
</style>
