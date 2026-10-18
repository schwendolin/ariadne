<!--
  Scope in den Einstellungen ändern (E129): «Entfernen» eines Ziels oder Ausschlusses und
  «Ausschliessen» eines neuen Eintrags, jeweils mit Bestätigung und dem genauen Eintrag gross.
  Jede Änderung ist ein Entscheid (rückgängig über die Zeitachse oder hier sofort danach), der
  Server wertet neu aus. Im Profil customer nur der Hinweis auf `ariadne scope`. Besitzer: ui.
-->
<script lang="ts">
  import type { ScopeChangeResult } from '../api/types';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Button from '../ui/Button.svelte';
  import CommandLine from '../ui/CommandLine.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import TextField from '../ui/TextField.svelte';
  import Txt from '../ui/Txt.svelte';

  let {
    app,
    project,
    op,
    entry = '',
    list = 'include',
    onclose,
  }: { app: AppState; project: ProjectStore; op: 'remove' | 'exclude'; entry?: string; list?: 'include' | 'exclude'; onclose: () => void } = $props();

  const scope = $derived(project.scope);
  let typed = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let done = $state.raw<ScopeChangeResult | null>(null);
  let undone = $state(false);
  const target = $derived(op === 'remove' ? entry : typed.trim());
  const blockReason = $derived(busy ? t('next.loading') : app.offline ? t('err.network') : !target ? t('scope.edit.empty') : null);

  async function submit(): Promise<void> {
    if (!target || busy || blockReason) return;
    busy = true;
    error = null;
    const res = await scope.change({ op, entry: target, source: null });
    busy = false;
    if (!res.ok) {
      error = res.error;
      return;
    }
    done = res.result;
    app.ui.notify('info', op === 'remove' ? t('scope.edit.removed') : t('scope.edit.excluded'));
    void app.refreshStatus();
  }

  async function undo(): Promise<void> {
    if (!done?.decision_id || busy) return;
    busy = true;
    const ok = await scope.undo(done.decision_id);
    busy = false;
    if (ok) {
      undone = true;
      void app.refreshStatus();
    }
  }
</script>

<Dialog title={op === 'remove' ? t('scope.edit.removeTitle') : t('scope.edit.excludeTitle')} {onclose} size="m">
  {#if !scope.editable}
    <p class="text">{t('scope.add.customer')}</p>
    <CommandLine command="ariadne scope" size="s" />
  {:else if done}
    <div class="box" data-testid="scope-edit-done">
      <p class="entry big"><Txt value={target} mono max={200} /></p>
      <p class="status" role="status">
        {#if undone}{t('scope.add.undone')}{:else if scope.reevaluated > 0}{t('scope.add.reevaluated')}{:else}{t('scope.add.reevaluating')}{/if}
      </p>
    </div>
  {:else if op === 'remove'}
    <p class="text">{t('scope.edit.removeText')}</p>
    <div class="box"><p class="entry big" data-testid="scope-edit-entry"><Txt value={entry} mono max={200} /></p></div>
    <p class="hint">{list === 'include' ? t('scope.edit.removeInclude') : t('scope.edit.removeExclude')}</p>
    <p class="hint">{t('scope.add.decision')}</p>
  {:else}
    <TextField id="scope-exclude" label={t('scope.edit.excludeLabel')} mono bind:value={typed} maxlength={253} autofocus />
    {#if target}<div class="box"><p class="entry big" data-testid="scope-edit-entry"><Txt value={target} mono max={200} /></p></div>{/if}
    <p class="hint">{t('scope.edit.excludeHint')}</p>
    <p class="hint">{t('scope.add.decision')}</p>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#snippet footer()}
    {#if !scope.editable}
      <Button variant="primary" onclick={onclose}>{t('scope.add.close')}</Button>
    {:else if done}
      {#if done.decision_id && !undone}<Button disabled={busy || app.offline} reason={busy ? t('next.loading') : app.offline ? t('err.network') : null} onclick={undo}>{t('scope.add.undo')}</Button>{/if}
      <Button variant="primary" onclick={onclose}>{t('scope.add.close')}</Button>
    {:else}
      <Button onclick={onclose}>{t('scope.add.cancel')}</Button>
      <Button variant="primary" disabled={!!blockReason} reason={blockReason} onclick={submit}>{op === 'remove' ? t('scope.edit.remove') : t('scope.edit.exclude')}</Button>
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
  .status {
    margin: var(--sp-2) 0 0;
    color: var(--muted);
  }
  .hint {
    margin: var(--sp-3) 0 0;
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .error {
    margin: var(--sp-2) 0 0;
    color: var(--error);
  }
</style>
