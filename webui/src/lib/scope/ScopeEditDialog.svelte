<!--
  Scope in den Einstellungen ändern (E129): «Entfernen» eines Ziels oder Ausschlusses und
  «Ausschliessen» eines neuen Eintrags, jeweils mit Bestätigung und dem genauen Eintrag gross.
  Jede Änderung ist ein Entscheid (rückgängig über die Zeitachse oder hier sofort danach), der
  Server wertet neu aus. Beim Ausschliessen fragt der Dialog den Server mit `dry_run` und zeigt den
  Eintrag so, wie er gespeichert wird (z. B. «box.lab» statt «Box.LAB.», xn--Form); danach steht dort
  der gespeicherte Eintrag. «Rückgängig» kann den Scope wieder erweitern (Ausschluss weg, Ziel wieder
  drin) und braucht deshalb eine Bestätigung mit Wirkung und Eintrag (E129, wie in der Zeitachse).
  «Hinzufügen …» (E131, E133): freier Eintrag mit `dry_run`; braucht er «kein Kundenauftrag»
  (`needs_not_customer`, 403 guardrail), bleibt der Knopf gesperrt mit dem Befehl fürs Terminal;
  sehr breite Einträge (`broad`) bekommen einen Warnhinweis.
  Im Profil customer nur der Hinweis auf `ariadne scope`. Besitzer: ui.
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
  import { addCommand } from './open';

  let {
    app,
    project,
    op,
    entry = '',
    list = 'include',
    onclose,
  }: { app: AppState; project: ProjectStore; op: 'add' | 'remove' | 'exclude'; entry?: string; list?: 'include' | 'exclude'; onclose: () => void } = $props();

  const scope = $derived(project.scope);
  let typed = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let done = $state.raw<ScopeChangeResult | null>(null);
  let undone = $state(false);
  let confirmUndo = $state(false);
  const target = $derived(op === 'remove' ? entry : typed.trim());
  // Vorschau per dry_run (web-api.md 20.2) beim Ausschliessen und Hinzufügen, kurz verzögert beim Tippen
  let preview = $state.raw<{ typed: string; entry: string | null; error: string | null; needsNc: boolean; broad: boolean } | null>(null);
  let previewSeq = 0;
  $effect(() => {
    const value = op !== 'remove' ? typed.trim() : '';
    if (!value || done || !scope.editable) return;
    const seq = ++previewSeq;
    const timer = setTimeout(() => {
      void scope.preview({ op: op === 'add' ? 'add' : 'exclude', entry: value }).then((r) => {
        if (seq !== previewSeq) return;
        preview = r.ok
          ? { typed: value, entry: r.result.entries?.[0] ?? value, error: null, needsNc: !!r.result.needs_not_customer, broad: r.result.broad === true }
          : r.code === 'guardrail'
            ? { typed: value, entry: value, error: null, needsNc: true, broad: false }
            : { typed: value, entry: null, error: r.error, needsNc: false, broad: false };
      });
    }, 250);
    return () => clearTimeout(timer);
  });
  const current = $derived(preview && preview.typed === target ? preview : null);
  // der genaue Eintrag: nach dem Speichern der gespeicherte, vorher die Vorschau des Servers
  const shown = $derived(done ? (done.entries?.length ? done.entries.join(', ') : target) : op === 'remove' ? entry : (current?.entry ?? target));
  const undoText = $derived(
    op === 'add' ? t('scope.edit.undoAdd') : op === 'exclude' ? t('scope.edit.undoExclude') : list === 'exclude' ? t('scope.edit.undoReexclude') : t('scope.edit.undoRemove'),
  );
  // 403 guardrail beim Schreiben: wie die Vorschau sperren, mit dem Befehl fürs Terminal (E132)
  let guardrailFor = $state<string | null>(null);
  const needsNc = $derived(op === 'add' && (!!current?.needsNc || (guardrailFor !== null && guardrailFor === target)));
  const blockReason = $derived(
    busy
      ? t('next.loading')
      : app.offline
        ? t('err.network')
        : !target
          ? t('scope.edit.empty')
          : needsNc
            ? t('scope.edit.err.guardrail')
            : current?.error
              ? current.error
              : null,
  );

  async function submit(): Promise<void> {
    if (!target || busy || blockReason) return;
    busy = true;
    error = null;
    const res = await scope.change({ op, entry: target, source: null });
    busy = false;
    if (!res.ok) {
      error = res.error;
      if (res.code === 'guardrail') guardrailFor = target;
      return;
    }
    done = res.result;
    app.ui.notify('info', op === 'add' ? t('scope.add.notice') : op === 'remove' ? t('scope.edit.removed') : t('scope.edit.excluded'));
    if (op === 'add') void project.next.load();
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
      void app.refreshStatus();
    }
  }
</script>

<Dialog title={op === 'add' ? t('scope.edit.addTitle') : op === 'remove' ? t('scope.edit.removeTitle') : t('scope.edit.excludeTitle')} {onclose} size="m" tone={op === 'add' && current?.broad && !done ? 'attention' : 'neutral'}>
  {#if !scope.editable}
    <p class="text">{t('scope.add.customer')}</p>
    <CommandLine command="ariadne scope" size="s" />
  {:else if done}
    <div class="box" data-testid="scope-edit-done">
      <p class="entry big" data-testid="scope-edit-saved"><Txt value={shown} mono max={200} /></p>
      <p class="status" role="status">
        {#if undone}{t('scope.add.undone')}{:else if scope.reevaluated > 0}{t('scope.add.reevaluated')}{:else}{t('scope.add.reevaluating')}{/if}
      </p>
    </div>
    {#if confirmUndo && !undone}
      <p class="hint undo-confirm" data-testid="scope-edit-undo-confirm">{undoText} <span class="undo-entry"><Txt value={shown} mono max={200} /></span></p>
    {/if}
  {:else if op === 'remove'}
    <p class="text">{t('scope.edit.removeText')}</p>
    <div class="box"><p class="entry big" data-testid="scope-edit-entry"><Txt value={entry} mono max={200} /></p></div>
    <p class="hint">{list === 'include' ? t('scope.edit.removeInclude') : t('scope.edit.removeExclude')}</p>
    <p class="hint">{t('scope.add.decision')}</p>
  {:else}
    <TextField id={op === 'add' ? 'scope-add-entry' : 'scope-exclude'} label={op === 'add' ? t('scope.edit.addLabel') : t('scope.edit.excludeLabel')} mono bind:value={typed} maxlength={253} autofocus />
    {#if target}<div class="box"><p class="entry big" data-testid="scope-edit-entry"><Txt value={shown} mono max={200} /></p></div>{/if}
    {#if current?.error && !error}<p class="error" data-testid="scope-edit-preview-error">{current.error}</p>{/if}
    {#if op === 'add' && current?.broad}<p class="warn" role="note" data-testid="scope-broad"><span aria-hidden="true">!</span> {t('scope.add.broad')}</p>{/if}
    {#if needsNc}
      <p class="warn" role="note" data-testid="scope-edit-guardrail"><span aria-hidden="true">!</span> {t('scope.add.outsideLab')}</p>
      <p class="hint">{t('scope.add.guardrailCmd')}</p>
      <CommandLine command={addCommand(current?.entry ?? target)} size="s" />
    {/if}
    <p class="hint">{op === 'add' ? t('scope.edit.addHint') : t('scope.edit.excludeHint')}</p>
    <p class="hint">{t('scope.add.decision')}</p>
  {/if}
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
      <Button variant="primary" disabled={!!blockReason} reason={blockReason} onclick={submit}>{op === 'add' ? t('scope.edit.add') : op === 'remove' ? t('scope.edit.remove') : t('scope.edit.exclude')}</Button>
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
  .warn {
    margin: var(--sp-2) 0 0;
    color: var(--attention);
    font-size: var(--fs-s);
  }
  .undo-entry {
    font-weight: 600;
    overflow-wrap: anywhere;
  }
</style>
