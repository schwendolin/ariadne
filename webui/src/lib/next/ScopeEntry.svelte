<!--
  Scope-Warnung als erster Eintrag der Spalte «Als Nächstes» (E120, Entwurf api-paket 2): vor
  «Klären», Rand --attention, ohne Ordnungsnummer, zählt nicht in `open`. Inhalt: Terminal, Befehl
  (Zieldaten, über Txt), Ziel mit Urteil, Zeit. «Quittieren» schreibt `PUT /ui/scope-ack`, danach
  lädt die Spalte `/next` neu (der Eintrag verschwindet); «In der Zeitachse» springt zur Zeile.
  Die Karte unten rechts entfällt; das Kennzeichen in der Kopfzeile führt hierher (`scopeFocus`).
  E129: «In den Scope aufnehmen …» öffnet den Bestätigungsdialog mit den Vorschlägen des Servers
  für die Ziele der Warnung; im Profil customer gesperrt mit Hinweis auf `ariadne scope`.
  Besitzer: ui.
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import type { ScopeWarning, Verdict } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Txt from '../ui/Txt.svelte';
  import { url } from '../url/state.svelte';
  import { termShort } from '../util/format';
  import { hhmm } from '../util/time';

  let { app, project, warning }: { app: AppState; project: ProjectStore; warning: ScopeWarning } = $props();
  const w = $derived(warning);
  const term = $derived(termShort(w.terminal ?? { terminal_id: w.terminal_id, ordinal: null }));
  let busy = $state(false);
  let node: HTMLElement | undefined = $state();

  const VERDICT: Record<Verdict, MessageKey> = {
    out: 'scope.notIn',
    excluded: 'scope.excluded',
    outside_window: 'scope.outsideWindow',
    unknown: 'scope.unknown',
    in: 'scope.unknown',
  };

  // Kennzeichen in der Kopfzeile: hierher springen und den Eintrag fokussieren
  $effect(() => {
    if (app.ui.scopeFocus && node) {
      const el = node;
      untrack(() => (app.ui.scopeFocus = false));
      el.scrollIntoView?.({ block: 'nearest' });
      el.focus({ preventScroll: true });
    }
  });

  function toTimeline(): void {
    url.go('zeitachse', { zeile: w.cmd_id });
  }

  const editable = $derived(project.scope.editable && w.change_allowed !== false);
  const addReason = $derived(app.offline ? t('err.network') : !editable ? t('scope.edit.err.policy') : null);

  function addToScope(): void {
    const values = (w.targets ?? []).filter((tg) => tg.value.length > 0).map((tg) => ({ value: tg.value, ctrl: tg.ctrl, verdict: tg.verdict, proposals: tg.proposals ?? null }));
    if (values.length === 0) return;
    app.ui.openDialog({ kind: 'scope-add', values, source: { cmd_id: w.cmd_id } });
  }

  async function ack(): Promise<void> {
    busy = true;
    const ok = await app.ackScopeWarning(w.cmd_id);
    busy = false;
    if (ok) await project.next.load();
  }
</script>

<div class="entry" role="group" aria-labelledby="scope-entry-title" tabindex="-1" bind:this={node} data-scope-entry>
  <h3 id="scope-entry-title"><span aria-hidden="true">!</span> {t('scope.title')}</h3>
  <p class="cmd">{term}: <Txt value={w.text ?? w.cmd_ref} mono ctrl={w.ctrl ?? false} max={160} /></p>
  {#each w.targets ?? [] as tg, i (`${i}:${tg.value}`)}
    <p class="muted">
      <Txt value={tg.value} mono ctrl={tg.ctrl} max={80} />
      {t(VERDICT[tg.verdict] ?? 'scope.unknown', { scope: (w.scope ?? []).join(', ') || '–', time: hhmm(w.ts, { seconds: true }) })}
    </p>
  {/each}
  <div class="actions">
    <button type="button" class="primary" disabled={busy || app.offline} onclick={ack}>{t('scope.ack')}</button>
    {#if (w.targets ?? []).length > 0}
      <button type="button" class="secondary" disabled={!!addReason} title={addReason ?? undefined} onclick={addToScope}>{t('scope.add.button')}</button>
    {/if}
    <button type="button" class="secondary" onclick={toTimeline}>{t('scope.toTimeline')}</button>
  </div>
</div>

<style>
  .entry {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    margin: 4px 0 6px;
    padding: 12px 14px;
    border-radius: var(--r-card);
    background: var(--surface-2);
    border: 1.5px solid var(--attention);
    color: var(--fg);
    line-height: 1.35;
    outline: none;
  }
  .entry:focus-visible {
    box-shadow: 0 0 0 2px var(--focus);
  }
  h3 {
    margin: 0;
    font-size: var(--fs-m);
    font-weight: 600;
    color: var(--attention);
  }
  p {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .muted {
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .actions {
    display: flex;
    gap: var(--sp-2);
    align-items: center;
    flex-wrap: wrap;
  }
  .primary,
  .secondary {
    padding: 7px 12px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    cursor: pointer;
    font-size: 13px;
    line-height: 1;
  }
  .primary {
    background: var(--fg);
    color: var(--bg);
    border-color: var(--fg);
    font-weight: 600;
  }
  .primary:disabled,
  .secondary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
