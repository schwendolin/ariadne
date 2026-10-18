<!--
  Dialog «Bericht exportieren» (Screen 10, Briefing 5.12, Entwurf api-export): Vorlage cys/htb,
  Hinweis auf die Phasen in der Zeitachse («3 Befehle ohne Phase · in der Zeitachse prüfen ›»),
  Credentials verdeckt, Fortschritt (Daten sammeln, Dateien schreiben), Ergebnis mit Ordner im
  Projekt und Warnungen (Sync-Ordner, mögliche Secrets), Liste der früheren Exporte. Klartext gibt
  es nur im Terminal (`ariadne export --klartext`); der Dialog nennt nur den Befehl.
  Pfade sind relativ zum Projektordner und werden als Text gezeigt. Besitzer: ui.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import type { ExportEntry, ExportTemplate, PhasesView } from '../api/types';
  import { num, t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import { exportStepKey, openPhases } from '../stores/exports.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import Txt from '../ui/Txt.svelte';
  import { url } from '../url/state.svelte';
  import { errorText } from '../util/errors';
  import { hhmm } from '../util/time';

  let { app, project, onclose }: { app: AppState; project: ProjectStore; onclose: () => void } = $props();
  const ex = $derived(project.exports);

  let template = $state<ExportTemplate>('cys');
  let phases = $state.raw<PhasesView | null>(null);
  let phasesError = $state<string | null>(null);
  const missing = $derived(openPhases(phases));
  const progress = $derived(ex.progress);
  const running = $derived(ex.running);

  const templates = [
    { value: 'cys' as const, label: 'cys' },
    { value: 'htb' as const, label: 'htb' },
  ];

  onMount(() => {
    void ex.refresh();
  });

  $effect(() => {
    const tp = template;
    phases = null;
    phasesError = null;
    let live = true;
    ex.phases(tp).then(
      (v) => {
        if (live) phases = v;
      },
      (e: unknown) => {
        if (live) phasesError = errorText(e, 'tl.phase.loadFailed');
      },
    );
    return () => {
      live = false;
    };
  });

  function toTimeline(): void {
    onclose();
    url.go('zeitachse', { phasen: template });
  }

  function day(iso: string): string {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString('de-CH');
  }

  function warnings(e: ExportEntry): string[] {
    return e.warnings.map((w) => t(`export.warn.${w}`));
  }
</script>

<Dialog title={t('export.title')} {onclose} size="m">
  <div class="body">
    <div class="field">
      <span class="lbl">{t('export.template')}</span>
      <Segmented options={templates} value={template} onchange={(v) => (template = v)} label={t('export.template')} disabled={running} />
    </div>
    <dl class="facts">
      <dt>{t('export.phases')}</dt>
      <dd>
        <span class="muted" data-export-phases>
          {#if phasesError}{phasesError}{:else if !phases}{t('export.phasesLoading')}{:else if missing > 0}{t('export.phasesOpen', { n: missing })}{:else}{t('export.phasesAll')}{/if}
        </span>
        · <button type="button" class="link" onclick={toTimeline}>{t('export.phasesLink')}</button>
      </dd>
      <dt>{t('export.creds')}</dt>
      <dd class="muted">{t('export.credsValue')}</dd>
    </dl>
    <p class="hint">{t('export.klartext')}</p>

    <div class="run">
      <Button variant="primary" disabled={running || app.offline} reason={running ? t('export.running') : app.offline ? t('err.network') : null} onclick={() => void ex.start(template)}
        >{t('export.run')}</Button
      >
      {#if progress && progress.status === 'running'}
        <div class="progress" role="status" aria-live="polite" data-export-progress>
          <span>{t(exportStepKey(progress))}</span>
          <progress max="100" value={Math.max(0, Math.min(100, progress.pct ?? 0))} aria-hidden="true"></progress>
          <span class="mono">{progress.pct ?? 0} %</span>
        </div>
      {:else if progress && progress.status === 'failed'}
        <p class="err" role="alert">{t('export.step.failed')}</p>
      {/if}
    </div>
    {#if ex.error}<p class="err" role="alert">{ex.error}</p>{/if}

    {#if ex.result && progress?.status === 'done'}
      <div class="result" role="status" data-export-result>
        <strong>{t('export.done')}</strong>
        <span>{t('export.folder')}: <Txt value={ex.result.path} mono max={200} /></span>
        <span class="muted">{t('export.files', { n: ex.result.files })} · {t('export.chain', { seq: num(ex.result.chain.seq) })}</span>
        {#each warnings(ex.result) as w (w)}<span class="warn">! {w}</span>{/each}
      </div>
    {/if}

    <div class="list">
      <span class="lbl">{t('export.list')}</span>
      {#if ex.loadError}
        <span class="err">{ex.loadError}</span>
      {:else if ex.view && ex.view.exports.length === 0}
        <span class="muted">{t('export.listEmpty')}</span>
      {:else if ex.view}
        <ul>
          {#each ex.view.exports.slice(0, 20) as e (e.export_id)}
            <li data-export-id={e.export_id}>
              <span class="mono">{day(e.created_at)} {hhmm(e.created_at)}</span>
              <span>{e.template}</span>
              <span class="path"><Txt value={e.path} mono max={120} /></span>
              <span class="muted">{t('export.files', { n: e.files })}</span>
              {#if e.warnings.length > 0}<span class="warn" title={warnings(e).join('\n')}>! {e.warnings.length}</span>{/if}
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  </div>
  {#snippet footer()}
    <Button onclick={onclose}>{t('export.close')}</Button>
  {/snippet}
</Dialog>

<style>
  .body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .field {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
  }
  .lbl {
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .facts {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 6px var(--sp-3);
    margin: 0;
  }
  dd {
    margin: 0;
    text-align: right;
  }
  .muted {
    color: var(--muted);
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
  }
  .hint {
    margin: 0;
    font-size: var(--fs-s);
    color: var(--muted);
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    cursor: pointer;
    font: inherit;
  }
  .link:hover {
    color: var(--fg);
    text-decoration: underline;
  }
  .run {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    flex-wrap: wrap;
  }
  .progress {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: var(--fs-s);
  }
  progress {
    width: 140px;
    height: 6px;
    accent-color: var(--fg);
  }
  .result {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 12px;
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--line-strong);
    font-size: var(--fs-s);
  }
  .warn {
    color: var(--attention);
    font-size: var(--fs-s);
  }
  .err {
    margin: 0;
    color: var(--error);
    font-size: var(--fs-s);
  }
  .list {
    border-top: var(--lw-1) solid var(--line);
    padding-top: 10px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: var(--fs-s);
  }
  ul {
    margin: 0;
    padding: 0;
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 4px;
    max-height: 180px;
    overflow: auto;
  }
  li {
    display: grid;
    grid-template-columns: auto auto minmax(0, 1fr) auto auto;
    gap: 10px;
    align-items: baseline;
  }
  .path {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
