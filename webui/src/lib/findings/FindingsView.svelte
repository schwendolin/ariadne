<!--
  Reiter Findings (Screen 8, E113): Liste links (32 %, 340 bis 520 px) mit «Neues Finding», Karten
  «F1 · Entwurf · Titel · Kritisch · 192.168.56.101:21 · 3 Belege» und Warnungen; rechts das
  Formular (FindingForm). Leer: «Noch keine Findings. Findings entstehen aus Belegen.» «Als
  Finding» aus der Belegansicht öffnet dasselbe Formular (`?finding=neu`, Beleg vorgefüllt).
  Offenes Finding in der URL (`finding`). Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { tick, untrack } from 'svelte';
  import type { FindingSummary } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Txt from '../ui/Txt.svelte';
  import { url } from '../url/state.svelte';
  import { errorCode, errorText } from '../util/errors';
  import FindingForm from './FindingForm.svelte';
  import { emptyForm, formFrom } from './form';

  let { app, project }: { app: AppState; project: ProjectStore } = $props();
  const SEP = ' · ';

  const store = $derived(project.findings);
  const list = $derived(store.list);
  const fid = $derived(url.get('finding'));
  const current = $derived(store.current);

  $effect(() => {
    const id = fid;
    untrack(() => void store.open(id));
  });

  // Ohne Auswahl das erste Finding zeigen (wie im Design)
  $effect(() => {
    if (!fid && store.loaded && list.length > 0) url.set({ finding: list[0]?.finding_id ?? null });
  });

  const formKey = $derived(fid === 'neu' ? 'neu' : (current?.finding_id ?? (store.waiting ? fid : null)));
  const draft = $derived(fid === 'neu' && store.draftFrom ? { ref: store.draftFrom, label: store.draftLabel ?? t('ev.title') } : null);
  const initial = $derived.by(() => {
    if (fid === 'neu') return { ...emptyForm(), evidenceAdd: draft ? [draft] : [] };
    if (current) return formFrom(current);
    if (store.lastSaved && store.lastSaved.id === fid) return store.lastSaved.form;
    return emptyForm();
  });
  const notFound = $derived(!!fid && fid !== 'neu' && !current && !store.waiting && store.currentError !== null && errorCode(store.currentError) === 'not_found');

  function sevText(f: FindingSummary): string {
    return f.severity ? t(`fd.sev.${f.severity}` as MessageKey) : t('fd.sev.none');
  }

  function newFinding(): void {
    store.clearDraft();
    url.set({ finding: 'neu' }, { push: true });
  }

  // Nach dem Speichern eines neuen Findings ersetzt das Formular sich selbst (anderer Schlüssel);
  // der Fokus geht an die neue Karte in der Liste statt auf body (wie Korrektur A13).
  let listEl: HTMLUListElement | undefined = $state();
  let focusSaved = $state<string | null>(null);

  function saved(id: string | null): void {
    if (id && fid === 'neu') {
      url.set({ finding: id });
      focusSaved = id;
    }
  }

  $effect(() => {
    const id = focusSaved;
    if (!id || !list.some((f) => f.finding_id === id)) return;
    untrack(() => {
      focusSaved = null;
      void tick().then(() => {
        const active = document.activeElement;
        if (active && active !== document.body) return;
        listEl?.querySelector<HTMLElement>('a.card.sel')?.focus({ preventScroll: true });
      });
    });
  });
</script>

<section class="findings" aria-label={t('fd.title')}>
  <aside class="list">
    <div class="head">
      <h2>{t('fd.title')}</h2>
      <button type="button" class="new" disabled={app.offline} onclick={newFinding}>{t('fd.new')}</button>
    </div>
    {#if store.error}
      <p class="error-box" role="alert">{errorText(store.error, 'fd.loadFailed')}</p>
    {/if}
    {#if store.loaded && list.length === 0}
      <div class="empty">
        <strong>{t('fd.empty')}</strong>
        <span>{t('fd.emptyHint')}</span>
      </div>
    {/if}
    <ul class="cards" aria-label={t('fd.listLabel')} bind:this={listEl}>
      {#if fid === 'neu'}
        <li><div class="card sel"><span class="meta"><span class="mono">F?</span><span>{t('fd.status.draft')}</span></span><strong>{t('fd.newTitle')}</strong></div></li>
      {/if}
      {#each list as f (f.finding_id)}
        <li>
          <a
            class="card"
            class:sel={f.finding_id === fid}
            href={url.href('findings', { finding: f.finding_id })}
            aria-current={f.finding_id === fid ? 'true' : undefined}
            onclick={(e) => {
              e.preventDefault();
              url.set({ finding: f.finding_id }, { push: true });
            }}
          >
            <span class="meta"><span class="mono">F{f.ordinal}</span><span>{t(`fd.status.${f.status}` as MessageKey)}</span></span>
            <span class="title"><Txt value={f.title} max={120} ctrl={f.ctrl} /></span>
            <span class="sub">
              {sevText(f)}{#each f.affected.slice(0, 2) as a (a.subject)}{SEP}<Txt value={a.label.split(' ')[0] ?? a.label} mono max={40} ctrl={a.ctrl} />{/each}{#if f.affected.length > 2}{SEP}+{f.affected.length - 2}{/if}{SEP}{t('fd.evidenceN', { n: f.evidence_count })}
            </span>
            {#each f.warnings.filter((w) => w === 'evidence_distrusted' || w === 'evidence_missing') as w (w)}
              <span class="warn"><span class="bang" aria-hidden="true">!</span>{t(`fd.warn.${w}` as MessageKey)}</span>
            {/each}
          </a>
        </li>
      {/each}
    </ul>
  </aside>

  <div class="detail">
    {#if formKey}
      {#key formKey}
        <FindingForm {app} {project} base={fid === 'neu' ? null : current} {initial} {draft} onsaved={saved} />
      {/key}
      {#if store.waiting}<p class="muted">{t('fd.waiting')}</p>{/if}
    {:else if notFound}
      <p class="muted">{t('fd.notFound')}</p>
    {:else if fid && store.currentError}
      <p class="error-box" role="alert">{errorText(store.currentError, 'fd.loadFailed')}</p>
    {:else if fid && fid !== 'neu'}
      <p class="muted">{t('common.loading')}</p>
    {:else if list.length > 0}
      <p class="muted">{t('fd.pick')}</p>
    {/if}
  </div>
</section>

<style>
  .findings {
    height: 100%;
    display: flex;
    min-height: 0;
  }
  .list {
    flex: 0 0 32%;
    min-width: 340px;
    max-width: 520px;
    border-right: var(--lw-1) solid var(--line);
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: auto;
  }
  .head {
    padding: 18px 20px 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  h2 {
    margin: 0;
    font-size: var(--fs-l);
    font-weight: 600;
  }
  .new {
    padding: 6px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    font-size: var(--fs-s);
    cursor: pointer;
  }
  .new:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .cards {
    list-style: none;
    margin: 0;
    padding: 0 12px 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 12px;
    border-radius: var(--r-card);
    color: var(--fg);
    text-decoration: none;
    border: var(--lw-1) solid transparent;
  }
  .card:hover {
    background: var(--rec-bg);
  }
  .card.sel {
    background: var(--surface-2);
    box-shadow: 0 0 0 var(--lw-focus) var(--focus);
  }
  .meta {
    display: flex;
    justify-content: space-between;
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .mono {
    font-family: var(--font-mono);
  }
  .title {
    font-weight: 600;
    line-height: 1.35;
  }
  .sub {
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .warn {
    font-size: var(--fs-s);
    display: flex;
    gap: 8px;
  }
  .bang {
    color: var(--attention);
    font-weight: 700;
  }
  .empty {
    margin: 0 12px;
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--line);
    padding: 28px 20px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .empty span {
    color: var(--muted);
  }
  .detail {
    flex: 1;
    min-width: 0;
    overflow: auto;
    padding: var(--sp-6) 40px;
  }
  .muted {
    color: var(--muted);
  }
  .error-box {
    margin: 0 12px 8px;
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--error);
    padding: var(--sp-3) 14px;
  }
</style>
