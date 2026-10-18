<!--
  Formular eines Findings (Screen 8, E113): Titel, Schwere (5 Stufen, setzt nur der Mensch),
  Status (Entwurf, final), Betroffen, Beschreibung und Massnahme (Markdown ohne HTML, Vorschau nur
  über SafeMarkdown), ATT&CK und CVE (Hypothese ohne eigenen Beleg markiert), Belege (öffnen,
  entfernen; neue aus «Als Finding» bzw. «Zu Finding hinzufügen»), Speichern (⌘↵), Herkunft,
  Verlauf, Löschen als Entscheid mit Grund. Warnungen (Beleg misstraut, fehlt) oben. Fehler stehen
  im Formular. Ändert jemand das Finding anderswo, während hier ungespeicherte Änderungen stehen,
  erscheint ein Hinweis; sonst übernimmt das Formular den neuen Stand. Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import type { FindingDetail, FindingEvidence, Severity } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import { registerKeys } from '../keys/keymap';
  import SafeMarkdown from '../safe/SafeMarkdown.svelte';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Button from '../ui/Button.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import Txt from '../ui/Txt.svelte';
  import { encodeEvidence, url } from '../url/state.svelte';
  import { hhmm } from '../util/time';
  import AffectedPicker from './AffectedPicker.svelte';
  import { cleanTitle, formFrom, isDirty, SEVERITIES, TEXT_MAX, TITLE_MAX, validate, type FindingForm, type NewEvidence, type RefEntry } from './form';
  import RefList from './RefList.svelte';

  let {
    app,
    project,
    base,
    initial,
    draft = null,
    onsaved,
  }: {
    app: AppState;
    project: ProjectStore;
    /** gespeicherter Stand, null bei einem neuen Finding */
    base: FindingDetail | null;
    initial: FindingForm;
    /** vorgefüllter Beleg aus der Belegansicht («Als Finding») */
    draft?: NewEvidence | null;
    onsaved: (id: string | null) => void;
  } = $props();
  const SEP = ' · ';

  // Absicht: Der Formularstand beginnt mit `initial`; spätere Änderungen von `initial` übernimmt
  // der Effekt unten nur, solange nichts ungespeichert ist.
  let form = $state<FindingForm>(untrack(() => $state.snapshot(initial) as FindingForm));
  let baseSeen = $state(untrack(() => base?.updated_at ?? null));
  let elsewhere = $state(false);
  let errors = $state<ReturnType<typeof validate>>({});
  let saveError = $state<string | null>(null);
  let savedNote = $state(false);
  let noChange = $state(false);
  let preview = $state<{ description: boolean; remediation: boolean }>({ description: false, remediation: false });
  let deleting = $state(false);
  let deleteReason = $state('');
  let deleteError = $state<string | null>(null);

  // Neuer Stand vom Server (anderer Tab, Belegzustand nach Reparse)
  $effect(() => {
    const b = base;
    if (!b || b.updated_at === baseSeen) return;
    baseSeen = b.updated_at;
    if (isDirty(form, b) && !savedNote) {
      elsewhere = true;
    } else {
      form = formFrom(b);
      elsewhere = false;
    }
  });

  const dirty = $derived(isDirty(form, base));
  const sevOptions = $derived(SEVERITIES.map((s) => ({ value: s, label: t(`fd.sev.${s}` as MessageKey) })));
  const statusOptions = $derived([
    { value: 'draft' as const, label: t('fd.status.draft') },
    { value: 'final' as const, label: t('fd.status.final') },
  ]);
  const okEvidence = $derived((base?.evidence ?? []).some((e) => e.state === 'ok' && !form.evidenceRemove.includes(e.evidence_id)) || form.evidenceAdd.length > 0);
  const saving = $derived(project.findings.saving);
  const created = $derived(base?.created_from ?? null);

  function hypothesisOf(list: { id: string; supported: boolean; hypothesis: boolean }[]) {
    return (e: RefEntry): boolean => {
      const server = list.find((x) => x.id === e.id && x.supported === e.supported);
      if (server && !dirty) return server.hypothesis;
      return !(e.supported && okEvidence);
    };
  }

  function setSeverity(v: Severity): void {
    form.severity = v;
    if (errors.status) errors = validate(form);
  }

  function setStatus(v: 'draft' | 'final'): void {
    form.status = v;
    errors = { ...errors, status: validate(form).status };
  }

  async function save(): Promise<void> {
    if (saving) return;
    form.title = cleanTitle(form.title);
    errors = validate(form);
    saveError = null;
    if (Object.keys(errors).length > 0) return;
    if (base && !dirty) {
      noChange = true;
      setTimeout(() => (noChange = false), 2500);
      return;
    }
    const res = await project.findings.save($state.snapshot(form) as FindingForm, base);
    if (!res.ok) {
      saveError = res.error;
      return;
    }
    savedNote = true;
    setTimeout(() => (savedNote = false), 2500);
    if (base) {
      form.evidenceAdd = [];
      form.evidenceRemove = [];
    }
    elsewhere = false;
    onsaved(res.id);
  }

  function openEvidence(ref: FindingEvidence['ref']): void {
    if (ref.claim_key) url.set({ beleg: encodeEvidence({ kind: 'claim', claim_key: ref.claim_key }) }, { push: true });
    else if (ref.unit_id) url.set({ beleg: encodeEvidence({ kind: 'unit', unit_id: ref.unit_id, lines: ref.lines }) }, { push: true });
  }

  function toggleRemove(id: string): void {
    form.evidenceRemove = form.evidenceRemove.includes(id) ? form.evidenceRemove.filter((x) => x !== id) : [...form.evidenceRemove, id];
  }

  async function remove(): Promise<void> {
    if (!base) return;
    deleteError = await project.findings.remove(base.finding_id, deleteReason);
    if (!deleteError) deleting = false;
  }

  function historyText(kind: string): string {
    if (kind === 'd.finding.create') return t('fd.hist.create');
    if (kind === 'd.finding.update') return t('fd.hist.update');
    if (kind === 'd.finding.evidence.add') return t('fd.hist.evidenceAdd');
    if (kind === 'd.finding.evidence.remove') return t('fd.hist.evidenceRemove');
    return t('fd.hist.other');
  }

  onMount(() =>
    registerKeys([{ keys: ['Mod+Enter'], allowInInput: true, when: () => url.route === 'findings' && !url.get('beleg'), run: () => void save() }]),
  );
</script>

<form
  class="form"
  aria-label={base ? t('fd.title') : t('fd.newTitle')}
  onsubmit={(e) => {
    e.preventDefault();
    void save();
  }}
  novalidate
>
  {#if base && base.warnings.some((w) => w === 'evidence_distrusted' || w === 'evidence_missing')}
    <div class="warnings" role="note">
      {#each base.warnings.filter((w) => w === 'evidence_distrusted' || w === 'evidence_missing') as w (w)}
        <p><span class="bang" aria-hidden="true">!</span>{t(`fd.warn.${w}` as MessageKey)}</p>
      {/each}
    </div>
  {/if}
  {#if elsewhere}<p class="elsewhere" role="status">{t('fd.f.changedElsewhere')}</p>{/if}

  <div class="field">
    <label for="fd-title">{t('fd.f.title')}</label>
    <input
      id="fd-title"
      class="title"
      class:invalid={!!errors.title}
      bind:value={form.title}
      maxlength={TITLE_MAX + 20}
      autocomplete="off"
      oninput={() => {
        form.title = cleanTitle(form.title);
        if (errors.title) errors = { ...errors, title: undefined };
      }}
    />
    {#if errors.title}<p class="err" role="alert">{t(errors.title)}</p>{/if}
  </div>

  <div class="row2">
    <div class="field">
      <span class="lbl" id="fd-sev-l">{t('fd.f.severity')}</span>
      <Segmented options={sevOptions} value={form.severity} onchange={setSeverity} label={t('fd.f.severity')} disabled={saving} />
    </div>
    <div class="field">
      <span class="lbl">{t('fd.f.status')}</span>
      <Segmented options={statusOptions} value={form.status} onchange={setStatus} label={t('fd.f.status')} disabled={saving} />
      {#if errors.status}<p class="err" role="alert">{t(errors.status)}</p>{/if}
    </div>
  </div>

  <div class="field">
    <span class="lbl">{t('fd.f.affected')}</span>
    <AffectedPicker {app} {project} entries={form.affected} onchange={(v) => (form.affected = v)} disabled={saving} />
    {#if errors.affected}<p class="err" role="alert">{t(errors.affected)}</p>{/if}
  </div>

  <div class="grid">
    {#each ['description', 'remediation'] as const as k (k)}
      <div class="field">
        <span class="lblrow">
          <label for="fd-{k}">{t(k === 'description' ? 'fd.f.description' : 'fd.f.remediation')}</label>
          <button type="button" class="link" aria-pressed={preview[k]} onclick={() => (preview = { ...preview, [k]: !preview[k] })}
            >{preview[k] ? t('fd.f.edit') : t('fd.f.preview')}</button
          >
        </span>
        {#if preview[k]}
          <div class="md" id="fd-{k}">
            {#if form[k].trim()}<SafeMarkdown source={form[k]} />{:else}<span class="muted">{t('fd.f.empty')}</span>{/if}
          </div>
        {:else}
          <textarea id="fd-{k}" class:invalid={!!errors[k]} bind:value={form[k]} rows="5" maxlength={TEXT_MAX} placeholder={t('fd.f.empty')}></textarea>
        {/if}
        {#if errors[k]}<p class="err" role="alert">{t(errors[k] as MessageKey)}</p>{/if}
      </div>
    {/each}
  </div>

  <div class="grid">
    <RefList kind="attack" label={t('fd.f.attack')} entries={form.attack} hypothesis={hypothesisOf(base?.attack ?? [])} onchange={(v) => (form.attack = v)} disabled={saving} />
    <RefList kind="cve" label={t('fd.f.cve')} entries={form.cves} hypothesis={hypothesisOf(base?.cves ?? [])} onchange={(v) => (form.cves = v)} disabled={saving} />
  </div>

  <div class="field">
    <span class="lbl">{t('fd.f.evidence')}</span>
    <div class="evidence">
      {#each base?.evidence ?? [] as e (e.evidence_id)}
        {@const removed = form.evidenceRemove.includes(e.evidence_id)}
        <div class="ev" class:removed>
          <span class="evl">
            <Txt value={e.label} max={120} ctrl={e.ctrl} />{#if e.ts}<span class="muted">{SEP}{hhmm(e.ts, { seconds: true })}</span>{/if}
            {#if e.state === 'distrusted'}<span class="badge warn">{t('fd.ev.distrusted')}</span>{:else if e.state === 'missing'}<span class="badge warn">{t('fd.ev.missing')}</span>{/if}
            {#if removed}<span class="badge">{t('fd.f.evidenceRemoved')}</span>{/if}
          </span>
          <span class="evact">
            {#if e.state !== 'missing'}
              <button type="button" class="link" aria-label={t('fd.f.openFor', { label: e.label })} onclick={() => openEvidence(e.ref)}>{t('fd.f.open')}</button>
            {/if}
            <button type="button" class="link" disabled={saving} aria-label={t('fd.f.evidenceRemoveFor', { label: e.label })} onclick={() => toggleRemove(e.evidence_id)}
              >{removed ? t('fd.f.evidenceKeep') : t('fd.f.evidenceRemove')}</button
            >
          </span>
        </div>
      {/each}
      {#each form.evidenceAdd as n, i (i)}
        <div class="ev new">
          <span class="evl"><Txt value={n.label} max={120} /><span class="badge">{t('fd.f.evidenceNew')}</span></span>
          <span class="evact">
            <button type="button" class="link" aria-label={t('fd.f.evidenceRemoveFor', { label: n.label })} onclick={() => (form.evidenceAdd = form.evidenceAdd.filter((_, j) => j !== i))}
              >{t('fd.f.evidenceRemove')}</button
            >
          </span>
        </div>
      {/each}
      {#if (base?.evidence.length ?? 0) === 0 && form.evidenceAdd.length === 0}
        <p class="empty">{t('fd.f.evidenceEmpty')}</p>
      {/if}
    </div>
  </div>

  <div class="save">
    <Button variant="primary" type="submit" kbd="⌘↵" disabled={saving || app.offline} reason={saving ? t('fd.f.saving') : t('term.offline')}
      >{saving ? t('fd.f.saving') : t('fd.f.save')}</Button
    >
    <span class="origin">
      {#if savedNote}{t('fd.f.saved')}{SEP}{:else if noChange}{t('fd.f.noChanges')}{SEP}{/if}{t('fd.f.origin')}{#if created}{SEP}{t('fd.f.createdFrom')} <Txt value={created.label} max={80} />{:else if !base && draft}{SEP}{t('fd.f.createdFrom')} <Txt value={draft.label} max={80} />{/if}
    </span>
  </div>
  {#if saveError}<p class="error-box" role="alert">{saveError}</p>{/if}

  {#if base}
    <div class="foot">
      {#if base.history.length > 0}
        <p class="history">
          {t('fd.f.history')}:
          {#each base.history as h, i (h.decision_id)}{i > 0 ? ' · ' : ' '}{historyText(h.kind)} {hhmm(h.ts)}{/each}
        </p>
      {/if}
      {#if deleting}
        <div class="delete" role="group" aria-label={t('fd.f.deleteTitle')}>
          <strong>{t('fd.f.deleteTitle')}</strong>
          <p>{t('fd.f.deleteText')}</p>
          <label class="sr-only" for="fd-del-reason">{t('fd.f.deleteReason')}</label>
          <input id="fd-del-reason" bind:value={deleteReason} placeholder={t('fd.f.deleteReason')} maxlength="500" autocomplete="off" />
          <div class="btns">
            <Button variant="danger" disabled={app.offline} reason={t('term.offline')} onclick={() => void remove()}>{t('fd.f.deleteConfirm')}</Button>
            <Button onclick={() => (deleting = false)}>{t('common.cancel')}</Button>
          </div>
          {#if deleteError}<p class="err" role="alert">{deleteError}</p>{/if}
        </div>
      {:else}
        <button type="button" class="link danger" disabled={app.offline} onclick={() => (deleting = true)}>{t('fd.f.delete')}</button>
      {/if}
    </div>
  {/if}
</form>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: 18px;
    max-width: 900px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }
  label,
  .lbl {
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .lblrow {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
  }
  input,
  textarea {
    padding: 9px 12px;
    border-radius: 7px;
    border: var(--lw-1) solid var(--line-strong);
    background: var(--surface);
    color: var(--fg);
  }
  input:focus,
  textarea:focus {
    border-color: var(--focus);
    outline: none;
  }
  .title {
    font-size: var(--fs-l);
    font-weight: 600;
  }
  textarea {
    min-height: 96px;
    line-height: 1.5;
    resize: vertical;
    color: var(--fg-2);
  }
  textarea::placeholder,
  input::placeholder {
    color: var(--faint);
  }
  .invalid {
    border-color: var(--error);
  }
  .row2 {
    display: flex;
    gap: var(--sp-8);
    flex-wrap: wrap;
  }
  .grid {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: var(--sp-4);
  }
  .md {
    min-height: 96px;
    padding: 9px 12px;
    border-radius: 7px;
    border: var(--lw-1) solid var(--line-strong);
    background: var(--surface);
    color: var(--fg-2);
    line-height: 1.5;
    overflow-wrap: anywhere;
  }
  .md :global(p) {
    margin: 0 0 8px;
  }
  .evidence {
    display: flex;
    flex-direction: column;
    border: var(--lw-1) solid var(--line);
    border-radius: 8px;
  }
  .ev {
    display: flex;
    justify-content: space-between;
    gap: var(--sp-3);
    padding: 9px 12px;
  }
  .ev + .ev {
    border-top: var(--lw-1) solid var(--line);
  }
  .ev.removed .evl {
    text-decoration: line-through;
    color: var(--faint);
  }
  .evl {
    min-width: 0;
    overflow-wrap: anywhere;
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    align-items: baseline;
  }
  .evact {
    display: flex;
    gap: var(--sp-3);
    flex: none;
  }
  .badge {
    padding: 0 6px;
    border-radius: var(--r-badge);
    border: var(--lw-1) solid var(--line-strong);
    font-size: 11.5px;
    color: var(--muted);
  }
  .badge.warn {
    border-color: var(--attention);
    color: var(--attention);
  }
  .empty {
    margin: 0;
    padding: 9px 12px;
    color: var(--muted);
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    cursor: pointer;
    font-size: var(--fs-s);
  }
  .link:hover:not(:disabled) {
    color: var(--fg);
    text-decoration: underline;
  }
  .link:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }
  .danger {
    color: var(--error);
  }
  .save {
    display: flex;
    gap: var(--sp-2);
    align-items: center;
    flex-wrap: wrap;
  }
  .origin {
    color: var(--faint);
    font-size: var(--fs-s);
  }
  .muted {
    color: var(--muted);
  }
  .err {
    margin: 0;
    color: var(--error);
    font-size: var(--fs-s);
  }
  .error-box {
    margin: 0;
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--error);
    padding: var(--sp-3) 14px;
  }
  .warnings {
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--line);
    padding: var(--sp-3) 14px;
  }
  .warnings p {
    margin: 0;
    display: flex;
    gap: 10px;
  }
  .bang {
    color: var(--attention);
    font-weight: 700;
  }
  .elsewhere {
    margin: 0;
    color: var(--attention);
    font-size: var(--fs-s);
  }
  .foot {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--sp-4);
    border-top: var(--lw-1) solid var(--line);
    padding-top: var(--sp-3);
  }
  .history {
    margin: 0;
    color: var(--faint);
    font-size: var(--fs-xs);
  }
  .delete {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    max-width: 420px;
    border: var(--lw-1) solid var(--error);
    border-radius: var(--r-card);
    padding: var(--sp-3);
  }
  .delete p {
    margin: 0;
    color: var(--fg-2);
    font-size: var(--fs-s);
  }
  .btns {
    display: flex;
    gap: var(--sp-2);
  }
</style>
