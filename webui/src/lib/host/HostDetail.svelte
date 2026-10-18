<!--
  Host-Detail in der Spalte (SCREENS 3, Briefing 5.3, web-api.md 8 und 18.8). Ersetzt den Inhalt
  der Spalte; Kopf «← Als Nächstes» und `Esc` (Fokus zurück auf den Host, KarteView).
  - Kopf: Zugriffssymbol, Adresse, Betriebssystem bzw. «im Nebel».
  - Überblick: Zugriff (mit Entscheid und «ändern»), Wissen, Arbeitsstand (Menü, Sackgasse mit
    Grund), Faden-Schritte, offene Einträge zu diesem Host.
  - Host im Nebel: Erklärung, Annehmen `a`, Verwerfen `x` (über `candidate_claims`), Kennung, Quelle.
  - Services (ServicesBlock), Widersprüche mit Aktionen, Kennungen mit Scope-Urteil und Punycode,
    Tags, Notiz (SafeMarkdown), stille Zähler, Befehle in diesem Kontext (zur Zeitachse),
    Schlüsselschritt markieren, Secrets verdeckt (Aufdecken einzeln, «In die Kali»).
  - Kali: KaliDetail. Verschwundener Host: «nicht mehr da», zurück zur Liste.
  Jede Aktion ist ein Entscheid; Zieldaten nur über Txt, Notizen nur über SafeMarkdown.
  Besitzer: ui-karte.
-->
<script lang="ts">
  import { COMMA, DOT, PLUS, SP } from '../karte/sep';
  import { onMount } from 'svelte';
  import type { AccessLevel, Keystep, WorkStatus } from '../api/types';
  import { t } from '../i18n';
  import { registerKeys } from '../keys/keymap';
  import { hostSymbol } from '../karte/model';
  import SafeMarkdown from '../safe/SafeMarkdown.svelte';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Button from '../ui/Button.svelte';
  import Popover from '../ui/Popover.svelte';
  import SecretValue from '../ui/SecretValue.svelte';
  import TextField from '../ui/TextField.svelte';
  import Txt from '../ui/Txt.svelte';
  import { encodeEvidence, url } from '../url/state.svelte';
  import { hhmm } from '../util/time';
  import KaliDetail from './KaliDetail.svelte';
  import ServicesBlock from './ServicesBlock.svelte';

  let { app, project, hostId, onback }: { app: AppState; project: ProjectStore; hostId: string; onback: () => void } = $props();

  const store = $derived(project.host);
  const d = $derived(store.detail && store.detail.id === hostId ? store.detail : null);
  const node = $derived(project.map.host(hostId));
  const fog = $derived(d ? d.claim_state === 'candidate' : node?.claim_state === 'candidate');
  const blocked = $derived(store.busy ? t('host.loading') : app.offline ? t('err.network') : null);
  const WORK: WorkStatus[] = ['open', 'in_progress', 'dead_end', 'done', 'out_of_scope'];
  const ACCESS: AccessLevel[] = ['none', 'user', 'admin'];
  const STEPS: Keystep[] = ['foothold', 'privesc', 'pivot', 'loot'];
  const secrets = $derived(d?.facts.filter((f) => f.is_secret) ?? []);
  const namesOut = $derived(d?.identifiers.filter((i) => i.type !== 'ip' && i.type !== 'mac' && i.verdict !== 'in').map((i) => i.label) ?? []);
  const quietLine = $derived.by(() => {
    if (!d) return '';
    const parts: string[] = [];
    if (d.quiet.system_accounts > 0) parts.push(t('host.quiet.system', { n: d.quiet.system_accounts }));
    if (d.quiet.mentions > 0) parts.push(t('host.quiet.mentions', { n: d.quiet.mentions }));
    if (d.quiet.heuristic > 0) parts.push(t('host.quiet.heuristic', { n: d.quiet.heuristic }));
    if (d.quiet.out_of_scope > 0 && namesOut.length === 0) parts.push(t('host.quiet.out', { n: d.quiet.out_of_scope }));
    return parts.join(' · ');
  });

  let reasonOpen = $state(false);
  let reason = $state('');
  let tagOpen = $state(false);
  let tag = $state('');
  let tagError = $state<string | null>(null);
  let noteOpen = $state(false);
  let note = $state('');
  let stepNote = $state('');

  $effect(() => {
    void store.open(hostId);
  });

  function accessText(): string {
    if (!d) return '';
    const base = t(`host.access.${d.access}`);
    const by = d.access_by;
    if (!by || d.access === 'none') return base;
    return `${base}, ${t(`host.accessBy.${by.source}`, { time: hhmm(by.ts) })}`;
  }

  async function setWork(v: WorkStatus): Promise<void> {
    if (v === 'dead_end') {
      app.ui.closePopover('host-work');
      reason = d?.work_reason ?? '';
      reasonOpen = true;
      return;
    }
    app.ui.closePopover('host-work');
    await store.setWork(v);
  }

  async function saveDeadEnd(): Promise<void> {
    if (await store.setWork('dead_end', reason)) reasonOpen = false;
  }

  async function addTag(): Promise<void> {
    const v = tag.trim();
    if (!v) return;
    if (v.length > 64) {
      tagError = t('host.tagTooLong');
      return;
    }
    if (await store.addTag(v)) {
      tag = '';
      tagOpen = false;
      tagError = null;
    }
  }

  function editNote(): void {
    note = d?.note ?? '';
    noteOpen = true;
  }

  async function saveNote(): Promise<void> {
    if (await store.setNote(note)) noteOpen = false;
  }

  async function mark(step: Keystep): Promise<void> {
    app.ui.closePopover('host-step');
    await store.markStep(step, stepNote);
    stepNote = '';
  }

  function openItems(): void {
    const first = d?.open_items[0];
    url.set({ host: null, sel: first ?? null });
  }

  function openSource(): void {
    const u = d?.first_source;
    if (u) url.set({ beleg: encodeEvidence({ kind: 'unit', unit_id: u.unit_id, lines: null }) }, { push: true });
  }

  onMount(() =>
    registerKeys([
      { keys: ['a'], help: 'help.k.decide', when: () => fog && !!d && !app.offline, run: () => void store.decideFog(true) },
      { keys: ['x'], when: () => fog && !!d && !app.offline, run: () => void store.decideFog(false) },
    ]),
  );
</script>

<section class="detail" aria-label={t('host.cardHint')}>
  <header class="top">
    <button type="button" class="back" aria-label={t('host.backAria')} onclick={onback}>← {t('host.back')}</button>
    <span class="esc">{t('common.esc')}</span>
  </header>

  {#if hostId === 'kali'}
    <KaliDetail {app} {project} />
  {:else if store.gone}
    <div class="pad">
      <p class="muted">{t('host.gone')}</p>
      <Button onclick={onback}>{t('host.goneBack')}</Button>
    </div>
  {:else if !d}
    <p class="pad muted">{t('host.loading')}</p>
  {:else}
    {@const sym = hostSymbol(d)}
    <div class="id">
      <span class="sym s-{fog ? 'fog' : d.access}" class:dead={sym === '⊘'} aria-hidden="true">{sym}</span>
      <div class="idtext">
        <h2 class="label"><Txt value={d.label} mono ctrl={d.ctrl} max={80} /></h2>
        <span class="muted">{#if fog}{t('host.fog')}{:else if d.os}<Txt value={d.os} max={80} />{/if}</span>
      </div>
    </div>

    {#if fog}
      <p class="fogtext">{d.first_source?.ts ? t('host.fogTextAt', { time: hhmm(d.first_source.ts) }) : t('host.fogText')}</p>
      <div class="actions pad-x">
        <Button
          variant="primary"
          kbd="a"
          disabled={!!blocked || d.candidate_claims.length === 0}
          reason={blocked ?? (d.candidate_claims.length === 0 ? t('host.fogNoClaims') : null)}
          onclick={() => store.decideFog(true)}>{t('host.accept')}</Button
        >
        <Button
          kbd="x"
          disabled={!!blocked || d.candidate_claims.length === 0}
          reason={blocked ?? (d.candidate_claims.length === 0 ? t('host.fogNoClaims') : null)}
          onclick={() => store.decideFog(false)}>{t('host.reject')}</Button
        >
      </div>
      <div class="grid sep">
        <span class="k">{t('host.f.id')}</span><span><Txt value={d.label} mono max={80} /> · {t(`host.verdict.${d.identifiers.find((i) => i.key === d.id)?.verdict ?? 'in'}`)}</span>
        {#if d.first_source}
          <span class="k">{t('host.f.source')}</span>
          <span><button type="button" class="link" onclick={openSource}><Txt value={d.first_source.title} mono max={60} />{#if d.first_source.ts}{DOT}{hhmm(d.first_source.ts)}{/if} · {t('next.a.evidence')} ›</button></span>
        {/if}
        <span class="k">{t('host.f.services')}</span><span class="muted">{d.services.length === 0 ? t('host.noServices') : t('karte.services', { n: d.services.length })}</span>
      </div>
    {:else}
      <div class="grid">
        <span class="k">{t('host.f.access')}</span>
        <span class="rel">
          {accessText()}
          <button type="button" class="link faint" aria-haspopup="menu" aria-expanded={app.ui.popover === 'host-access'} disabled={!!blocked} onclick={() => app.ui.togglePopover('host-access')}>· {t('host.change')}</button>
          <Popover open={app.ui.popover === 'host-access'} onclose={() => app.ui.closePopover('host-access')} label={t('host.changeAccess')}>
            <div class="menu" role="menu">
              {#each ACCESS as a (a)}
                <button type="button" role="menuitemradio" aria-checked={d.access === a} class="mi" onclick={() => { app.ui.closePopover('host-access'); void store.setAccess(a); }}>{t(`host.access.${a}`)}</button>
              {/each}
            </div>
          </Popover>
        </span>
        <span class="k">{t('host.f.knowledge')}</span><span>{t(`host.knowledge.${d.knowledge}`)}</span>
        <span class="k">{t('host.f.work')}</span>
        <span class="rel">
          <button type="button" class="drop" aria-haspopup="menu" aria-expanded={app.ui.popover === 'host-work'} disabled={!!blocked} onclick={() => app.ui.togglePopover('host-work')}>
            {t(`host.work.${d.work}`)}{#if d.work === 'dead_end' && d.work_reason}{DOT}<Txt value={d.work_reason} max={40} />{/if} ▾
          </button>
          <Popover open={app.ui.popover === 'host-work'} onclose={() => app.ui.closePopover('host-work')} label={t('host.workMenu')}>
            <div class="menu" role="menu">
              {#each WORK as w (w)}
                <button type="button" role="menuitemradio" aria-checked={d.work === w} class="mi" onclick={() => setWork(w)}>{t(`host.work.${w}`)}</button>
              {/each}
            </div>
          </Popover>
        </span>
        {#if reasonOpen}
          <span class="k"></span>
          <span class="inline-form">
            <TextField id="host-dead-reason" label={t('host.workReason')} placeholder={t('host.workReasonPh')} bind:value={reason} maxlength={500} autofocus />
            <span class="actions">
              <Button variant="primary" size="s" disabled={!!blocked} reason={blocked} onclick={saveDeadEnd}>{t('host.workSave')}</Button>
              <Button size="s" onclick={() => (reasonOpen = false)}>{t('host.noteCancel')}</Button>
            </span>
          </span>
        {/if}
        <span class="k">{t('host.f.thread')}</span>
        <span class="thread">
          {#each d.thread as s (s.id)}
            <span><b class="seq">{s.seq}</b> {t(`karte.step.${s.step}`)}{#if s.note}{DOT}<Txt value={s.note} max={80} />{/if} · {hhmm(s.ts)}</span>
          {:else}
            <span class="muted">{t('host.noThread')}</span>
          {/each}
          <span class="rel">
            <button type="button" class="link faint" aria-haspopup="menu" aria-expanded={app.ui.popover === 'host-step'} disabled={!!blocked} onclick={() => app.ui.togglePopover('host-step')}>+ {t('host.markStep')}</button>
            <Popover open={app.ui.popover === 'host-step'} onclose={() => app.ui.closePopover('host-step')} label={t('host.markStep')}>
              <div class="menu">
                <TextField id="host-step-note" label={t('host.markStepNote')} bind:value={stepNote} maxlength={500} />
                {#each STEPS as st (st)}
                  <button type="button" class="mi" onclick={() => mark(st)}>{t(`karte.step.${st}`)}</button>
                {/each}
              </div>
            </Popover>
          </span>
        </span>
        <span class="k">{t('host.f.open')}</span>
        <span>
          {#if d.open_items.length > 0}
            <button type="button" class="link plain" onclick={openItems}>{t('host.openItems', { n: d.open_items.length })} ›</button>
          {:else}
            <span class="muted">{t('host.noOpen')}</span>
          {/if}
        </span>
      </div>
    {/if}

    {#if !fog}
      <div class="section-head"><span>{t('host.services')}</span><span class="n">{d.services.length}</span></div>
      {#if d.services.length === 0}
        <p class="pad-x muted">{t('host.noServices')}</p>
      {:else}
        <ServicesBlock services={d.services} />
      {/if}
    {/if}

    {#if d.conflicts.length > 0}
      <div class="section-head"><span>{t('host.conflicts')}</span><span class="n">{d.conflicts.length}</span></div>
      <div class="pad-x conflicts">
        {#each d.conflicts as c (c.conflict_key)}
          <div class="conflict">
            <span class="muted">{c.predicate}</span>
            {#each c.values as v (v.claim_key)}
              <span class="cv">
                <Txt value={v.value} mono ctrl={v.ctrl} max={80} />
                <span class="muted">{t('next.sources', { n: v.sources })}</span>
                {#if c.state === 'open'}<Button size="s" disabled={!!blocked} reason={blocked} onclick={() => store.resolveConflict(c.conflict_key, v.claim_key)}>{t('next.a.choose')}</Button>{/if}
              </span>
            {/each}
            {#if c.state === 'open'}<Button size="s" disabled={!!blocked} reason={blocked} onclick={() => store.resolveConflict(c.conflict_key, null)}>{t('next.a.keepOpen')}</Button>{/if}
          </div>
        {/each}
      </div>
    {/if}

    {#if secrets.length > 0}
      <div class="pad-x secrets">
        {#each secrets as f (f.claim_key)}
          <span class="cv">
            <span class="muted">{f.predicate}</span>
            <SecretValue secret={{ ref: 'claim', claim_key: f.claim_key }} pid={project.pid} backend={project.backend} presentation={app.presentation} profile={app.profile} />
          </span>
        {/each}
      </div>
    {/if}

    {#if d.identifiers.length > 1 && !fog}
      <div class="section-head"><span>{t('host.ids')}</span><span class="n">{d.identifiers.length}</span></div>
      <ul class="ids pad-x">
        {#each d.identifiers as i (i.key)}
          <li>
            <span class="mono"><Txt value={i.label} mono ctrl={i.ctrl} max={80} /></span>
            {#if i.punycode}<span class="muted mono"><Txt value={i.punycode} mono max={80} /></span>{/if}
            <span class="muted">{i.type} · {t(`host.verdict.${i.verdict}`)}</span>
          </li>
        {/each}
      </ul>
    {/if}

    <div class="foot-block" class:hidden={fog}>
      <div class="tags">
        {#each d.tags as tg (tg)}
          <span class="tag"><Txt value={tg} max={64} /><button type="button" class="x" aria-label={`${t('host.tagRemove')}: ${tg}`} disabled={!!blocked} onclick={() => store.removeTag(tg)}>×</button></span>
        {/each}
        {#if !tagOpen}
          <button type="button" class="tag add" disabled={!!blocked} onclick={() => (tagOpen = true)}>{t('host.addTag')}</button>
        {/if}
      </div>
      {#if tagOpen}
        <div class="inline-form">
          <TextField id="host-tag" label={t('host.tagLabel')} bind:value={tag} maxlength={64} error={tagError} autofocus />
          <span class="actions">
            <Button variant="primary" size="s" disabled={!!blocked} reason={blocked} onclick={addTag}>{t('host.noteSave')}</Button>
            <Button size="s" onclick={() => { tagOpen = false; tagError = null; }}>{t('host.noteCancel')}</Button>
          </span>
        </div>
      {/if}
      {#if noteOpen}
        <div class="inline-form">
          <TextField id="host-note" label={t('host.noteLabel')} bind:value={note} multiline rows={5} maxlength={100000} autofocus />
          <span class="actions">
            <Button variant="primary" size="s" disabled={!!blocked} reason={blocked} onclick={saveNote}>{t('host.noteSave')}</Button>
            <Button size="s" onclick={() => (noteOpen = false)}>{t('host.noteCancel')}</Button>
          </span>
        </div>
      {:else if d.note}
        <button type="button" class="note" title={t('host.noteEdit')} disabled={!!blocked} onclick={editNote}><SafeMarkdown source={d.note} /></button>
      {:else}
        <button type="button" class="tag add note-add" disabled={!!blocked} onclick={editNote}>{t('host.noteAdd')}</button>
      {/if}
      {#if quietLine || namesOut.length}
        <p class="quiet">{quietLine}{#if quietLine && namesOut.length}{DOT}{/if}{#each namesOut.slice(0, 4) as n, i (i)}{#if i > 0}{COMMA}{/if}<Txt value={n} max={60} />{/each}{#if namesOut.length > 4}{PLUS}{namesOut.length - 4}{/if}{#if namesOut.length}{SP}{t('host.verdict.out')}{/if}</p>
      {/if}
    </div>

    {#if d.commands.length > 0}
      <div class="section-head"><span>{t('host.commands')}</span><span class="n">{d.commands.length}</span></div>
      <ul class="cmds pad-x">
        {#each d.commands.slice(0, 10) as c (c.cmd_id)}
          <li>
            <button type="button" class="link plain cmd" onclick={() => url.go('zeitachse', { zeile: c.cmd_id, hostf: d.id })}>
              <span class="mono"><Txt value={c.text ?? c.cmd_ref} mono max={70} /></span><span class="muted">{hhmm(c.started_at)}</span>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</section>

<style>
  .detail {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    overflow: auto;
    font-size: var(--fs-m);
  }
  .top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 20px;
    font-size: var(--fs-s);
    color: var(--muted);
    border-bottom: var(--lw-1) solid var(--line);
    flex: none;
  }
  .back {
    padding: 0;
    border: none;
    background: none;
    color: var(--muted);
    font: inherit;
    cursor: pointer;
  }
  .back:hover {
    color: var(--fg);
  }
  .esc {
    font-family: var(--font-mono);
  }
  .pad {
    padding: 16px 20px;
  }
  .pad-x {
    padding-left: 20px;
    padding-right: 20px;
  }
  .muted {
    color: var(--muted);
  }
  .faint {
    color: var(--faint) !important;
  }
  .mono {
    font-family: var(--font-mono);
  }
  .id {
    display: flex;
    gap: 12px;
    align-items: flex-start;
    padding: 16px 20px 12px;
  }
  .sym {
    width: 36px;
    height: 36px;
    flex: none;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 19px;
    border: var(--lw-node) solid var(--line-strong);
  }
  .s-admin {
    background: var(--access-root);
    border-color: var(--access-root);
    color: var(--bg);
  }
  .s-user {
    background: var(--access-user);
    border-color: var(--access-user);
    color: var(--bg);
  }
  .s-fog {
    border-style: dotted;
    border-color: var(--fog);
  }
  .sym.dead {
    font-family: var(--font-ui);
    font-weight: 400;
    font-size: 17px;
    color: var(--muted);
  }
  .idtext {
    display: flex;
    flex-direction: column;
    gap: 3px;
    min-width: 0;
  }
  .label {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .fogtext {
    margin: 0;
    padding: 0 20px 14px;
    color: var(--fg-2);
    line-height: 1.5;
  }
  .grid {
    display: grid;
    grid-template-columns: 96px minmax(0, 1fr);
    gap: 8px 12px;
    padding: 0 20px 14px;
    font-size: 13px;
  }
  .grid.sep {
    margin-top: 16px;
    padding-top: 12px;
    border-top: var(--lw-1) solid var(--line);
  }
  .k {
    color: var(--muted);
  }
  .rel {
    position: relative;
  }
  .link {
    padding: 0;
    border: none;
    background: none;
    font: inherit;
    color: var(--muted);
    cursor: pointer;
    text-align: left;
  }
  .link.plain {
    color: var(--fg);
  }
  .link:hover:not(:disabled) {
    color: var(--fg);
    text-decoration: underline;
  }
  .drop {
    padding: 2px 8px;
    border-radius: 5px;
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    font: inherit;
    cursor: pointer;
  }
  .menu {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 180px;
  }
  .mi {
    padding: 6px 10px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--fg);
    text-align: left;
    font: inherit;
    cursor: pointer;
  }
  .mi:hover,
  .mi[aria-checked='true'] {
    background: var(--surface-3);
  }
  .thread {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .seq {
    color: var(--thread);
  }
  .actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .inline-form {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .section-head {
    display: flex;
    justify-content: space-between;
    padding: 10px 20px 6px;
    color: var(--muted);
    font-size: var(--fs-xs);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border-top: var(--lw-1) solid var(--line);
  }
  .n {
    font-family: var(--font-mono);
  }
  .conflicts,
  .secrets {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-bottom: 12px;
  }
  .conflict {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .cv {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .ids {
    list-style: none;
    margin: 0;
    padding-bottom: 12px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: var(--fs-s);
  }
  .ids li {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .foot-block.hidden {
    display: none;
  }
  .foot-block {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px 20px;
    border-top: var(--lw-1) solid var(--line);
  }
  .tags {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .tag {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: var(--r-pill);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    font: inherit;
    font-size: var(--fs-xs);
  }
  .tag.add {
    border-style: dashed;
    color: var(--muted);
    cursor: pointer;
    align-self: flex-start;
  }
  .x {
    padding: 0 0 0 2px;
    border: none;
    background: none;
    color: var(--muted);
    font: inherit;
    cursor: pointer;
  }
  .x:hover {
    color: var(--fg);
  }
  .note {
    display: block;
    width: 100%;
    padding: 9px 10px;
    border-radius: 7px;
    border: none;
    background: var(--surface-3);
    color: var(--fg-2);
    text-align: left;
    font: inherit;
    cursor: text;
  }
  .note :global(p) {
    margin: 0;
  }
  .quiet {
    margin: 0;
    font-size: var(--fs-s);
    color: var(--faint);
  }
  .cmds {
    list-style: none;
    margin: 0;
    padding-bottom: 16px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .cmd {
    display: flex;
    justify-content: space-between;
    gap: 8px;
    width: 100%;
    font-size: var(--fs-xs);
  }
</style>
