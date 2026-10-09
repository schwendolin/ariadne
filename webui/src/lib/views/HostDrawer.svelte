<!--
  Host-Detail als Schublade rechts; die Karte bleibt sichtbar (Architektur 7.4).
  Adressen, drei Status-Achsen, Tags, Services, Credentials, Fakten mit Quelle und
  Konflikten, Notizen (SafeMarkdown), Screenshots und Befehle in diesem Kontext.
  Jede Änderung ist ein Entscheid (POST /decisions).
-->
<script lang="ts">
  import type { AccessLevel, DecisionInput, HostDetail, Keystep, WorkStatus } from '../api/types';
  import { t } from '../i18n';
  import { router } from '../router.svelte';
  import SafeMarkdown from '../safe/SafeMarkdown.svelte';
  import { punycodeHint } from '../safe/displaySafe';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import ConfBadge from '../ui/ConfBadge.svelte';
  import FactBadges from '../ui/FactBadges.svelte';
  import ScopeBadge from '../ui/ScopeBadge.svelte';
  import Txt from '../ui/Txt.svelte';
  import { errText } from '../util/errors';
  import { predLabel, shortId } from '../util/labels';
  import { timeLocal, utcTooltip } from '../util/time';

  let { project, hostId }: { project: ProjectStore; hostId: string } = $props();

  const WORK: WorkStatus[] = ['open', 'in_progress', 'dead_end', 'done', 'out_of_scope'];
  const ACCESS: AccessLevel[] = ['none', 'user', 'admin'];
  const STEPS: Keystep[] = ['foothold', 'privesc', 'pivot', 'loot'];

  let host = $state<HostDetail | null>(null);
  let error = $state<string | null>(null);
  let notFound = $state(false);
  let noteEdit = $state(false);
  let noteDraft = $state('');
  let notePreview = $state(false);
  let tagDraft = $state('');
  let reasonDraft = $state('');
  let shotUrls = $state<Record<string, string>>({});

  $effect(() => {
    const id = hostId;
    void project.version;
    const ctrl = new AbortController();
    notFound = false;
    project.backend
      .host(project.pid, id, ctrl.signal)
      .then((h) => {
        host = h;
        reasonDraft = h.work_reason ?? '';
        for (const s of h.shots) {
          if (!shotUrls[s.blob_id]) {
            project.blobUrl(s.blob_id).then((u) => (shotUrls = { ...shotUrls, [s.blob_id]: u })).catch(() => undefined);
          }
        }
      })
      .catch((e) => {
        if (ctrl.signal.aborted) return;
        host = null;
        notFound = true;
        error = errText(e);
      });
    return () => ctrl.abort();
  });

  async function decide(d: DecisionInput) {
    error = null;
    try {
      await project.backend.decide(project.pid, [d]);
    } catch (e) {
      error = errText(e);
    }
  }

  function setWork(value: WorkStatus) {
    if (!host) return;
    void decide({ kind: 'd.status.work', payload: { subject: host.id, value, reason: value === 'dead_end' ? reasonDraft || null : null } });
  }

  function setAccess(value: AccessLevel) {
    if (!host) return;
    void decide({ kind: 'd.status.access', payload: { subject: host.id, value } });
  }

  function addTag(e: SubmitEvent) {
    e.preventDefault();
    const tag = tagDraft.trim();
    if (!host || !tag) return;
    tagDraft = '';
    void decide({ kind: 'd.tag.add', payload: { subject: host.id, tag } });
  }

  function saveNote() {
    if (!host) return;
    noteEdit = false;
    void decide({ kind: 'd.note.set', payload: { subject: host.id, text: noteDraft } });
  }

  function markStep(step: Keystep) {
    if (!host) return;
    void decide({ kind: 'd.keystep.mark', payload: { step, host: host.id } });
  }

  function close() {
    router.setParam('host', null);
  }
</script>

<aside class="drawer" aria-labelledby="host-title">
  <header class="head">
    <div class="stack grow">
      <span class="muted small">{t('host.title')}</span>
      <h2 id="host-title">
        {#if host}
          {#if host.access === 'admin'}<span class="sym" aria-hidden="true">#</span>{:else if host.access === 'user'}<span class="sym" aria-hidden="true">$</span>{/if}<Txt value={host.label} max={60} />
        {:else}
          <Txt value={shortId(hostId)} max={60} />
        {/if}
      </h2>
    </div>
    <button type="button" class="ghost" onclick={close}>{t('common.close')}</button>
  </header>

  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#if notFound}
    <p class="muted">{t('host.notFound')}</p>
  {:else if !host}
    <p class="muted">{t('common.loading')}</p>
  {:else}
    <section>
      <div class="row badges">
        <ScopeBadge verdict={host.scope} />
        <ConfBadge level={host.confidence} />
        <Badge tone={host.claim_state === 'candidate' ? 'warn' : 'muted'}>{t(`claim.${host.claim_state}`)}</Badge>
        {#if host.on_thread}<Badge tone="danger">{t('host.onThread')}</Badge>{/if}
        <FactBadges ai={host.ai} conflict={host.conflicts > 0} />
      </div>
      <dl class="kv">
        <dt>{t('host.addresses')}</dt>
        <dd>{#each host.addresses as a (a)}<code><Txt value={a} /></code> {/each}</dd>
        {#if host.names.length}
          <dt>{t('host.names')}</dt>
          <dd>
            {#each host.names as n (n)}
              {@const puny = punycodeHint(n)}
              <div><Txt value={n} max={80} />{#if puny}<span class="muted small"> ({t('host.punycode', { p: puny })})</span>{/if}</div>
            {/each}
          </dd>
        {/if}
        {#if host.os}<dt>{t('host.os')}</dt><dd><Txt value={host.os} /></dd>{/if}
        <dt>{t('host.identifiers')}</dt>
        <dd>
          {#each host.identifiers as id (id.key)}
            <div class="row"><code><Txt value={id.key} max={80} /></code><ScopeBadge verdict={id.scope} /></div>
          {/each}
        </dd>
      </dl>
    </section>

    <section>
      <h3>{t('host.status')}</h3>
      <div class="axes">
        <div>
          <span class="muted small">{t('host.knowledge')}</span>
          <div>{t(`knowledge.${host.knowledge}`)}</div>
        </div>
        <label>
          <span class="muted small">{t('host.access')}</span>
          <select value={host.access} onchange={(e) => setAccess((e.currentTarget as HTMLSelectElement).value as AccessLevel)}>
            {#each ACCESS as a (a)}<option value={a}>{t(`access.${a}`)}</option>{/each}
          </select>
        </label>
        <label>
          <span class="muted small">{t('host.work')}</span>
          <select value={host.work} onchange={(e) => setWork((e.currentTarget as HTMLSelectElement).value as WorkStatus)}>
            {#each WORK as w (w)}<option value={w}>{t(`work.${w}`)}</option>{/each}
          </select>
        </label>
      </div>
      {#if host.work === 'dead_end'}
        <label class="stack reason">
          <span class="muted small">{t('host.workReason')}</span>
          <input type="text" bind:value={reasonDraft} onchange={() => setWork('dead_end')} />
        </label>
      {/if}
      <p class="small muted">{t('host.progress', { n: host.progress })}</p>
      <div class="row">
        <span class="muted small">{t('host.keystep')}:</span>
        {#each STEPS as s (s)}<button type="button" class="small" onclick={() => markStep(s)}>{t(`keystep.${s}`)}</button>{/each}
      </div>
    </section>

    <section>
      <h3>{t('host.tags')}</h3>
      <div class="row">
        {#each host.tags as tag (tag)}
          <span class="tag">
            <Txt value={tag} max={40} />
            <button
              type="button"
              class="ghost small"
              aria-label={t('host.removeTag', { tag })}
              onclick={() => decide({ kind: 'd.tag.remove', payload: { subject: host!.id, tag } })}>×</button>
          </span>
        {/each}
        <form class="row" onsubmit={addTag}>
          <input type="text" bind:value={tagDraft} maxlength="64" placeholder={t('host.addTag')} aria-label={t('host.addTag')} />
        </form>
      </div>
    </section>

    {#if host.services.length}
      <section>
        <h3>{t('host.services')} ({host.services.length})</h3>
        <table>
          <thead><tr><th>{t('col.port')}</th><th>{t('col.service')}</th><th>{t('col.version')}</th><th></th></tr></thead>
          <tbody>
            {#each host.services as s (s.service_id)}
              <tr class:fog={s.claim_state === 'candidate'}>
                <td class="mono">{s.port}/{s.proto}</td>
                <td><Txt value={s.name ?? ''} max={20} /></td>
                <td>
                  <Txt value={[s.product, s.version].filter(Boolean).join(' ')} max={48} />
                  {#each s.cves as c (c)} <Badge tone="danger">{c}</Badge>{/each}
                  <FactBadges ai={s.ai} conflict={s.conflicts > 0} />
                </td>
                <td>{#if s.fact_id}<button type="button" class="small ghost" onclick={() => router.setParam('fact', s.fact_id)}>{t('inbox.source')}</button>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {/if}

    {#if host.credentials.length}
      <section>
        <h3>{t('host.credentials')}</h3>
        <table>
          <thead><tr><th>{t('col.identity')}</th><th>{t('col.secret')}</th><th>{t('col.validOn')}</th></tr></thead>
          <tbody>
            {#each host.credentials as c (c.credential_id)}
              <tr>
                <td><Txt value={c.identity.name} max={40} /> <FactBadges ai={c.ai} offered={c.origin === 'target_offered'} /></td>
                <td class="mono">{c.secret_kind}: {c.secret_masked}</td>
                <td>{#each c.valid_on as v (v.service_id)}<div><Txt value={v.label} max={48} /></div>{:else}<span class="muted">{t('common.none')}</span>{/each}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {/if}

    <section>
      <h3>{t('host.facts')} ({host.facts.length})</h3>
      <table class="facts">
        <thead><tr><th>{t('col.predicate')}</th><th>{t('col.value')}</th><th>{t('col.confidence')}</th><th></th></tr></thead>
        <tbody>
          {#each host.facts as f (f.fact_id)}
            <tr class:fog={f.state === 'candidate'} class:rejected={f.state === 'rejected'}>
              <td>
                {predLabel(f.predicate)}
                {#if f.subject !== host.id}<div class="small muted"><Txt value={shortId(f.subject)} max={40} /></div>{/if}
              </td>
              <td><code><Txt value={f.value} max={60} /></code> <FactBadges ai={f.ai} offered={f.offered_by_target} injection={f.injection_suspect} conflict={!!f.conflict_key} /></td>
              <td><ConfBadge level={f.confidence_level} /></td>
              <td><button type="button" class="small ghost" onclick={() => router.setParam('fact', f.fact_id)}>{t('inbox.source')}</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>

    {#if host.conflicts_detail.length}
      <section>
        <h3>{t('host.conflicts')}</h3>
        {#each host.conflicts_detail as c (c.conflict_key)}
          <div class="card small">
            <strong>{predLabel(c.predicate)}</strong> · <Txt value={shortId(c.subject)} />
            <ul>
              {#each c.values as v (v.claim_key)}<li><code><Txt value={v.value} /></code> <span class="muted">({t(`trust.${v.trust}`)})</span></li>{/each}
            </ul>
          </div>
        {/each}
      </section>
    {/if}

    <section>
      <div class="row">
        <h3>{t('host.notes')}</h3>
        <div class="spacer"></div>
        {#if !noteEdit}
          <button type="button" class="small" onclick={() => { noteDraft = host?.note?.text ?? ''; noteEdit = true; notePreview = false; }}>{t('note.edit')}</button>
        {/if}
      </div>
      {#if noteEdit}
        {#if notePreview}
          <div class="card"><SafeMarkdown source={noteDraft} /></div>
        {:else}
          <textarea bind:value={noteDraft} placeholder={t('note.placeholder')} aria-label={t('host.notes')}></textarea>
        {/if}
        <div class="row">
          <button type="button" class="small" onclick={() => (notePreview = !notePreview)}>{t('note.preview')}</button>
          <div class="spacer"></div>
          <button type="button" class="small ghost" onclick={() => (noteEdit = false)}>{t('note.cancel')}</button>
          <button type="button" class="small primary" onclick={saveNote}>{t('note.save')}</button>
        </div>
      {:else if host.note}
        <SafeMarkdown source={host.note.text} />
        <p class="small muted"><time title={utcTooltip(host.note.updated_at)}>{timeLocal(host.note.updated_at)}</time></p>
      {:else}
        <p class="muted">{t('host.noNote')}</p>
      {/if}
    </section>

    {#if host.shots.length}
      <section>
        <h3>{t('host.shots')}</h3>
        <div class="shots">
          {#each host.shots as s (s.blob_id)}
            <figure>
              {#if shotUrls[s.blob_id]}<img src={shotUrls[s.blob_id]} alt={s.note ?? s.window_title ?? ''} />{/if}
              <figcaption class="small muted"><time title={utcTooltip(s.taken_at)}>{timeLocal(s.taken_at)}</time> · <Txt value={s.window_title ?? ''} max={40} /></figcaption>
            </figure>
          {/each}
        </div>
      </section>
    {/if}

    {#if host.commands.length}
      <section>
        <h3>{t('host.commands')}</h3>
        <ul class="cmds">
          {#each host.commands as c (c.cmd_id)}
            <li>
              <time class="small muted" title={utcTooltip(c.started_at)}>{timeLocal(c.started_at)}</time>
              <code><Txt value={c.text ?? '–'} max={90} /></code>
              {#if c.exit !== null}<span class="small muted">{t('tl.exit', { n: c.exit })}</span>{/if}
            </li>
          {/each}
        </ul>
      </section>
    {/if}
  {/if}
</aside>

<style>
  .drawer {
    position: absolute;
    top: 0;
    right: 0;
    bottom: 0;
    width: min(560px, 100%);
    overflow: auto;
    padding: 14px 16px 24px;
    background: var(--surface);
    border-left: 1px solid var(--border);
    box-shadow: var(--shadow);
    z-index: 20;
  }
  .head {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin-bottom: 8px;
  }
  .head h2 {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .grow {
    flex: 1;
    gap: 0;
  }
  .sym {
    margin-right: 0.4em;
    font-family: var(--font-mono);
    color: var(--text-muted);
  }
  section {
    margin: 14px 0;
  }
  .badges {
    gap: 4px;
  }
  .kv {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 12px;
    margin: 8px 0 0;
  }
  .kv dt {
    color: var(--text-muted);
  }
  .kv dd {
    margin: 0;
    min-width: 0;
  }
  .axes {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
  }
  .axes label {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .reason {
    margin-top: 8px;
    gap: 2px;
  }
  .tag {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding: 0 0 0 8px;
    border: 1px solid var(--border);
    border-radius: 999px;
    font-size: 0.85rem;
  }
  tr.fog td {
    opacity: 0.7;
    font-style: italic;
  }
  tr.rejected td {
    text-decoration: line-through;
    opacity: 0.6;
  }
  .shots {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .shots figure {
    margin: 0;
    width: 240px;
  }
  .shots img {
    width: 100%;
    border-radius: 4px;
    border: 1px solid var(--border);
  }
  .cmds {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }
</style>
