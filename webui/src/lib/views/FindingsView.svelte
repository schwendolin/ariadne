<!--
  Findings: Titel, Schweregrad, betroffene Assets, Belege, Massnahme, MITRE ATT&CK.
  Ein Fakt ist kein Finding: Findings entstehen nur durch den Nutzer (Entscheid d.finding).
-->
<script lang="ts">
  import type { Severity } from '../api/types';
  import { t } from '../i18n';
  import { router } from '../router.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Badge from '../ui/Badge.svelte';
  import Txt from '../ui/Txt.svelte';
  import { errText } from '../util/errors';
  import { dateTimeLocal, utcTooltip } from '../util/time';

  let { project }: { project: ProjectStore } = $props();

  const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  let creating = $state(false);
  let error = $state<string | null>(null);
  let form = $state({ title: '', severity: 'medium' as Severity, assets: '', description: '', mitigation: '', attack: '' });

  const findings = $derived([...project.findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]));

  function tone(s: Severity) {
    return s === 'critical' || s === 'high' ? 'danger' : s === 'medium' ? 'warn' : 'muted';
  }

  function split(s: string): string[] {
    return s.split(',').map((x) => x.trim()).filter(Boolean);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!form.title.trim()) return;
    error = null;
    const id = `F-${Date.now().toString(36).toUpperCase()}`;
    try {
      await project.backend.decide(project.pid, [{
        kind: 'd.finding',
        payload: {
          finding_id: id, action: 'create', title: form.title.trim(), severity: form.severity, assets: split(form.assets),
          description: form.description, mitigation: form.mitigation, attack_ids: split(form.attack),
        },
      }]);
      creating = false;
      form = { title: '', severity: 'medium', assets: '', description: '', mitigation: '', attack: '' };
    } catch (err) {
      error = errText(err);
    }
  }
</script>

<section class="view" aria-labelledby="fd-title">
  <div class="view-head">
    <h1 id="fd-title">{t('fd.title')}</h1>
    {#if !creating}<button type="button" class="primary" onclick={() => (creating = true)}>{t('fd.new')}</button>{/if}
  </div>
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#if creating}
    <form class="card stack new" onsubmit={save}>
      <label class="stack">{t('fd.titleField')}<input type="text" bind:value={form.title} required /></label>
      <label class="stack">{t('fd.severity')}
        <select bind:value={form.severity}>{#each SEVERITIES as s (s)}<option value={s}>{t(`severity.${s}`)}</option>{/each}</select>
      </label>
      <label class="stack">{t('fd.assets')}<input type="text" bind:value={form.assets} placeholder={t('fd.assetsHint')} /></label>
      <label class="stack">{t('fd.description')}<textarea bind:value={form.description}></textarea></label>
      <label class="stack">{t('fd.mitigation')}<textarea bind:value={form.mitigation}></textarea></label>
      <label class="stack">{t('fd.attack')}<input type="text" bind:value={form.attack} placeholder="T1210, T1078" /></label>
      <div class="row">
        <div class="spacer"></div>
        <button type="button" class="ghost" onclick={() => (creating = false)}>{t('fd.cancel')}</button>
        <button type="submit" class="primary">{t('fd.save')}</button>
      </div>
    </form>
  {/if}

  {#if findings.length === 0 && !creating}
    <p class="muted">{t('fd.empty')}</p>
  {/if}
  <div class="list">
    {#each findings as f (f.finding_id)}
      <article class="card">
        <header class="row">
          <Badge tone={tone(f.severity)}>{t(`severity.${f.severity}`)}</Badge>
          <span class="mono small muted">{f.finding_id}</span>
          <Badge tone="muted">{t(`fd.status.${f.status}`)}</Badge>
          <div class="spacer"></div>
          <time class="small muted" title={utcTooltip(f.updated_at)}>{dateTimeLocal(f.updated_at)}</time>
        </header>
        <h2><Txt value={f.title} max={200} /></h2>
        <dl class="kv">
          <dt>{t('fd.assets')}</dt>
          <dd>{#each f.assets as a (a.id)}<span class="asset"><Txt value={a.label} max={60} /></span>{/each}</dd>
          {#if f.description}<dt>{t('fd.description')}</dt><dd><Txt value={f.description} max={2000} /></dd>{/if}
          {#if f.mitigation}<dt>{t('fd.mitigation')}</dt><dd><Txt value={f.mitigation} max={2000} /></dd>{/if}
          {#if f.attack_ids.length}<dt>{t('fd.attack')}</dt><dd class="mono">{f.attack_ids.join(', ')}</dd>{/if}
          {#if f.cves.length}<dt>{t('fd.cves')}</dt><dd class="mono">{f.cves.join(', ')}</dd>{/if}
          {#if f.evidence.length}
            <dt>{t('fd.evidence')}</dt>
            <dd>
              {#each f.evidence as e, i (i)}
                {#if e.fact_id}<button type="button" class="small ghost" onclick={() => router.setParam('fact', e.fact_id)}><Txt value={e.label} max={60} /></button>{/if}
              {/each}
            </dd>
          {/if}
        </dl>
      </article>
    {/each}
  </div>
</section>

<style>
  .list {
    display: grid;
    gap: 12px;
    max-width: 960px;
  }
  .new {
    max-width: 720px;
    margin-bottom: 16px;
  }
  .new label {
    gap: 2px;
    color: var(--text-muted);
    font-size: 0.9rem;
  }
  h2 {
    margin: 8px 0;
    font-size: 1rem;
  }
  .kv {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 12px;
    margin: 0;
  }
  .kv dt {
    color: var(--text-muted);
  }
  .kv dd {
    margin: 0;
  }
  .asset {
    display: inline-block;
    margin-right: 8px;
  }
</style>
