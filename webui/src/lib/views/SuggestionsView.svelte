<!--
  Denkanstösse aus Regeln und KI. KI nur auf Knopfdruck; das Modell sieht nur das
  Lagebild (Architektur 6.3). Lernmodus: Stufen erscheinen einzeln.
-->
<script lang="ts">
  import type { StreamPayloads, Status } from '../api/types';
  import { t } from '../i18n';
  import type { ProjectStore } from '../stores/project.svelte';
  import { errText } from '../util/errors';
  import { readPref, writePref } from '../util/prefs';
  import SuggestionCard from './SuggestionCard.svelte';

  let { project, status, jobs }: { project: ProjectStore; status: Status | null; jobs: Record<string, StreamPayloads['progress']> } = $props();

  let learning = $state(readPref<boolean | null>('ariadne.learning', null, (v): v is boolean => typeof v === 'boolean') ?? true);
  let showClosed = $state(false);
  let error = $state<string | null>(null);
  let requesting = $state(false);

  const list = $derived(project.suggestions.filter((s) => showClosed || s.status === 'open'));
  const aiJobs = $derived(Object.values(jobs).filter((j) => j.kind === 'ai.denkanstoss'));
  const running = $derived(aiJobs.filter((j) => j.status === 'queued' || j.status === 'running'));
  const failed = $derived(aiJobs.filter((j) => j.status === 'failed' || j.status === 'refused'));
  const llmReady = $derived(!!status && status.llm.mode !== 'off' && status.llm.available);

  function setLearning(v: boolean) {
    learning = v;
    writePref('ariadne.learning', v);
  }

  async function request() {
    error = null;
    requesting = true;
    try {
      await project.backend.denkanstoss(project.pid, {});
    } catch (e) {
      error = errText(e);
    } finally {
      requesting = false;
    }
  }

  async function decide(key: string, done: boolean) {
    error = null;
    try {
      await project.backend.decide(project.pid, [{ kind: done ? 'd.suggestion.done' : 'd.suggestion.dismiss', payload: { suggestion_key: key } }]);
    } catch (e) {
      error = errText(e);
    }
  }
</script>

<section class="view" aria-labelledby="sg-title">
  <div class="view-head">
    <h1 id="sg-title">{t('sg.title')}</h1>
    <button type="button" class="primary" disabled={!llmReady || requesting || running.length > 0} onclick={request} title={t('sg.requestHint')}>
      {t('sg.request')}
    </button>
    <label class="row small" title={t('sg.learningHint')}>
      <input type="checkbox" checked={learning} onchange={(e) => setLearning((e.currentTarget as HTMLInputElement).checked)} />
      {t('sg.learning')}
    </label>
    <label class="row small">
      <input type="checkbox" bind:checked={showClosed} />
      {t('sg.showClosed')}
    </label>
  </div>
  <p class="muted small">{t('sg.noExec')} {t('sg.requestHint')}</p>
  {#each running as j (j.job_id)}
    <p class="job small" role="status">{t('sg.job', { msg: j.message ?? j.status })}</p>
  {/each}
  {#each failed as j (j.job_id)}
    <p class="error small" role="alert">{j.status === 'refused' ? t('sg.refused') : t('sg.failed')}</p>
  {/each}
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#if list.length === 0}
    <p class="muted">{t('sg.empty')}</p>
  {/if}
  <div class="cards">
    {#each list as s (s.suggestion_key)}
      <SuggestionCard {s} {learning} onDone={() => decide(s.suggestion_key, true)} onDismiss={() => decide(s.suggestion_key, false)} />
    {/each}
  </div>
</section>

<style>
  .cards {
    display: grid;
    gap: 12px;
    max-width: 960px;
  }
  .job {
    color: var(--badge-ai-text);
  }
</style>
