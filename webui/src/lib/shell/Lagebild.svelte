<!-- Lagebild-Streifen: Hosts entdeckt, gescannt, mit Zugriff, ungetestete Credential-Kombinationen, Inbox, Denkanstösse. -->
<script lang="ts">
  import { t } from '../i18n';
  import { link, router } from '../router.svelte';
  import type { ProjectStore } from '../stores/project.svelte';

  let { project }: { project: ProjectStore } = $props();

  const inScope = $derived(project.hosts.filter((h) => h.scope === 'in' && h.claim_state !== 'rejected'));
  const discovered = $derived(inScope.length);
  const scanned = $derived(inScope.filter((h) => h.knowledge !== 'discovered').length);
  const access = $derived(inScope.filter((h) => h.access !== 'none').length);
  const untested = $derived(project.credentials.reduce((n, c) => n + c.untested, 0));
  const inbox = $derived(project.inbox?.open ?? 0);
  const suggestions = $derived(project.suggestions.filter((s) => s.status === 'open').length);
</script>

<ul class="lage" aria-label={t('lage.label')}>
  <li><strong>{discovered}</strong> {t('lage.discovered')}</li>
  <li><strong>{scanned}</strong> {t('lage.scanned')}</li>
  <li class:hot={access > 0}><strong>{access}</strong> {t('lage.access')}</li>
  <li><strong>{untested}</strong> {t('lage.untested')}</li>
  <li><a href={router.href('inbox')} use:link><strong>{inbox}</strong> {t('lage.inbox')}</a></li>
  <li><a href={router.href('denkanstoesse')} use:link><strong>{suggestions}</strong> {t('lage.suggestions')}</a></li>
</ul>

<style>
  .lage {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 14px;
    margin: 0;
    padding: 0;
    list-style: none;
    font-size: 0.85rem;
    color: var(--text-muted);
  }
  strong {
    color: var(--text);
    font-variant-numeric: tabular-nums;
  }
  .hot strong {
    color: var(--map-user);
  }
  a {
    color: inherit;
    text-decoration: none;
  }
  a:hover {
    text-decoration: underline;
  }
</style>
