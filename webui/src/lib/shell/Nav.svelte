<script lang="ts">
  import { t } from '../i18n';
  import { link, router, ROUTES, type RouteId } from '../router.svelte';
  import type { ProjectStore } from '../stores/project.svelte';

  let { project }: { project: ProjectStore | null } = $props();

  const counts = $derived<Partial<Record<RouteId, number>>>({
    inbox: project?.inbox?.open ?? 0,
    denkanstoesse: project?.suggestions.filter((s) => s.status === 'open').length ?? 0,
    terminals: project?.terminals.filter((x) => x.alive && x.stack.some((s) => s.kind === 'unknown')).length ?? 0,
  });
</script>

<nav aria-label={t('nav.label')}>
  <ul>
    {#each ROUTES as r (r)}
      <li>
        <a href={router.href(r)} use:link aria-current={router.route === r ? 'page' : undefined}>
          {t(`nav.${r}`)}
          {#if counts[r]}<span class="count" class:warn={r === 'terminals'}>{counts[r]}</span>{/if}
        </a>
      </li>
    {/each}
  </ul>
</nav>

<style>
  ul {
    display: flex;
    gap: 2px;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  a {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border-bottom: 2px solid transparent;
    color: var(--text-muted);
    text-decoration: none;
    font-weight: 600;
  }
  a:hover {
    color: var(--text);
  }
  a[aria-current='page'] {
    color: var(--text);
    border-bottom-color: var(--accent);
  }
  .count {
    min-width: 20px;
    padding: 0 6px;
    border-radius: 999px;
    background: var(--badge-info-bg);
    color: var(--badge-info-text);
    font-size: 0.75rem;
    text-align: center;
  }
  .count.warn {
    background: var(--badge-warn-bg);
    color: var(--badge-warn-text);
  }
</style>
