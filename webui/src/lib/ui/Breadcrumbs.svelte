<!-- Kontextstapel als Brotkrumen: Kali › lame.htb (root) › mysql. Unbekannt ist auffällig. -->
<script lang="ts">
  import type { StageView } from '../api/types';
  import { t } from '../i18n';
  import Txt from './Txt.svelte';

  let { stack }: { stack: StageView[] } = $props();
</script>

<ol class="crumbs">
  {#each stack as s (s.depth)}
    <li class:unknown={s.kind === 'unknown'} class:suspended={s.state === 'suspended'}>
      {#if s.depth === 0 && s.kind === 'local'}
        Kali
      {:else if s.kind === 'unknown'}
        <strong>{t('stage.unknown')}</strong>{#if s.candidate}<span class="small"> (<Txt value={s.candidate} max={40} />?)</span>{/if}
      {:else}
        <Txt value={s.host_label ?? s.host ?? '?'} max={40} />{#if s.user} <span class="muted">(<Txt value={s.user} max={24} />)</span>{/if}
        <span class="kind small muted">{t(`stage.${s.kind}`)}</span>
      {/if}
    </li>
  {/each}
</ol>

<style>
  .crumbs {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 2px;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  li {
    display: inline-flex;
    align-items: baseline;
    gap: 3px;
  }
  li + li::before {
    content: '›';
    margin: 0 4px;
    color: var(--text-muted);
  }
  .unknown {
    padding: 0 6px;
    border-radius: 4px;
    background: var(--badge-warn-bg);
    color: var(--badge-warn-text);
  }
  .suspended {
    opacity: 0.6;
  }
  .kind {
    font-size: 0.75rem;
  }
</style>
