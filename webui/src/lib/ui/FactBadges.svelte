<!-- Kennzeichen eines Werts: KI, vom Ziel angeboten, Injection-Verdacht, Konflikt. -->
<script lang="ts">
  import { t } from '../i18n';
  import Badge from './Badge.svelte';

  let { ai = false, offered = false, injection = false, conflict = false }: { ai?: boolean; offered?: boolean; injection?: boolean; conflict?: boolean } = $props();
</script>

{#if ai}<Badge tone="ai" title={t('badge.aiTitle')}>{t('badge.ai')}</Badge>{/if}
{#if offered}<Badge tone="warn" title={t('badge.offeredTitle')}>{t('badge.offered')}</Badge>{/if}
{#if injection}<Badge tone="danger">{t('badge.injection')}</Badge>{/if}
{#if conflict}<Badge tone="warn">{t('badge.conflict')}</Badge>{/if}
