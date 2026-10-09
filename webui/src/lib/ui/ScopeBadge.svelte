<script lang="ts">
  import type { VerdictKind } from '../api/types';
  import { t } from '../i18n';
  import Badge from './Badge.svelte';

  let { verdict }: { verdict: VerdictKind } = $props();
  const tone = $derived(verdict === 'in' ? 'ok' : verdict === 'unknown' ? 'warn' : 'danger');
</script>

<Badge {tone}>{t(`scope.${verdict}`)}</Badge>
