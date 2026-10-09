<script lang="ts">
  import type { ConfidenceLevel } from '../api/types';
  import { t } from '../i18n';
  import Badge from './Badge.svelte';

  let { level }: { level: ConfidenceLevel } = $props();
  const tone = $derived(level === 'high' ? 'muted' : level === 'medium' ? 'info' : 'warn');
</script>

<Badge {tone} title={t('conf.label')}>{t(`conf.${level}`)}</Badge>
