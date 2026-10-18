<!--
  Dialog «Screenshot der Kali» (Screen 10): Fenster, Monitor, Bereich, Countdown 3 s. In v0.1
  antwortet der Daemon 501: Hinweis, Knöpfe gesperrt. Besitzer: ui-verlauf. Gerüst aus Phase 1.
-->
<script lang="ts">
  import { t } from '../i18n';
  import Dialog from '../ui/Dialog.svelte';

  let { onclose }: { onclose: () => void } = $props();
</script>

<Dialog title={t('shot.title')} {onclose} size="s">
  <p>{t('shot.later')}</p>
</Dialog>
