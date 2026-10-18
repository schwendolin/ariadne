<!--
  Dialog «Bericht exportieren» (Screen 10): Vorlage cys/htb, Phasen geprüft, Credentials verdeckt,
  Warnungen, Liste der Exporte. In v0.1 antwortet der Daemon 501: der Dialog zeigt den klaren
  Hinweis, alle Knöpfe ausser Schliessen sind gesperrt. Besitzer: ui-verlauf. Gerüst aus Phase 1.
-->
<script lang="ts">
  import { t } from '../i18n';
  import Dialog from '../ui/Dialog.svelte';

  let { onclose }: { onclose: () => void } = $props();
</script>

<Dialog title={t('export.title')} {onclose} size="m">
  <p>{t('export.later')}</p>
</Dialog>
