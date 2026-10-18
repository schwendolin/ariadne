<!--
  Dialog «Kontext für T3 «listener»» (Screen 10, Briefing 5.4): Host als Freitext mit Vorschlägen
  (Vorschlag aus Callback, bekannt, unbekannter Host), Benutzer, «Gilt ab» (rückwirkend), Setzen
  über POST /terminals/{tid}/context, danach Warnungen (ausserhalb, ausgeschlossen, unbekannt).
  Fokus gefangen. Besitzer: ui-verlauf. Gerüst aus Phase 1.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Dialog from '../ui/Dialog.svelte';

  let {
    terminalId,
    onclose,
  }: {
    app: AppState;
    project: ProjectStore;
    terminalId: string;
    itemKey?: string | undefined;
    fromOff?: number | undefined;
    onclose: () => void;
  } = $props();
</script>

<Dialog title={t('ctx.title', { term: terminalId.slice(-8) })} {onclose} size="m">
  <p class="hint">{t('ctx.hint')}</p>
</Dialog>

<style>
  .hint {
    color: var(--faint);
    font-size: var(--fs-xs);
  }
</style>
