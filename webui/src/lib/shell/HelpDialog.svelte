<!--
  Hilfe `?` (Screen 10, BEHAVIOR «Tastatur»): Kürzel des Dashboards und des Terminals. Einzeltasten
  wirken nur mit Fokus ausserhalb von Eingabefeldern; in Dialogen sind sie aus. Texte fest (i18n).
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t, type MessageKey } from '../i18n';
  import { modLabel } from '../keys/keymap';
  import Dialog from '../ui/Dialog.svelte';

  let { onclose }: { onclose: () => void } = $props();

  const DASH: [string, MessageKey][] = [
    [modLabel('K'), 'help.k.palette'],
    ['1 bis 4', 'help.k.tabs'],
    ['j k ↵', 'help.k.lists'],
    ['a x e u', 'help.k.decide'],
    ['Tab, Pfeile', 'help.k.hosts'],
    ['+ − 0', 'help.k.zoom'],
    ['t', 'help.k.table'],
    ['n', 'help.k.nextSuggestion'],
    ['⇧P', 'help.k.presentation'],
    ['?', 'help.k.help'],
    ['Esc', 'help.k.close'],
  ];
  const TERM: [string, MessageKey][] = [
    ['F12 r', 'help.t.pause'],
    ['F12 h / b', 'help.t.host'],
    ['F12 k / s', 'help.t.keystep'],
  ];
</script>

<Dialog title={t('help.title')} {onclose} size="m">
  <h3 class="cap">{t('help.dashboard')}</h3>
  <dl>
    {#each DASH as [k, label] (label)}<dt><kbd>{k}</kbd></dt><dd>{t(label)}</dd>{/each}
  </dl>
  <h3 class="cap second">{t('help.terminal')}</h3>
  <dl>
    {#each TERM as [k, label] (label)}<dt><kbd>{k}</kbd></dt><dd>{t(label)}</dd>{/each}
  </dl>
</Dialog>

<style>
  dl {
    display: grid;
    grid-template-columns: 96px minmax(0, 1fr);
    gap: 7px var(--sp-3);
    margin: 0;
    font-size: 13px;
  }
  .cap {
    margin: 0 0 7px;
    font-weight: 400;
    color: var(--faint);
    font-size: 11.5px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .second {
    margin-top: 13px;
  }
  dd {
    margin: 0;
  }
  kbd {
    font-family: var(--font-mono);
    color: var(--muted);
  }
</style>
