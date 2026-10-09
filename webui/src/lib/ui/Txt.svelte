<!--
  Text aus Zieldaten anzeigen. Svelte escapt HTML; displaySafe macht zusätzlich
  Steuer-, Bidi- und Zero-Width-Zeichen sichtbar und kürzt. Der volle Wert
  (ebenfalls sicher) steht im Tooltip.
-->
<script lang="ts">
  import { displaySafe, hasHiddenChars } from '../safe/displaySafe';
  import { t } from '../i18n';

  let { value, max = 120, mono = false }: { value: unknown; max?: number; mono?: boolean } = $props();

  const raw = $derived(typeof value === 'string' ? value : value === null || value === undefined ? '' : String(value));
  const shown = $derived(displaySafe(raw, max));
  const full = $derived(displaySafe(raw, 0));
  const hidden = $derived(hasHiddenChars(raw));
  const title = $derived(hidden ? `${full} (${t('badge.hidden')})` : shown !== full ? full : undefined);
</script>

<span class="txt" class:mono class:hidden {title}>{shown}</span>

<style>
  .txt {
    overflow-wrap: anywhere;
  }
  .hidden {
    text-decoration: underline dotted var(--target-underline);
    text-underline-offset: 3px;
  }
</style>
