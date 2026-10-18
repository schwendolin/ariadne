<!--
  Text aus Zieldaten (Briefing 9.1, E13). Svelte escapt HTML; displaySafe macht zusätzlich
  Steuer-, Bidi- und Zero-Width-Zeichen sichtbar (<ESC>, <U+202E>) und kürzt auf `max`
  Codepoints mit «…». Der volle (ebenfalls sichere) Wert steht im title; er ist nur eine
  Abkürzung, den vollen Wert zeigt immer auch das Detail. `ctrl` (vom Server) oder gefundene
  Steuerzeichen ergeben das Kennzeichen «enthält Steuerzeichen». `target` unterstreicht gepunktet
  (Zieldaten in Vorlagen). Nie {@html}, nie Links. Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t } from '../i18n';
  import { displaySafe, hasHiddenChars } from '../safe/displaySafe';

  let {
    value,
    max = 120,
    mono = false,
    target = false,
    ctrl = false,
    flag = true,
  }: {
    value: unknown;
    max?: number;
    mono?: boolean;
    target?: boolean;
    /** vom Server: Steuerzeichen wurden sichtbar gemacht */
    ctrl?: boolean;
    /** Kennzeichen «enthält Steuerzeichen» zeigen */
    flag?: boolean;
  } = $props();

  const raw = $derived(typeof value === 'string' ? value : value === null || value === undefined ? '' : String(value));
  const shown = $derived(displaySafe(raw, max));
  const full = $derived(displaySafe(raw, 0));
  const hidden = $derived(ctrl || hasHiddenChars(raw) || /<(ESC|BEL|U\+[0-9A-F]{4,6}|0x[0-9A-F]{2})>/.test(raw));
  const title = $derived(hidden ? `${full} (${t('common.ctrl')})` : shown !== full ? full : undefined);
</script>

<span class="txt" class:mono class:target class:hidden {title}>{shown}</span>{#if hidden && flag}<span class="sr-only"> ({t('common.ctrl')})</span>{/if}

<style>
  .txt {
    overflow-wrap: anywhere;
  }
  .mono {
    font-family: var(--font-mono);
  }
  .target {
    text-decoration: underline dotted var(--muted);
    text-underline-offset: 3px;
  }
  .hidden {
    text-decoration: underline dotted var(--attention);
    text-underline-offset: 3px;
  }
</style>
