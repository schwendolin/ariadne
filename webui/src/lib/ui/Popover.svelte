<!--
  Popover (Aufnahme, Out of Scope, Ebenen, Menü). Höchstens eines offen (UiStore.popover).
  Schliesst mit Esc und Klick ausserhalb; der Fokus geht zurück zum Auslöser. Kein Inline-Style:
  Lage über Klassen `align-left`/`align-right` relativ zum umgebenden Element (position: relative).
  Aussehen nach Screen 10 und 11: Radius 12, --surface-2, Rand --line-strong, 6 px Innenabstand;
  `flush` ohne Innenabstand (Aufnahme-Popover mit eigenen Abschnitten).
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { onDestroy } from 'svelte';
  import { restoreFocus } from '../keys/focus';
  import { registerKeys } from '../keys/keymap';
  import { fadeIn } from '../util/motion';
  import { clickOutside } from './actions';

  let {
    open,
    onclose,
    label,
    align = 'left',
    placement = 'below',
    wide = false,
    flush = false,
    children,
  }: {
    open: boolean;
    onclose: () => void;
    label: string;
    align?: 'left' | 'right';
    placement?: 'below' | 'above' | 'left';
    wide?: boolean;
    flush?: boolean;
    children: Snippet;
  } = $props();

  let trigger: Element | null = null;
  let off: (() => void) | null = null;

  $effect(() => {
    if (open) {
      trigger = document.activeElement;
      off = registerKeys([{ keys: ['Escape'], allowInInput: true, run: () => close() }]);
    } else {
      off?.();
      off = null;
    }
  });

  function close() {
    onclose();
    restoreFocus(trigger);
  }

  onDestroy(() => off?.());
</script>

{#if open}
  <div class="popover a-{align} p-{placement}" class:wide class:flush role="dialog" aria-label={label} use:clickOutside={() => onclose()} use:fadeIn>
    {@render children()}
  </div>
{/if}

<style>
  .popover {
    position: absolute;
    z-index: 40;
    min-width: 260px;
    max-width: 420px;
    background: var(--surface-2);
    border: var(--lw-1) solid var(--line-strong);
    border-radius: var(--r-dialog);
    box-shadow: var(--shadow);
    padding: 6px;
    color: var(--fg);
    font-size: var(--fs-m);
    text-align: left;
  }
  .flush {
    padding: 0;
    overflow: hidden;
  }
  .wide {
    min-width: 380px;
    max-width: 520px;
  }
  .p-below {
    top: calc(100% + 6px);
  }
  .p-above {
    bottom: calc(100% + 6px);
  }
  .a-left {
    left: 0;
  }
  .a-right {
    right: 0;
  }
  .p-left {
    top: 0;
    left: auto;
    right: calc(100% + 6px);
  }
</style>
