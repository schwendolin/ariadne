<!--
  Modaler Dialog (Kontext setzen, Palette, Hilfe, Export, Screenshot, Scope-Warnung). Fokus
  gefangen, Einzeltasten der Seite aus (eigene Tastatur-Ebene), Esc schliesst, der Fokus geht
  zurück zum Auslöser. Bindungen des Dialogs: `keys`-Prop (auf der Dialog-Ebene).
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { onDestroy, onMount } from 'svelte';
  import { trapFocus } from '../keys/focus';
  import { pushLayer, registerKeys, type KeyBinding } from '../keys/keymap';
  import { fadeIn } from '../util/motion';

  let {
    title,
    onclose,
    keys = [],
    size = 'm',
    position = 'center',
    bare = false,
    tone = 'neutral',
    children,
    footer,
  }: {
    title: string;
    onclose: () => void;
    keys?: KeyBinding[];
    size?: 's' | 'm' | 'l';
    position?: 'center' | 'top';
    /** ohne sichtbaren Titel und Innenabstand (Palette); der Titel bleibt als aria-label */
    bare?: boolean;
    /** 'attention': Rand in --attention (Warnungen) */
    tone?: 'neutral' | 'attention';
    children: Snippet;
    footer?: Snippet;
  } = $props();

  let layer: { layer: number; pop: () => void } | null = null;
  let off: (() => void) | null = null;

  onMount(() => {
    layer = pushLayer();
    off = registerKeys([{ keys: ['Escape'], allowInInput: true, run: () => onclose() }, ...keys], layer.layer);
  });
  onDestroy(() => {
    off?.();
    layer?.pop();
  });
</script>

<div class="backdrop" role="presentation">
  <div class="dialog {size} {position} {tone}" class:bare role="dialog" aria-modal="true" aria-label={title} use:trapFocus use:fadeIn>
    {#if !bare}<h2 class="title">{title}</h2>{/if}
    <div class="body">{@render children()}</div>
    {#if footer}<div class="foot">{@render footer()}</div>{/if}
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: flex;
    justify-content: center;
    align-items: center;
    background: var(--scrim);
  }
  .dialog {
    background: var(--surface-2);
    border: var(--lw-1) solid var(--line-strong);
    border-radius: var(--r-dialog);
    box-shadow: var(--shadow);
    padding: var(--sp-5);
    max-height: 80vh;
    max-width: calc(100vw - 32px);
    overflow: auto;
    color: var(--fg);
  }
  .dialog:focus,
  .dialog:focus-visible {
    outline: none;
  }
  .bare {
    padding: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }
  .bare .body {
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .attention {
    border: 1.5px solid var(--attention);
  }
  .top {
    align-self: flex-start;
    margin-top: 12vh;
  }
  .s {
    width: 420px;
  }
  .m {
    width: 460px;
  }
  .l {
    width: 560px;
  }
  .title {
    margin: 0 0 14px;
    font-size: 16px;
    font-weight: 600;
  }
  .foot {
    display: flex;
    justify-content: flex-end;
    gap: var(--sp-2);
    margin-top: var(--sp-4);
  }
</style>
