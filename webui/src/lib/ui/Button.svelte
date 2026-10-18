<!--
  Knopf nach Design v0.1: `primary` (Füllung --fg, Schrift --bg, etwa «Übernehmen»),
  `secondary` (Rand --line-strong), `ghost` (ohne Rand). Optional ein Tastenhinweis (Kbd).
  Ein deaktivierter Knopf nennt den Grund im title und für Bildschirmleser.
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Kbd from './Kbd.svelte';

  let {
    variant = 'secondary',
    size = 'm',
    kbd = null,
    disabled = false,
    reason = null,
    pressed = undefined,
    type = 'button',
    label = undefined,
    onclick,
    children,
    ...rest
  }: {
    variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
    size?: 's' | 'm';
    kbd?: string | null;
    disabled?: boolean;
    /** Grund, warum der Knopf gesperrt ist (Pflicht bei disabled) */
    reason?: string | null;
    pressed?: boolean | undefined;
    type?: 'button' | 'submit';
    label?: string | undefined;
    onclick?: (e: MouseEvent) => void;
    children?: Snippet;
    [key: `data-${string}`]: string | undefined;
  } = $props();
</script>

<button
  {type}
  class="btn {variant} {size}"
  {disabled}
  aria-pressed={pressed}
  aria-label={label}
  title={disabled && reason ? reason : undefined}
  {onclick}
  {...rest}
>
  {@render children?.()}
  {#if kbd}<Kbd keys={kbd} subtle />{/if}
  {#if disabled && reason}<span class="sr-only">{reason}</span>{/if}
</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    padding: 5px 12px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    font-size: var(--fs-m);
    cursor: pointer;
    white-space: nowrap;
  }
  .btn.s {
    padding: 3px 9px;
    font-size: var(--fs-s);
  }
  .btn:hover:not(:disabled) {
    border-color: var(--line-hover);
  }
  .primary {
    background: var(--fg);
    color: var(--bg);
    border-color: var(--fg);
    font-weight: 600;
  }
  .ghost {
    border-color: transparent;
  }
  .danger {
    border-color: var(--error);
    color: var(--error);
  }
  .btn:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .btn[aria-pressed='true'] {
    background: var(--surface-2);
  }
</style>
