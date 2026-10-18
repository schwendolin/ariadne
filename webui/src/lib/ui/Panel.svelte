<!--
  Tafel von rechts über Karte und Spalte (Belegansicht, Einstellungen; README «Belegansicht»):
  52 % Breite, 620 bis 860 px, Karte dahinter gedimmt. Immer nur eine Tafel offen (URL `beleg`
  bzw. `tafel`). Esc schliesst, der Fokus geht zurück zum Auslöser. `locked`: lässt sich nicht
  wegklicken (Hash-Kette verletzt). Einblenden 160 ms von rechts (WAAPI). Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { onDestroy, onMount } from 'svelte';
  import { t } from '../i18n';
  import { restoreFocus } from '../keys/focus';
  import { registerKeys } from '../keys/keymap';
  import { slideInRight } from '../util/motion';

  let {
    title,
    onclose,
    locked = false,
    header,
    footer,
    children,
  }: {
    title: string;
    onclose: () => void;
    locked?: boolean;
    header?: Snippet;
    footer?: Snippet;
    children: Snippet;
  } = $props();

  let trigger: Element | null = null;
  let node: HTMLElement | undefined = $state();
  let off: (() => void) | null = null;

  onMount(() => {
    trigger = document.activeElement;
    queueMicrotask(() => node?.focus({ preventScroll: true }));
    off = registerKeys([{ keys: ['Escape'], allowInInput: true, run: () => (locked ? false : close()) }]);
  });
  onDestroy(() => {
    off?.();
    restoreFocus(trigger);
  });

  function close(): void {
    onclose();
  }
</script>

<div class="scrim" aria-hidden="true"></div>
<section class="panel" class:locked aria-label={title} tabindex="-1" bind:this={node} use:slideInRight>
  <header class="head">
    {#if header}{@render header()}{:else}<h2>{title}</h2>{/if}
    {#if !locked}<button type="button" class="close" onclick={close} aria-label={t('common.close')}>{t('common.close')} <kbd>{t('common.esc')}</kbd></button>{/if}
  </header>
  <div class="body">{@render children()}</div>
  {#if footer}<footer class="foot">{@render footer()}</footer>{/if}
</section>

<style>
  .scrim {
    position: absolute;
    inset: 0;
    background: var(--scrim);
    z-index: 30;
  }
  .panel {
    position: absolute;
    top: 0;
    right: 0;
    bottom: 0;
    z-index: 31;
    width: var(--panel-w);
    min-width: var(--panel-min);
    max-width: var(--panel-max);
    display: flex;
    flex-direction: column;
    background: var(--surface);
    border-left: var(--lw-1) solid var(--line);
    box-shadow: var(--shadow);
    outline: none;
  }
  .locked {
    border-left: var(--lw-focus) solid var(--error);
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-3);
    padding: var(--sp-4) var(--sp-6);
    border-bottom: var(--lw-1) solid var(--line);
  }
  .head h2 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
  }
  .close {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    border-radius: var(--r-btn);
    padding: 4px 6px;
  }
  .close:hover {
    color: var(--fg);
    background: var(--surface-3);
  }
  .close kbd {
    font-family: var(--font-mono);
    font-size: 11.5px;
    padding: 1px 5px;
    border-radius: var(--r-badge);
    background: var(--kbd-bg);
  }
  .body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: var(--sp-4) var(--sp-6);
  }
  .foot {
    display: flex;
    gap: var(--sp-2);
    padding: var(--sp-3) var(--sp-6);
    border-top: var(--lw-1) solid var(--line);
  }
</style>
