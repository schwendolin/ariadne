<!--
  Tafel von rechts über Karte und Spalte (Belegansicht, Einstellungen; README «Belegansicht»):
  52 % Breite, 620 bis 860 px, Karte dahinter gedimmt. Immer nur eine Tafel offen (URL `beleg`
  bzw. `tafel`). Esc schliesst, der Fokus geht zurück zum Auslöser. `locked`: lässt sich nicht
  wegklicken (Hash-Kette verletzt). Einblenden 160 ms von rechts (WAAPI). Besitzer: ui-fundament.
  Solange die Tafel offen ist, ist der Rest des Inhalts (Karte, Spalte, Listen) `inert`: Tab und
  Bildschirmleser erreichen nur die Tafel und die Kopfzeile (Korrektur A7, WCAG 2.4.3, 2.4.11).
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

  /** Geschwister im selben Container, die die Tafel inert gesetzt hat (und nur die). */
  const madeInert = new Set<Element>();
  let observer: MutationObserver | null = null;

  function inertSiblings(): void {
    const parent = node?.parentElement;
    if (!parent || !node) return;
    for (const el of Array.from(parent.children)) {
      if (el === node || el.classList.contains('scrim') || el.classList.contains('panel') || madeInert.has(el)) continue;
      if (el.hasAttribute('inert')) continue;
      el.setAttribute('inert', '');
      madeInert.add(el);
    }
  }

  onMount(() => {
    trigger = document.activeElement;
    queueMicrotask(() => node?.focus({ preventScroll: true }));
    off = registerKeys([{ keys: ['Escape'], allowInInput: true, run: () => (locked ? false : close()) }]);
    inertSiblings();
    // Ein Reiterwechsel bei offener Tafel hängt eine neue Ansicht ein: auch sie inert setzen
    if (node?.parentElement && typeof MutationObserver !== 'undefined') {
      observer = new MutationObserver(() => inertSiblings());
      observer.observe(node.parentElement, { childList: true });
    }
  });
  onDestroy(() => {
    off?.();
    observer?.disconnect();
    for (const el of madeInert) el.removeAttribute('inert');
    madeInert.clear();
    restoreFocus(trigger);
  });

  function close(): void {
    onclose();
  }
</script>

<div class="scrim" aria-hidden="true"></div>
<div class="panel" class:locked role="dialog" aria-label={title} tabindex="-1" bind:this={node} use:slideInRight>
  <header class="head">
    {#if header}{@render header()}{:else}<h2>{title}</h2>{/if}
    {#if !locked}<button type="button" class="close" data-offline-ok onclick={close} aria-label={t('common.close')}><kbd>{t('common.esc')}</kbd> {t('common.closeVerb')}</button>{/if}
  </header>
  <div class="body">{@render children()}</div>
  {#if footer}<footer class="foot">{@render footer()}</footer>{/if}
</div>

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
