<!--
  Menü hinter ⋯ (Screen 11): Präsentationsmodus (⇧P), Screenshot der Kali …, Bericht exportieren …,
  Scope ansehen, Einstellungen, Hilfe (?), Abmelden mit Herkunft der Sitzung. Pfeiltasten wechseln
  die Einträge, Esc schliesst (Fokus zurück auf ⋯). Ohne Projekt sind die Projektaktionen gesperrt.
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import Popover from '../ui/Popover.svelte';
  import { url } from '../url/state.svelte';

  let { app }: { app: AppState } = $props();
  const ID = 'menu';
  const open = $derived(app.ui.popover === ID);
  const project = $derived(app.phase === 'project');
  let list: HTMLUListElement | undefined = $state();

  function pick(fn: () => void): () => void {
    return () => {
      app.ui.closePopover(ID);
      fn();
    };
  }

  function items(): HTMLButtonElement[] {
    return Array.from(list?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? []);
  }

  function onkey(e: KeyboardEvent): void {
    const all = items();
    if (all.length === 0) return;
    const i = all.indexOf(document.activeElement as HTMLButtonElement);
    let next: HTMLButtonElement | undefined;
    if (e.key === 'ArrowDown') next = all[(i + 1) % all.length];
    else if (e.key === 'ArrowUp') next = all[(i - 1 + all.length) % all.length];
    else if (e.key === 'Home') next = all[0];
    else if (e.key === 'End') next = all[all.length - 1];
    if (!next) return;
    e.preventDefault();
    e.stopPropagation();
    next.focus();
  }

  function toggle(e: MouseEvent): void {
    const viaKeyboard = e.detail === 0;
    app.ui.togglePopover(ID);
    if (viaKeyboard) queueMicrotask(() => items()[0]?.focus());
  }
</script>

<span class="wrap">
  <button type="button" class="dots" aria-label={t('header.menu')} aria-haspopup="menu" aria-expanded={open} onclick={toggle}>⋯</button>
  <Popover {open} onclose={() => app.ui.closePopover(ID)} label={t('header.menu')} align="right">
    <ul class="menu" role="menu" aria-label={t('header.menu')} bind:this={list} onkeydown={onkey}>
      <li role="none">
        <button type="button" role="menuitemcheckbox" aria-checked={app.presentation} disabled={app.offline} onclick={pick(() => void app.togglePresentation())}
          >{t('menu.presentation')}<span class="end">{#if app.presentation}<span aria-hidden="true">✓</span>{/if}<kbd>⇧P</kbd></span></button
        >
      </li>
      <li role="none">
        <button type="button" role="menuitem" disabled={!project} onclick={pick(() => app.ui.openDialog({ kind: 'screenshot' }))}>{t('menu.screenshot')}</button>
      </li>
      <li role="none">
        <button type="button" role="menuitem" disabled={!project} onclick={pick(() => app.ui.openDialog({ kind: 'export' }))}>{t('menu.export')}</button>
      </li>
      <li role="none">
        <button type="button" role="menuitem" disabled={!project} onclick={pick(() => app.ui.openDialog({ kind: 'scope-view' }))}>{t('menu.scope')}</button>
      </li>
      <li class="sep" role="separator"></li>
      <li role="none">
        <button type="button" role="menuitem" onclick={pick(() => url.set({ tafel: 'einstellungen' }, { push: true }))}>{t('menu.settings')}</button>
      </li>
      <li role="none">
        <button type="button" role="menuitem" onclick={pick(() => app.ui.openDialog({ kind: 'help' }))}>{t('menu.help')}<kbd>?</kbd></button>
      </li>
      <li class="sep" role="separator"></li>
      <li role="none">
        <button type="button" role="menuitem" class="logout" onclick={pick(() => void app.logout())}>
          <span>{t('menu.logout')}</span>
          <span class="hint">{app.status?.session?.origin === 'local' ? t('menu.logoutHint.local') : t('menu.logoutHint.sshd')}</span>
        </button>
      </li>
    </ul>
  </Popover>
</span>

<style>
  .wrap {
    position: relative;
  }
  .dots {
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: none;
    border-radius: var(--r-btn);
    background: transparent;
    color: var(--muted);
    font-size: 16px;
    cursor: pointer;
  }
  .dots:hover,
  .dots[aria-expanded='true'] {
    background: var(--surface-3);
    color: var(--fg);
  }
  .menu {
    list-style: none;
    margin: 0;
    padding: 0;
    min-width: 286px;
  }
  .menu button {
    width: 100%;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-2) 10px;
    border: none;
    border-radius: var(--r-btn);
    background: none;
    text-align: left;
    cursor: pointer;
    color: var(--fg);
  }
  .menu button:hover:not(:disabled),
  .menu button:focus-visible {
    background: var(--surface-3);
  }
  .menu button:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .end {
    display: inline-flex;
    gap: var(--sp-2);
    align-items: center;
  }
  .logout {
    flex-direction: column;
    align-items: flex-start !important;
    gap: 2px !important;
  }
  .hint {
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .sep {
    height: 1px;
    margin: var(--sp-1) 6px;
    background: var(--line);
  }
  kbd {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--muted);
  }
</style>
