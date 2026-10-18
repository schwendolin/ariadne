/**
 * Fokus: Fokusfalle für Dialoge und Palette, Rückgabe an den Auslöser (BEHAVIOR «Tastatur»,
 * «Belegansicht»: Esc schliesst, der Fokus geht zurück). Besitzer: ui-fundament.
 */

const FOCUSABLE = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled]):not([type="hidden"])', 'select:not([disabled])',
  'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])', '[contenteditable="true"]',
].join(',');

export function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.hasAttribute('inert') && el.getAttribute('aria-hidden') !== 'true',
  );
}

/** Fokussiert ein Element, ohne zu scrollen, wenn es noch im Dokument ist. */
export function restoreFocus(el: Element | null | undefined): void {
  if (el instanceof HTMLElement && el.isConnected) el.focus({ preventScroll: true });
}

/**
 * Svelte-Action: fängt den Fokus im Element. Beim Einhängen geht der Fokus auf
 * `[data-autofocus]` oder das erste fokussierbare Element; beim Abbau zurück zum Element, das
 * vorher den Fokus hatte (oder zu `returnTo`).
 */
export function trapFocus(node: HTMLElement, opts: { returnTo?: HTMLElement | null } = {}) {
  const before = (opts.returnTo ?? document.activeElement) as Element | null;
  const first = node.querySelector<HTMLElement>('[data-autofocus]') ?? focusables(node)[0] ?? node;
  if (first === node && !node.hasAttribute('tabindex')) node.tabIndex = -1;
  queueMicrotask(() => first.focus({ preventScroll: true }));

  function onKey(e: KeyboardEvent) {
    if (e.key !== 'Tab') return;
    const list = focusables(node);
    if (list.length === 0) {
      e.preventDefault();
      return;
    }
    const firstEl = list[0] as HTMLElement;
    const lastEl = list[list.length - 1] as HTMLElement;
    const active = document.activeElement;
    if (e.shiftKey && (active === firstEl || !node.contains(active))) {
      e.preventDefault();
      lastEl.focus();
    } else if (!e.shiftKey && (active === lastEl || !node.contains(active))) {
      e.preventDefault();
      firstEl.focus();
    }
  }
  function onFocusIn(e: FocusEvent) {
    if (e.target instanceof Node && !node.contains(e.target)) (focusables(node)[0] ?? node).focus();
  }
  node.addEventListener('keydown', onKey);
  document.addEventListener('focusin', onFocusIn);
  return {
    destroy() {
      node.removeEventListener('keydown', onKey);
      document.removeEventListener('focusin', onFocusIn);
      restoreFocus(before);
    },
  };
}
