/**
 * Fokus: Fokusfalle für Dialoge und Palette, Rückgabe an den Auslöser (BEHAVIOR «Tastatur»,
 * «Belegansicht»: Esc schliesst, der Fokus geht zurück). Besitzer: ui-fundament.
 */

const FOCUSABLE = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled]):not([type="hidden"])', 'select:not([disabled])',
  'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])', '[contenteditable="true"]',
].join(',');

/**
 * Elemente, die Tab erreicht (in Dokumentreihenfolge). Ohne `tabindex="-1"` (etwa Optionen nach
 * dem Muster aria-activedescendant) und ohne Elemente in `inert` oder `aria-hidden` (Korrektur A15).
 */
export function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => el.tabIndex >= 0 && !el.closest('[inert]') && !el.closest('[aria-hidden="true"]'),
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

  // Tab und Shift+Tab führt die Falle selbst (Korrektur A15): Ein scrollbarer Bereich, den der
  // Browser von sich aus fokussierbar macht (Liste der Palette), ist so nie ein Ausgang.
  function onKey(e: KeyboardEvent) {
    if (e.key !== 'Tab') return;
    e.preventDefault();
    const list = focusables(node);
    if (list.length === 0) {
      node.focus({ preventScroll: true });
      return;
    }
    const active = document.activeElement;
    let i = active instanceof HTMLElement ? list.indexOf(active) : -1;
    if (i < 0) {
      // Fokus auf einem Element ausserhalb der Liste (Container, scrollbarer Bereich): nach Lage einordnen
      const after = list.findIndex((el) => active instanceof Node && !!(active.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING));
      i = after < 0 ? list.length : after;
      i = e.shiftKey ? i : i - 1;
    }
    const next = e.shiftKey ? (i - 1 + list.length) % list.length : (i + 1) % list.length;
    (list[next] as HTMLElement).focus();
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
