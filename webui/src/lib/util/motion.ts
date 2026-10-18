/**
 * Bewegung (BEHAVIOR «Bewegung»): Einblenden 180 ms ease-out, Tafel 160 ms von rechts, Puls einmal
 * 900 ms. Nur über die Web Animations API (`element.animate`): CSP-konform, keine eingefügten
 * <style>-Elemente. Svelte-Übergänge (`transition:`, `in:`, `out:`) sind nicht erlaubt; diese
 * Actions ersetzen sie. Bei `prefers-reduced-motion` gibt es keine Bewegung; statt des Pulses
 * steht 2 s lang ein statischer Ring (Klasse `pulse-static` aus app.css).
 * Besitzer: ui-fundament.
 */

export function reducedMotion(): boolean {
  try {
    return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}

function canAnimate(node: Element): boolean {
  return typeof (node as HTMLElement).animate === 'function' && !reducedMotion();
}

/** Action: blendet beim Einhängen ein (180 ms). */
export function fadeIn(node: HTMLElement) {
  if (canAnimate(node)) node.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: 'ease-out' });
  return {};
}

/** Action: Tafel fährt von rechts ein (160 ms). */
export function slideInRight(node: HTMLElement) {
  if (canAnimate(node)) {
    node.animate([{ transform: 'translateX(24px)', opacity: 0 }, { transform: 'translateX(0)', opacity: 1 }], {
      duration: 160,
      easing: 'ease-out',
    });
  }
  return {};
}

/** Lässt ein Element einmal pulsieren (900 ms) bzw. zeigt 2 s einen statischen Ring. */
export function pulseOnce(node: HTMLElement): void {
  if (reducedMotion() || typeof node.animate !== 'function') {
    node.classList.add('pulse-static');
    setTimeout(() => node.classList.remove('pulse-static'), 2000);
    return;
  }
  node.animate(
    [
      { boxShadow: '0 0 0 0 var(--focus)' },
      { boxShadow: '0 0 0 10px transparent' },
    ],
    { duration: 900, easing: 'ease-out' },
  );
}

/**
 * Action: pulsiert, sobald sich `token` ändert und `active` wahr ist.
 * `<div use:pulse={{ token: ui.pulseToken, active: ui.isPulsing(id) }}>`
 */
export function pulse(node: HTMLElement, arg: { token: number; active: boolean }) {
  let last = arg.token;
  return {
    update(next: { token: number; active: boolean }) {
      if (next.token !== last && next.active) pulseOnce(node);
      last = next.token;
    },
  };
}
