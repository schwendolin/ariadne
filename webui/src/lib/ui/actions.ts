/**
 * Svelte-Actions für dynamische Werte ohne Inline-Styles (CSP: `style-src 'self'` ohne
 * 'unsafe-inline'). Besitzer: ui-fundament.
 *
 * - `styleProps` (Alias `cssVars`) setzt nur CSS-Variablen (`--name`) per CSSOM
 *   (`element.style.setProperty`), nur mit Zahlen- oder Längenwerten. Style-Attribute im Markup
 *   und `setAttribute('style')` sind verboten (ESLint `svelte/no-inline-styles`,
 *   `no-restricted-syntax`).
 * - `clickOutside` schliesst Popover.
 */
export type StyleProps = Record<`--${string}`, string | number | null>;

const SAFE_VALUE = /^-?[\d.]+(px|%|em|rem|s|ms|deg|fr)?$/;

function apply(node: HTMLElement, props: StyleProps, prev: StyleProps | null): void {
  if (prev) {
    for (const k of Object.keys(prev)) if (!(k in props)) node.style.removeProperty(k);
  }
  for (const [k, v] of Object.entries(props)) {
    if (v === null) {
      node.style.removeProperty(k);
      continue;
    }
    const value = typeof v === 'number' ? (Number.isFinite(v) ? `${v}` : '') : v;
    if (!SAFE_VALUE.test(value)) continue;
    node.style.setProperty(k, value);
  }
}

export function styleProps(node: HTMLElement, props: StyleProps) {
  let prev: StyleProps | null = null;
  apply(node, props, prev);
  prev = props;
  return {
    update(next: StyleProps) {
      apply(node, next, prev);
      prev = next;
    },
  };
}

export const cssVars = styleProps;

/** Ruft `cb`, wenn ausserhalb des Elements geklickt wird (Popover, Menü). */
export function clickOutside(node: HTMLElement, cb: (e: MouseEvent) => void) {
  let handler = cb;
  const onDown = (e: MouseEvent) => {
    if (e.target instanceof Node && !node.contains(e.target)) handler(e);
  };
  document.addEventListener('mousedown', onDown, true);
  return {
    update(next: (e: MouseEvent) => void) {
      handler = next;
    },
    destroy() {
      document.removeEventListener('mousedown', onDown, true);
    },
  };
}
