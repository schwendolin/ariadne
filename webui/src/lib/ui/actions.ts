/**
 * Dynamische Styles nur über CSSOM (element.style.setProperty).
 *
 * Die CSP erlaubt style-src 'self' ohne 'unsafe-inline'. Style-Attribute im
 * Markup und setAttribute('style') wären Verletzungen; CSSOM-Zugriffe nicht.
 * ESLint verbietet style-Attribute in Svelte (svelte/no-inline-styles).
 * Erlaubt sind nur CSS-Variablen (--name) mit Zahlen- oder Längenwerten.
 */
export type StyleProps = Record<`--${string}`, string | number | null>;

const SAFE_VALUE = /^-?[\d.]+(px|%|em|rem|s|ms|deg)?$/;

function apply(node: HTMLElement, props: StyleProps, prev: StyleProps | null): void {
  if (prev) {
    for (const k of Object.keys(prev)) if (!(k in props)) node.style.removeProperty(k);
  }
  for (const [k, v] of Object.entries(props)) {
    if (v === null) {
      node.style.removeProperty(k);
      continue;
    }
    const value = typeof v === 'number' ? `${v}` : v;
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

/** Kopiert Text in die Zwischenablage, ohne Zeilenumbruch anzuhängen. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
