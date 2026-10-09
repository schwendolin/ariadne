/**
 * Encoder für Zieldaten in der Web-UI (Architektur 7.7, 9.2).
 *
 * Gleiche Semantik wie `src/ariadne/termsafe.py`:
 * - `visible(text)` ersetzt C0, DEL, C1, Bidi-, Zero-Width- und Unicode-Tag-Zeichen
 *   sowie alle Zeichen der Kategorien Cf, Cs, Co und Cn durch eine sichtbare
 *   Ersatzform (`<ESC>`, `<0x01>`, `<U+202E>`, `<U+E0041>`).
 * - `displaySafe(value, max)` macht dasselbe und kürzt danach auf höchstens
 *   `max` Zeichen (Codepoints, wie `len()` in Python), mit `…` am Ende.
 *
 * Svelte escapt HTML ohnehin. displaySafe sorgt zusätzlich dafür, dass ein Ziel
 * die Anzeige nicht mit unsichtbaren oder richtungsumkehrenden Zeichen fälschen
 * kann (z. B. `\u202egnp.exe` als `<U+202E>gnp.exe`).
 *
 * Kleine Abweichung zu Python: welche Codepoints «nicht zugewiesen» (Cn) sind,
 * hängt von der Unicode-Version der Laufzeit ab (ICU im Browser, unicodedata in
 * Python). Für zugewiesene Zeichen ist das Ergebnis identisch.
 */

const INVISIBLE = new Set<number>([
  0x061c, // ARABIC LETTER MARK
  0x180e, // MONGOLIAN VOWEL SEPARATOR
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
  0x2066, 0x2067, 0x2068, 0x2069,
  0xfeff,
]);

const NAMES: Record<number, string> = {
  0x1b: 'ESC',
  0x07: 'BEL',
  0x08: 'BS',
  0x7f: 'DEL',
  0x0d: 'CR',
  0x0a: 'LF',
  0x09: 'TAB',
};

// Cf: Format, Cs: Surrogat (nur einzeln stehende), Co: Private Use, Cn: nicht zugewiesen.
const HIDDEN_CATEGORY = /^[\p{Cf}\p{Cs}\p{Co}\p{Cn}]$/u;

function escapeCodepoint(cp: number): string {
  const name = NAMES[cp];
  if (name) return `<${name}>`;
  const hex = cp.toString(16).toUpperCase();
  if (cp <= 0xff) return `<0x${hex.padStart(2, '0')}>`;
  return `<U+${hex.padStart(4, '0')}>`;
}

function isHidden(ch: string, cp: number): boolean {
  return (
    cp < 0x20 ||
    cp === 0x7f ||
    (cp >= 0x80 && cp <= 0x9f) ||
    INVISIBLE.has(cp) ||
    (cp >= 0xe0000 && cp <= 0xe007f) ||
    HIDDEN_CATEGORY.test(ch)
  );
}

/** Macht Steuer-, Bidi-, Zero-Width- und Tag-Zeichen sichtbar, ohne zu kürzen. */
export function visible(text: string): string {
  let out = '';
  // for..of iteriert über Codepoints; einzelne Surrogate bleiben einzelne Einheiten.
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    out += isHidden(ch, cp) ? escapeCodepoint(cp) : ch;
  }
  return out;
}

/** Wandelt beliebige Werte so in Text um wie `str()` in Python (ohne Exceptions). */
function toText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return '';
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value);
  }
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '';
  }
}

/**
 * Sichere Textdarstellung für Labels und Tabellen.
 *
 * Das Ergebnis enthält garantiert kein C0, C1, DEL, Bidi-, Zero-Width- oder
 * Tag-Zeichen und ist höchstens `max` Codepoints lang (`max <= 0`: ungekürzt).
 */
export function displaySafe(value: unknown, max = 200): string {
  const safe = visible(toText(value));
  if (max > 0) {
    const cps = Array.from(safe);
    if (cps.length > max) {
      return cps.slice(0, Math.max(0, max - 1)).join('') + '…';
    }
  }
  return safe;
}

/** true, wenn displaySafe den Wert verändert (für Hinweise wie «enthält Steuerzeichen»). */
export function hasHiddenChars(value: string): boolean {
  return visible(value) !== value;
}

/**
 * Hostnamen mit Nicht-ASCII-Zeichen zusätzlich in Punycode (Architektur 7.7).
 * Gibt null zurück, wenn der Name nur ASCII enthält oder sich nicht umwandeln lässt.
 * Es findet keine Namensauflösung statt, nur die URL-Normalisierung des Browsers.
 */
export function punycodeHint(name: string): string | null {
  if (!Array.from(name).some((ch) => (ch.codePointAt(0) ?? 0) > 0x7f)) return null;
  if (hasHiddenChars(name) || /[\s/\\?#@:]/.test(name)) return null;
  try {
    const host = new URL(`http://${name}/`).hostname;
    return host && host !== name ? host : null;
  } catch {
    return null;
  }
}
