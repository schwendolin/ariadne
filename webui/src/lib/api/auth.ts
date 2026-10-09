/**
 * Token-Ablage und Einmalcode (Architektur 7.2).
 *
 * - Das Token liegt nur in sessionStorage, nie in localStorage. Es gilt damit nur
 *   für diesen Tab und verschwindet beim Schliessen.
 * - Der Einmalcode kommt als Fragment `#c=<code>` aus der Startdatei von
 *   `ariadne ui`. Fragmente gehen nie an den Server und nicht in Logs. Die SPA
 *   entfernt das Fragment sofort per history.replaceState.
 * - Dieses Modul ist (mit prefs.ts) der einzige Zugang zu den Web-Storages
 *   (per ESLint erzwungen).
 */

const TOKEN_KEY = 'ariadne.token';
const EXPIRES_KEY = 'ariadne.token.expires';

export interface TokenStore {
  get(): string | null;
  set(token: string, expiresAt: string | null): void;
  clear(): void;
}

function storage(): Storage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage;
  } catch {
    return null;
  }
}

/** Token im sessionStorage; bei gesperrtem Storage nur im Speicher. */
export function createSessionTokenStore(): TokenStore {
  let memory: string | null = null;
  let memoryExpires: string | null = null;
  return {
    get() {
      const s = storage();
      let token: string | null = memory;
      let expires: string | null = memoryExpires;
      try {
        if (s) {
          token = s.getItem(TOKEN_KEY) ?? memory;
          expires = s.getItem(EXPIRES_KEY) ?? memoryExpires;
        }
      } catch {
        /* Storage blockiert: Speicherwert */
      }
      if (token && expires && Date.parse(expires) <= Date.now()) {
        this.clear();
        return null;
      }
      return token;
    },
    set(token, expiresAt) {
      memory = token;
      memoryExpires = expiresAt;
      const s = storage();
      try {
        s?.setItem(TOKEN_KEY, token);
        if (expiresAt) s?.setItem(EXPIRES_KEY, expiresAt);
        else s?.removeItem(EXPIRES_KEY);
      } catch {
        /* nur im Speicher */
      }
    },
    clear() {
      memory = null;
      memoryExpires = null;
      const s = storage();
      try {
        s?.removeItem(TOKEN_KEY);
        s?.removeItem(EXPIRES_KEY);
      } catch {
        /* nichts zu tun */
      }
    },
  };
}

/** Nur im Speicher (Tests, Mock). */
export function createMemoryTokenStore(): TokenStore {
  let token: string | null = null;
  return {
    get: () => token,
    set: (t) => {
      token = t;
    },
    clear: () => {
      token = null;
    },
  };
}

const CODE_RE = /^[A-Za-z0-9_-]{8,128}$/;

/**
 * Liest den Einmalcode aus `#c=<code>` und entfernt das Fragment aus der Adresse.
 * Gibt null zurück, wenn kein gültiger Code vorhanden ist.
 */
export function takeCodeFromLocation(loc: Location = window.location, hist: History = window.history): string | null {
  const hash = loc.hash.startsWith('#') ? loc.hash.slice(1) : loc.hash;
  if (!hash) return null;
  const params = new URLSearchParams(hash);
  const code = params.get('c');
  if (code === null) return null;
  // Fragment immer entfernen, auch wenn der Code ungültig ist.
  hist.replaceState(hist.state, '', loc.pathname + loc.search);
  return CODE_RE.test(code) ? code : null;
}

/** Codes zum Eintippen (`ariadne ui --code`): Leerzeichen und Bindestriche erlaubt. */
export function normalizeTypedCode(input: string): string | null {
  const code = input.replace(/[\s-]+/g, '');
  return CODE_RE.test(code) ? code : null;
}
