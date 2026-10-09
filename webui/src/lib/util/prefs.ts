/**
 * Ansichtseinstellungen pro Browser (Theme, Ebenen, im Mock auch Kartenpositionen).
 *
 * Einziger Zugang zu localStorage (per ESLint erzwungen). Nur Schlüssel aus der
 * Allowlist, nie Tokens, nie Projektdaten aus Zielen. Jeder Zugriff ist in
 * try/catch, damit die UI auch ohne Storage (privates Fenster) funktioniert.
 */

const ALLOWED = /^ariadne\.(theme|layers|learning|mock\.positions\.[A-Za-z0-9._-]{1,120})$/;

function store(): Storage | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null;
  }
}

function check(key: string): void {
  if (!ALLOWED.test(key)) throw new Error(`prefs: Schlüssel nicht erlaubt: ${key}`);
}

export function readPref<T>(key: string, fallback: T, validate?: (v: unknown) => v is T): T {
  check(key);
  try {
    const raw = store()?.getItem(key);
    if (raw === null || raw === undefined) return fallback;
    const v: unknown = JSON.parse(raw);
    if (validate && !validate(v)) return fallback;
    return v as T;
  } catch {
    return fallback;
  }
}

export function writePref(key: string, value: unknown): void {
  check(key);
  try {
    store()?.setItem(key, JSON.stringify(value));
  } catch {
    /* Storage voll oder blockiert: Einstellung gilt nur bis zum Neuladen */
  }
}

export function removePref(key: string): void {
  check(key);
  try {
    store()?.removeItem(key);
  } catch {
    /* nichts zu tun */
  }
}
