/**
 * Kleines i18n-Modul. Alle UI-Texte laufen über t(), Standard ist Deutsch.
 *
 * - Platzhalter `{name}` werden durch Parameter ersetzt. Parameter sind Text,
 *   die Ausgabe wird in Svelte normal escapt.
 * - Plural mit «Einzahl|Mehrzahl», gewählt über `n`.
 * - tKey() für Schlüssel aus Serverwerten (z. B. Prädikate) mit Rückfall auf den Rohwert.
 */
import { de } from './de';

export type MessageKey = keyof typeof de;
export type Messages = Record<MessageKey, string>;

let messages: Messages = de;
export const locale = 'de-CH';

export function setMessages(next: Messages): void {
  messages = next;
}

function format(msg: string, params?: Record<string, string | number>): string {
  let text = msg;
  if (text.includes('|') && params && typeof params.n === 'number') {
    const [one, other] = text.split('|');
    text = (params.n === 1 ? one : other) ?? text;
  }
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (all, k: string) => (params[k] !== undefined ? String(params[k]) : all));
}

export function t(key: MessageKey, params?: Record<string, string | number>): string {
  return format(messages[key] ?? key, params);
}

/** Für Schlüssel, die aus Serverwerten zusammengesetzt sind; unbekannte geben `fallback` zurück. */
export function tKey(key: string, fallback: string, params?: Record<string, string | number>): string {
  const msg = (messages as Record<string, string>)[key];
  return msg === undefined ? fallback : format(msg, params);
}

export function hasKey(key: string): key is MessageKey {
  return key in messages;
}

/** Zahl im Schweizer Format (Tausendertrennzeichen ’). */
export function num(n: number): string {
  return n.toLocaleString(locale);
}
