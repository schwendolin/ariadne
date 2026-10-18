/**
 * i18n: alle UI-Texte laufen über t(). Deutsch (Schweiz): echte Umlaute, nie «ß», keine Emojis.
 * Besitzer: ui-fundament.
 *
 * Drei Wörterbücher, je ein Besitzer (Vertrag v0.1-Oberfläche, Abschnitt 6):
 *   de.ts         ui-fundament  Präfixe app, nav, header, rec, login, state, menu, settings, palette,
 *                               help, err, copy, secret, common, time, keys, present, scope, notice
 *   de.karte.ts   ui-karte      Präfixe karte, lage, oos, layers, table, next, sug, host
 *   de.verlauf.ts ui-verlauf    Präfixe term, ctx, tl, pending, ev, fd, export, shot
 * tests/fundament/i18n.test.ts prüft: keine doppelten Schlüssel, Präfixe passen zum Besitzer,
 * kein «ß», keine Emojis.
 *
 * Platzhalter `{name}` werden durch Parameter ersetzt (Text, Svelte escapt). Plural mit
 * «Einzahl|Mehrzahl», gewählt über den Parameter `n`.
 */
import { de } from './de';
import { deKarte } from './de.karte';
import { deVerlauf } from './de.verlauf';

const all = { ...de, ...deKarte, ...deVerlauf } as const;

export type MessageKey = keyof typeof de | keyof typeof deKarte | keyof typeof deVerlauf;
export const locale = 'de-CH';

const messages: Record<string, string> = all;

function format(msg: string, params?: Record<string, string | number>): string {
  let text = msg;
  if (text.includes('|') && params && typeof params.n === 'number') {
    const [one, other] = text.split('|');
    text = (params.n === 1 ? one : other) ?? text;
  }
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (whole, k: string) => (params[k] !== undefined ? String(params[k]) : whole));
}

export function t(key: MessageKey, params?: Record<string, string | number>): string {
  return format(messages[key] ?? key, params);
}

/** Für Schlüssel aus Serverwerten (Prädikate, Gründe); unbekannte ergeben `fallback`. */
export function tKey(key: string, fallback: string, params?: Record<string, string | number>): string {
  const msg = messages[key];
  return msg === undefined ? fallback : format(msg, params);
}

export function hasKey(key: string): key is MessageKey {
  return key in messages;
}

/** Zahl im Schweizer Format (Tausendertrennzeichen ’). */
export function num(n: number): string {
  return n.toLocaleString(locale);
}

/** Nur für Tests: die drei Wörterbücher einzeln. */
export const dictionaries = { de, deKarte, deVerlauf };
