import { tKey } from '../i18n';

/** Prädikat lesbar machen; unbekannte Prädikate erscheinen roh. */
export function predLabel(predicate: string): string {
  return tKey(`pred.${predicate}`, predicate);
}

/** Kennung wie `ip:default/10.10.10.3` kurz anzeigen (ohne Typ und Adressraum). */
export function shortId(identifier: string): string {
  const m = /^ip:[^/]+\/(.+)$/.exec(identifier);
  if (m?.[1]) return m[1];
  const s = /^svc:ip:[^/]+\/([^|]+)\|(\w+)\/(\d+)$/.exec(identifier);
  if (s) return `${s[1]}:${s[3]}/${s[2]}`;
  return identifier;
}
