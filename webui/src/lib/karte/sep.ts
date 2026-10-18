/**
 * Trenner im Markup der Karte, der Spalte und des Host-Details. Svelte entfernt Leerraum am Rand
 * von Blöcken und Elementen ({#if}…{/if}, <span>…</span>); als Wert gesetzt bleiben die
 * Leerzeichen stehen («T3 «listener» · Reverse Shell» statt «…»· Reverse Shell»). Eine
 * Zeichenkette direkt im Markup ({' · '}) meldet eslint (svelte/no-useless-mustaches).
 * Besitzer: ui-karte.
 */
export const DOT = ' · ';
export const COMMA = ', ';
export const SP = ' ';
export const PLUS = ' +';
