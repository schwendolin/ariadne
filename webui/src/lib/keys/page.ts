/**
 * Seiten-Kürzel (Korrektur A2, A8). Besitzer: ui-fundament.
 *
 * Die Kürzel eines Reiters (j k ↵ a x e u n t + − 0 Pfeile) wirken nur, solange keine Tafel offen
 * ist (Belegansicht `beleg`, Einstellungen `tafel`): Die Tafel verdeckt die Seite, Entscheide über
 * verdeckte Einträge darf es nicht geben. Dialoge sind eigene Ebenen (keymap.ts).
 */
import { url, type RouteId } from '../url/state.svelte';

export function pageKeysActive(route: RouteId): boolean {
  return url.route === route && !url.get('beleg') && !url.get('tafel');
}

/** true, wenn der Fokus im Element mit `data-keyzone="<zone>"` liegt (Zuständigkeit für j k ↵). */
export function focusInZone(zone: string): boolean {
  const el = typeof document === 'undefined' ? null : document.activeElement;
  return el instanceof Element && el.closest(`[data-keyzone="${zone}"]`) !== null;
}
