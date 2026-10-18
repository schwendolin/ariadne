/**
 * Cytoscape legt beim ersten Start ein <style>-Element mit der ID
 * `__________cytoscape_stylesheet` an, ausser es existiert schon ein Element mit
 * dieser ID. Unter `style-src 'self'` wäre das eine CSP-Verletzung. Wir legen
 * deshalb einen Platzhalter an; die eine Regel steht in src/app.css. Besitzer: ui-karte.
 */
export const CYTOSCAPE_STYLESHEET_ID = '__________cytoscape_stylesheet';

export function ensureCytoscapeCspShim(doc: Document = document): void {
  if (doc.getElementById(CYTOSCAPE_STYLESHEET_ID)) return;
  const marker = doc.createElement('meta');
  marker.id = CYTOSCAPE_STYLESHEET_ID;
  marker.setAttribute('name', 'ariadne-cytoscape-csp');
  doc.head.prepend(marker);
}
