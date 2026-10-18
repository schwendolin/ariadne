/**
 * Einzige Stelle mit `navigator.clipboard` (Briefing 9.5, E111, FZ R14). Besitzer: ui-fundament.
 *
 * Hierher kommen nur Befehlsvorlagen, Einzelwerte und Belege, nie Secrets: Secrets gehen «in die
 * Kali» über `Backend.copyToKali`, nie in die Zwischenablage des Browsers. Kopiert wird ohne
 * Zeilenumbruch am Ende. Ohne Zwischenablage (unsicherer Kontext, Berechtigung) meldet die
 * Funktion `false`; die Komponente zeigt dann ein markiertes Textfeld zum Kopieren von Hand.
 */
export async function copyText(text: string): Promise<boolean> {
  const value = text.replace(/[\r\n]+$/, '');
  try {
    if (!navigator.clipboard?.writeText) return false;
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}
