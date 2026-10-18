/**
 * Quellen der Befehlspalette (Briefing 4.3, Screen 10). Besitzer: ui-fundament.
 *
 * Jeder Bereich meldet eine Quelle an (`registerPaletteSource`), solange er Daten hat:
 * ui-karte: Hosts und Services, Einträge «Als Nächstes»; ui-verlauf: Befehle der Zeitachse,
 * Findings; ui-fundament: Aktionen (Reiter, Präsentationsmodus, Einstellungen, Hilfe, Abmelden)
 * und «Im Rohlog suchen» (GET /search). Höchstens 40 Treffer, gruppiert.
 * Treffertexte aus Zieldaten zeigt die Palette über Txt.
 */
import type { MessageKey } from '../i18n';

export type PaletteGroup = 'hosts' | 'next' | 'commands' | 'actions' | 'log';

export interface PaletteItem {
  id: string;
  group: PaletteGroup;
  /** Anzeige (darf Zieldaten enthalten; wird über Txt gezeigt) */
  label: string;
  mono?: boolean;
  /** rechte Spalte, etwa «Host-Detail», «D2», «T2 · 16:43», «⇧P» */
  hint?: string;
  /** Suchtext (klein geschrieben) */
  keywords: string;
  run: () => void;
}

export type PaletteSource = (query: string) => PaletteItem[];

const sources = new Map<string, PaletteSource>();

export function registerPaletteSource(name: string, src: PaletteSource): () => void {
  sources.set(name, src);
  return () => {
    if (sources.get(name) === src) sources.delete(name);
  };
}

export const GROUP_ORDER: PaletteGroup[] = ['hosts', 'next', 'commands', 'actions', 'log'];
export const GROUP_LABEL: Record<PaletteGroup, MessageKey> = {
  hosts: 'palette.group.hosts',
  next: 'palette.group.next',
  commands: 'palette.group.commands',
  actions: 'palette.group.actions',
  log: 'palette.group.log',
};

/** Einfache Suche: alle Wörter der Anfrage kommen in `keywords` vor. */
export function matches(item: PaletteItem, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return words.every((w) => item.keywords.includes(w));
}

export function search(query: string, limit = 40): PaletteItem[] {
  const out: PaletteItem[] = [];
  for (const src of sources.values()) {
    for (const item of src(query)) if (!query || matches(item, query)) out.push(item);
  }
  out.sort((a, b) => GROUP_ORDER.indexOf(a.group) - GROUP_ORDER.indexOf(b.group));
  return out.slice(0, limit);
}
