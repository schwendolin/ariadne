/**
 * Vorlieben auf dem Server (E112, web-api.md 18.2): Theme, Dichte, Lernmodus. Kein Browser-Speicher.
 * Bis die Antwort da ist, folgt die Oberfläche dem System. Besitzer: ui-fundament.
 */
import type { Backend } from '../api/backend';
import type { Prefs } from '../api/types';
import { errorText } from '../util/errors';
import type { UiStore } from './ui.svelte';

export const DEFAULT_PREFS: Prefs = { theme: 'system', density: 'comfortable', learning: true };

/** Setzt `data-theme` und `data-density` auf <html> (Tokens in theme/tokens.css). */
export function applyPrefs(prefs: Prefs, root: HTMLElement | null = typeof document === 'undefined' ? null : document.documentElement): void {
  if (!root) return;
  if (prefs.theme === 'system') delete root.dataset.theme;
  else root.dataset.theme = prefs.theme;
  if (prefs.density === 'compact') root.dataset.density = 'compact';
  else delete root.dataset.density;
}

export class PrefsStore {
  prefs = $state<Prefs>({ ...DEFAULT_PREFS });
  loaded = $state(false);
  saving = $state(false);

  constructor(
    private readonly backend: Backend,
    private readonly ui: UiStore,
  ) {}

  /** Zähler der lokalen Änderungen: ältere Antworten überschreiben nie eine neuere Wahl. */
  private version = 0;
  private pending = 0;

  async load(signal?: AbortSignal): Promise<void> {
    const at = this.version;
    try {
      const v = await this.backend.prefs(signal);
      if (at !== this.version || this.pending > 0) return; // inzwischen lokal geändert
      this.prefs = { ...DEFAULT_PREFS, ...v.prefs };
      this.loaded = true;
      applyPrefs(this.prefs);
    } catch {
      // Ohne Antwort bleibt die Standardanzeige (System); kein Fehler für die Anmeldung.
    }
  }

  /**
   * Setzt Felder sofort sichtbar und speichert; bei Fehler zurück und Meldung. Antworten kommen
   * in beliebiger Reihenfolge: nur die Antwort der jüngsten Änderung wird übernommen.
   */
  async set(patch: Partial<Prefs>): Promise<void> {
    const before = this.prefs;
    const mine = ++this.version;
    this.prefs = { ...before, ...patch };
    applyPrefs(this.prefs);
    this.pending++;
    this.saving = true;
    try {
      const v = await this.backend.savePrefs(patch);
      if (mine === this.version) {
        this.prefs = { ...DEFAULT_PREFS, ...v.prefs };
        applyPrefs(this.prefs);
      }
    } catch (e) {
      if (mine === this.version) {
        this.prefs = before;
        applyPrefs(before);
      }
      this.ui.notify('error', errorText(e, 'settings.saveFailed'));
    } finally {
      this.pending--;
      this.saving = this.pending > 0;
    }
  }
}
