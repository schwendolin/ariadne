/**
 * Zustand der Oberfläche ohne Daten: Dialoge, Popover, Meldungen, Puls. Besitzer: ui-fundament.
 *
 * - Es ist höchstens ein Dialog offen (`dialog`) und höchstens ein Popover (`popover`).
 *   Dialoge rendert App.svelte nach `dialog.kind`; jeder Bereich öffnet sie nur über `openDialog`.
 * - Die Scope-Warnung steht als erster Eintrag in «Als Nächstes» (E120); `openDialog({ kind:
 *   'scope-warning' })` (Kennzeichen in der Kopfzeile) setzt `scopeFocus`, der Eintrag nimmt dann
 *   den Fokus (auch erst nach dem Wechsel auf den Reiter Karte). `scopeCard` merkt nur noch, dass eine neue Warnung eingetroffen ist.
 * - Tafeln (Beleg, Einstellungen) stehen in der URL (`beleg`, `tafel`), nicht hier.
 * - Meldungen nennen nie Zieldaten (feste Texte aus i18n).
 * - Puls («+N seit», E106): `pulse(ids)` erhöht `pulseToken`; Komponenten fragen `isPulsing(id)`
 *   und nutzen die Action `pulse` aus util/motion.ts.
 */
import type { NewSince, ScopeChange, ScopeOption } from '../api/types';

/**
 * «In den Scope aufnehmen …» (E129): Ziele, für die der Server Vorschläge liefert, oder fertige
 * Vorschläge einer Klärung (E130); `selected` wählt einen Eintrag vor.
 */
export interface ScopeAddRequest {
  kind: 'scope-add';
  /** Ziele; `proposals` vom Server (am Ziel der Warnung, in der Klärung), sonst fragt der Dialog nach */
  values: { value: string; ctrl?: boolean; verdict?: string; proposals?: ScopeOption[] | null }[];
  source: NonNullable<ScopeChange['source']>;
  selected?: string;
}

export type DialogRequest =
  | { kind: 'context'; terminalId: string; itemKey?: string; fromOff?: number }
  | { kind: 'export' }
  | { kind: 'screenshot' }
  | { kind: 'help' }
  | { kind: 'palette' }
  | { kind: 'scope-warning' }
  | { kind: 'scope-view' }
  | ScopeAddRequest
  | { kind: 'scope-edit'; op: 'add' | 'remove' | 'exclude'; entry?: string; list?: 'include' | 'exclude' }
  /** E131: Scope öffnen bzw. schliessen (Einstellungen) */
  | { kind: 'scope-open'; op: 'open' | 'close' };

export interface Notice {
  id: number;
  kind: 'error' | 'info';
  text: string;
}

export class UiStore {
  dialog = $state<DialogRequest | null>(null);
  /** Meldung «Ziel ausserhalb des Scopes» (nicht modal) */
  scopeCard = $state(false);
  /** Kennzeichen geklickt: der Eintrag in der Spalte nimmt den Fokus, sobald er da ist (E120) */
  scopeFocus = $state(false);
  /** Element, das den Dialog geöffnet hat (Fokus kehrt dorthin zurück) */
  dialogReturn: HTMLElement | null = null;
  popover = $state<string | null>(null);
  notices = $state<Notice[]>([]);
  pulseToken = $state(0);
  pulseIds = $state.raw<Set<string>>(new Set());
  /**
   * Ein Formular mit ungespeicherten Änderungen ist offen (Finding, Notiz). Solange sperren die
   * Reiterkürzel 1 bis 4 und melden das, statt den Entwurf zu verwerfen (Korrektur A6, A11).
   */
  dirtyForms = $state.raw<Set<string>>(new Set());
  private nextNotice = 1;

  setDirty(id: string, dirty: boolean): void {
    if (dirty === this.dirtyForms.has(id)) return;
    const next = new Set(this.dirtyForms);
    if (dirty) next.add(id);
    else next.delete(id);
    this.dirtyForms = next;
  }

  get hasDirtyForm(): boolean {
    return this.dirtyForms.size > 0;
  }

  openDialog(req: DialogRequest): void {
    if (req.kind === 'scope-warning') {
      this.popover = null;
      this.scopeCard = true;
      this.scopeFocus = true;
      return;
    }
    this.dialogReturn = typeof document !== 'undefined' && document.activeElement instanceof HTMLElement ? document.activeElement : null;
    this.popover = null;
    this.dialog = req;
  }

  closeDialog(): void {
    this.dialog = null;
  }

  togglePopover(id: string): void {
    this.popover = this.popover === id ? null : id;
  }

  closePopover(id?: string): void {
    if (!id || this.popover === id) this.popover = null;
  }

  notify(kind: Notice['kind'], text: string, timeoutMs = kind === 'error' ? 8000 : 4000): number {
    const id = this.nextNotice++;
    this.notices = [...this.notices.slice(-3), { id, kind, text }];
    if (timeoutMs > 0) setTimeout(() => this.dismiss(id), timeoutMs);
    return id;
  }

  dismiss(id: number): void {
    this.notices = this.notices.filter((n) => n.id !== id);
  }

  /** Lässt die neuen Elemente einmal pulsieren (BEHAVIOR «Neu seit»). */
  pulse(n: NewSince | null): void {
    if (!n) return;
    this.pulseIds = new Set([...n.hosts, ...n.access, ...n.services, ...n.items, ...n.keysteps]);
    this.pulseToken++;
  }

  isPulsing(id: string): boolean {
    return this.pulseIds.has(id);
  }
}
