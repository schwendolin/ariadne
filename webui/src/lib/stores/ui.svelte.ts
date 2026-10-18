/**
 * Zustand der Oberfläche ohne Daten: Dialoge, Popover, Meldungen, Puls. Besitzer: ui-fundament.
 *
 * - Es ist höchstens ein Dialog offen (`dialog`) und höchstens ein Popover (`popover`).
 *   Dialoge rendert App.svelte nach `dialog.kind`; jeder Bereich öffnet sie nur über `openDialog`.
 * - Die Scope-Warnung (Briefing 4.5, Screen 10) ist kein modaler Dialog, sondern eine Meldung
 *   beim Eintreffen (`scopeCard`), die einen offenen Dialog nicht verdrängt; `openDialog({ kind:
 *   'scope-warning' })` öffnet sie wieder (Kennzeichen in der Kopfzeile).
 * - Tafeln (Beleg, Einstellungen) stehen in der URL (`beleg`, `tafel`), nicht hier.
 * - Meldungen nennen nie Zieldaten (feste Texte aus i18n).
 * - Puls («+N seit», E106): `pulse(ids)` erhöht `pulseToken`; Komponenten fragen `isPulsing(id)`
 *   und nutzen die Action `pulse` aus util/motion.ts.
 */
import type { NewSince } from '../api/types';

export type DialogRequest =
  | { kind: 'context'; terminalId: string; itemKey?: string; fromOff?: number }
  | { kind: 'export' }
  | { kind: 'screenshot' }
  | { kind: 'help' }
  | { kind: 'palette' }
  | { kind: 'scope-warning' }
  | { kind: 'scope-view' };

export interface Notice {
  id: number;
  kind: 'error' | 'info';
  text: string;
}

export class UiStore {
  dialog = $state<DialogRequest | null>(null);
  /** Meldung «Ziel ausserhalb des Scopes» (nicht modal) */
  scopeCard = $state(false);
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
