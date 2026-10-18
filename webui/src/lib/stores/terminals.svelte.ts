/**
 * Reiter Terminals (Briefing 5.4, Screen 5, web-api.md 5, 10.2, 18.8). Besitzer: ui-verlauf.
 *
 * - Lädt `/terminals` und die Eingaben (`/inputs`, für «Eingabe ohne Echo» pro Terminal) beim
 *   Öffnen, nach dem Ereignis `terminal` (gebündelt) und nach `changes` (Namen ändern sich über
 *   den Entscheid `d.terminal.label`).
 * - Ein Terminal, das aus der Liste verschwindet, bleibt bis zum Projektwechsel als «geschlossen»
 *   stehen (Briefing 5.14), ohne Aktionen.
 * - Pause und Fortsetzen laufen über AppState (gemeinsam mit dem Popover der Aufnahme, E107, E117);
 *   Kontext setzen über den Kontext-Dialog (`POST /terminals/{tid}/context`).
 */
import type { ChangeSet, InputView, StreamEvent, Terminal } from '../api/types';
import { decideWithError } from '../timeline/decide';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

const LABEL_MAX = 64;
const CLOSED_MAX = 20;
const INPUTS_LIMIT = 200;

export class TerminalsStore implements ProjectPart {
  list = $state.raw<Terminal[]>([]);
  /** verschwundene Terminals (geschlossen), neueste zuerst */
  closed = $state.raw<Terminal[]>([]);
  inputs = $state.raw<InputView[]>([]);
  loaded = $state(false);
  error = $state<unknown>(null);
  private req = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly ctx: ProjectCtx) {}

  /** Liste für die Ansicht: offene in der Reihenfolge des Daemons, dann geschlossene. */
  get all(): { term: Terminal; closed: boolean }[] {
    return [...this.list.map((term) => ({ term, closed: false })), ...this.closed.map((term) => ({ term, closed: true }))];
  }

  byId(tid: string): Terminal | null {
    return this.list.find((x) => x.terminal_id === tid) ?? this.closed.find((x) => x.terminal_id === tid) ?? null;
  }

  isClosed(tid: string): boolean {
    return !this.list.some((x) => x.terminal_id === tid) && this.closed.some((x) => x.terminal_id === tid);
  }

  /** verdeckte Eingaben (E104) eines Terminals, neueste zuerst */
  hiddenInputs(tid: string): InputView[] {
    return this.inputs.filter((i) => i.terminal_id === tid && i.hidden).reverse();
  }

  async load(): Promise<void> {
    const id = ++this.req;
    try {
      const [terms, inputs] = await Promise.all([
        this.ctx.backend.terminals(this.ctx.signal),
        this.ctx.backend.inputs(this.ctx.pid, { limit: INPUTS_LIMIT }, this.ctx.signal).catch((e: unknown) => {
          if (isAbort(e)) throw e;
          return null;
        }),
      ]);
      if (id !== this.req) return;
      this.apply(terms);
      if (inputs) this.inputs = inputs;
      this.loaded = true;
      this.error = null;
    } catch (e) {
      if (!isAbort(e) && id === this.req) {
        this.error = e;
        this.loaded = true;
      }
    }
  }

  private apply(terms: Terminal[]): void {
    const now = new Set(terms.map((x) => x.terminal_id));
    const gone = this.loaded ? this.list.filter((x) => !now.has(x.terminal_id) && x.state !== 'held') : [];
    const kept = this.closed.filter((x) => !now.has(x.terminal_id) && !gone.some((g) => g.terminal_id === x.terminal_id));
    this.closed = [...gone.map((x) => ({ ...x, connected: false })), ...kept].slice(0, CLOSED_MAX);
    this.list = terms;
  }

  private reloadSoon(delay = 150): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.load();
    }, delay);
  }

  onChanges(cs: ChangeSet): void {
    if (cs.changes.length > 0) this.reloadSoon();
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'terminal' || ev.name === 'presentation') this.reloadSoon(ev.name === 'presentation' ? 0 : 150);
  }

  /** Terminal umbenennen (`d.terminal.label`, höchstens 64 Zeichen). Gibt den Fehlertext zurück. */
  async rename(tid: string, label: string): Promise<string | null> {
    const v = label.trim();
    if (!v || [...v].length > LABEL_MAX) return null;
    const out = await decideWithError(this.ctx, [{ kind: 'd.terminal.label', payload: { terminal_id: tid, label: v } }], 'term.renameFailed');
    if (out.res) this.reloadSoon(0);
    return out.error;
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
  }
}
