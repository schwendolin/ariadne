/**
 * Zeitachse und Warteliste (Briefing 5.5, 5.8, Screen 6, web-api.md 10, 13 und 18.8).
 * Besitzer: ui-verlauf.
 *
 * - Filter (Typ, Terminal, Host) kommen aus der URL (TimelineView setzt sie mit `setFilter`).
 *   Ohne Typfilter fragt der Store alle Typen samt Eingaben ab; die Ansicht zeigt davon nur die
 *   verdeckten Eingaben (timeline/model.ts).
 * - Seiten mit Cursor («Ältere laden»). Live: nach `changes` und nach dem Ereignis `terminal`
 *   (Befehl, Kontext, Zustand) lädt der Store gebündelt neu, und zwar so viele Einträge, wie schon
 *   geladen sind (höchstens 1000; darüber wird die erste Seite eingemischt). Beim Nachladen bleibt
 *   der alte Stand stehen, Auswahl und Scrollposition bleiben (Briefing 8).
 * - Rückgängig pro Befehl (E42, web-api.md 12): `d.unit.distrust` allein in der Anfrage, mit
 *   optionalem Grund; die Rückmeldung «18 verworfen, 0 geschwächt» steht inline in der Zeile,
 *   «Wieder vertrauen» hebt mit `d.revoke` auf. Fehler stehen inline («Rückgängig nicht
 *   gespeichert: Das Projekt ist gesperrt»).
 * - Palette: Quelle «commands» (Befehle der geladenen Zeitachse), solange das Projekt offen ist.
 */
import type { ChangeSet, PendingResponse, StreamEvent, TimelineItem, TimelineQuery } from '../api/types';
import { registerPaletteSource, type PaletteItem } from '../shell/palette';
import { decideWithError } from '../timeline/decide';
import { ALL_TYPES, NO_FILTER, mergeItems, rowMatches, sameFilter, shortCommand, visibleRows, type TimelineFilter } from '../timeline/model';
import { url } from '../url/state.svelte';
import { isAbort } from '../util/errors';
import { termShort } from '../util/format';
import { hhmm } from '../util/time';
import type { ProjectCtx, ProjectPart } from './ctx';

export const PAGE = 200;
const MAX_REFRESH = 1000;
const REASON_MAX = 500;

export type UndoPhase = 'ask' | 'busy' | 'done' | 'error' | 'trusting' | 'trusted' | 'trust_error';

export interface UndoState {
  /** TimelineItem.id der Befehlszeile */
  rowId: string;
  cmdId: string;
  cmdRef: string;
  /** «nmap 14:02» für den Satz im Formular */
  short: string;
  phase: UndoPhase;
  effect: { rejected: number; weakened: number } | null;
  decisionId: string | null;
  error: string | null;
}

export class TimelineStore implements ProjectPart {
  items = $state.raw<TimelineItem[]>([]);
  nextCursor = $state<string | null>(null);
  pending = $state.raw<PendingResponse | null>(null);
  pendingError = $state<unknown>(null);
  loaded = $state(false);
  loadingMore = $state(false);
  error = $state<unknown>(null);
  filter = $state.raw<TimelineFilter>(NO_FILTER);
  undo = $state.raw<UndoState | null>(null);
  /** Zeit (Date.now) der letzten erfolgreichen Antwort, für Tests und «Stand» */
  loadedAt = $state<number | null>(null);

  private req = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private offPalette: (() => void) | null;
  private disposed = false;

  constructor(private readonly ctx: ProjectCtx) {
    this.offPalette = registerPaletteSource('commands', () => this.paletteItems());
  }

  /** Zeilen, die die Ansicht zeigt (verdeckte Eingaben ohne Typfilter, sonst nach Filter). */
  get rows(): TimelineItem[] {
    return visibleRows(this.items, this.filter);
  }

  private query(limit: number, cursor?: string): TimelineQuery {
    const f = this.filter;
    return {
      types: f.types ?? ALL_TYPES,
      terminal: f.terminal ?? undefined,
      host: f.host ?? undefined,
      cursor,
      limit,
    };
  }

  async load(): Promise<void> {
    await Promise.all([this.fetchFirst(PAGE, true), this.loadPending()]);
  }

  /** Erste Seite neu (bei `replace` ersetzt sie die Liste, sonst deckt sie das Geladene ab). */
  private async fetchFirst(limit: number, replace: boolean): Promise<void> {
    const id = ++this.req;
    try {
      const page = await this.ctx.backend.timeline(this.ctx.pid, this.query(limit), this.ctx.signal);
      if (id !== this.req || this.disposed) return;
      if (replace || this.items.length <= MAX_REFRESH) {
        this.items = page.items;
        this.nextCursor = page.next_cursor;
      } else {
        this.items = mergeItems(this.items, page.items);
      }
      this.loaded = true;
      this.error = null;
      this.loadedAt = Date.now();
    } catch (e) {
      if (isAbort(e) || id !== this.req) return;
      this.error = e;
      this.loaded = true;
    }
  }

  async loadPending(): Promise<void> {
    try {
      this.pending = await this.ctx.backend.pending(this.ctx.pid, this.ctx.signal);
      this.pendingError = null;
    } catch (e) {
      if (!isAbort(e)) this.pendingError = e;
    }
  }

  /** Neu laden mit derselben Abdeckung wie bisher (Live-Aktualisierung ohne Springen). */
  async refresh(): Promise<void> {
    const limit = Math.min(MAX_REFRESH, Math.max(PAGE, this.items.length));
    await this.fetchFirst(limit, false);
  }

  /** «Ältere laden» */
  async loadMore(): Promise<void> {
    const cursor = this.nextCursor;
    if (!cursor || this.loadingMore) return;
    this.loadingMore = true;
    const id = this.req;
    try {
      const page = await this.ctx.backend.timeline(this.ctx.pid, this.query(PAGE, cursor), this.ctx.signal);
      if (id !== this.req || this.disposed) return;
      const known = new Set(this.items.map((x) => x.id));
      this.items = [...this.items, ...page.items.filter((x) => !known.has(x.id))];
      this.nextCursor = page.next_cursor;
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    } finally {
      this.loadingMore = false;
    }
  }

  /** Filter setzen (aus der URL); lädt nur bei echter Änderung neu. */
  setFilter(f: TimelineFilter): void {
    if (sameFilter(f, this.filter)) return;
    this.filter = f;
    this.undo = null;
    void this.fetchFirst(PAGE, true);
  }

  /**
   * Sorgt dafür, dass die Zeile `zeile` geladen ist (Sprung aus Scope-Warnung, Host-Detail,
   * Palette): lädt höchstens `maxPages` ältere Seiten nach. Gibt zurück, ob sie da ist.
   */
  async ensureRow(zeile: string, maxPages = 5): Promise<boolean> {
    for (let i = 0; i <= maxPages; i++) {
      if (this.items.some((x) => rowMatches(x, zeile))) return true;
      if (!this.nextCursor || this.disposed) return false;
      await this.loadMore();
    }
    return this.items.some((x) => rowMatches(x, zeile));
  }

  findByCmd(cmdId: string | null): Extract<TimelineItem, { type: 'command' }> | null {
    if (!cmdId) return null;
    for (const it of this.items) if (it.type === 'command' && (it.cmd.cmd_id === cmdId || it.cmd.cmd_ref === cmdId)) return it;
    return null;
  }

  private refreshSoon(delay = 250): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.refresh();
    }, delay);
  }

  onChanges(cs: ChangeSet): void {
    if (cs.changes.length === 0) return;
    this.refreshSoon();
    if (cs.changes.some((c) => c.entity === 'unit')) void this.loadPending();
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'terminal' && ev.data.change !== 'opened') {
      this.refreshSoon();
      if (ev.data.change === 'command') void this.loadPending();
    } else if (ev.name === 'presentation') {
      this.refreshSoon(0);
    }
  }

  // ------------------------------------------------------------------ Rückgängig pro Befehl
  askUndo(it: TimelineItem): void {
    if (it.type !== 'command' || it.distrusted) return;
    this.undo = {
      rowId: it.id,
      cmdId: it.cmd.cmd_id,
      cmdRef: it.cmd.cmd_ref,
      short: shortCommand(it.cmd.text, hhmm(it.ts)),
      phase: 'ask',
      effect: null,
      decisionId: null,
      error: null,
    };
  }

  cancelUndo(): void {
    if (this.undo && (this.undo.phase === 'busy' || this.undo.phase === 'trusting')) return;
    this.undo = null;
  }

  /** «Rückgängig machen»: d.unit.distrust (allein), Rückmeldung inline. */
  async distrust(reason: string): Promise<boolean> {
    const u = this.undo;
    if (!u || (u.phase !== 'ask' && u.phase !== 'error')) return false;
    const r = reason.trim().slice(0, REASON_MAX);
    this.undo = { ...u, phase: 'busy', error: null };
    const out = await decideWithError(
      this.ctx,
      [{ kind: 'd.unit.distrust', payload: r ? { cmd_id: u.cmdId, reason: r } : { cmd_id: u.cmdId } }],
      'tl.undo.failed',
    );
    if (this.undo?.rowId !== u.rowId) return out.res !== null;
    if (!out.res) {
      this.undo = { ...u, phase: 'error', error: out.error };
      return false;
    }
    const res = out.res.results[0];
    this.undo = { ...u, phase: 'done', effect: res?.effect ?? null, decisionId: res?.decision_id ?? null, error: null };
    this.refreshSoon(0);
    return true;
  }

  /** «Wieder vertrauen»: d.revoke auf den Entscheid von «Rückgängig pro Befehl». */
  async trustAgain(it: TimelineItem, decisionId: string): Promise<boolean> {
    if (it.type !== 'command') return false;
    const cur = this.undo && this.undo.rowId === it.id ? this.undo : null;
    const base: UndoState = cur ?? {
      rowId: it.id,
      cmdId: it.cmd.cmd_id,
      cmdRef: it.cmd.cmd_ref,
      short: shortCommand(it.cmd.text, hhmm(it.ts)),
      phase: 'trusting',
      effect: null,
      decisionId,
      error: null,
    };
    this.undo = { ...base, phase: 'trusting', decisionId, error: null };
    const out = await decideWithError(this.ctx, [{ kind: 'd.revoke', payload: { decision_id: decisionId } }], 'tl.undo.trustFailed');
    if (this.undo?.rowId !== it.id) return out.res !== null;
    if (!out.res) {
      this.undo = { ...base, phase: 'trust_error', decisionId, error: out.error };
      return false;
    }
    this.undo = { ...base, phase: 'trusted', decisionId, error: null };
    this.refreshSoon(0);
    return true;
  }

  // ------------------------------------------------------------------ Palette
  private paletteItems(): PaletteItem[] {
    const out: PaletteItem[] = [];
    for (const it of this.items) {
      if (it.type !== 'command') continue;
      const text = it.cmd.text ?? '';
      if (!text) continue;
      const term = termShort(it.terminal ?? { ordinal: null, terminal_id: it.terminal_id ?? '' });
      out.push({
        id: `cmd:${it.id}`,
        group: 'commands',
        label: text,
        mono: true,
        hint: `${term} · ${hhmm(it.ts)}`,
        keywords: `${text} ${term} befehl`.toLowerCase(),
        run: () => url.go('zeitachse', { zeile: it.cmd.cmd_id, typ: null, terminal: null, hostf: null }),
      });
      if (out.length >= 200) break;
    }
    return out;
  }

  dispose(): void {
    this.disposed = true;
    if (this.timer) clearTimeout(this.timer);
    this.offPalette?.();
    this.offPalette = null;
  }
}
