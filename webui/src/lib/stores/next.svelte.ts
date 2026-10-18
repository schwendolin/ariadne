/**
 * «Als Nächstes» (E105, E110, Briefing 5.2, BEHAVIOR «Spalte», web-api.md 9 und 18.6).
 * Besitzer: ui-karte.
 *
 * - Lädt `/next` beim Öffnen und nach `inbox`, `suggestion`, `changes` und `presentation`
 *   (gebündelt, 250 ms). `open` ist die Zahl offener Klärungen (Tab-Titel, Favicon).
 * - Reihenfolge: Klären vor Denkanstössen. Es ist immer genau ein Eintrag gewählt (`sel` in der
 *   URL, sonst der erste offene); der gewählte offene Eintrag ist aufgeklappt.
 * - Eigene Entscheide: kein optimistisches Ausblenden. Der Eintrag ist «busy», bis der neue Stand
 *   ihn nicht mehr enthält; dann steht er gedämpft als erledigt da (mit «Rückgängig», wenn es einen
 *   Entscheid zum Widerrufen gibt) und der Cursor springt zur nächsten Klärung, sonst zum ersten
 *   Denkanstoss (Ruhezustand).
 * - Verschwindet ein Eintrag, ohne dass dieser Tab entschieden hat, steht er als «In einem anderen
 *   Tab entschieden» da; der Cursor springt nicht.
 * - Erledigte bleiben bis zum nächsten Wechsel ins Dashboard stehen (Tab wieder sichtbar).
 * - Lernmodus (Vorlieben, E112): Stufen Frage, Richtung, Vorlage, jede erst auf Klick.
 * - Palette: Quelle «next».
 */
import type { ChangeSet, ContextResult, DecisionInput, NextItem, NextView, StreamEvent, Suggestion, TextPart } from '../api/types';
import { t, type MessageKey } from '../i18n';
import { hostOfService } from '../karte/model';
import { registerPaletteSource, type PaletteItem } from '../shell/palette';
import { encodeEvidence, url, type EvidenceTarget } from '../url/state.svelte';
import { errorText, isAbort } from '../util/errors';
import { termShort } from '../util/format';
import type { ProjectCtx, ProjectPart } from './ctx';

export type Group = 'clarify' | 'suggestion';

export interface DoneMsg {
  key: MessageKey;
  params: Record<string, string>;
  /** Parameter, die Zieldaten sind (Mono, über Txt) */
  mono: string[];
}

export interface DoneEntry {
  key: string;
  group: Group;
  /** Position in der Gruppe beim Erledigen (der Eintrag bleibt an seinem Platz) */
  index: number;
  state: 'done' | 'dismissed' | 'other_tab';
  msg: DoneMsg | null;
  /** ursprüngliche Zeile (anderer Tab, verworfen durchgestrichen) */
  line: ItemLine;
  decisionId: string | null;
  /** Kontext lässt sich nicht widerrufen, nur neu setzen («Ändern …») */
  ctx: { terminalId: string; fromOff: number } | null;
}

export interface ItemLine {
  /** fester Text (Art) */
  kind: string;
  /** Zieldaten in Teilen */
  parts: TextPart[];
}

export type Row =
  | { type: 'clarify'; key: string; index: number; item: NextItem }
  | { type: 'suggestion'; key: string; index: number; s: Suggestion }
  | { type: 'done'; key: string; entry: DoneEntry };

interface Pending {
  group: Group;
  index: number;
  state: DoneEntry['state'];
  msg: DoneMsg | null;
  line: ItemLine;
  decisionId: string | null;
  ctx: DoneEntry['ctx'];
  until: number;
}

const BUSY_MS = 6000;

/** Kurze Zeile eines Eintrags (einzeilig in der Liste, Palette, Erledigt-Zeile). */
export function itemLine(item: NextItem, short: (s: string) => string = (s) => s): ItemLine {
  const kind = t(`next.kind.${item.kind}` as MessageKey);
  const p = (text: string): TextPart => ({ text: short(text), target: true });
  switch (item.kind) {
    case 'ctx_suggestion':
      return { kind: t('next.kind.ctx_unknown'), parts: [{ text: `${termShort(item.terminal ?? { ordinal: null, terminal_id: item.terminal_id })} · `, target: false }, p(item.suggested_label)] };
    case 'ctx_unknown': {
      const parts: TextPart[] = [];
      if (item.terminal || item.terminal_id) parts.push({ text: termShort(item.terminal ?? { ordinal: null, terminal_id: item.terminal_id ?? undefined }), target: false });
      if (item.candidate) parts.push({ text: parts.length ? ' · ' : '', target: false }, p(item.candidate));
      else if (item.unit) parts.push({ text: parts.length ? ' · ' : '', target: false }, p(item.unit.title));
      return { kind, parts };
    }
    case 'merge_suggestion': {
      const ids = item.identifiers.filter((i) => i.key !== item.shared);
      const parts: TextPart[] = [];
      ids.forEach((i, n) => {
        if (n > 0) parts.push({ text: ' + ', target: false });
        parts.push(p(i.label));
      });
      return { kind, parts };
    }
    case 'conflict':
      return { kind, parts: [p(item.conflict.subject_label)] };
    case 'decide_value':
      return { kind, parts: [p(item.fact.subject_label), { text: ' · ', target: false }, { text: item.fact.is_secret ? '••••••••' : item.fact.value, target: true }] };
    case 'orphan_decision':
      return { kind, parts: item.ref ? [p(item.ref)] : [] };
    case 'mass_find':
      return { kind, parts: [p(item.unit.title)] };
    default:
      return { kind: t('next.kind.unknown'), parts: [] };
  }
}

/** Host-IDs, die ein Eintrag betrifft (Markierung auf der Karte). */
export function itemHosts(item: NextItem): string[] {
  switch (item.kind) {
    case 'ctx_suggestion':
      return [item.suggested_host];
    case 'merge_suggestion':
      return item.identifiers.filter((i) => i.key !== item.shared).map((i) => i.key);
    case 'conflict':
      return [hostOfService(item.conflict.subject) ?? item.conflict.subject];
    case 'decide_value':
      return [hostOfService(item.fact.subject) ?? item.fact.subject];
    case 'ctx_unknown': {
      const c = item.candidate;
      if (!c) return [];
      return [/^[\d.]+$/.test(c) || /^[0-9a-f:]+$/i.test(c) ? `ip:default/${c}` : `name:${c}`];
    }
    default:
      return [];
  }
}

/** Belegansicht zu einem Eintrag (↵), sonst null. */
export function itemEvidence(item: NextItem): EvidenceTarget | null {
  switch (item.kind) {
    case 'ctx_suggestion':
      if (item.claim_key) return { kind: 'claim', claim_key: item.claim_key };
      return item.excerpt ? { kind: 'unit', unit_id: item.excerpt.unit_id, lines: item.excerpt.lines } : null;
    case 'ctx_unknown':
      if (item.excerpt) return { kind: 'unit', unit_id: item.excerpt.unit_id, lines: item.excerpt.lines };
      return item.unit ? { kind: 'unit', unit_id: item.unit.unit_id, lines: null } : null;
    case 'decide_value':
      return { kind: 'claim', claim_key: item.fact.claim_key };
    case 'conflict': {
      const v = item.conflict.values[0];
      return v ? { kind: 'claim', claim_key: v.claim_key } : null;
    }
    case 'mass_find':
      return { kind: 'unit', unit_id: item.unit.unit_id, lines: null };
    default:
      return null;
  }
}

export function suggestionEvidence(s: Suggestion): EvidenceTarget | null {
  const e = s.evidence[0];
  if (!e) return null;
  if (e.unit_id) return { kind: 'unit', unit_id: e.unit_id, lines: e.lines };
  if (e.claim_key) return { kind: 'claim', claim_key: e.claim_key };
  return null;
}

export class NextStore implements ProjectPart {
  view = $state.raw<NextView | null>(null);
  error = $state<unknown>(null);
  done = $state.raw<DoneEntry[]>([]);
  busy = $state.raw<Record<string, true>>({});
  /** Lernmodus: aufgedeckte Stufen pro Denkanstoss (0 bis 3) */
  stages = $state.raw<Record<string, number>>({});
  /** `e`: Ändern im gewählten Eintrag (Wert entscheiden) */
  editToken = $state(0);
  private pending = new Map<string, Pending>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private busyTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private hiddenSince = false;
  private offPalette: (() => void) | null = null;
  private readonly onVisibility = () => {
    if (document.visibilityState === 'hidden') this.hiddenSince = true;
    else if (this.hiddenSince) {
      // nächster Wechsel ins Dashboard: Erledigte verschwinden
      this.hiddenSince = false;
      this.done = [];
    }
  };

  constructor(private readonly ctx: ProjectCtx) {
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', this.onVisibility);
    this.offPalette = registerPaletteSource('next', () => this.paletteItems());
  }

  /** offene Klärungen (Favicon, Tab-Titel «ms2 · 2 zu klären») */
  get open(): number {
    return this.view?.open ?? 0;
  }

  get clarifyItems(): NextItem[] {
    return this.view?.clarify ?? [];
  }

  get suggestionItems(): Suggestion[] {
    return this.view?.suggestions ?? [];
  }

  /** Zeilen einer Gruppe: offene Einträge, Erledigte an ihrem Platz. */
  rowsOf(group: Group): Row[] {
    const rows: Row[] =
      group === 'clarify'
        ? this.clarifyItems.map((item, index) => ({ type: 'clarify' as const, key: item.item_key, index, item }))
        : this.suggestionItems.map((s, index) => ({ type: 'suggestion' as const, key: s.suggestion_key, index, s }));
    const done = this.done
      .map((d, order) => ({ d, order }))
      .filter((x) => x.d.group === group)
      .sort((a, b) => a.d.index - b.d.index || a.order - b.order);
    for (const { d } of done) {
      if (rows.some((r) => r.key === d.key)) continue;
      const at = Math.min(Math.max(0, d.index), rows.length);
      rows.splice(at, 0, { type: 'done', key: d.key, entry: d });
    }
    return rows;
  }

  get rows(): Row[] {
    return [...this.rowsOf('clarify'), ...this.rowsOf('suggestion')];
  }

  /** gewählter Eintrag: `sel` aus der URL, sonst der erste offene (Klären vor Denkanstössen) */
  get selectedKey(): string | null {
    const rows = this.rows;
    const sel = url.get('sel');
    if (sel && rows.some((r) => r.key === sel)) return sel;
    return rows.find((r) => r.type === 'clarify')?.key ?? rows.find((r) => r.type === 'suggestion')?.key ?? rows[0]?.key ?? null;
  }

  get selectedRow(): Row | null {
    const key = this.selectedKey;
    return this.rows.find((r) => r.key === key) ?? null;
  }

  /** «K2», «D1»: Nummer eines offenen Eintrags in seiner Gruppe */
  ordinal(key: string): string | null {
    const ci = this.clarifyItems.findIndex((i) => i.item_key === key);
    if (ci >= 0) return `K${ci + 1}`;
    const si = this.suggestionItems.findIndex((s) => s.suggestion_key === key);
    return si >= 0 ? `D${si + 1}` : null;
  }

  /** Hosts des gewählten offenen Eintrags (Karte: gestrichelter Ring) */
  get linkedHosts(): string[] {
    const row = this.selectedRow;
    if (!row) return [];
    // Wie im Design (1a): markiert wird der Host einer gewählten Klärung, nicht der eines Denkanstosses.
    return row.type === 'clarify' ? itemHosts(row.item) : [];
  }

  select(key: string | null): void {
    if (key === url.get('sel')) return;
    url.set({ sel: key });
  }

  /** j/k: nächster bzw. vorheriger Eintrag */
  move(delta: 1 | -1): void {
    const rows = this.rows;
    if (rows.length === 0) return;
    const i = rows.findIndex((r) => r.key === this.selectedKey);
    const next = rows[Math.max(0, Math.min(rows.length - 1, (i < 0 ? 0 : i) + delta))];
    if (next) this.select(next.key);
  }

  /** n: nächster offener Denkanstoss (mit Umlauf) */
  nextSuggestion(): void {
    const sugs = this.suggestionItems;
    if (sugs.length === 0) return;
    const i = sugs.findIndex((s) => s.suggestion_key === this.selectedKey);
    const s = sugs[(i + 1) % sugs.length];
    if (s) this.select(s.suggestion_key);
  }

  stageOf(key: string): number {
    return this.stages[key] ?? 0;
  }

  revealStage(key: string): void {
    this.stages = { ...this.stages, [key]: Math.min(3, this.stageOf(key) + 1) };
  }

  requestEdit(): void {
    this.editToken++;
  }

  isBusy(key: string): boolean {
    return this.busy[key] === true;
  }

  async load(): Promise<void> {
    try {
      const v = await this.ctx.backend.next(this.ctx.pid, this.ctx.signal);
      this.apply(v);
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) this.error = e;
    }
  }

  /** Neuen Stand übernehmen: Verschwundenes wird erledigt (eigen) oder «anderer Tab». */
  private apply(v: NextView): void {
    const before = this.view;
    const selected = this.selectedKey;
    let jumpFrom: { group: Group; index: number } | null = null;
    if (before) {
      const now = new Set([...v.clarify.map((i) => i.item_key), ...v.suggestions.map((s) => s.suggestion_key)]);
      // Plätze in der bisherigen Liste (mit Erledigten), damit Erledigte an ihrem Platz bleiben
      const rowIndex = (group: Group, key: string) => this.rowsOf(group).findIndex((r) => r.key === key);
      const added: DoneEntry[] = [];
      before.clarify.forEach((item, index) => {
        if (now.has(item.item_key)) return;
        added.push(this.toDone(item.item_key, 'clarify', rowIndex('clarify', item.item_key), itemLine(item)));
        if (item.item_key === selected && this.pending.has(item.item_key)) jumpFrom = { group: 'clarify', index };
      });
      before.suggestions.forEach((s, index) => {
        if (now.has(s.suggestion_key)) return;
        added.push(this.toDone(s.suggestion_key, 'suggestion', rowIndex('suggestion', s.suggestion_key), { kind: t('sug.rule'), parts: s.title_parts }));
        if (s.suggestion_key === selected && this.pending.has(s.suggestion_key)) jumpFrom = { group: 'suggestion', index };
      });
      // Anderer Tab: der Cursor springt nicht, er bleibt auf der erledigten Zeile (auch ohne `sel`)
      const stay = added.find((d) => d.key === selected && d.state === 'other_tab');
      if (stay && url.get('sel') !== stay.key) url.set({ sel: stay.key });
      for (const d of added) this.pending.delete(d.key);
      if (added.length) {
        const keys = new Set(added.map((d) => d.key));
        this.done = [...this.done.filter((d) => !keys.has(d.key)), ...added];
        for (const k of keys) this.clearBusy(k);
      }
    }
    // Wiederkehrende Einträge (Rückgängig, neuer Anlass) sind nicht mehr erledigt.
    const reopened = new Set([...v.clarify.map((i) => i.item_key), ...v.suggestions.map((s) => s.suggestion_key)]);
    if (this.done.some((d) => reopened.has(d.key))) this.done = this.done.filter((d) => !reopened.has(d.key));
    this.view = v;
    if (jumpFrom) this.jumpAfter(jumpFrom);
  }

  private toDone(key: string, group: Group, index: number, line: ItemLine): DoneEntry {
    const p = this.pending.get(key);
    if (p && p.until > Date.now()) {
      return { key, group, index, state: p.state, msg: p.msg, line: p.line, decisionId: p.decisionId, ctx: p.ctx };
    }
    return { key, group, index, state: 'other_tab', msg: null, line, decisionId: null, ctx: null };
  }

  /** Cursor nach eigenem Entscheid: nächste Klärung, sonst erster Denkanstoss (Ruhezustand). */
  private jumpAfter(from: { group: Group; index: number }): void {
    const clarify = this.clarifyItems;
    const sugs = this.suggestionItems;
    const key =
      from.group === 'clarify'
        ? (clarify[from.index]?.item_key ?? clarify[0]?.item_key ?? sugs[0]?.suggestion_key ?? null)
        : (sugs[from.index]?.suggestion_key ?? sugs[0]?.suggestion_key ?? clarify[0]?.item_key ?? null);
    if (key) url.set({ sel: key });
  }

  private reloadSoon(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.load();
    }, 250);
  }

  onChanges(_cs: ChangeSet): void {
    this.reloadSoon();
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'inbox' || ev.name === 'suggestion' || ev.name === 'presentation') this.reloadSoon();
  }

  // ------------------------------------------------------------------ Aktionen

  private setBusy(key: string): void {
    this.busy = { ...this.busy, [key]: true };
    const old = this.busyTimers.get(key);
    if (old) clearTimeout(old);
    this.busyTimers.set(
      key,
      setTimeout(() => {
        this.clearBusy(key);
        this.pending.delete(key);
      }, BUSY_MS),
    );
  }

  private clearBusy(key: string): void {
    const tm = this.busyTimers.get(key);
    if (tm) clearTimeout(tm);
    this.busyTimers.delete(key);
    if (this.busy[key]) {
      const { [key]: _gone, ...rest } = this.busy;
      this.busy = rest;
    }
  }

  private indexOf(key: string, group: Group): number {
    return group === 'clarify' ? this.clarifyItems.findIndex((i) => i.item_key === key) : this.suggestionItems.findIndex((s) => s.suggestion_key === key);
  }

  private remember(key: string, group: Group, p: Omit<Pending, 'group' | 'index' | 'until' | 'line'> & { line: ItemLine }): void {
    this.pending.set(key, { ...p, group, index: Math.max(0, this.indexOf(key, group)), until: Date.now() + BUSY_MS });
    this.reloadSoon();
  }

  /** Entscheid schreiben und als eigenen merken. */
  private async decideFor(key: string, group: Group, d: DecisionInput, after: Omit<Pending, 'group' | 'index' | 'until' | 'decisionId'>): Promise<boolean> {
    if (this.isBusy(key) || this.ctx.app.offline) return false;
    this.setBusy(key);
    const res = await this.ctx.decide([d]);
    if (!res) {
      this.clearBusy(key);
      return false;
    }
    this.remember(key, group, { ...after, decisionId: res.results[0]?.decision_id ?? null });
    return true;
  }

  /** Kontextvorschlag übernehmen (a): POST /terminals/{tid}/context mit `accept`. */
  async acceptContext(item: Extract<NextItem, { kind: 'ctx_suggestion' }>): Promise<boolean> {
    const key = item.item_key;
    if (this.isBusy(key) || this.ctx.app.offline) return false;
    this.setBusy(key);
    let res: ContextResult;
    try {
      res = await this.ctx.backend.setContext(item.terminal_id, { op: 'accept', item_key: key });
    } catch (e) {
      this.clearBusy(key);
      if (!isAbort(e)) this.ctx.app.ui.notify('error', errorText(e, 'next.ctxFailed'));
      return false;
    }
    for (const w of res.warnings) this.ctx.app.ui.notify('info', t(`next.ctxWarn.${w.code}` as MessageKey));
    const term = termShort(item.terminal ?? { ordinal: null, terminal_id: item.terminal_id });
    this.remember(key, 'clarify', {
      state: 'done',
      msg: { key: 'next.d.ctx', params: { term, host: item.suggested_label }, mono: ['host'] },
      line: itemLine(item),
      decisionId: null,
      ctx: { terminalId: item.terminal_id, fromOff: item.from_off },
    });
    return true;
  }

  /** «Anderer Host …» bzw. «Host setzen …»: Kontext-Dialog (ui-verlauf). */
  openContextDialog(item: NextItem): void {
    if (item.kind !== 'ctx_suggestion' && item.kind !== 'ctx_unknown') return;
    if (!item.terminal_id) return;
    this.ctx.app.ui.openDialog({ kind: 'context', terminalId: item.terminal_id, itemKey: item.item_key, fromOff: item.from_off ?? undefined });
  }

  merge(item: Extract<NextItem, { kind: 'merge_suggestion' }>, together: boolean): Promise<boolean> {
    const ids = item.identifiers.filter((i) => i.key !== item.shared);
    const [a, b] = [ids[0]?.label ?? '', ids[1]?.label ?? ''];
    const outside = ids.find((i) => i.verdict !== 'in') ?? ids[1];
    const inside = ids.find((i) => i !== outside) ?? ids[0];
    return this.decideFor(
      item.item_key,
      'clarify',
      { kind: together ? 'd.entity.merge' : 'd.entity.split', payload: { identifiers: ids.map((i) => i.key) } },
      {
        state: 'done',
        msg: together
          ? { key: 'next.d.merged', params: { a: outside?.label ?? a, b: inside?.label ?? b }, mono: ['a', 'b'] }
          : { key: 'next.d.separate', params: { a, b }, mono: ['a', 'b'] },
        line: itemLine(item),
        ctx: null,
      },
    );
  }

  decideValue(item: Extract<NextItem, { kind: 'decide_value' }>, action: 'confirm' | 'reject' | 'edit', value?: string): Promise<boolean> {
    const payload: Record<string, unknown> = { claim_key: item.fact.claim_key };
    if (action === 'edit') payload.value = value ?? '';
    const kind = action === 'confirm' ? 'd.claim.confirm' : action === 'reject' ? 'd.claim.reject' : 'd.claim.edit';
    const msgKey: MessageKey = action === 'confirm' ? 'next.d.confirmed' : action === 'reject' ? 'next.d.rejected' : 'next.d.edited';
    return this.decideFor(item.item_key, 'clarify', { kind, payload }, {
      state: action === 'reject' ? 'dismissed' : 'done',
      msg: { key: msgKey, params: {}, mono: [] },
      line: itemLine(item),
      ctx: null,
    });
  }

  resolveConflict(item: Extract<NextItem, { kind: 'conflict' }>, choice: string | null): Promise<boolean> {
    const payload: Record<string, unknown> = { conflict_key: item.conflict.conflict_key };
    if (choice) payload.choice = choice;
    else payload.keep_open = true;
    return this.decideFor(item.item_key, 'clarify', { kind: 'd.conflict.resolve', payload }, {
      state: 'done',
      msg: { key: choice ? 'next.d.resolved' : 'next.d.keptOpen', params: {}, mono: [] },
      line: itemLine(item),
      ctx: null,
    });
  }

  revokeOrphan(item: Extract<NextItem, { kind: 'orphan_decision' }>): Promise<boolean> {
    return this.decideFor(item.item_key, 'clarify', { kind: 'd.revoke', payload: { decision_id: item.decision_id } }, {
      state: 'done',
      msg: { key: 'next.d.revoked', params: {}, mono: [] },
      line: itemLine(item),
      ctx: null,
    });
  }

  suggestionDone(s: Suggestion): Promise<boolean> {
    return this.decideFor(s.suggestion_key, 'suggestion', { kind: 'd.suggestion.done', payload: { suggestion_key: s.suggestion_key, basis: s.basis } }, {
      state: 'done',
      // Zeile zeigt den Titel gedämpft (ein blosses «erledigt» sagt nicht, was erledigt ist)
      msg: null,
      line: { kind: t('sug.rule'), parts: s.title_parts },
      ctx: null,
    });
  }

  suggestionDismiss(s: Suggestion): Promise<boolean> {
    return this.decideFor(s.suggestion_key, 'suggestion', { kind: 'd.suggestion.dismiss', payload: { suggestion_key: s.suggestion_key } }, {
      state: 'dismissed',
      msg: { key: 'next.d.sugDismissed', params: {}, mono: [] },
      line: { kind: t('sug.rule'), parts: s.title_parts },
      ctx: null,
    });
  }

  /** Rückgängig (u): Entscheid widerrufen; der Eintrag kommt mit dem neuen Stand zurück. */
  async undo(entry: DoneEntry): Promise<boolean> {
    if (!entry.decisionId || this.isBusy(entry.key) || this.ctx.app.offline) return false;
    this.setBusy(entry.key);
    const res = await this.ctx.decide([{ kind: 'd.revoke', payload: { decision_id: entry.decisionId } }], { errorPrefix: 'next.undoFailed' });
    this.clearBusy(entry.key);
    if (!res) return false;
    this.done = this.done.filter((d) => d.key !== entry.key);
    this.reloadSoon();
    return true;
  }

  /** u ohne gewählte Erledigt-Zeile: die jüngste mit Entscheid */
  get lastUndoable(): DoneEntry | null {
    const list = this.done.filter((d) => d.decisionId && d.state !== 'other_tab');
    return list[list.length - 1] ?? null;
  }

  /** ↵: Belegansicht des gewählten Eintrags (Tafel von ui-verlauf). */
  openEvidence(row: Row | null = this.selectedRow): boolean {
    if (!row) return false;
    const target = row.type === 'clarify' ? itemEvidence(row.item) : row.type === 'suggestion' ? suggestionEvidence(row.s) : null;
    if (!target) return false;
    url.set({ beleg: encodeEvidence(target) }, { push: true });
    return true;
  }

  private paletteItems(): PaletteItem[] {
    const out: PaletteItem[] = [];
    this.clarifyItems.forEach((item, i) => {
      const line = itemLine(item);
      const text = line.parts.map((p) => p.text).join('');
      out.push({
        id: `next:${item.item_key}`,
        group: 'next',
        label: `${line.kind}${text ? ` · ${text}` : ''}`,
        hint: `K${i + 1}`,
        keywords: `${line.kind} ${text} klären`.toLowerCase(),
        run: () => url.go('karte', { sel: item.item_key, host: null }, { keep: true }),
      });
    });
    this.suggestionItems.forEach((s, i) => {
      out.push({
        id: `next:${s.suggestion_key}`,
        group: 'next',
        label: s.title,
        hint: `D${i + 1}`,
        keywords: `${s.title} ${s.rule_id} ${s.goal_id ?? ''} denkanstoss`.toLowerCase(),
        run: () => url.go('karte', { sel: s.suggestion_key, host: null }, { keep: true }),
      });
    });
    return out;
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
    for (const tm of this.busyTimers.values()) clearTimeout(tm);
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', this.onVisibility);
    this.offPalette?.();
  }
}
