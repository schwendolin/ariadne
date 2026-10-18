/**
 * Findings (E113, Screen 8, web-api.md 18.5). Besitzer: ui-verlauf.
 *
 * - Liste (`/findings`) und das offene Finding (`/findings/{id}`, URL `finding=`); nach `changes`
 *   an Findings, Werten oder Einheiten gebündelt neu (Belegzustand «misstraut», «fehlt»).
 * - «Als Finding» aus der Belegansicht setzt `draftFrom` (und `draftLabel`) und öffnet
 *   `?finding=neu`: dasselbe Formular, Beleg und «angelegt aus» vorgefüllt.
 * - Speichern schreibt die Entscheide aus findings/form.ts in einer Anfrage. Nach dem Anlegen
 *   kennt die Projektion das Finding erst nach der Auswertung; bis dahin zeigt das Formular den
 *   gespeicherten Stand (`lastSaved`) und lädt nach dem nächsten `changes` nach.
 * - Palette: Quelle «findings» (Gruppe «Befehle», Vertrag 7.1).
 */
import type { ChangeSet, EvidenceRefIn, FindingDetail, FindingSummary, StreamEvent } from '../api/types';
import { buildDecisions, type FindingForm } from '../findings/form';
import { t } from '../i18n';
import { registerPaletteSource, type PaletteItem } from '../shell/palette';
import { decideWithError } from '../timeline/decide';
import { url } from '../url/state.svelte';
import { errorCode, isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export interface SaveResult {
  ok: boolean;
  id: string | null;
  error: string | null;
}

export class FindingsStore implements ProjectPart {
  list = $state.raw<FindingSummary[]>([]);
  current = $state.raw<FindingDetail | null>(null);
  /** gewünschtes Finding (URL); null oder 'neu' = keines */
  currentId = $state<string | null>(null);
  currentError = $state<unknown>(null);
  loaded = $state(false);
  error = $state<unknown>(null);
  saving = $state(false);
  /** «Als Finding» aus der Belegansicht: Beleg für das neue Formular (`?finding=neu`) */
  draftFrom = $state.raw<EvidenceRefIn | null>(null);
  /** Anzeige zum vorgefüllten Beleg («T2 msf 16:45:12 · Zeilen 44 bis 47») */
  draftLabel = $state<string | null>(null);
  /** gerade gespeichert, aber noch nicht ausgewertet: Formularstand je finding_id */
  lastSaved = $state.raw<{ id: string; form: FindingForm } | null>(null);

  private timer: ReturnType<typeof setTimeout> | null = null;
  private req = 0;
  /** Versuche, ein gerade angelegtes Finding in der Liste zu finden */
  private waitTries = 0;
  private offPalette: (() => void) | null;

  constructor(private readonly ctx: ProjectCtx) {
    this.offPalette = registerPaletteSource('findings', () => this.paletteItems());
  }

  async load(): Promise<void> {
    try {
      this.list = await this.ctx.backend.findings(this.ctx.pid, this.ctx.signal);
      this.loaded = true;
      this.error = null;
    } catch (e) {
      if (!isAbort(e)) {
        this.error = e;
        this.loaded = true;
      }
    }
    if (this.currentId && this.currentId !== 'neu') await this.fetchCurrent(this.currentId);
    // gerade angelegt, die Auswertung kennt es noch nicht: bald wieder nachsehen (höchstens 40-mal)
    const saved = this.lastSaved;
    if (saved && !this.list.some((f) => f.finding_id === saved.id) && this.waitTries < 40) {
      this.waitTries += 1;
      this.reloadSoon(500);
    }
  }

  /** Finding öffnen (aus der URL). */
  async open(findingId: string | null): Promise<void> {
    const id = findingId && findingId !== 'neu' ? findingId : null;
    if (findingId === this.currentId && (id === null || this.current?.finding_id === id)) return;
    this.currentId = findingId;
    this.currentError = null;
    if (!id) {
      this.current = null;
      return;
    }
    if (this.current?.finding_id !== id) this.current = null;
    await this.fetchCurrent(id);
  }

  private async fetchCurrent(id: string): Promise<void> {
    // Gerade angelegt und noch nicht in der Liste: nicht anfragen. Die Antwort wäre 404, und der
    // Browser meldet jede 404 in der Konsole; load() fragt wieder, sobald die Liste es kennt.
    if (this.lastSaved?.id === id && this.loaded && !this.list.some((f) => f.finding_id === id)) return;
    const req = ++this.req;
    try {
      const d = await this.ctx.backend.finding(this.ctx.pid, id, this.ctx.signal);
      if (req !== this.req || this.currentId !== id) return;
      this.current = d;
      this.currentError = null;
      if (this.lastSaved?.id === id) this.lastSaved = null;
    } catch (e) {
      if (isAbort(e) || req !== this.req || this.currentId !== id) return;
      this.current = null;
      this.currentError = e;
    }
  }

  /** Wartet das Formular auf die Auswertung eines gerade angelegten Findings? */
  get waiting(): boolean {
    const id = this.currentId;
    return !!id && this.lastSaved?.id === id && !this.current && (this.currentError === null || errorCode(this.currentError) === 'not_found');
  }

  private reloadSoon(ms = 200): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.load();
    }, ms);
  }

  onChanges(cs: ChangeSet): void {
    if (cs.changes.some((c) => c.entity === 'finding' || c.entity === 'claim' || c.entity === 'unit')) this.reloadSoon();
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'presentation') this.reloadSoon();
  }

  /** «Als Finding»: Beleg vormerken und das neue Formular öffnen (Tafel schliessen). */
  startFromEvidence(ref: EvidenceRefIn, label: string): void {
    this.draftFrom = ref;
    this.draftLabel = label;
    url.go('findings', { finding: 'neu', beleg: null, tafel: null });
  }

  clearDraft(): void {
    this.draftFrom = null;
    this.draftLabel = null;
  }

  /** Speichern: neu (create) oder Änderungen (update, Belege). */
  async save(form: FindingForm, base: FindingDetail | null): Promise<SaveResult> {
    const created = base ? null : this.draftFrom;
    const decisions = buildDecisions(form, base, created);
    if (decisions.length === 0) return { ok: true, id: base?.finding_id ?? null, error: null };
    this.saving = true;
    try {
      const out = await decideWithError(this.ctx, decisions, 'fd.f.saveFailed');
      if (!out.res) return { ok: false, id: null, error: out.error };
      const id = base ? base.finding_id : (out.res.results[0]?.decision_id ?? null);
      if (!base && id) {
        this.waitTries = 0;
        this.lastSaved = { id, form: { ...form, evidenceAdd: [], evidenceRemove: [] } };
        this.clearDraft();
      }
      this.reloadSoon();
      return { ok: true, id, error: null };
    } finally {
      this.saving = false;
    }
  }

  /** Finding löschen (als Entscheid mit Grund; d.revoke stellt es wieder her). */
  async remove(findingId: string, reason: string): Promise<string | null> {
    const r = reason.trim().slice(0, 500);
    const out = await decideWithError(
      this.ctx,
      [{ kind: 'd.finding.delete', payload: r ? { finding_id: findingId, reason: r } : { finding_id: findingId } }],
      'fd.f.deleteFailed',
    );
    if (!out.res) return out.error;
    if (this.currentId === findingId) {
      this.current = null;
      url.set({ finding: null });
    }
    this.ctx.app.ui.notify('info', t('fd.f.deleted'));
    this.reloadSoon();
    return null;
  }

  /** «Zu Finding hinzufügen» aus der Belegansicht. Gibt den Fehlertext zurück. */
  async addEvidence(findingId: string, ref: EvidenceRefIn): Promise<string | null> {
    const p: Record<string, unknown> = { finding_id: findingId };
    if (ref.claim_key) p.claim_key = ref.claim_key;
    if (ref.unit_id) p.unit_id = ref.unit_id;
    if (ref.lines) p.lines = [ref.lines[0], ref.lines[1]];
    const out = await decideWithError(this.ctx, [{ kind: 'd.finding.evidence.add', payload: p }], 'ev.addFailed');
    if (out.res) this.reloadSoon();
    return out.error;
  }

  private paletteItems(): PaletteItem[] {
    return this.list.map((f) => ({
      id: `finding:${f.finding_id}`,
      group: 'findings' as const,
      label: `F${f.ordinal} · ${f.title}`,
      hint: t('fd.palette', { ordinal: `F${f.ordinal}` }),
      keywords: `f${f.ordinal} ${f.title} finding`.toLowerCase(),
      run: () => url.go('findings', { finding: f.finding_id }),
    }));
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
    this.offPalette?.();
    this.offPalette = null;
  }
}
