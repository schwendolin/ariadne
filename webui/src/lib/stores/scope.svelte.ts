/**
 * Scope erweitern (E129, E130). Besitzer: ui.
 *
 * - `view`: Scope aus `GET /scope` (Einschlüsse, Ausschlüsse, Zeitfenster, `change_allowed`); ohne
 *   die Route (älterer Server) die Eingaben aus `GET /project`, dann ohne Fenster.
 * - Ändern nur über `POST /scope/changes` (jede Änderung ein Entscheid `d.scope.update` auf dem
 *   Server, rückgängig mit `op: 'revert'`). Die UI urteilt nie selbst über den Scope und löst nie Namen auf: Vorschläge und
 *   «öffentliche Endung» kommen vom Server (ScopeMatcher).
 * - Nach einer Änderung meldet der Server `scope` und nach der Neuauswertung `changes` (SSE).
 *   `reevaluated` zählt die `changes` nach der letzten eigenen Änderung (Rückmeldung im Dialog).
 * - Im Profil customer (oder `editable: false`) nur Anzeige mit Hinweis auf `ariadne scope`.
 * - Meldungen nennen nie den Eintrag (Zieldaten); den zeigt der Dialog über Txt.
 */
import { isApiError } from '../api/client';
import type { ChangeSet, ScopeChange, ScopeChangeResult, ScopeOptions, ScopeView, StreamEvent } from '../api/types';
import { t } from '../i18n';
import { errorText, isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export type ScopeChangeOutcome = { ok: true; result: ScopeChangeResult } | { ok: false; error: string };

export class ScopeStore implements ProjectPart {
  view = $state.raw<ScopeView | null>(null);
  /** Route fehlt (404/501): Anzeige aus `GET /project` */
  missing = $state(false);
  /** Zahl der `changes`-Ereignisse seit der letzten eigenen Änderung (Neuauswertung über SSE) */
  reevaluated = $state(0);
  /** Version nach der letzten eigenen Änderung */
  lastVersion = $state<number | null>(null);
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly ctx: ProjectCtx,
    private readonly reloadInfo: () => Promise<void>,
  ) {}

  /** Ändern im Dashboard erlaubt? Nein im Profil customer (E129) und wenn der Server es sperrt. */
  get editable(): boolean {
    if (this.ctx.app.profile === 'customer') return false;
    return this.view ? this.view.change_allowed && this.view.profile !== 'customer' : true;
  }

  async load(): Promise<void> {
    try {
      this.view = await this.ctx.backend.scope(this.ctx.pid, this.ctx.signal);
      this.missing = false;
    } catch (e) {
      if (isAbort(e)) return;
      if (isApiError(e, 'not_found') || isApiError(e, 'not_implemented') || isApiError(e, 'method')) this.missing = true;
    }
  }

  onChanges(_cs: ChangeSet): void {
    this.reevaluated++;
    this.reloadSoon();
  }

  onEvent(ev: StreamEvent): void {
    if ((ev.name === 'project' || ev.name === 'scope') && ev.data.project_id === this.ctx.pid) this.reloadSoon();
  }

  private reloadSoon(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.load();
    }, 300);
  }

  /** Vorschläge des Servers für ein Ziel (exakter Name, Domain-Wildcard, IP). */
  options(value: string, signal?: AbortSignal): Promise<ScopeOptions> {
    return this.ctx.backend.scopeOptions(this.ctx.pid, value, signal);
  }

  /** Vorschau (`dry_run`): was die Änderung bewirkt; Fehler als fester Text. */
  async preview(change: ScopeChange): Promise<ScopeChangeOutcome> {
    try {
      return { ok: true, result: await this.ctx.backend.previewScope(this.ctx.pid, change) };
    } catch (e) {
      if (isAbort(e)) return { ok: false, error: t('err.aborted') };
      return { ok: false, error: this.errorFor(e) };
    }
  }

  private errorFor(e: unknown): string {
    if (isApiError(e, 'guardrail')) return t('scope.edit.err.guardrail');
    if (isApiError(e, 'policy') || isApiError(e, 'forbidden')) return t('scope.edit.err.policy');
    if (isApiError(e, 'conflict')) return t('scope.edit.err.conflict');
    if (isApiError(e, 'validation')) return t('scope.edit.err.validation');
    return errorText(e, 'scope.edit.err.prefix');
  }

  /** Eine Änderung schreiben; Fehler als fester Text (nie Zieldaten) für den Dialog. */
  async change(change: ScopeChange): Promise<ScopeChangeOutcome> {
    if (this.ctx.app.offline) return { ok: false, error: t('err.network') };
    if (!this.editable) return { ok: false, error: t('scope.edit.err.policy') };
    let result: ScopeChangeResult;
    try {
      result = await this.ctx.backend.changeScope(this.ctx.pid, change);
    } catch (e) {
      if (isAbort(e)) return { ok: false, error: t('err.aborted') };
      return { ok: false, error: this.errorFor(e) };
    }
    this.ctx.noteOwn(`d.scope.${change.op}`, { entry: change.entry, item_key: change.source?.item_key ?? null }, result.decision_id);
    this.reevaluated = 0;
    this.lastVersion = result.version;
    await Promise.all([this.load(), this.reloadInfo()]);
    return { ok: true, result };
  }

  /** Rückgängig: `POST /scope/changes` mit `op: 'revert'` (d.revoke gilt für Scope-Änderungen nicht). */
  async undo(decisionId: string): Promise<boolean> {
    if (this.ctx.app.offline) return false;
    try {
      const r = await this.ctx.backend.revertScope(this.ctx.pid, decisionId);
      this.ctx.noteOwn('d.scope.revert', { revert_of: decisionId }, r.decision_id);
    } catch (e) {
      if (!isAbort(e)) this.ctx.app.ui.notify('error', isApiError(e, 'policy') ? t('scope.edit.err.policy') : errorText(e, 'scope.edit.err.undo'));
      return false;
    }
    this.reevaluated = 0;
    await Promise.all([this.load(), this.reloadInfo()]);
    return true;
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
  }
}
