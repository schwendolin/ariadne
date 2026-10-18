/**
 * Store des offenen Projekts (Vertrag v0.1-Oberfläche, Abschnitt 4). Besitzer: ui-fundament.
 *
 * - Hält die Projekt-Stores der drei UI-Teile und verteilt SSE-Ereignisse an sie.
 * - `changes`: holt `/changes?since=<eigene Generation>` (gebündelt, 250 ms) und reicht das
 *   ChangeSet weiter; bei `reset: true` lädt er alles neu. `reset` (Reparse, Puffer, Neustart)
 *   lädt ebenfalls alles neu.
 * - `dispose()` bricht jeden laufenden Abruf ab (AbortController) und verwirft alle Teile;
 *   AppState legt bei `project`, Sperre und Abmelden einen neuen Store an (E70).
 */
import type { Backend } from '../api/backend';
import type { ChangeSet, DecisionInput, DecisionResponse, ProjectView, StreamEvent } from '../api/types';
import { errorText, isAbort } from '../util/errors';
import { clientRef, type AppApi, type DecideOptions, type OwnDecision, type ProjectCtx, type ProjectPart } from './ctx';
import { AiStore } from './ai.svelte';
import { EvidenceStore } from './evidence.svelte';
import { ExportStore } from './exports.svelte';
import { FindingsStore } from './findings.svelte';
import { HostStore } from './host.svelte';
import { MapStore } from './map.svelte';
import { NextStore } from './next.svelte';
import { ScopeStore } from './scope.svelte';
import { SeenStore } from './seen.svelte';
import { ShotsStore } from './shots.svelte';
import { TerminalsStore } from './terminals.svelte';
import { TimelineStore } from './timeline.svelte';

export class ProjectStore implements ProjectCtx {
  readonly pid: string;
  readonly slug: string;
  readonly backend: Backend;
  readonly app: AppApi;
  private readonly abort = new AbortController();

  info = $state.raw<ProjectView | null>(null);
  generation = $state<number | null>(null);
  loaded = $state(false);

  readonly map: MapStore;
  readonly next: NextStore;
  readonly host: HostStore;
  readonly seen: SeenStore;
  readonly terminals: TerminalsStore;
  readonly timeline: TimelineStore;
  readonly evidence: EvidenceStore;
  readonly findings: FindingsStore;
  readonly ai: AiStore;
  readonly shots: ShotsStore;
  readonly exports: ExportStore;
  readonly scope: ScopeStore;
  private readonly parts: ProjectPart[];
  private changesTimer: ReturnType<typeof setTimeout> | null = null;
  private changesBusy = false;
  /** `changes` kam, während ein Abruf lief: danach noch einmal holen (nichts geht verloren) */
  private changesAgain = false;

  constructor(pid: string, slug: string, app: AppApi, generation: number | null = null) {
    this.pid = pid;
    this.slug = slug;
    this.app = app;
    this.backend = app.backend;
    this.generation = generation;
    this.map = new MapStore(this);
    this.next = new NextStore(this);
    this.host = new HostStore(this);
    this.seen = new SeenStore(this);
    this.terminals = new TerminalsStore(this);
    this.timeline = new TimelineStore(this);
    this.evidence = new EvidenceStore(this);
    this.findings = new FindingsStore(this);
    this.ai = new AiStore(this);
    this.shots = new ShotsStore(this);
    this.exports = new ExportStore(this);
    this.scope = new ScopeStore(this, () => this.reloadInfo());
    this.parts = [this.map, this.next, this.host, this.seen, this.terminals, this.timeline, this.evidence, this.findings, this.ai, this.shots, this.exports, this.scope];
  }

  get signal(): AbortSignal {
    return this.abort.signal;
  }

  get disposed(): boolean {
    return this.abort.signal.aborted;
  }

  async loadAll(): Promise<void> {
    try {
      this.info = await this.backend.project(this.pid, this.signal);
    } catch (e) {
      if (!isAbort(e)) this.info = null;
    }
    await Promise.all(this.parts.map((p) => p.load().catch(() => undefined)));
    this.loaded = true;
  }

  /** Projektangaben neu holen (Scope nach einer Änderung, E129) */
  async reloadInfo(): Promise<void> {
    try {
      this.info = await this.backend.project(this.pid, this.signal);
    } catch {
      /* alter Stand bleibt */
    }
  }

  /** Eigene Entscheide dieses Tabs (höchstens 100, 10 Minuten), Korrektur A5. */
  private own: OwnDecision[] = [];

  noteOwn(kind: string, payload: Record<string, unknown>, decisionId: string | null): void {
    const now = Date.now();
    this.own = [...this.own.filter((o) => now - o.at < 600_000).slice(-99), { kind, payload, decisionId, at: now }];
  }

  ownSince(ms: number): readonly OwnDecision[] {
    const from = Date.now() - ms;
    return this.own.filter((o) => o.at >= from);
  }

  async decide(decisions: DecisionInput[], opts: DecideOptions = {}): Promise<DecisionResponse | null> {
    if (this.app.offline || this.disposed) return null;
    try {
      const res = await this.backend.decide(
        this.pid,
        decisions.map((d) => ({ ...d, client_ref: d.client_ref ?? clientRef() })),
      );
      decisions.forEach((d, i) => this.noteOwn(d.kind, d.payload as Record<string, unknown>, res.results[i]?.decision_id ?? null));
      return res;
    } catch (e) {
      if (isAbort(e)) return null;
      const text = errorText(e, opts.errorPrefix ?? 'err.decisionPrefix');
      if (opts.onError) opts.onError(text);
      else if (!opts.silent) this.app.ui.notify('error', text);
      return null;
    }
  }

  /** SSE-Ereignis (ausser `project`, das AppState behandelt). */
  dispatch(ev: StreamEvent): void {
    if (this.disposed) return;
    if (ev.name === 'changes') {
      if (ev.data.project_id !== this.pid) return;
      this.scheduleChanges();
    } else if (ev.name === 'reset') {
      this.generation = null;
      void this.loadAll();
      return;
    }
    for (const p of this.parts) p.onEvent?.(ev);
  }

  private scheduleChanges(): void {
    if (this.changesTimer) return;
    this.changesTimer = setTimeout(() => {
      this.changesTimer = null;
      void this.fetchChanges();
    }, 250);
  }

  private async fetchChanges(): Promise<void> {
    if (this.disposed) return;
    if (this.changesBusy) {
      this.changesAgain = true;
      return;
    }
    this.changesBusy = true;
    this.changesAgain = false;
    try {
      if (this.generation === null) {
        await this.loadAll();
        return;
      }
      const cs: ChangeSet = await this.backend.changes(this.pid, this.generation, this.signal);
      this.generation = cs.to;
      if (cs.reset) {
        await this.loadAll();
        return;
      }
      if (cs.changes.length > 0) for (const p of this.parts) p.onChanges?.(cs);
    } catch (e) {
      if (!isAbort(e)) this.generation = null;
    } finally {
      this.changesBusy = false;
      if (this.changesAgain && !this.disposed) {
        this.changesAgain = false;
        this.scheduleChanges();
      }
    }
  }

  dispose(): void {
    if (this.changesTimer) clearTimeout(this.changesTimer);
    this.abort.abort();
    for (const p of this.parts) p.dispose();
  }
}
