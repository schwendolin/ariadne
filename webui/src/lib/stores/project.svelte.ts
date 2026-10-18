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
import { clientRef, type AppApi, type DecideOptions, type ProjectCtx, type ProjectPart } from './ctx';
import { EvidenceStore } from './evidence.svelte';
import { FindingsStore } from './findings.svelte';
import { HostStore } from './host.svelte';
import { MapStore } from './map.svelte';
import { NextStore } from './next.svelte';
import { SeenStore } from './seen.svelte';
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
  private readonly parts: ProjectPart[];
  private changesTimer: ReturnType<typeof setTimeout> | null = null;
  private changesBusy = false;

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
    this.parts = [this.map, this.next, this.host, this.seen, this.terminals, this.timeline, this.evidence, this.findings];
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

  async decide(decisions: DecisionInput[], opts: DecideOptions = {}): Promise<DecisionResponse | null> {
    if (this.app.offline || this.disposed) return null;
    try {
      return await this.backend.decide(
        this.pid,
        decisions.map((d) => ({ ...d, client_ref: d.client_ref ?? clientRef() })),
      );
    } catch (e) {
      if (!opts.silent && !isAbort(e)) this.app.ui.notify('error', errorText(e, opts.errorPrefix ?? 'err.decisionPrefix'));
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
    if (this.changesBusy || this.disposed) return;
    this.changesBusy = true;
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
    }
  }

  dispose(): void {
    if (this.changesTimer) clearTimeout(this.changesTimer);
    this.abort.abort();
    for (const p of this.parts) p.dispose();
  }
}
