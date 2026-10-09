/**
 * Zustand der App: Anmeldung, Status (REC, Sperre, KI, Präsentation),
 * SSE-Verbindung und der Store des aktiven Projekts.
 *
 * Regeln (Architektur 7.3, 7.4):
 * - Der REC-Knopf zeigt den neuen Zustand erst nach Bestätigung per SSE,
 *   weil auch Hotkey und CLI REC ändern.
 * - Beim Ereignis `project` wird der Projekt-Store verworfen und neu aufgebaut.
 * - Ohne aktives oder bei gesperrtem Projekt fragt die App /status alle 5 s ab.
 */
import type { Backend } from '../api/backend';
import { isApiError } from '../api/client';
import type { ConnectionState } from '../api/sse';
import type { Status, StreamEvent, StreamPayloads } from '../api/types';
import { ProjectStore } from './project.svelte';

export type AuthState = 'init' | 'login' | 'ready';
type ProgressInfo = StreamPayloads['progress'];

export class AppState {
  readonly backend: Backend;
  auth = $state<AuthState>('init');
  status = $state<Status | null>(null);
  connection = $state<ConnectionState>('closed');
  project = $state<ProjectStore | null>(null);
  /** gewünschter REC-Zustand, bis SSE ihn bestätigt */
  recPending = $state<boolean | null>(null);
  jobs = $state.raw<Record<string, ProgressInfo>>({});
  error = $state<string | null>(null);
  loginError = $state<string | null>(null);

  private unsubscribe: (() => void) | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private recTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;

  constructor(backend: Backend) {
    this.backend = backend;
    backend.onUnauthorized(() => this.toLogin());
  }

  async start(code: string | null = null): Promise<void> {
    if (code) {
      try {
        await this.backend.login(code);
      } catch (e) {
        this.loginError = isApiError(e) ? e.code : 'internal';
      }
    }
    if (this.backend.needsLogin()) {
      this.auth = 'login';
      return;
    }
    this.auth = 'ready';
    await this.refreshStatus();
  }

  async login(code: string): Promise<void> {
    this.loginError = null;
    try {
      await this.backend.login(code);
      this.auth = 'ready';
      await this.refreshStatus();
    } catch (e) {
      this.loginError = isApiError(e) ? e.code : 'internal';
    }
  }

  private toLogin(): void {
    this.closeProject();
    this.status = null;
    this.auth = 'login';
  }

  async refreshStatus(): Promise<void> {
    try {
      const s = await this.backend.status();
      this.status = s;
      this.error = null;
      this.syncProject();
    } catch (e) {
      this.error = isApiError(e) ? e.code : 'internal';
      this.connection = 'retrying';
      this.ensurePolling();
    }
  }

  /** Projekt-Store an den Status anpassen: öffnen, verwerfen oder warten. */
  private syncProject(): void {
    const s = this.status;
    const pid = s && !s.locked ? (s.project?.id ?? null) : null;
    if (this.project && this.project.pid !== pid) this.closeProject();
    if (pid && !this.project) {
      this.stopPolling();
      const store = new ProjectStore(pid, this.backend);
      this.project = store;
      this.unsubscribe = this.backend.subscribe(pid, {
        onEvent: (ev) => this.handleEvent(ev),
        onState: (st) => {
          this.connection = st;
        },
      });
      void store.loadAll();
    }
    if (!pid) this.ensurePolling();
  }

  private closeProject(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
    this.project?.dispose();
    this.project = null;
    this.jobs = {};
  }

  private ensurePolling(): void {
    if (this.pollTimer || this.stopped) return;
    this.pollTimer = setInterval(() => void this.refreshStatus(), 5000);
  }

  private stopPolling(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.pollTimer = null;
  }

  handleEvent(ev: StreamEvent): void {
    const p = this.project;
    switch (ev.name) {
      case 'changes':
        void p?.onChanges(ev.data.generation);
        break;
      case 'rec':
        if (this.status) this.status = { ...this.status, rec: ev.data };
        this.recPending = null;
        if (this.recTimer) clearTimeout(this.recTimer);
        break;
      case 'terminal':
        p?.refresh('terminals', 'timeline');
        break;
      case 'inbox':
        p?.refresh('inbox');
        break;
      case 'suggestion':
        p?.refresh('suggestions');
        break;
      case 'progress': {
        const jobs = { ...this.jobs, [ev.data.job_id]: ev.data };
        this.jobs = jobs;
        if (ev.data.status === 'done' || ev.data.status === 'failed' || ev.data.status === 'refused') {
          const id = ev.data.job_id;
          setTimeout(() => {
            const { [id]: _done, ...rest } = this.jobs;
            this.jobs = rest;
          }, 5000);
        }
        break;
      }
      case 'presentation':
        if (this.status) this.status = { ...this.status, presentation: ev.data.on };
        p?.refresh('credentials');
        if (p) p.version++;
        break;
      case 'project':
        // Projekt gewechselt, gesperrt oder geschlossen: alles verwerfen.
        this.closeProject();
        void this.refreshStatus();
        break;
      case 'reset':
        void p?.onReset();
        break;
    }
  }

  /** REC umschalten; die Anzeige wechselt erst mit dem SSE-Ereignis `rec`. */
  async toggleRec(): Promise<void> {
    const current = this.status?.rec.on ?? false;
    this.recPending = !current;
    try {
      await this.backend.setRec(!current);
      if (this.recTimer) clearTimeout(this.recTimer);
      // Bleibt die Bestätigung aus, Status direkt nachladen.
      this.recTimer = setTimeout(() => {
        if (this.recPending !== null) {
          this.recPending = null;
          void this.refreshStatus();
        }
      }, 5000);
    } catch (e) {
      this.recPending = null;
      this.error = isApiError(e) ? e.code : 'internal';
    }
  }

  async togglePresentation(): Promise<void> {
    const on = !(this.status?.presentation ?? false);
    try {
      await this.backend.setPresentation(on);
    } catch (e) {
      this.error = isApiError(e) ? e.code : 'internal';
    }
  }

  stop(): void {
    this.stopped = true;
    this.stopPolling();
    if (this.recTimer) clearTimeout(this.recTimer);
    this.closeProject();
  }
}
