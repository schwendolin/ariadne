/**
 * Host-Detail in der Spalte (Briefing 5.3, Screen 3, web-api.md 8 und 18.8). Besitzer: ui-karte.
 *
 * - Lädt das Detail des Hosts aus der URL (`host=`) und nach Änderungen gebündelt nach; beim
 *   Nachladen bleibt der alte Stand stehen. `kali` hat kein Detail vom Server (Kali-Detail aus dem
 *   Graph und den Terminals).
 * - 404: der Host ist verworfen oder zusammengeführt (`gone`), die Spalte bietet «Zurück zur Liste».
 * - Jede Aktion ist ein Entscheid über `ctx.decide` (kein optimistisches Ändern); der neue Stand
 *   kommt über `changes`.
 */
import { isApiError } from '../api/client';
import type { AccessLevel, ChangeSet, HostDetail, Keystep, StreamEvent, WorkStatus } from '../api/types';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

export class HostStore implements ProjectPart {
  hostId = $state<string | null>(null);
  detail = $state.raw<HostDetail | null>(null);
  error = $state<unknown>(null);
  loading = $state(false);
  busy = $state(false);
  private timer: ReturnType<typeof setTimeout> | null = null;
  private seq = 0;

  constructor(private readonly ctx: ProjectCtx) {}

  /** Host nicht mehr da (verworfen, zusammengeführt) */
  get gone(): boolean {
    return isApiError(this.error, 'not_found');
  }

  async load(): Promise<void> {
    if (this.hostId && this.hostId !== 'kali') await this.fetch(this.hostId);
  }

  /** Detail öffnen (oder schliessen mit `null`). Gleiche ID lädt nicht neu. */
  async open(hostId: string | null): Promise<void> {
    if (hostId === this.hostId && (this.detail || this.loading || this.error)) return;
    this.hostId = hostId;
    if (!hostId || hostId === 'kali') {
      this.detail = null;
      this.error = null;
      return;
    }
    if (this.detail && this.detail.id !== hostId) this.detail = null;
    this.error = null;
    await this.fetch(hostId);
  }

  private async fetch(hostId: string): Promise<void> {
    const mine = ++this.seq;
    this.loading = true;
    try {
      const d = await this.ctx.backend.host(this.ctx.pid, hostId, this.ctx.signal);
      if (mine === this.seq && this.hostId === hostId) {
        this.detail = d;
        this.error = null;
      }
    } catch (e) {
      if (!isAbort(e) && mine === this.seq && this.hostId === hostId) {
        this.error = e;
        if (isApiError(e, 'not_found')) this.detail = null;
      }
    } finally {
      if (mine === this.seq) this.loading = false;
    }
  }

  private reloadSoon(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.load();
    }, 250);
  }

  onChanges(cs: ChangeSet): void {
    if (this.hostId && this.hostId !== 'kali' && cs.changes.length > 0) this.reloadSoon();
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'presentation' || ev.name === 'inbox') this.reloadSoon();
  }

  // ------------------------------------------------------------------ Aktionen (Entscheide)

  private async run(kind: Parameters<ProjectCtx['decide']>[0][number]['kind'], payload: Record<string, unknown>): Promise<boolean> {
    if (this.busy || this.ctx.app.offline) return false;
    this.busy = true;
    try {
      const res = await this.ctx.decide([{ kind, payload }]);
      if (res) this.reloadSoon();
      return res !== null;
    } finally {
      this.busy = false;
    }
  }

  setWork(value: WorkStatus, reason?: string): Promise<boolean> {
    const d = this.detail;
    if (!d) return Promise.resolve(false);
    const payload: Record<string, unknown> = { subject: d.id, value };
    if (reason && reason.trim()) payload.reason = reason.trim();
    return this.run('d.status.work', payload);
  }

  setAccess(value: AccessLevel): Promise<boolean> {
    const d = this.detail;
    return d ? this.run('d.status.access', { subject: d.id, value }) : Promise.resolve(false);
  }

  addTag(tag: string): Promise<boolean> {
    const d = this.detail;
    const v = tag.trim();
    if (!d || !v || v.length > 64) return Promise.resolve(false);
    return this.run('d.tag.add', { subject: d.id, tag: v });
  }

  removeTag(tag: string): Promise<boolean> {
    const d = this.detail;
    return d ? this.run('d.tag.remove', { subject: d.id, tag }) : Promise.resolve(false);
  }

  setNote(text: string): Promise<boolean> {
    const d = this.detail;
    if (!d || text.length > 100_000) return Promise.resolve(false);
    return this.run('d.note.set', { subject: d.id, text });
  }

  markStep(step: Keystep, note?: string): Promise<boolean> {
    const d = this.detail;
    if (!d) return Promise.resolve(false);
    const payload: Record<string, unknown> = { step, host: d.id };
    if (note && note.trim()) payload.note = note.trim();
    return this.run('d.keystep.mark', payload);
  }

  /** Host im Nebel annehmen (a) bzw. verwerfen (x): über die Claims, die ihn einfärben (18.8). */
  async decideFog(accept: boolean): Promise<boolean> {
    const d = this.detail;
    if (!d || d.candidate_claims.length === 0 || this.busy || this.ctx.app.offline) return false;
    this.busy = true;
    try {
      const kind = accept ? 'd.claim.confirm' : 'd.claim.reject';
      const res = await this.ctx.decide(d.candidate_claims.slice(0, 500).map((claim_key) => ({ kind, payload: { claim_key } })));
      if (res) this.reloadSoon();
      return res !== null;
    } finally {
      this.busy = false;
    }
  }

  resolveConflict(conflictKey: string, choice: string | null): Promise<boolean> {
    const payload: Record<string, unknown> = { conflict_key: conflictKey };
    if (choice) payload.choice = choice;
    else payload.keep_open = true;
    return this.run('d.conflict.resolve', payload);
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
  }
}
