/**
 * Zustand der Anwendung (Briefing 4.1, SCREENS 9, BEHAVIOR). Besitzer: ui-fundament.
 *
 * - Anmeldung: Code aus dem Fragment (main.ts) oder getippt; Fehler nur als Code.
 * - Status: `/status` beim Start, nach jedem `terminal`/`project`/`presentation`-Ereignis, jede
 *   Minute (Pause-Restzeit, Leerlauf) und ohne Projekt alle 5 s.
 * - Ein globaler SSE-Strom pro Tab (auch ohne Projekt). Bei `project` wird der ProjectStore
 *   verworfen und neu angelegt (E70); bei 401 geht es zur Anmeldung.
 * - Abmeldegrund (Praxistest 1): Endet die Sitzung (401 während der Anmeldung), nennt die
 *   Anmeldeseite den Grund (`endNotice`): aus dem SSE-Ereignis `session` vor dem Ende, sonst aus
 *   `project` (closed mit `reason`, locked, Wechsel), sonst «neu gestartet», wenn der Strom vorher
 *   keine Verbindung bekam, sonst aus dem letzten Status (`active.stopped`), sonst allgemein.
 *   Selbst abmelden zeigt keinen Grund.
 * - Keine Verbindung: nach 5 s ohne offenen Strom bzw. bei Netzfehlern `offline = true`; Daten
 *   bleiben gedämpft sichtbar mit «Stand HH:MM», Aktionen sind gesperrt.
 * - Pause und Fortsetzen: Anzeige «wartet auf Bestätigung», bis das Ereignis `terminal` den neuen
 *   Zustand meldet (nach 5 s ohne Ereignis lädt sie `/status`). Lehnt der Server ab (403 `policy`,
 *   E117: mehr als 30 min Web-Pause in der gleitenden Stunde), bleibt die Grenze am Terminal sichtbar
 *   (`pauseRefused`), bis der Status ein neues Budget meldet.
 * - Scope-Warnung (Briefing 4.5): eine Meldung beim Eintreffen eines neuen, nicht quittierten
 *   Befehls (`ui.scopeCard`), das Kennzeichen in der Kopfzeile bis zum Quittieren
 *   (`PUT /ui/scope-ack`, kein Browser-Speicher).
 * - Präsentationsmodus: umschalten über Menü, Palette und Shift+P; angezeigt wird er erst nach dem
 *   SSE-Ereignis `presentation` (bzw. dem nächsten `/status`), mit einer kurzen Meldung.
 */
import type { Backend } from '../api/backend';
import { isApiError, type ClientErrorCode } from '../api/client';
import type { ConnectionState } from '../api/sse';
import type { Profile, SessionEndReason, Status, StreamEvent } from '../api/types';
import { t } from '../i18n';
import { errorText } from '../util/errors';
import type { AppApi } from './ctx';
import { PrefsStore } from './prefs.svelte';
import { ProjectStore } from './project.svelte';
import { UiStore } from './ui.svelte';
import { url } from '../url/state.svelte';

export type AuthState = 'init' | 'login' | 'ready';
export type Phase = 'boot' | 'login' | 'no_project' | 'locked' | 'project';
export type PendingPause = { kind: 'pause' | 'resume'; since: number };
export type EndNotice = { reason: SessionEndReason | 'other'; slug: string | null };

/** So lange gilt ein Hinweis aus dem Strom als Ursache eines folgenden 401 */
const END_HINT_MS = 120_000;

const OFFLINE_AFTER_MS = 5000;

export class AppState implements AppApi {
  readonly backend: Backend;
  readonly ui = new UiStore();
  readonly prefs: PrefsStore;

  auth = $state<AuthState>('init');
  loginError = $state<ClientErrorCode | null>(null);
  status = $state.raw<Status | null>(null);
  /** Zeitpunkt des letzten erfolgreichen /status (Anzeige «Stand HH:MM» ohne Verbindung) */
  lastGoodAt = $state<number | null>(null);
  connection = $state<ConnectionState>('closed');
  offline = $state(false);
  project = $state.raw<ProjectStore | null>(null);
  pendingPause = $state<Record<string, PendingPause>>({});
  /** Terminals, deren Web-Pause der Server abgelehnt hat (E117), mit dem Budget zu dem Zeitpunkt */
  pauseRefused = $state<Record<string, number | null>>({});
  /** Grund der beendeten Sitzung für die Anmeldeseite (nur im Speicher dieses Tabs) */
  endNotice = $state.raw<EndNotice | null>(null);
  private endHint: (EndNotice & { at: number }) | null = null;
  /** Der Strom bekam seit der letzten offenen Verbindung keine Verbindung (Daemon weg) */
  private netLostSinceOpen = false;

  private unsubscribe: (() => void) | null = null;
  private offUnauthorized: (() => void) | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private statusSoon: ReturnType<typeof setTimeout> | null = null;
  private offlineTimer: ReturnType<typeof setTimeout> | null = null;
  /** zuletzt geöffnetes Projekt (Korrektur A19) */
  private lastPid: string | null = null;
  private pauseTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private stopped = false;
  /** cmd_id der zuletzt gemeldeten Scope-Warnung (nur im Speicher dieses Tabs) */
  private scopeShownFor: string | null = null;
  private readonly onVisibility = () => {
    if (typeof document !== 'undefined' && document.visibilityState === 'visible') void this.refreshStatus();
  };

  constructor(backend: Backend) {
    this.backend = backend;
    this.prefs = new PrefsStore(backend, this.ui);
    this.offUnauthorized = backend.onUnauthorized(() => this.sessionEnded());
  }

  get presentation(): boolean {
    return this.status?.presentation ?? false;
  }

  get profile(): Profile | null {
    return this.status?.project?.profile ?? null;
  }

  /** Mock-Daten statt Daemon (nur Mock-Build und Dev-Server) */
  get mock(): boolean {
    return this.backend.kind === 'mock';
  }

  get phase(): Phase {
    if (this.auth === 'init') return 'boot';
    if (this.auth === 'login') return 'login';
    const s = this.status;
    if (!s) return 'boot';
    if (s.project) return 'project';
    if (s.locked || (s.active && !s.active.stopped)) return 'locked';
    return 'no_project';
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
      // Vorlieben gibt es erst nach der Anmeldung (Bearer); bis dahin folgt die Seite dem System.
      this.auth = 'login';
      return;
    }
    await this.enter();
  }

  async login(code: string): Promise<boolean> {
    this.loginError = null;
    try {
      await this.backend.login(code);
    } catch (e) {
      this.loginError = isApiError(e) ? e.code : 'internal';
      return false;
    }
    await this.enter();
    return true;
  }

  private async enter(): Promise<void> {
    this.auth = 'ready';
    this.loginError = null;
    this.endNotice = null;
    this.endHint = null;
    this.netLostSinceOpen = false;
    void this.prefs.load();
    this.subscribe();
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this.onVisibility);
      document.addEventListener('visibilitychange', this.onVisibility);
    }
    await this.refreshStatus();
    this.ensurePolling();
  }

  /** Fehler der Anmeldung vergessen (neuer Versuch nach «zu viele Versuche»). */
  clearLoginError(): void {
    this.loginError = null;
  }

  async logout(): Promise<void> {
    try {
      await this.backend.logout();
    } finally {
      this.toLogin();
    }
  }

  /** 401: Sitzung beendet; Grund aus Strom, Verbindung oder letztem Status (Praxistest 1). */
  private sessionEnded(): void {
    if (this.auth === 'ready') this.endNotice = this.endReason();
    this.toLogin();
  }

  private endReason(): EndNotice {
    const slug = this.status?.project?.slug ?? this.status?.active?.slug ?? null;
    const h = this.endHint;
    if (h && Date.now() - h.at < END_HINT_MS) return { reason: h.reason, slug: h.slug ?? slug };
    if (this.netLostSinceOpen || this.offline) return { reason: 'restart', slug };
    const a = this.status?.active;
    if (a?.stopped && (a.end_reason === 'stop' || a.end_reason === 'idle')) return { reason: a.end_reason, slug: a.slug };
    if (this.status?.locked) return { reason: 'lock', slug };
    return { reason: 'other', slug };
  }

  /** Hinweis aus dem Strom merken (Grund eines folgenden 401). */
  private hintEnd(reason: SessionEndReason, slug: string | null): void {
    this.endHint = { reason, slug, at: Date.now() };
  }

  /** Sitzung beendet (401, Abmelden): Anmeldung, alle Daten weg. */
  private toLogin(): void {
    this.closeProject();
    this.unsubscribe?.();
    this.unsubscribe = null;
    this.status = null;
    this.loginError = null;
    this.offline = false;
    if (this.offlineTimer) clearTimeout(this.offlineTimer);
    this.offlineTimer = null;
    this.pendingPause = {};
    this.pauseRefused = {};
    this.scopeShownFor = null;
    this.ui.closeDialog();
    this.ui.closePopover();
    this.ui.scopeCard = false;
    this.auth = 'login';
  }

  private subscribe(): void {
    this.unsubscribe?.();
    this.unsubscribe = this.backend.subscribe({
      onEvent: (ev) => this.handleEvent(ev),
      onState: (st, cause) => this.setConnection(st, cause),
    });
  }

  private setConnection(st: ConnectionState, cause?: 'network' | 'ended' | null): void {
    this.connection = st;
    if (st === 'retrying' && cause === 'network') this.netLostSinceOpen = true;
    if (st === 'open') {
      this.netLostSinceOpen = false;
      if (this.offlineTimer) clearTimeout(this.offlineTimer);
      this.offlineTimer = null;
      if (this.offline) {
        this.offline = false;
        void this.refreshStatus();
      }
    } else if (st === 'retrying' && !this.offlineTimer && !this.offline) {
      this.offlineTimer = setTimeout(() => {
        this.offlineTimer = null;
        if (this.connection !== 'open') this.offline = true;
      }, OFFLINE_AFTER_MS);
    }
  }

  async refreshStatus(): Promise<void> {
    if (this.auth !== 'ready') return;
    try {
      const s = await this.backend.status();
      if (this.auth !== 'ready') return;
      const before = this.status?.presentation;
      this.status = s;
      this.lastGoodAt = Date.now();
      // Ein REST-Fehler allein macht offline; zurück, sobald Status und Strom wieder gehen.
      if (this.offline && this.connection === 'open') this.offline = false;
      if (before !== undefined && before !== s.presentation) this.announcePresentation(s.presentation);
      this.syncPending(s);
      this.syncRefused(s);
      this.syncScopeWarning(s);
      this.syncProject();
    } catch (e) {
      if (isApiError(e, 'network') || isApiError(e, 'timeout') || isApiError(e, 'bad_response')) this.offline = true;
    }
  }

  /** Neue, nicht quittierte Scope-Warnung: einmal als Meldung zeigen (Briefing 4.5). */
  private syncScopeWarning(s: Status): void {
    const w = s.scope_warning;
    if (!w || w.acked === true) {
      if (this.ui.scopeCard && (!w || w.acked === true)) this.ui.scopeCard = false;
      return;
    }
    if (w.cmd_id !== this.scopeShownFor) {
      this.scopeShownFor = w.cmd_id;
      this.ui.scopeCard = true;
    }
  }

  /** Quittiert die Scope-Warnung auf dem Server (kein Browser-Speicher); Fehler als Meldung. */
  async ackScopeWarning(cmdId?: string): Promise<boolean> {
    const w = this.status?.scope_warning;
    const p = this.project;
    const id = cmdId ?? w?.cmd_id;
    if (!id || !p || this.offline) return false;
    try {
      await this.backend.ackScopeWarning(p.pid, id);
    } catch (e) {
      this.ui.notify('error', errorText(e));
      return false;
    }
    this.ui.scopeCard = false;
    if (w && this.status?.scope_warning?.cmd_id === id) {
      this.status = { ...this.status, scope_warning: { ...w, acked: true } };
    }
    void this.refreshStatus();
    return true;
  }

  /** Projekt-Store an den Status anpassen: öffnen, verwerfen oder warten. */
  private syncProject(): void {
    const s = this.status;
    const pid = s?.project?.id ?? null;
    if (this.project && this.project.pid !== pid) this.closeProject();
    if (pid && s?.project && !this.project) {
      // Korrektur A19: Nach einem Projektwechsel gelten Auswahl, Zeile, Finding und Beleg des alten
      // Projekts nicht mehr (Sperren und Entsperren desselben Projekts behält sie).
      if (this.lastPid !== null && this.lastPid !== pid) {
        url.set({ host: null, sel: null, zeile: null, finding: null, beleg: null, hostf: null, terminal: null });
      }
      this.lastPid = pid;
      const store = new ProjectStore(pid, s.project.slug, this, s.generation);
      this.project = store;
      void store.loadAll();
    }
  }

  private closeProject(): void {
    this.project?.dispose();
    this.project = null;
  }

  private ensurePolling(): void {
    if (this.pollTimer || this.stopped) return;
    // Ohne Projekt und ohne Verbindung alle 5 s (Briefing 8), sonst jede Minute (Restzeit, Leerlauf).
    let tick = 0;
    this.pollTimer = setInterval(() => {
      tick++;
      if (this.auth !== 'ready') return;
      if (!this.project || this.offline || tick % 12 === 0) void this.refreshStatus();
    }, 5000);
  }

  handleEvent(ev: StreamEvent): void {
    switch (ev.name) {
      case 'session':
        // Praxistest 1: die Sitzung endet gleich, der Grund kommt vor dem 401
        if (ev.data.change === 'ending') this.hintEnd(ev.data.reason, ev.data.slug ?? this.status?.project?.slug ?? null);
        return;
      case 'project': {
        const slug = ev.data.slug ?? this.status?.project?.slug ?? null;
        if (ev.data.change === 'closed') this.hintEnd(ev.data.reason ?? 'stop', slug);
        else if (ev.data.change === 'locked') this.hintEnd('lock', slug);
        else if (ev.data.change === 'opened' && this.project && ev.data.project_id !== this.project.pid) this.hintEnd('switch', slug);
        // Projekt gewechselt, gesperrt oder geschlossen: alles verwerfen (E70).
        this.closeProject();
        void this.refreshStatus();
        return;
      }
      case 'terminal':
        void this.refreshStatus();
        break;
      case 'changes':
        // Nach einer Auswertung: die Scope-Warnung (Briefing 4.5) entsteht erst in der Projektion
        // und soll beim Eintreffen erscheinen, nicht erst beim nächsten Abruf in einer Minute.
        this.refreshStatusSoon();
        break;
      case 'presentation':
        if (this.status && this.status.presentation !== ev.data.on) {
          this.status = { ...this.status, presentation: ev.data.on };
          this.announcePresentation(ev.data.on);
        }
        break;
      case 'prefs':
        void this.prefs.load();
        return;
      case 'progress':
        // KI und Export (Etappe 4): die Projekt-Stores werten `kind` aus
        break;
      default:
        break;
    }
    this.project?.dispatch(ev);
  }

  /** Status gebündelt nachladen (mehrere Auswertungen kurz hintereinander ergeben einen Abruf). */
  private refreshStatusSoon(): void {
    if (this.statusSoon || this.stopped) return;
    this.statusSoon = setTimeout(() => {
      this.statusSoon = null;
      if (this.auth === 'ready') void this.refreshStatus();
    }, 400);
  }

  private announcePresentation(on: boolean): void {
    this.ui.notify('info', on ? t('present.on') : t('present.off'), 2500);
  }

  // ------------------------------------------------------------------ Pause (E22, E107, E117)
  /** Abgelehnte Pausen vergessen, sobald der Status wieder genug Budget meldet. */
  private syncRefused(s: Status): void {
    const ids = Object.keys(this.pauseRefused);
    if (ids.length === 0) return;
    const next = { ...this.pauseRefused };
    let changed = false;
    for (const tid of ids) {
      const term = s.terminals.find((x) => x.terminal_id === tid);
      const left = term?.web_pause_left_s;
      const was = this.pauseRefused[tid];
      if (!term || (typeof left === 'number' && typeof was === 'number' && left > was) || (typeof left === 'number' && left >= 600)) {
        delete next[tid];
        changed = true;
      }
    }
    if (changed) this.pauseRefused = next;
  }

  private syncPending(s: Status): void {
    const next = { ...this.pendingPause };
    let changed = false;
    for (const [tid, p] of Object.entries(this.pendingPause)) {
      const term = s.terminals.find((x) => x.terminal_id === tid);
      const done = !term || (p.kind === 'pause' ? term.state === 'paused' : term.state !== 'paused');
      if (done) {
        delete next[tid];
        const tm = this.pauseTimers.get(tid);
        if (tm) clearTimeout(tm);
        this.pauseTimers.delete(tid);
        changed = true;
      }
    }
    if (changed) this.pendingPause = next;
  }

  private markPending(tid: string, kind: PendingPause['kind']): void {
    this.pendingPause = { ...this.pendingPause, [tid]: { kind, since: Date.now() } };
    const old = this.pauseTimers.get(tid);
    if (old) clearTimeout(old);
    this.pauseTimers.set(
      tid,
      setTimeout(() => {
        const { [tid]: _gone, ...rest } = this.pendingPause;
        this.pendingPause = rest;
        void this.refreshStatus();
      }, 5000),
    );
  }

  /** Pause pro Terminal (Standard 10 min). Gibt den Fehlercode zurück (z. B. 'policy' bei E117). */
  async pause(tid: string, minutes = 10): Promise<ClientErrorCode | null> {
    if (this.offline) return 'network';
    if (this.pendingPause[tid]) return null;
    try {
      await this.backend.pause(tid, minutes);
      this.markPending(tid, 'pause');
      return null;
    } catch (e) {
      const code = isApiError(e) ? e.code : 'internal';
      if (code === 'policy') {
        const term = this.status?.terminals.find((x) => x.terminal_id === tid);
        this.pauseRefused = { ...this.pauseRefused, [tid]: term?.web_pause_left_s ?? null };
        this.ui.notify('error', t('rec.budgetEmpty'));
      } else {
        this.ui.notify('error', errorText(e));
      }
      return code;
    }
  }

  async resume(tid: string): Promise<ClientErrorCode | null> {
    if (this.offline) return 'network';
    if (this.pendingPause[tid]) return null;
    try {
      await this.backend.resume(tid);
      this.markPending(tid, 'resume');
      return null;
    } catch (e) {
      this.ui.notify('error', errorText(e));
      return isApiError(e) ? e.code : 'internal';
    }
  }

  /** Präsentationsmodus umschalten (Menü, Palette, Shift+P); die Anzeige folgt dem SSE-Ereignis. */
  async togglePresentation(): Promise<void> {
    if (this.offline || this.auth !== 'ready') return;
    try {
      await this.backend.setPresentation(!this.presentation);
    } catch (e) {
      this.ui.notify('error', errorText(e));
    }
  }

  stop(): void {
    this.stopped = true;
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', this.onVisibility);
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.statusSoon) clearTimeout(this.statusSoon);
    this.statusSoon = null;
    if (this.offlineTimer) clearTimeout(this.offlineTimer);
    for (const tm of this.pauseTimers.values()) clearTimeout(tm);
    this.unsubscribe?.();
    this.offUnauthorized?.();
    this.closeProject();
  }
}
