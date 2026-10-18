/**
 * SSE-Client auf fetch-Basis (Architektur 7.3, web-api.md 14): ein globaler Strom
 * `GET /api/v1/events` pro Tab, auch ohne Projekt.
 *
 * `EventSource` kann keine Header setzen, das Token muss aber als Bearer mit.
 * Deshalb liest dieser Client `text/event-stream` selbst:
 * - Bearer-Token, `Last-Event-ID` bei jeder Wiederverbindung
 * - Backoff 1 s, 2 s, 4 s ... höchstens 30 s, zurückgesetzt nach erfolgreichem Verbindungsaufbau
 * - Wachhund: kommt länger als `idleTimeoutMs` nichts (auch kein Herzschlag), wird neu verbunden
 * - 401 beendet den Strom und meldet `onUnauthorized`
 * - `reset` und `project` reicht er wie jedes andere Ereignis an den Store weiter;
 *   der Store lädt dann neu bzw. verwirft alles.
 *
 * Der Strom enthält nie Daten oder Secrets, nur Invalidierungen. Die Daten holt
 * der Store per REST.
 */
import type { TokenStore } from './auth';
import type { StreamEvent, StreamEventName } from './types';

export interface SseMessage {
  event: string;
  data: string;
  id: string | null;
}

/** Inkrementeller Parser nach der WHATWG-Spezifikation für text/event-stream. */
export class SseParser {
  private buffer = '';
  private pendingCR = false;
  private eventType = '';
  private dataLines: string[] = [];
  private hasData = false;
  /** zuletzt gesehene ID; bleibt über Ereignisse hinweg bestehen */
  lastEventId: string | null = null;
  /** vom Server per `retry:` verlangte Wartezeit */
  retryMs: number | null = null;

  push(chunk: string): SseMessage[] {
    const out: SseMessage[] = [];
    let text = chunk;
    if (this.pendingCR) {
      // CR am Ende des letzten Stücks: ein folgendes LF gehört zum selben Zeilenende.
      if (text.startsWith('\n')) text = text.slice(1);
      this.pendingCR = false;
    }
    this.buffer += text;
    let start = 0;
    for (let i = 0; i < this.buffer.length; i++) {
      const c = this.buffer.charCodeAt(i);
      if (c !== 0x0a && c !== 0x0d) continue;
      const line = this.buffer.slice(start, i);
      if (c === 0x0d) {
        if (i + 1 === this.buffer.length) {
          this.pendingCR = true;
        } else if (this.buffer.charCodeAt(i + 1) === 0x0a) {
          i++;
        }
      }
      start = i + 1;
      const msg = this.line(line);
      if (msg) out.push(msg);
    }
    this.buffer = this.buffer.slice(start);
    return out;
  }

  private line(line: string): SseMessage | null {
    if (line === '') return this.dispatch();
    if (line.startsWith(':')) return null; // Kommentar, z. B. Herzschlag
    const colon = line.indexOf(':');
    let field = line;
    let value = '';
    if (colon >= 0) {
      field = line.slice(0, colon);
      value = line.slice(colon + 1);
      if (value.startsWith(' ')) value = value.slice(1);
    }
    switch (field) {
      case 'event':
        this.eventType = value;
        break;
      case 'data':
        this.dataLines.push(value);
        this.hasData = true;
        break;
      case 'id':
        if (!value.includes('\u0000')) this.lastEventId = value;
        break;
      case 'retry':
        if (/^\d+$/.test(value)) this.retryMs = Number(value);
        break;
      default:
        break;
    }
    return null;
  }

  private dispatch(): SseMessage | null {
    const type = this.eventType || 'message';
    this.eventType = '';
    if (!this.hasData) {
      this.dataLines = [];
      return null;
    }
    const data = this.dataLines.join('\n');
    this.dataLines = [];
    this.hasData = false;
    return { event: type, data, id: this.lastEventId };
  }
}

/** Wartezeit vor dem n-ten Wiederverbindungsversuch (n ab 0): 1, 2, 4, 8, 16, 30, 30 ... Sekunden. */
export function backoffDelay(attempt: number, initialMs = 1000, maxMs = 30000, jitter = 0, random: () => number = Math.random): number {
  const base = Math.min(maxMs, initialMs * 2 ** Math.max(0, Math.min(attempt, 30)));
  if (jitter <= 0) return base;
  const spread = base * jitter;
  return Math.max(0, Math.min(maxMs, Math.round(base - spread + random() * 2 * spread)));
}

const EVENT_NAMES = new Set<StreamEventName>([
  'changes', 'terminal', 'inbox', 'suggestion', 'progress', 'presentation', 'project', 'reset', 'prefs', 'screenshot', 'session', 'scope',
]);

/** Wandelt eine SSE-Nachricht in ein typisiertes Ereignis; unbekannte oder kaputte werden verworfen. */
export function toStreamEvent(msg: SseMessage): StreamEvent | null {
  if (!EVENT_NAMES.has(msg.event as StreamEventName)) return null;
  let data: unknown;
  try {
    data = JSON.parse(msg.data);
  } catch {
    return null;
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) return null;
  return { name: msg.event, id: msg.id, data } as StreamEvent;
}

export type ConnectionState = 'connecting' | 'open' | 'retrying' | 'closed';

export interface SseClientOptions {
  url: string;
  tokens: TokenStore;
  onEvent: (ev: StreamEvent) => void;
  onState?: (state: ConnectionState, info: { attempt: number; delayMs: number | null; cause?: 'network' | 'ended' | null }) => void;
  onUnauthorized?: () => void;
  fetch?: typeof fetch;
  initialDelayMs?: number;
  maxDelayMs?: number;
  jitter?: number;
  /** 0 schaltet den Wachhund ab */
  idleTimeoutMs?: number;
  random?: () => number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}

function defaultSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

export class SseClient {
  private readonly opts: SseClientOptions;
  private readonly stopCtrl = new AbortController();
  private running = false;
  lastEventId: string | null = null;
  attempt = 0;

  constructor(opts: SseClientOptions) {
    this.opts = opts;
  }

  start(): Promise<void> {
    if (this.running) return Promise.resolve();
    this.running = true;
    return this.loop();
  }

  stop(): void {
    this.stopCtrl.abort();
    this.running = false;
  }

  get stopped(): boolean {
    return this.stopCtrl.signal.aborted;
  }

  private async loop(): Promise<void> {
    const { opts } = this;
    const fetchImpl = opts.fetch ?? ((...a) => globalThis.fetch(...a));
    const sleep = opts.sleep ?? defaultSleep;
    let serverRetry: number | null = null;

    while (!this.stopped) {
      opts.onState?.(this.attempt === 0 ? 'connecting' : 'retrying', { attempt: this.attempt, delayMs: null });
      const token = opts.tokens.get();
      if (!token) {
        opts.onUnauthorized?.();
        break;
      }
      const conn = new AbortController();
      const onStop = () => conn.abort();
      this.stopCtrl.signal.addEventListener('abort', onStop, { once: true });
      let watchdog: ReturnType<typeof setTimeout> | null = null;
      const idle = opts.idleTimeoutMs ?? 45000;
      const kick = () => {
        if (idle <= 0) return;
        if (watchdog) clearTimeout(watchdog);
        watchdog = setTimeout(() => conn.abort(), idle);
      };

      let unauthorized = false;
      let cause: 'network' | 'ended' | null = null;
      try {
        const headers: Record<string, string> = {
          Accept: 'text/event-stream',
          Authorization: `Bearer ${token}`,
          'Cache-Control': 'no-cache',
        };
        if (this.lastEventId !== null) headers['Last-Event-ID'] = this.lastEventId;
        kick();
        const res = await fetchImpl(opts.url, {
          method: 'GET',
          headers,
          signal: conn.signal,
          credentials: 'omit',
          cache: 'no-store',
          redirect: 'error',
          referrerPolicy: 'no-referrer',
        });
        if (res.status === 401) {
          unauthorized = true;
          opts.tokens.clear();
        } else if (res.ok && (res.headers.get('content-type') ?? '').includes('text/event-stream') && res.body) {
          this.attempt = 0;
          opts.onState?.('open', { attempt: 0, delayMs: null });
          const parser = new SseParser();
          parser.lastEventId = this.lastEventId;
          const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
          // Abbruch (stop, Wachhund) beendet auch ein hängendes read().
          const onAbort = () => void reader.cancel().catch(() => undefined);
          conn.signal.addEventListener('abort', onAbort, { once: true });
          try {
            for (;;) {
              const { value, done } = await reader.read();
              if (done) {
                cause = 'ended';
                break;
              }
              kick();
              for (const msg of parser.push(value)) {
                this.lastEventId = parser.lastEventId;
                const ev = toStreamEvent(msg);
                if (ev) opts.onEvent(ev);
              }
              if (parser.retryMs !== null) serverRetry = parser.retryMs;
            }
          } finally {
            conn.signal.removeEventListener('abort', onAbort);
          }
        }
      } catch {
        // Netzfehler, Abbruch durch Wachhund oder stop(): unten entscheiden.
        if (!conn.signal.aborted && cause === null) cause = 'network';
      } finally {
        if (watchdog) clearTimeout(watchdog);
        this.stopCtrl.signal.removeEventListener('abort', onStop);
      }

      if (unauthorized) {
        opts.onUnauthorized?.();
        break;
      }
      if (this.stopped) break;
      const delay = backoffDelay(this.attempt, serverRetry ?? opts.initialDelayMs ?? 1000, opts.maxDelayMs ?? 30000, opts.jitter ?? 0.2, opts.random);
      opts.onState?.('retrying', { attempt: this.attempt, delayMs: delay, cause });
      this.attempt++;
      await sleep(delay, this.stopCtrl.signal);
    }
    this.running = false;
    opts.onState?.('closed', { attempt: this.attempt, delayMs: null });
  }
}
