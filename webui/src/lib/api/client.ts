/**
 * Typisierter HTTP-Client für /api/v1 (Architektur 7.2, 7.3).
 *
 * - Jeder Aufruf trägt `Authorization: Bearer <token>`, keine Cookies
 *   (`credentials: 'omit'`, beim Abmelden `same-origin` für `Clear-Site-Data`), keine
 *   Weiterleitungen (`redirect: 'error'`).
 * - Fehler kommen immer als ApiError mit stabilem `code`. Die UI übersetzt
 *   über den Code, nie über den Servertext.
 * - Abbruch über AbortSignal; zusätzlich ein Zeitlimit pro Aufruf.
 * - Pfadsegmente werden einzeln kodiert. Kennungen wie `ip:default/10.10.10.3`
 *   enthalten `/` und `:` und landen als `%2F`/`%3A` im Pfad.
 * - Modus `cors` (web-api.md 17, «UI-Bau»): Nur so schickt der Browser trotz
 *   `Referrer-Policy: no-referrer` bei schreibenden Anfragen den echten `Origin` statt `null`;
 *   der Daemon verlangt ihn (R12).
 * - Kein Token in URL, Log oder Konsole. Fehlermeldungen enthalten nie Antworttexte.
 */
import type { TokenStore } from './auth';
import type { ApiErrorBody, ApiErrorCode, SessionResponse } from './types';

export type ClientErrorCode = ApiErrorCode | 'network' | 'aborted' | 'timeout' | 'bad_response' | 'http';

export class ApiError extends Error {
  readonly code: ClientErrorCode;
  readonly status: number;
  readonly detail: ApiErrorBody['error']['detail'] | null;

  constructor(code: ClientErrorCode, status: number, message: string, detail: ApiErrorBody['error']['detail'] | null = null) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

export function isApiError(e: unknown, code?: ClientErrorCode): e is ApiError {
  return e instanceof ApiError && (code === undefined || e.code === code);
}

const STATUS_CODES: Record<number, ApiErrorCode> = {
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  405: 'method',
  409: 'conflict',
  413: 'too_large',
  421: 'host',
  422: 'validation',
  423: 'locked',
  429: 'rate_limited',
  500: 'internal',
  501: 'not_implemented',
  503: 'unavailable',
};

const KNOWN_CODES = new Set<string>([
  'unauthorized', 'forbidden', 'policy', 'not_found', 'method', 'no_project', 'project_mismatch',
  'conflict', 'too_large', 'host', 'validation', 'locked', 'rate_limited', 'not_implemented',
  'unavailable', 'internal', 'clipboard_tool', 'clipboard_session',
  'shot_display', 'shot_wayland', 'shot_window', 'shot_region', 'shot_failed', 'guardrail',
  'no_include', 'noop',
]);

export interface ApiClientOptions {
  baseUrl?: string;
  tokens: TokenStore;
  fetch?: typeof fetch;
  /** Wird bei 401 aufgerufen, nachdem das Token verworfen wurde. */
  onUnauthorized?: () => void;
  timeoutMs?: number;
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined | null | string[]>;
  body?: unknown;
  signal?: AbortSignal;
  /** json (Standard), blob (log.txt) oder none (202/204) */
  expect?: 'json' | 'blob' | 'none';
  /** fetch keepalive (für PUT /ui/seen beim Unsichtbarwerden des Tabs) */
  keepalive?: boolean;
  /** ohne Token senden (nur /session) */
  anonymous?: boolean;
  timeoutMs?: number;
  /**
   * Nur beim Abmelden: `credentials: 'same-origin'`, damit der Browser `Clear-Site-Data` des
   * Daemons anwendet (mit `omit` verwirft Chrome den Header mit einer Fehlermeldung in der
   * Konsole). Der Daemon setzt nie Cookies; mitgeschickt wird darum nichts.
   */
  clearSiteData?: boolean;
}

/** Baut einen Pfad aus Segmenten; jedes Segment wird kodiert. */
export function apiPath(...segments: (string | number)[]): string {
  return '/' + segments.map((s) => encodeURIComponent(String(s))).join('/');
}

function buildQuery(query: RequestOptions['query']): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      if (v.length) params.set(k, v.join(','));
    } else {
      params.set(k, String(v));
    }
  }
  const s = params.toString();
  return s ? `?${s}` : '';
}

/** Verknüpft ein äusseres Signal mit einem Zeitlimit. */
function linkSignals(outer: AbortSignal | undefined, timeoutMs: number): { signal: AbortSignal; done: () => void; timedOut: () => boolean } {
  const ctrl = new AbortController();
  let timedOut = false;
  const onAbort = () => ctrl.abort(outer?.reason);
  if (outer) {
    if (outer.aborted) ctrl.abort(outer.reason);
    else outer.addEventListener('abort', onAbort, { once: true });
  }
  const timer = timeoutMs > 0
    ? setTimeout(() => {
        timedOut = true;
        ctrl.abort();
      }, timeoutMs)
    : null;
  return {
    signal: ctrl.signal,
    done: () => {
      if (timer) clearTimeout(timer);
      outer?.removeEventListener('abort', onAbort);
    },
    timedOut: () => timedOut,
  };
}

export class ApiClient {
  readonly baseUrl: string;
  private readonly tokens: TokenStore;
  private readonly fetchImpl: typeof fetch;
  private readonly onUnauthorized: (() => void) | undefined;
  private readonly timeoutMs: number;

  constructor(opts: ApiClientOptions) {
    this.baseUrl = (opts.baseUrl ?? '/api/v1').replace(/\/$/, '');
    this.tokens = opts.tokens;
    this.fetchImpl = opts.fetch ?? ((...args) => globalThis.fetch(...args));
    this.onUnauthorized = opts.onUnauthorized;
    this.timeoutMs = opts.timeoutMs ?? 15000;
  }

  hasToken(): boolean {
    return this.tokens.get() !== null;
  }

  async request<T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, opts: RequestOptions = {}): Promise<T> {
    const headers: Record<string, string> = { Accept: opts.expect === 'blob' ? '*/*' : 'application/json' };
    if (!opts.anonymous) {
      const token = this.tokens.get();
      if (!token) {
        this.onUnauthorized?.();
        throw new ApiError('unauthorized', 401, 'Kein Token');
      }
      headers.Authorization = `Bearer ${token}`;
    }
    let body: string | undefined;
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }

    const link = linkSignals(opts.signal, opts.timeoutMs ?? this.timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(this.baseUrl + path + buildQuery(opts.query), {
        method,
        headers,
        body,
        signal: link.signal,
        credentials: opts.clearSiteData ? 'same-origin' : 'omit',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        mode: 'cors',
        keepalive: opts.keepalive ?? false,
      });
    } catch (e) {
      link.done();
      if (link.timedOut()) throw new ApiError('timeout', 0, 'Zeitüberschreitung');
      if (opts.signal?.aborted || (e instanceof DOMException && e.name === 'AbortError')) {
        throw new ApiError('aborted', 0, 'Abgebrochen');
      }
      throw new ApiError('network', 0, 'Daemon nicht erreichbar');
    }

    try {
      if (!res.ok) throw await this.toError(res);
      if (opts.expect === 'none' || res.status === 204) return undefined as T;
      if (opts.expect === 'blob') return (await res.blob()) as T;
      const type = res.headers.get('content-type') ?? '';
      if (!type.includes('application/json')) {
        throw new ApiError('bad_response', res.status, 'Antwort ist kein JSON');
      }
      try {
        return (await res.json()) as T;
      } catch {
        throw new ApiError('bad_response', res.status, 'Antwort ist kein gültiges JSON');
      }
    } catch (e) {
      if (e instanceof ApiError) throw e;
      if (link.timedOut()) throw new ApiError('timeout', 0, 'Zeitüberschreitung');
      throw new ApiError('aborted', 0, 'Abgebrochen');
    } finally {
      link.done();
    }
  }

  private async toError(res: Response): Promise<ApiError> {
    let parsed: ApiErrorBody | null = null;
    try {
      if ((res.headers.get('content-type') ?? '').includes('application/json')) {
        parsed = (await res.json()) as ApiErrorBody;
      }
    } catch {
      parsed = null;
    }
    const fromBody = parsed?.error?.code;
    const code: ClientErrorCode = fromBody && KNOWN_CODES.has(fromBody) ? fromBody : (STATUS_CODES[res.status] ?? 'http');
    if (code === 'unauthorized') {
      this.tokens.clear();
      this.onUnauthorized?.();
    }
    const message = typeof parsed?.error?.message === 'string' ? parsed.error.message : `HTTP ${res.status}`;
    return new ApiError(code, res.status, message, parsed?.error?.detail ?? null);
  }

  get<T>(path: string, opts?: RequestOptions): Promise<T> {
    return this.request<T>('GET', path, opts);
  }
  post<T>(path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
    return this.request<T>('POST', path, { ...opts, body });
  }
  put<T>(path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
    return this.request<T>('PUT', path, { ...opts, body });
  }
  delete<T>(path: string, opts?: RequestOptions): Promise<T> {
    return this.request<T>('DELETE', path, opts);
  }

  /** Tauscht einen Einmalcode gegen ein Token (POST /session). */
  async login(code: string, signal?: AbortSignal): Promise<SessionResponse> {
    const res = await this.request<SessionResponse>('POST', '/session', { body: { code }, anonymous: true, signal });
    if (typeof res?.token !== 'string' || res.token.length < 32) {
      throw new ApiError('bad_response', 200, 'Ungültige Sitzungsantwort');
    }
    this.tokens.set(res.token, res.expires_at ?? null);
    return res;
  }

  async logout(): Promise<void> {
    try {
      await this.request<void>('DELETE', '/session', { expect: 'none', clearSiteData: true });
    } finally {
      this.tokens.clear();
    }
  }
}
