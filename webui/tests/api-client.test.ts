import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMemoryTokenStore, createSessionTokenStore, normalizeTypedCode, takeCodeFromLocation } from '../src/lib/api/auth';
import { ApiClient, ApiError, apiPath } from '../src/lib/api/client';

const TOKEN = 'a'.repeat(64);

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function setup(token: string | null = TOKEN, impl?: (url: string, init: RequestInit) => Promise<Response>) {
  const tokens = createMemoryTokenStore();
  if (token) tokens.set(token, null);
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return impl ? impl(String(url), init ?? {}) : json(200, { ok: true });
  });
  const onUnauthorized = vi.fn();
  const api = new ApiClient({ tokens, fetch: fetchMock as unknown as typeof fetch, onUnauthorized, timeoutMs: 1000 });
  return { api, tokens, calls, fetchMock, onUnauthorized };
}

describe('ApiClient', () => {
  it('sendet Bearer-Token ohne Cookies und ohne Weiterleitungen', async () => {
    const { api, calls } = setup();
    await api.get('/status');
    expect(calls).toHaveLength(1);
    const init = calls[0]!.init;
    expect(calls[0]!.url).toBe('/api/v1/status');
    expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${TOKEN}`);
    expect(init.credentials).toBe('omit');
    expect(init.redirect).toBe('error');
    expect(init.cache).toBe('no-store');
  });

  it('kodiert Kennungen als einzelne Pfadsegmente', () => {
    expect(apiPath('p', 'pid', 'hosts', 'ip:default/10.10.10.3')).toBe('/p/pid/hosts/ip%3Adefault%2F10.10.10.3');
  });

  it('hängt Query-Parameter an und lässt leere weg', async () => {
    const { api, calls } = setup();
    await api.get('/p/x/graph', { query: { layer: ['topology', 'services'], lens: 'karte', since: undefined } });
    expect(calls[0]!.url).toBe('/api/v1/p/x/graph?layer=topology%2Cservices&lens=karte');
  });

  it('ruft ohne Token gar nicht erst den Server und meldet unauthorized', async () => {
    const { api, fetchMock, onUnauthorized } = setup(null);
    await expect(api.get('/status')).rejects.toMatchObject({ code: 'unauthorized', status: 401 });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it('verwirft das Token bei 401', async () => {
    const { api, tokens, onUnauthorized } = setup(TOKEN, async () => json(401, { error: { code: 'unauthorized', message: 'Token abgelaufen' } }));
    await expect(api.get('/status')).rejects.toBeInstanceOf(ApiError);
    expect(tokens.get()).toBeNull();
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it('übernimmt den Fehlercode aus dem Body', async () => {
    const { api } = setup(TOKEN, async () => json(423, { error: { code: 'locked', message: 'gesperrt', request_id: 'r1' } }));
    const err = await api.get('/p/x/hosts').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ code: 'locked', status: 423, requestId: 'r1' });
  });

  it('ignoriert unbekannte Codes im Body und nimmt den HTTP-Status', async () => {
    const { api } = setup(TOKEN, async () => json(422, { error: { code: '<script>', message: 'x', detail: [{ loc: ['body', 'decisions', 0], type: 'missing' }] } }));
    const err = (await api.post('/p/x/decisions', {}).catch((e: unknown) => e)) as ApiError;
    expect(err.code).toBe('validation');
    expect(err.detail?.[0]?.type).toBe('missing');
  });

  it('kommt mit Fehlerseiten ohne JSON zurecht', async () => {
    const { api } = setup(TOKEN, async () => new Response('<h1>Bad Gateway</h1>', { status: 502, headers: { 'content-type': 'text/html' } }));
    await expect(api.get('/status')).rejects.toMatchObject({ code: 'http', status: 502 });
  });

  it('meldet Antworten, die kein JSON sind', async () => {
    const { api } = setup(TOKEN, async () => new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } }));
    await expect(api.get('/status')).rejects.toMatchObject({ code: 'bad_response' });
  });

  it('meldet Netzfehler als network', async () => {
    const { api } = setup(TOKEN, async () => {
      throw new TypeError('Failed to fetch');
    });
    await expect(api.get('/status')).rejects.toMatchObject({ code: 'network' });
  });

  it('bricht über AbortSignal ab', async () => {
    const ctrl = new AbortController();
    const { api } = setup(TOKEN, (_url, init) => new Promise((_res, rej) => {
      init.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')));
    }));
    const p = api.get('/status', { signal: ctrl.signal });
    ctrl.abort();
    await expect(p).rejects.toMatchObject({ code: 'aborted' });
  });

  it('meldet Zeitüberschreitung', async () => {
    const { api } = setup(TOKEN, (_url, init) => new Promise((_res, rej) => {
      init.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')));
    }));
    await expect(api.get('/status', { timeoutMs: 20 })).rejects.toMatchObject({ code: 'timeout' });
  });

  it('gibt bei expect none und 204 undefined zurück', async () => {
    const { api } = setup(TOKEN, async () => new Response(null, { status: 204 }));
    await expect(api.delete('/session', { expect: 'none' })).resolves.toBeUndefined();
  });
});

describe('Anmeldung und Token-Ablage', () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
  });
  afterEach(() => {
    sessionStorage.clear();
    localStorage.clear();
  });

  it('tauscht den Code gegen ein Token, das nur in sessionStorage landet', async () => {
    const tokens = createSessionTokenStore();
    const fetchMock = vi.fn(async () => json(200, { token: TOKEN, expires_at: new Date(Date.now() + 3600_000).toISOString() }));
    const api = new ApiClient({ tokens, fetch: fetchMock as unknown as typeof fetch });
    await api.login('code-1234567890');
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
    expect(JSON.parse(String(init.body))).toEqual({ code: 'code-1234567890' });
    expect(tokens.get()).toBe(TOKEN);
    expect(sessionStorage.getItem('ariadne.token')).toBe(TOKEN);
    expect(localStorage.length).toBe(0);
    for (let i = 0; i < localStorage.length; i++) expect(localStorage.getItem(localStorage.key(i)!)).not.toContain(TOKEN);
  });

  it('lehnt zu kurze Tokens ab', async () => {
    const tokens = createSessionTokenStore();
    const api = new ApiClient({ tokens, fetch: (async () => json(200, { token: 'kurz', expires_at: null })) as unknown as typeof fetch });
    await expect(api.login('code-1234567890')).rejects.toMatchObject({ code: 'bad_response' });
    expect(tokens.get()).toBeNull();
  });

  it('verwirft abgelaufene Tokens', () => {
    const tokens = createSessionTokenStore();
    tokens.set(TOKEN, new Date(Date.now() - 1000).toISOString());
    expect(tokens.get()).toBeNull();
    expect(sessionStorage.getItem('ariadne.token')).toBeNull();
  });

  it('liest den Einmalcode aus dem Fragment und entfernt das Fragment', () => {
    window.history.replaceState(null, '', '/karte#c=Zx9_abcdefgh12345');
    const replace = vi.spyOn(window.history, 'replaceState');
    expect(takeCodeFromLocation()).toBe('Zx9_abcdefgh12345');
    expect(replace).toHaveBeenCalled();
    expect(window.location.hash).toBe('');
  });

  it('entfernt auch ungültige Codes aus der Adresse', () => {
    window.history.replaceState(null, '', '/karte#c=<script>');
    expect(takeCodeFromLocation()).toBeNull();
    expect(window.location.hash).toBe('');
  });

  it('normalisiert eingetippte Codes', () => {
    expect(normalizeTypedCode(' abcd-efgh ijkl ')).toBe('abcdefghijkl');
    expect(normalizeTypedCode('kurz')).toBeNull();
  });
});
