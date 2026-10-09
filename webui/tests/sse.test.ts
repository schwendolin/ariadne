import { describe, expect, it, vi } from 'vitest';
import { createMemoryTokenStore } from '../src/lib/api/auth';
import { SseClient, SseParser, backoffDelay, toStreamEvent } from '../src/lib/api/sse';
import type { StreamEvent } from '../src/lib/api/types';

function stream(chunks: string[], keepOpen = false): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  return new ReadableStream({
    start(ctrl) {
      for (const c of chunks) ctrl.enqueue(enc.encode(c));
      if (!keepOpen) ctrl.close();
    },
  });
}

function sse(chunks: string[], keepOpen = false): Response {
  return new Response(stream(chunks, keepOpen), { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

describe('SseParser', () => {
  it('setzt Ereignisse über Chunk-Grenzen zusammen', () => {
    const p = new SseParser();
    expect(p.push('ev')).toEqual([]);
    expect(p.push('ent: changes\nid: 4')).toEqual([]);
    const out = p.push('2\ndata: {"generation":42}\n\n');
    expect(out).toEqual([{ event: 'changes', data: '{"generation":42}', id: '42' }]);
  });

  it('versteht CRLF, auch wenn CR und LF in verschiedenen Chunks liegen', () => {
    const p = new SseParser();
    expect(p.push('event: rec\r')).toEqual([]);
    expect(p.push('\ndata: {"on":true}\r\n\r\n')).toEqual([{ event: 'rec', data: '{"on":true}', id: null }]);
  });

  it('ignoriert Kommentare (Herzschlag) und verbindet mehrzeilige Daten', () => {
    const p = new SseParser();
    const out = p.push(': hb\n\ndata: a\ndata: b\n\n');
    expect(out).toEqual([{ event: 'message', data: 'a\nb', id: null }]);
  });

  it('behält die letzte ID und liest retry', () => {
    const p = new SseParser();
    p.push('id: 7\nretry: 2500\nevent: inbox\ndata: {}\n\n');
    expect(p.lastEventId).toBe('7');
    expect(p.retryMs).toBe(2500);
    const out = p.push('event: inbox\ndata: {}\n\n');
    expect(out[0]!.id).toBe('7');
  });

  it('löst ohne data kein Ereignis aus', () => {
    const p = new SseParser();
    expect(p.push('event: changes\n\n')).toEqual([]);
  });
});

describe('backoffDelay', () => {
  it('verdoppelt von 1 s bis höchstens 30 s', () => {
    expect([0, 1, 2, 3, 4, 5, 6, 20].map((a) => backoffDelay(a))).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
  });
  it('streut mit Jitter innerhalb der Grenzen', () => {
    expect(backoffDelay(1, 1000, 30000, 0.2, () => 0)).toBe(1600);
    expect(backoffDelay(1, 1000, 30000, 0.2, () => 1)).toBe(2400);
    expect(backoffDelay(10, 1000, 30000, 0.2, () => 1)).toBe(30000);
  });
});

describe('toStreamEvent', () => {
  it('nimmt nur bekannte Ereignisse mit JSON-Objekt an', () => {
    expect(toStreamEvent({ event: 'reset', data: '{"reason":"reparse","generation":3}', id: '1' })).toEqual({
      name: 'reset', id: '1', data: { reason: 'reparse', generation: 3 },
    });
    expect(toStreamEvent({ event: 'evil', data: '{}', id: null })).toBeNull();
    expect(toStreamEvent({ event: 'changes', data: 'kein json', id: null })).toBeNull();
    expect(toStreamEvent({ event: 'changes', data: '[1,2]', id: null })).toBeNull();
  });
});

describe('SseClient', () => {
  it('verbindet mit Backoff neu, sendet Last-Event-ID und stoppt bei 401', async () => {
    const tokens = createMemoryTokenStore();
    tokens.set('t'.repeat(64), null);
    const events: StreamEvent[] = [];
    const sleeps: number[] = [];
    const headers: Record<string, string>[] = [];
    let call = 0;
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      headers.push(init.headers as Record<string, string>);
      call++;
      if (call === 1) {
        return sse(['id: 10\nevent: changes\ndata: {"generation":43,"entities":{}}\n\n', 'id: 11\nevent: reset\ndata: {"reason":"reparse","generation":null}\n\n']);
      }
      if (call === 2) throw new TypeError('network');
      return new Response('', { status: 401 });
    });
    const onUnauthorized = vi.fn();
    const states: string[] = [];
    const client = new SseClient({
      url: '/api/v1/p/x/events',
      tokens,
      fetch: fetchMock as unknown as typeof fetch,
      onEvent: (e) => events.push(e),
      onState: (s) => states.push(s),
      onUnauthorized,
      jitter: 0,
      idleTimeoutMs: 0,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    await client.start();

    expect(events.map((e) => e.name)).toEqual(['changes', 'reset']);
    expect(headers[0]!.Authorization).toBe(`Bearer ${'t'.repeat(64)}`);
    expect(headers[0]!['Last-Event-ID']).toBeUndefined();
    expect(headers[1]!['Last-Event-ID']).toBe('11');
    expect(headers[2]!['Last-Event-ID']).toBe('11');
    // nach erfolgreicher Verbindung zurück auf 1 s, danach verdoppelt
    expect(sleeps).toEqual([1000, 2000]);
    expect(onUnauthorized).toHaveBeenCalledOnce();
    expect(tokens.get()).toBeNull();
    expect(states).toContain('open');
    expect(states[states.length - 1]).toBe('closed');
  });

  it('respektiert retry vom Server', async () => {
    const tokens = createMemoryTokenStore();
    tokens.set('t'.repeat(64), null);
    const sleeps: number[] = [];
    let call = 0;
    const client = new SseClient({
      url: '/e',
      tokens,
      fetch: (async () => (++call === 1 ? sse(['retry: 5000\n\n']) : new Response('', { status: 401 }))) as unknown as typeof fetch,
      onEvent: () => undefined,
      jitter: 0,
      idleTimeoutMs: 0,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    await client.start();
    expect(sleeps).toEqual([5000]);
  });

  it('beendet einen offenen Strom mit stop()', async () => {
    const tokens = createMemoryTokenStore();
    tokens.set('t'.repeat(64), null);
    const fetchMock = vi.fn(async () => sse([': hb\n\n'], true));
    const client = new SseClient({ url: '/e', tokens, fetch: fetchMock as unknown as typeof fetch, onEvent: () => undefined, idleTimeoutMs: 0 });
    const done = client.start();
    await new Promise((r) => setTimeout(r, 20));
    client.stop();
    await done;
    expect(client.stopped).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
