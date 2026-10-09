/**
 * Kleiner History-Router für die SPA (kein SvelteKit).
 *
 * Pfade: /karte, /inbox, /terminals, /zeitachse, /denkanstoesse, /findings.
 * Überlagerungen als Query: ?host=<kennung> (Host-Detail), ?fact=<fact_id> (Beleg).
 * Der Daemon liefert für alle diese Pfade die SPA-Shell aus.
 */

export const ROUTES = ['karte', 'inbox', 'terminals', 'zeitachse', 'denkanstoesse', 'findings'] as const;
export type RouteId = (typeof ROUTES)[number];

function isRoute(s: string): s is RouteId {
  return (ROUTES as readonly string[]).includes(s);
}

export class Router {
  path = $state('/karte');
  search = $state('');

  constructor() {
    if (typeof window === 'undefined') return;
    this.sync();
    window.addEventListener('popstate', () => this.sync());
    if (!isRoute(this.path.slice(1))) this.navigate('/karte', { replace: true });
  }

  private sync(): void {
    this.path = window.location.pathname;
    this.search = window.location.search;
  }

  get route(): RouteId {
    const seg = this.path.replace(/^\/+/, '').split('/')[0] ?? '';
    return isRoute(seg) ? seg : 'karte';
  }

  get params(): URLSearchParams {
    return new URLSearchParams(this.search);
  }

  param(key: string): string | null {
    return this.params.get(key);
  }

  href(route: RouteId, params: Record<string, string | null> = {}): string {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== null) q.set(k, v);
    const s = q.toString();
    return `/${route}${s ? `?${s}` : ''}`;
  }

  navigate(to: string, opts: { replace?: boolean } = {}): void {
    const url = new URL(to, window.location.origin);
    if (url.origin !== window.location.origin) return;
    const target = url.pathname + url.search;
    if (target === window.location.pathname + window.location.search) return;
    if (opts.replace) window.history.replaceState(null, '', target);
    else window.history.pushState(null, '', target);
    this.sync();
  }

  /** Setzt oder entfernt einen Query-Parameter auf der aktuellen Route. */
  setParam(key: string, value: string | null, opts: { replace?: boolean } = {}): void {
    const q = this.params;
    if (value === null) q.delete(key);
    else q.set(key, value);
    const s = q.toString();
    this.navigate(`${this.path}${s ? `?${s}` : ''}`, opts);
  }
}

export const router = new Router();

/** Svelte-Action für interne Links: <a href="/inbox" use:link>. */
export function link(node: HTMLAnchorElement) {
  const onClick = (e: MouseEvent) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const href = node.getAttribute('href');
    if (!href || !href.startsWith('/') || href.startsWith('//')) return;
    e.preventDefault();
    router.navigate(href);
  };
  node.addEventListener('click', onClick);
  return {
    destroy() {
      node.removeEventListener('click', onClick);
    },
  };
}
