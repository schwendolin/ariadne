/**
 * URL-Zustand (BEHAVIOR «Zustand», E112, web-api.md 1.7). Besitzer: ui-fundament.
 *
 * In der URL stehen Reiter, Ebenen, Auswahl und offene Tafel, damit Neuladen, Browser-Zurück und
 * Links funktionieren. Nie ein Token oder ein Code (der Einmalcode im Fragment `#c=` wird in
 * main.ts sofort entfernt). Es gibt kein localStorage und kein sessionStorage für UI-Zustand.
 *
 * Pfade: /karte, /terminals, /zeitachse, /findings (alles andere wird /karte).
 * Parameter (alle optional, unbekannte bleiben unangetastet):
 *   host      Host-Detail in der Spalte (host_id, auch 'kali')             Reiter Karte
 *   sel       gewählter Eintrag in «Als Nächstes» (item_key / suggestion_key)  Reiter Karte
 *   ebenen    sichtbare Ebenen, Komma-Liste aus GraphLayer ohne topology; fehlt = alle
 *   ansicht   'tabelle' = Host-Tabelle statt Karte (unter 200 Hosts mit `t`)
 *   tabelle   'hosts' | 'services' (Umschalter der Tabelle)
 *   beleg     offene Belegansicht (encodeEvidence), schliesst `tafel`
 *   tafel     'einstellungen' (Einstellungen als Tafel), schliesst `beleg`
 *   finding   offenes Finding (finding_id) oder 'neu'                        Reiter Findings
 *   zeile     gewählte Zeitachsenzeile (TimelineItem.id)                      Reiter Zeitachse
 *   typ, terminal, hostf   Filter der Zeitachse (Komma-Liste der Typen, terminal_id, host_id)
 *   utc       '1' = Zeiten in UTC statt Lokalzeit
 */

export const ROUTES = ['karte', 'terminals', 'zeitachse', 'findings'] as const;
export type RouteId = (typeof ROUTES)[number];

export const PARAM_KEYS = [
  'host', 'sel', 'ebenen', 'ansicht', 'tabelle', 'beleg', 'tafel', 'finding', 'zeile', 'typ', 'terminal', 'hostf', 'utc',
] as const;
export type ParamKey = (typeof PARAM_KEYS)[number];
export type ParamPatch = Partial<Record<ParamKey, string | null>>;

/** Ziel der Belegansicht (Tafel). */
export type EvidenceTarget =
  | { kind: 'claim'; claim_key: string }
  | { kind: 'unit'; unit_id: string; lines: [number, number] | null };

/** Parameter, die nur auf einem Reiter gelten und beim Reiterwechsel entfallen. */
const ROUTE_PARAMS: Record<RouteId, ParamKey[]> = {
  karte: ['host', 'sel', 'ansicht', 'tabelle'],
  terminals: [],
  zeitachse: ['zeile', 'typ', 'terminal', 'hostf'],
  findings: ['finding'],
};

export function isRoute(s: string): s is RouteId {
  return (ROUTES as readonly string[]).includes(s);
}

export function encodeEvidence(t: EvidenceTarget): string {
  if (t.kind === 'claim') return `c:${t.claim_key}`;
  return t.lines ? `u:${t.unit_id}:${t.lines[0]}-${t.lines[1]}` : `u:${t.unit_id}`;
}

export function decodeEvidence(s: string | null): EvidenceTarget | null {
  if (!s) return null;
  if (s.startsWith('c:')) {
    const key = s.slice(2);
    return /^[0-9a-f]{64}$/.test(key) ? { kind: 'claim', claim_key: key } : null;
  }
  if (s.startsWith('u:')) {
    const rest = s.slice(2);
    const m = /^(.*):(\d+)-(\d+)$/.exec(rest);
    if (m && m[1]) {
      const a = Number(m[2]);
      const b = Number(m[3]);
      if (a <= b) return { kind: 'unit', unit_id: m[1], lines: [a, b] };
    }
    return rest.length > 0 && rest.length <= 300 ? { kind: 'unit', unit_id: rest, lines: null } : null;
  }
  return null;
}

function routeOf(pathname: string): RouteId {
  const seg = pathname.replace(/^\/+/, '').split('/')[0] ?? '';
  return isRoute(seg) ? seg : 'karte';
}

export class UrlState {
  route = $state<RouteId>('karte');
  search = $state('');

  constructor(private readonly win: Window | null = typeof window === 'undefined' ? null : window) {
    if (!this.win) return;
    this.sync();
    this.win.addEventListener('popstate', () => this.sync());
    const seg = this.win.location.pathname.replace(/^\/+/, '').split('/')[0] ?? '';
    if (!isRoute(seg)) this.go('karte', {}, { replace: true, keep: true });
  }

  private sync(): void {
    if (!this.win) return;
    this.route = routeOf(this.win.location.pathname);
    this.search = this.win.location.search;
  }

  get params(): URLSearchParams {
    return new URLSearchParams(this.search);
  }

  get(key: ParamKey): string | null {
    return this.params.get(key);
  }

  /** Ebenen aus `ebenen`; null = alle. */
  get layers(): string[] | null {
    const v = this.get('ebenen');
    return v === null ? null : v.split(',').filter(Boolean);
  }

  evidence(): EvidenceTarget | null {
    return decodeEvidence(this.get('beleg'));
  }

  href(route: RouteId, patch: ParamPatch = {}, keep = false): string {
    const q = keep ? this.params : new URLSearchParams();
    if (keep && route !== this.route) for (const k of ROUTE_PARAMS[this.route]) q.delete(k);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === undefined || v === '') q.delete(k);
      else q.set(k, v);
    }
    const s = q.toString();
    return `/${route}${s ? `?${s}` : ''}`;
  }

  /**
   * Wechselt Reiter und Parameter. `keep`: übrige Parameter behalten (ausser denen des alten
   * Reiters). Ein neuer Verlaufseintrag nur bei Reiterwechsel oder ausdrücklich (`push`).
   */
  go(route: RouteId, patch: ParamPatch = {}, opts: { replace?: boolean; keep?: boolean } = {}): void {
    this.navigate(this.href(route, patch, opts.keep ?? true), opts.replace ?? false);
  }

  /** Setzt Parameter auf dem aktuellen Reiter (Standard: ersetzt den Verlaufseintrag). */
  set(patch: ParamPatch, opts: { push?: boolean } = {}): void {
    const p = { ...patch };
    if (p.beleg) p.tafel = null;
    if (p.tafel) p.beleg = null;
    this.navigate(this.href(this.route, p, true), !opts.push);
  }

  private navigate(target: string, replace: boolean): void {
    if (!this.win) {
      const u = new URL(target, 'http://x');
      this.route = routeOf(u.pathname);
      this.search = u.search;
      return;
    }
    if (target === this.win.location.pathname + this.win.location.search) return;
    if (replace) this.win.history.replaceState(null, '', target);
    else this.win.history.pushState(null, '', target);
    this.sync();
  }
}

export const url = new UrlState();
