/**
 * Mock: Scope erweitern (E129, E130), Szenarien `praxis` (Praxistest 1: Scope-Warnung für
 * recovery.vantis.internal, Klärungen nach nmap) und `customer` (Profil customer: nur Anzeige).
 * Praxistest 2 (E131 bis E133): `offen` (offener Scope ohne Einschlüsse, «kein Kundenauftrag»
 * bestätigt), `zu` (geschlossen, bestätigt: Öffnen geht). Lab-Allowlist nur .htb .local .lab .thm
 * .vl und private Netze (E132); «öffentliche Endung» über eine eigene Liste; `broad` im dry_run (E133).
 *
 * Nur Testattrappe im Mock-Build. Die Vorschläge bildet hier eine einfache Zerlegung nach, damit die
 * Oberfläche etwas zeigt; im Produkt kommen Vorschläge, Urteile und «öffentliche Endung» vom Server
 * (ScopeMatcher). Keine DNS-Auflösung. Besitzer: ui.
 */
import type { NextItem, ScopeChange, ScopeChangeResult, ScopeOption, ScopeOptions, ScopeView, TimelineItem, UnitBrief } from '../../api/types';
import * as base from '../data/base';
import type { MockState } from '../state';

/** E132: Lab-Allowlist (Endungen; dazu die privaten Netze). Alles andere braucht «kein Kundenauftrag». */
const LAB = ['htb', 'local', 'lab', 'thm', 'vl'];
/** E132: nicht öffentliche Endungen für den Warnhinweis «öffentliche Endung» (eigene Liste) */
const NON_PUBLIC = [...LAB, 'internal', 'test', 'lan', 'home', 'localdomain', 'home.arpa', 'example', 'invalid', 'localhost'];

function under(name: string, list: string[]): boolean {
  return list.some((sfx) => name === sfx || name.endsWith(`.${sfx}`));
}

function hostOf(value: string): string {
  const v = value.trim();
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i.exec(v);
  return (m?.[1] ?? v).toLowerCase().replace(/\.$/, '');
}

function isIp(v: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (/^[0-9a-f:]+$/i.test(v) && v.includes(':'));
}

function isPublicName(name: string): boolean {
  return !under(name, NON_PUBLIC);
}

function privateV4(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
}

function v4num(ip: string): number {
  return ip.split('.').reduce((n, x) => n * 256 + Number(x), 0);
}

/** E133: IPv4-Netz bzw. -Bereich grösser als /16, IPv6 grösser als /48 */
export function isBroad(entry: string): boolean {
  const cidr = /^([0-9a-f:.]+)\/(\d{1,3})$/i.exec(entry);
  if (cidr) return cidr[1]!.includes(':') ? Number(cidr[2]) < 48 : Number(cidr[2]) < 16;
  const range = /^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$/.exec(entry);
  if (range) return v4num(range[2]!) - v4num(range[1]!) + 1 > 65536;
  return false;
}

/** Ausserhalb der Lab-Allowlist (E132)? Grob für den Mock: Adressen, Netze, Namen, Wildcards, URLs. */
function outsideLab(entry: string): boolean {
  const host = hostOf(entry);
  const v4 = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/\d{1,2}|-\S+)?$/.exec(host);
  if (v4) return !privateV4(v4[1]!) || (host.includes('/') && Number(host.split('/')[1]) < 8);
  if (/^[0-9a-f:]+(\/\d{1,3})?$/i.test(host) && host.includes(':')) return !/^f[cd]/i.test(host);
  return !under(host.replace(/^\*\./, ''), LAB);
}

export function optionsFor(value: string): ScopeOption[] {
  const host = hostOf(value);
  if (!host) return [];
  if (isIp(host)) {
    const priv = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd])/i.test(host);
    return [{ entry: host, kind: 'ip', public: false, outside_lab: !priv }];
  }
  const labels = host.split('.');
  const pub = isPublicName(host);
  // wie der Server (E132): ausserhalb der Allowlist nur mit «kein Kundenauftrag»; .internal ist
  // nicht öffentlich (kein Warnhinweis), liegt aber ausserhalb der Allowlist
  const out: ScopeOption[] = [{ entry: host, kind: 'name', public: pub, outside_lab: outsideLab(host) }];
  if (labels.length >= 3) out.push({ entry: `*.${labels.slice(1).join('.')}`, kind: 'wildcard', public: pub, outside_lab: outsideLab(host) });
  return out;
}

export function scopeOptions(s: MockState, value: string): ScopeOptions {
  const covered = covers(s.scope, hostOf(value));
  return { value, ctrl: false, verdict: covered ? 'in' : 'out', options: optionsFor(value) };
}

/** Grobe Deckung für den Mock (exakt oder Wildcard an Label-Grenzen; IPs nur exakt oder im /24). */
function covers(scope: Pick<ScopeView, 'include' | 'exclude' | 'open'>, host: string): boolean {
  if (scope.exclude.includes(host)) return false;
  // E131: offener Scope trifft jede Kennung ausser Sonderadressen (Ausschluss schlägt ihn)
  if (scope.open && host && !/^(127\.|0\.0\.0\.0$|169\.254\.|::1?$|2(2[4-9]|3\d)\.|255\.255\.255\.255$)/.test(host)) return true;
  return scope.include.some((e) => {
    if (e === host) return true;
    if (e.startsWith('*.')) return host.endsWith(e.slice(1));
    if (e === base.SCOPE) return host.startsWith('192.168.56.');
    return false;
  });
}

export function scopeView(s: MockState): ScopeView {
  const sc = structuredClone(s.scope);
  return {
    version: sc.version, profile: s.profile, include: sc.include, exclude: sc.exclude, windows: sc.windows,
    not_customer: s.notCustomer, open: sc.open === true, change_allowed: s.profile !== 'customer', history: [],
  };
}

export type ScopeRefusal = 'validation' | 'conflict' | 'guardrail' | 'no_include' | 'noop';

const SUMMARY: Record<string, string> = {
  add: 'Scope erweitert', remove: 'Aus dem Scope entfernt', exclude: 'Aus dem Scope ausgeschlossen',
  open: 'Scope geöffnet', close: 'Scope geschlossen', revert: 'Scope-Änderung rückgängig',
};

type Effect = Required<Pick<ScopeChangeResult, 'include_added' | 'include_removed' | 'exclude_added' | 'exclude_removed'>>;

/** Wie der Server: jede Scope-Änderung steht als Entscheid in der Zeitachse (web-api.md 20.3). */
function timelineEntry(s: MockState, id: string, op: string, entries: string[], eff: Effect, revertOf: string | null, openBefore?: boolean): void {
  const ts = new Date().toISOString();
  const item: TimelineItem = {
    id, ts, ts_ns: base.nsOf(ts), terminal_id: null, context_label: null, host_id: null, ctrl: false, terminal: null,
    type: 'decision', decision_id: id, kind: 'd.scope.update', summary: `${SUMMARY[op] ?? 'Scope gesetzt'} (Version ${s.scope.version})`,
    detail: entries.length ? entries.slice(0, 6).join(', ') : null, reason: null, ref: null, effect: null,
    scope_change: {
      op: op as 'add', entries, version: s.scope.version, revert_of: revertOf, reverted_by: null, revertible: s.profile !== 'customer', ...eff,
      open_before: openBefore ?? s.scope.open === true, open_after: s.scope.open === true,
    },
  };
  s.timeline = [item, ...s.timeline];
}

function markReverted(s: MockState, id: string, by: string): void {
  s.timeline = s.timeline.map((i) => (i.type === 'decision' && i.decision_id === id && i.scope_change ? { ...i, scope_change: { ...i.scope_change, reverted_by: by, revertible: false } } : i));
}

/** Wendet eine Änderung an, entfernt erledigte Warnungen und Klärungen (Neuauswertung). */
export function applyScopeChange(s: MockState, c: ScopeChange, decisionId: string, dryRun = false): ScopeChangeResult | ScopeRefusal {
  const sc = s.scope;
  // E131: Öffnen und Schliessen ohne Einträge
  if (c.op === 'open' || c.op === 'close') {
    const open = c.op === 'open';
    if ((sc.open === true) === open) return 'noop';
    if (!open && sc.include.length === 0) return 'no_include';
    const none: Effect = { include_added: [], include_removed: [], exclude_added: [], exclude_removed: [] };
    if (dryRun) return { decision_id: null, dry_run: true, version: sc.version + 1, op: c.op, entries: [], outside: [], needs_not_customer: open && !s.notCustomer, open, ...none };
    if (open && !s.notCustomer) return 'guardrail';
    s.scope = { ...sc, open, version: sc.version + 1 };
    s.scopeDecisions.push({ decision_id: decisionId, change: { op: c.op, entry: '' } });
    timelineEntry(s, decisionId, c.op, [], none, null, !open);
    reevaluate(s);
    return { decision_id: decisionId, version: s.scope.version, op: c.op, entries: [], include: [...s.scope.include], exclude: [...s.scope.exclude], open };
  }
  const entry = c.entry.trim();
  // eslint-disable-next-line no-control-regex
  if (!entry || entry.length > 253 || /[\s\u0000-\u001f\u007f]/.test(entry)) return 'validation';
  // *.<eine Endung> bleibt überall abgelehnt (E133)
  if (/^\*\.[^.]+\.?$/.test(entry)) return 'validation';
  const outside = c.op === 'add' && outsideLab(entry) && !entry.startsWith('192.168.56.');
  const eff: Effect = {
    include_added: c.op === 'add' ? [entry] : [], exclude_removed: c.op === 'add' && sc.exclude.includes(entry) ? [entry] : c.op === 'remove' && sc.exclude.includes(entry) ? [entry] : [],
    include_removed: c.op === 'remove' && sc.include.includes(entry) ? [entry] : [], exclude_added: c.op === 'exclude' ? [entry] : [],
  };
  if ((c.op === 'add' && sc.include.includes(entry)) || (c.op === 'exclude' && sc.exclude.includes(entry))) return 'conflict';
  if (c.op === 'remove' && !sc.include.includes(entry) && !sc.exclude.includes(entry)) return 'conflict';
  // letzter Einschluss: nur bei offenem Scope erlaubt (E131)
  if (c.op === 'remove' && sc.include.includes(entry) && sc.include.length === 1 && sc.open !== true) return 'conflict';
  if (dryRun) {
    return {
      decision_id: null, dry_run: true, version: sc.version + 1, op: c.op, entries: [entry], outside: outside ? [entry] : [],
      needs_not_customer: outside && !s.notCustomer, broad: c.op === 'add' && isBroad(entry), ...eff,
    };
  }
  if (outside && !s.notCustomer) return 'guardrail';
  if (c.op === 'add') {
    // wie der Server: steht derselbe Eintrag im Ausschluss, fällt er dort weg
    s.scope = { ...sc, include: [...sc.include, entry], exclude: sc.exclude.filter((x) => x !== entry), version: sc.version + 1 };
  } else if (c.op === 'exclude') {
    s.scope = { ...sc, exclude: [...sc.exclude, entry], version: sc.version + 1 };
  } else if (c.op === 'remove') {
    s.scope = { ...sc, include: sc.include.filter((x) => x !== entry), exclude: sc.exclude.filter((x) => x !== entry), version: sc.version + 1 };
  } else {
    return 'validation';
  }
  s.scopeDecisions.push({ decision_id: decisionId, change: { ...c, entry }, effect: eff });
  timelineEntry(s, decisionId, c.op, [entry], eff, null);
  reevaluate(s);
  return { decision_id: decisionId, version: s.scope.version, op: c.op, entries: [entry], include: [...s.scope.include], exclude: [...s.scope.exclude], ...eff };
}

/** Rückgängig (`op: 'revert'`): Gegenoperation; prüft dieselben Bedingungen (E131). */
export function revertScopeDecision(s: MockState, decisionId: string, newId: string): ScopeChangeResult | 'not_found' | ScopeRefusal {
  const d = s.scopeDecisions.find((x) => x.decision_id === decisionId);
  if (!d) return 'not_found';
  const sc = s.scope;
  const none: Effect = { include_added: [], include_removed: [], exclude_added: [], exclude_removed: [] };
  if (d.change.op === 'open' || d.change.op === 'close') {
    const open = d.change.op === 'close';
    if (!open && sc.include.length === 0) return 'no_include';
    if (open && !s.notCustomer) return 'guardrail';
    s.scope = { ...sc, open, version: sc.version + 1 };
    s.scopeDecisions = s.scopeDecisions.filter((x) => x !== d);
    timelineEntry(s, newId, 'revert', [], none, decisionId, !open);
    markReverted(s, decisionId, newId);
    reevaluate(s);
    return { decision_id: newId, version: s.scope.version, op: 'revert', revert_of: decisionId, entries: [], open };
  }
  const e = d.change.entry;
  const eff = d.effect ?? none;
  const inc = [...sc.include.filter((x) => !eff.include_added.includes(x)), ...eff.include_removed.filter((x) => !sc.include.includes(x))];
  const exc = [...sc.exclude.filter((x) => !eff.exclude_added.includes(x)), ...eff.exclude_removed.filter((x) => !sc.exclude.includes(x))];
  if (inc.length === 0 && sc.open !== true) return 'conflict';
  s.scope = { ...sc, include: inc, exclude: exc, version: sc.version + 1 };
  s.scopeDecisions = s.scopeDecisions.filter((x) => x !== d);
  const back: Effect = { include_added: eff.include_removed, include_removed: eff.include_added, exclude_added: eff.exclude_removed, exclude_removed: eff.exclude_added };
  timelineEntry(s, newId, 'revert', [e], back, decisionId);
  markReverted(s, decisionId, newId);
  reevaluate(s);
  return { decision_id: newId, version: s.scope.version, op: 'revert', revert_of: decisionId, entries: [e], ...back };
}

/** Neuauswertung im Mock: Ziele, die jetzt im Scope liegen, verschwinden aus Warnung, Klärung und Rand. */
function reevaluate(s: MockState): void {
  const w = s.scopeWarning;
  if (w && w.targets.every((tg) => covers(s.scope, hostOf(tg.value)))) s.scopeAcked = true;
  const clarify = s.next.clarify.filter((i) => i.kind !== 'scope_name' || !covers(s.scope, i.name) || s.dismissedScope.includes(i.item_key));
  const items = s.graph.oos.items.filter((i) => !covers(s.scope, hostOf(i.label)));
  s.graph = { ...s.graph, oos: { total: items.length, items } };
  s.next = { ...s.next, clarify, open: clarify.length };
  s.generation++;
}

const PRAXIS_UNIT: UnitBrief = {
  unit_id: `${base.T1}@52000`, kind: 'command', cmd_id: `${base.T1}@52000`, cmd_ref: `${base.T1.slice(-8)}@52000`,
  title: 'nmap -sV -oX scans/full.xml 192.168.56.0/24', ctrl: false, terminal_id: base.T1, parser: 'nmap_xml', ts: base.at('16:41:10.000'),
};

/** E130: zwei Klärungen nach nmap, eine mit öffentlicher Endung. */
export function praxisClarify(): NextItem[] {
  return [
    {
      kind: 'scope_name', ordinal: 4, item_key: 'scope-name:5d1c0a7e2b9f4c31', suggestion_key: 'scope-name:5d1c0a7e2b9f4c31', ts: base.at('16:41:12.000'),
      name: 'recovery.vantis.internal', ip: '192.168.56.101', host_id: base.hostId('192.168.56.101'), source: 'nmap', source_label: 'nmap',
      text: 'recovery.vantis.internal gehört laut nmap zu 192.168.56.101 (im Scope). In den Scope aufnehmen?',
      choices: optionsFor('recovery.vantis.internal'), public: false, warning: null, claim_key: base.hex64('praxis-name-1'), unit: PRAXIS_UNIT,
      change_allowed: true, ctrl: false,
    },
    {
      kind: 'scope_name', ordinal: 5, item_key: 'scope-name:9e4b11c07d2a6f58', suggestion_key: 'scope-name:9e4b11c07d2a6f58', ts: base.at('16:41:12.000'),
      name: 'vpn.vantis-group.com', ip: '192.168.56.103', host_id: base.hostId('192.168.56.103'), source: 'ptr', source_label: 'PTR-Eintrag (nmap)',
      text: 'vpn.vantis-group.com gehört laut nmap zu 192.168.56.103 (im Scope). In den Scope aufnehmen?',
      choices: optionsFor('vpn.vantis-group.com'), public: true,
      warning: 'Öffentliche Domain: Die Zuordnung stammt vom Ziel. Nur aufnehmen, wenn sie sicher zum Auftrag gehört.',
      claim_key: base.hex64('praxis-name-2'), unit: PRAXIS_UNIT, change_allowed: true, ctrl: false,
    },
  ];
}

/** Scope-Warnung wie im Praxistest: curl auf einen Namen, dessen IP im Scope liegt (E49). */
export function praxisWarning(): MockState['scopeWarning'] {
  return {
    cmd_id: `${base.T1}@53000`, cmd_ref: `${base.T1.slice(-8)}@53000`, terminal_id: base.T1, ts: base.at('16:52:40.000'),
    terminal: base.TERM[base.T1] ?? { terminal_id: base.T1, ordinal: 1, label: 'scan' },
    text: 'curl http://recovery.vantis.internal/login', ctrl: false,
    targets: [{ value: 'http://recovery.vantis.internal/login', verdict: 'out', ctrl: false, proposals: optionsFor('http://recovery.vantis.internal/login').map((o, i) => (i === 0 ? { ...o, kind: 'url_host' } : o)) }],
    scope: [base.SCOPE], acked: false,
  };
}

/** E131: Öffnen beim Anlegen ohne Ziele (Szenario `offen`), rückgängig wie jede Scope-Änderung */
export const OPEN_ID = '0199a3c2-9a10-7000-8000-00000000d010';
export function openItem(): TimelineItem {
  const ts = base.at('16:02:10.000');
  return {
    id: OPEN_ID, ts, ts_ns: base.nsOf(ts), terminal_id: null, context_label: null, host_id: null, ctrl: false, terminal: null,
    type: 'decision', decision_id: OPEN_ID, kind: 'd.scope.update', summary: 'Scope geöffnet (Version 2)', detail: null, reason: null, ref: null, effect: null,
    scope_change: {
      op: 'open', entries: [], version: 2, revert_of: null, reverted_by: null, revertible: true,
      include_added: [], include_removed: [], exclude_added: [], exclude_removed: [], open_before: false, open_after: true,
    },
  };
}
