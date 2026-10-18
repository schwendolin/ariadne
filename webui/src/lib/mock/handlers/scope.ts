/**
 * Mock: Scope erweitern (E129, E130), Szenarien `praxis` (Praxistest 1: Scope-Warnung für
 * recovery.vantis.internal, Klärungen nach nmap) und `customer` (Profil customer: nur Anzeige).
 *
 * Nur Testattrappe im Mock-Build. Die Vorschläge bildet hier eine einfache Zerlegung nach, damit die
 * Oberfläche etwas zeigt; im Produkt kommen Vorschläge, Urteile und «öffentliche Endung» vom Server
 * (ScopeMatcher). Keine DNS-Auflösung. Besitzer: ui.
 */
import type { NextItem, ScopeChange, ScopeChangeResult, ScopeOption, ScopeOptions, ScopeView, UnitBrief } from '../../api/types';
import * as base from '../data/base';
import type { MockState } from '../state';

/** Interne Endungen (Mock); alles andere gilt als öffentlich und bekommt den Warnhinweis. */
const INTERNAL = new Set(['internal', 'local', 'lan', 'localdomain', 'htb', 'thm', 'test', 'lab', 'corp', 'home', 'intranet', 'example', 'invalid']);

function hostOf(value: string): string {
  const v = value.trim();
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i.exec(v);
  return (m?.[1] ?? v).toLowerCase().replace(/\.$/, '');
}

function isIp(v: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (/^[0-9a-f:]+$/i.test(v) && v.includes(':'));
}

function isPublicName(name: string): boolean {
  const tld = name.split('.').at(-1) ?? '';
  return !INTERNAL.has(tld);
}

export function optionsFor(value: string): ScopeOption[] {
  const host = hostOf(value);
  if (!host) return [];
  if (isIp(host)) return [{ entry: host, kind: 'ip', public: !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd])/i.test(host), ctrl: false }];
  const labels = host.split('.');
  const pub = isPublicName(host);
  const out: ScopeOption[] = [{ entry: host, kind: 'name', public: pub, ctrl: false }];
  if (labels.length >= 3) out.push({ entry: `*.${labels.slice(1).join('.')}`, kind: 'wildcard', public: pub, ctrl: false });
  return out;
}

export function scopeOptions(s: MockState, value: string): ScopeOptions {
  const covered = covers(s.scope, hostOf(value));
  return { value, ctrl: false, verdict: covered ? 'in' : 'out', options: optionsFor(value) };
}

/** Grobe Deckung für den Mock (exakt oder Wildcard an Label-Grenzen; IPs nur exakt oder im /24). */
function covers(scope: ScopeView, host: string): boolean {
  if (scope.exclude.includes(host)) return false;
  return scope.include.some((e) => {
    if (e === host) return true;
    if (e.startsWith('*.')) return host.endsWith(e.slice(1));
    if (e === base.SCOPE) return host.startsWith('192.168.56.');
    return false;
  });
}

export function scopeView(s: MockState): ScopeView {
  return { ...structuredClone(s.scope), editable: s.profile !== 'customer' };
}

/** Wendet eine Änderung an, entfernt erledigte Warnungen und Klärungen (Neuauswertung). */
export function applyScopeChange(s: MockState, c: ScopeChange, decisionId: string): ScopeChangeResult | 'validation' | 'conflict' {
  const entry = c.entry.trim();
  if (!entry || entry.length > 253 || /[\s\u0000-\u001f\u007f]/.test(entry)) return 'validation';
  const sc = s.scope;
  if (c.op === 'add') {
    if (sc.include.includes(entry)) return 'conflict';
    s.scope = { ...sc, include: [...sc.include, entry], version: sc.version + 1 };
  } else if (c.op === 'exclude') {
    if (sc.exclude.includes(entry)) return 'conflict';
    s.scope = { ...sc, exclude: [...sc.exclude, entry], version: sc.version + 1 };
  } else if (c.op === 'remove') {
    if (!sc.include.includes(entry) && !sc.exclude.includes(entry)) return 'conflict';
    s.scope = { ...sc, include: sc.include.filter((x) => x !== entry), exclude: sc.exclude.filter((x) => x !== entry), version: sc.version + 1 };
  } else {
    return 'validation';
  }
  s.scopeDecisions.push({ decision_id: decisionId, change: { ...c, entry } });
  reevaluate(s);
  return { decision_id: decisionId, version: s.scope.version };
}

/** Rückgängig (d.revoke auf eine Scope-Änderung): Gegenoperation. */
export function revokeScopeDecision(s: MockState, decisionId: string): boolean {
  const d = s.scopeDecisions.find((x) => x.decision_id === decisionId);
  if (!d) return false;
  const sc = s.scope;
  const e = d.change.entry;
  if (d.change.op === 'add') s.scope = { ...sc, include: sc.include.filter((x) => x !== e), version: sc.version + 1 };
  else if (d.change.op === 'exclude') s.scope = { ...sc, exclude: sc.exclude.filter((x) => x !== e), version: sc.version + 1 };
  s.scopeDecisions = s.scopeDecisions.filter((x) => x !== d);
  reevaluate(s);
  return true;
}

/** Neuauswertung im Mock: Ziele, die jetzt im Scope liegen, verschwinden aus Warnung, Klärung und Rand. */
function reevaluate(s: MockState): void {
  const w = s.scopeWarning;
  if (w && w.targets.every((tg) => covers(s.scope, hostOf(tg.value)))) s.scopeAcked = true;
  const clarify = s.next.clarify.filter((i) => i.kind !== 'scope_suggestion' || !covers(s.scope, i.name));
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
      kind: 'scope_suggestion', ordinal: 4, item_key: 'scope:recovery.vantis.internal', ts: base.at('16:41:12.000'),
      name: 'recovery.vantis.internal', ip: '192.168.56.101', options: optionsFor('recovery.vantis.internal'), unit: PRAXIS_UNIT, ctrl: false,
    },
    {
      kind: 'scope_suggestion', ordinal: 5, item_key: 'scope:vpn.vantis-group.com', ts: base.at('16:41:12.000'),
      name: 'vpn.vantis-group.com', ip: '192.168.56.103', options: optionsFor('vpn.vantis-group.com'), unit: PRAXIS_UNIT, ctrl: false,
    },
  ];
}

/** Scope-Warnung wie im Praxistest: curl auf einen Namen, dessen IP im Scope liegt (E49). */
export function praxisWarning(): MockState['scopeWarning'] {
  return {
    cmd_id: `${base.T1}@53000`, cmd_ref: `${base.T1.slice(-8)}@53000`, terminal_id: base.T1, ts: base.at('16:52:40.000'),
    terminal: base.TERM[base.T1] ?? { terminal_id: base.T1, ordinal: 1, label: 'scan' },
    text: 'curl http://recovery.vantis.internal/login', ctrl: false,
    targets: [{ value: 'recovery.vantis.internal', verdict: 'out', ctrl: false }],
    scope: [base.SCOPE], acked: false,
  };
}
