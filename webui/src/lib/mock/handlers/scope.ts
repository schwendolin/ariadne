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
  if (isIp(host)) {
    const priv = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd])/i.test(host);
    return [{ entry: host, kind: 'ip', public: false, outside_lab: !priv }];
  }
  const labels = host.split('.');
  const pub = isPublicName(host);
  // wie der Server: öffentliche Endungen liegen ausserhalb der Lab-Allowlist (nur im Terminal)
  const out: ScopeOption[] = [{ entry: host, kind: 'name', public: pub, outside_lab: pub }];
  if (labels.length >= 3) out.push({ entry: `*.${labels.slice(1).join('.')}`, kind: 'wildcard', public: pub, outside_lab: pub });
  return out;
}

export function scopeOptions(s: MockState, value: string): ScopeOptions {
  const covered = covers(s.scope, hostOf(value));
  return { value, ctrl: false, verdict: covered ? 'in' : 'out', options: optionsFor(value) };
}

/** Grobe Deckung für den Mock (exakt oder Wildcard an Label-Grenzen; IPs nur exakt oder im /24). */
function covers(scope: Pick<ScopeView, 'include' | 'exclude'>, host: string): boolean {
  if (scope.exclude.includes(host)) return false;
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
    not_customer: false, change_allowed: s.profile !== 'customer', history: [],
  };
}

/** Wendet eine Änderung an, entfernt erledigte Warnungen und Klärungen (Neuauswertung). */
export function applyScopeChange(s: MockState, c: ScopeChange, decisionId: string, dryRun = false): ScopeChangeResult | 'validation' | 'conflict' | 'guardrail' {
  const entry = c.entry.trim();
  const outside = c.op === 'add' && optionsFor(entry).some((o) => o.outside_lab) && !entry.startsWith('192.168.56.');
  if (dryRun) {
    const sc0 = s.scope;
    if ((c.op === 'add' && sc0.include.includes(entry)) || (c.op === 'exclude' && sc0.exclude.includes(entry))) return 'conflict';
    return {
      decision_id: null, dry_run: true, version: sc0.version + 1, op: c.op, entries: [entry], outside: outside ? [entry] : [], needs_not_customer: outside,
      include_added: c.op === 'add' ? [entry] : [], exclude_removed: c.op === 'add' && sc0.exclude.includes(entry) ? [entry] : [],
      include_removed: c.op === 'remove' && sc0.include.includes(entry) ? [entry] : [], exclude_added: c.op === 'exclude' ? [entry] : [],
    };
  }
  if (outside) return 'guardrail';
  // eslint-disable-next-line no-control-regex
  if (!entry || entry.length > 253 || /[\s\u0000-\u001f\u007f]/.test(entry)) return 'validation';
  const sc = s.scope;
  if (c.op === 'add') {
    if (sc.include.includes(entry)) return 'conflict';
    // wie der Server: steht derselbe Eintrag im Ausschluss, fällt er dort weg
    s.scope = { ...sc, include: [...sc.include, entry], exclude: sc.exclude.filter((x) => x !== entry), version: sc.version + 1 };
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
  return { decision_id: decisionId, version: s.scope.version, op: c.op, entries: [entry], include: [...s.scope.include], exclude: [...s.scope.exclude] };
}

/** Rückgängig (`op: 'revert'`): Gegenoperation. */
export function revertScopeDecision(s: MockState, decisionId: string, newId: string): ScopeChangeResult | 'not_found' {
  const d = s.scopeDecisions.find((x) => x.decision_id === decisionId);
  if (!d) return 'not_found';
  const sc = s.scope;
  const e = d.change.entry;
  if (d.change.op === 'add') s.scope = { ...sc, include: sc.include.filter((x) => x !== e), version: sc.version + 1 };
  else if (d.change.op === 'exclude') s.scope = { ...sc, exclude: sc.exclude.filter((x) => x !== e), version: sc.version + 1 };
  else if (d.change.op === 'remove') s.scope = { ...sc, include: [...sc.include, e], version: sc.version + 1 };
  s.scopeDecisions = s.scopeDecisions.filter((x) => x !== d);
  reevaluate(s);
  return { decision_id: newId, version: s.scope.version, op: 'revert', revert_of: decisionId, entries: [e] };
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
