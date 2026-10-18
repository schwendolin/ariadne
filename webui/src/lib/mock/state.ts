/**
 * Veränderlicher Zustand des Mocks (Besitzer: ui-fundament). Der Mock bildet die API aus
 * docs/web-api.md nach; Entscheide ändern diesen Zustand über die Handler der Bereiche
 * (handlers/map.ts: ui-karte, handlers/history.ts: ui-verlauf) und lösen dieselben SSE-Ereignisse
 * aus wie der Daemon. Nichts davon landet im Browser-Speicher.
 *
 * Szenarien über den Query-Parameter `mock` beim Laden (nur im Mock-Build):
 *   normal (Standard, Standbild 16:54), calm (Ruhezustand ohne Klärungen), empty (leeres Projekt),
 *   noproject, locked, held, offline (Strom öffnet nie), many (250 Hosts, Tabelle), hostile
 *   (feindliche Werte, D2 ohne Vorlage), login (Anmeldung nötig), chain (Hash-Kette verletzt),
 *   noclip (kein Werkzeug für die Zwischenablage).
 *   Kopfzeile (ui-fundament): allon (alle Terminals nehmen auf, Variante «normal»), present
 *   (Präsentationsmodus an), scope (Scope-Warnung nicht quittiert), noconfirm (Pause wird nie
 *   bestätigt: «wartet auf Bestätigung»), budget (E117: T2 ohne Budgetangabe, der Server lehnt ab;
 *   T3 mit 5 min Rest), local (Sitzung lokal, Browser in der Kali).
 *   Praxistest 1 (ui): praxis (Scope-Warnung für recovery.vantis.internal, zwei Klärungen E130),
 *   customer (dasselbe im Profil customer: nur Anzeige), ende (nach 1,5 s endet die Sitzung mit
 *   dem Ereignis `session`, Grund stop).
 */
import type {
  AiJob,
  DecisionInput,
  DecisionResult,
  ExportEntry,
  ExportRunning,
  ExportTemplate,
  Screenshot,
  FindingDetail,
  GraphView,
  HostDetail,
  HostNode,
  NextView,
  PendingResponse,
  PositionsView,
  PrefsView,
  Profile,
  ScopeChange,
  ScopeView,
  ScopeWarning,
  SeenView,
  ServiceView,
  StreamEvent,
  Suggestion,
  Terminal,
  TimelineItem,
} from '../api/types';
import * as base from './data/base';
import * as e4 from './data/etappe4';
import * as history from './data/history';
import * as map from './data/map';
import { praxisClarify, praxisWarning } from './handlers/scope';

export const SCENARIOS = [
  'normal', 'calm', 'empty', 'noproject', 'locked', 'held', 'offline', 'many', 'hostile', 'login', 'chain', 'noclip',
  'allon', 'present', 'scope', 'noconfirm', 'budget', 'local',
  // Korrektur A3: nach 2,5 s kommt ein neuer Host dazu (Karte springt nicht unter der Maus)
  'grow',
  // Etappe 4: KI-Zustände, E119 gruppierte Versionen
  'ki', 'kiwarn', 'kiover', 'kigone', 'kirefuse', 'kiinject', 'kirun', 'kioff', 'versions',
  // Praxistest 1: Scope erweitern (E129, E130), Profil customer, Abmeldung mit Grund
  'praxis', 'customer', 'ende',
] as const;
export type Scenario = (typeof SCENARIOS)[number];

export interface MockState {
  scenario: Scenario;
  generation: number;
  presentation: boolean;
  origin: 'sshd' | 'local';
  terminals: Terminal[];
  prefs: PrefsView;
  graph: GraphView;
  next: NextView;
  /** entschiedene Denkanstösse (erledigt oder verworfen) wie bei `/suggestions?state=all` */
  suggestionsDecided: Suggestion[];
  seen: SeenView;
  services: ServiceView[];
  hosts: Record<string, HostDetail>;
  timeline: TimelineItem[];
  findings: FindingDetail[];
  pending: PendingResponse;
  positions: PositionsView;
  scopeAcked: boolean;
  /** Scope-Warnung (Status und Spalte); null: Standard aus base.status */
  scopeWarning: ScopeWarning | null;
  /** Scope des Projekts (E129) und Profil */
  scope: Pick<ScopeView, 'include' | 'exclude' | 'windows' | 'version'>;
  /** E130: verworfene Klärungen (d.suggestion.dismiss mit Schlüssel «scope-name:») */
  dismissedScope: string[];
  /** Entscheid-ID des Verwerfens: verworfene Klärung (für d.revoke) */
  dismissedScopeItems: Record<string, NextView['clarify'][number]>;
  profile: Profile;
  scopeDecisions: { decision_id: string; change: ScopeChange }[];
  /** Etappe 4: KI-Modus, letzter Auftrag, Screenshots, Exporte, Phasenkorrekturen */
  aiMode: e4.AiMode;
  aiJob: AiJob | null;
  screenshots: Screenshot[];
  exports: ExportEntry[];
  exportRunning: ExportRunning | null;
  phaseDecisions: Record<ExportTemplate, Record<string, string>>;
  decisions: { decision_id: string; kind: string; payload: Record<string, unknown> }[];
  /** gesetzt vom MockBackend: Ereignis an alle Abonnenten */
  emit: (ev: StreamEvent) => void;
}

const AI_MODES: Partial<Record<Scenario, e4.AiMode>> = {
  ki: 'ready', kiwarn: 'warn', kiover: 'over', kigone: 'gone', kirefuse: 'refuse', kiinject: 'inject', kirun: 'run', kioff: 'notallowed',
};

export function scenarioFromLocation(loc: Location | null = typeof location === 'undefined' ? null : location): Scenario {
  const v = loc ? new URLSearchParams(loc.search).get('mock') : null;
  return (SCENARIOS as readonly string[]).includes(v ?? '') ? (v as Scenario) : 'normal';
}

function manyHosts(): HostNode[] {
  const proto = map.hostNodes()[2] as HostNode;
  return Array.from({ length: 250 }, (_, i) => {
    const ip = `192.168.56.${i + 1}`;
    return {
      ...proto, id: base.hostId(ip), label: ip, addresses: [ip], work: 'open', work_reason: null, knowledge: 'scanned' as const,
      ports: i % 3 === 0 ? [22, 80, 443] : i % 3 === 1 ? [445] : [3389], services_total: i % 3 === 0 ? 3 : 1,
      conflicts: i === 16 || i === 202 ? 1 : 0, hint: i === 16 || i === 202 ? ('conflict' as const) : ('services' as const),
      conflict_brief: i === 16 ? { predicate: 'service.name', port: 445 } : i === 202 ? { predicate: 'service.version', port: 80 } : null,
    };
  });
}

export function createState(scenario: Scenario = 'normal'): MockState {
  const generation = 43;
  const graph = map.graph(generation);
  const hosts: Record<string, HostDetail> = {};
  for (const h of map.hostNodes()) {
    const d = map.hostDetail(h.id);
    if (d) hosts[h.id] = d;
  }
  const s: MockState = {
    scenario,
    generation,
    presentation: false,
    origin: 'sshd',
    terminals: base.terminals(),
    prefs: base.prefs(),
    graph,
    next: map.next(),
    suggestionsDecided: [],
    seen: map.seen(),
    services: map.services(),
    hosts,
    timeline: history.timeline(),
    findings: [history.findingF1()],
    pending: history.pending(),
    positions: { positions: {}, updated_at: null },
    scopeAcked: true,
    scopeWarning: null,
    scope: { include: [base.SCOPE], exclude: [], windows: [], version: 1 },
    profile: 'lab',
    scopeDecisions: [],
    dismissedScope: [],
    dismissedScopeItems: {},
    aiMode: AI_MODES[scenario] ?? 'off',
    aiJob: null,
    screenshots: e4.screenshots(),
    exports: e4.exportsList(),
    exportRunning: null,
    phaseDecisions: { cys: {}, htb: {} },
    decisions: [],
    emit: () => undefined,
  };
  if (scenario === 'calm') s.next = { ...s.next, clarify: [], open: 0 };
  if (scenario === 'allon') s.terminals = s.terminals.map((x) => ({ ...x, state: 'on' as const, pause_until: null }));
  if (scenario === 'present') s.presentation = true;
  if (scenario === 'scope') s.scopeAcked = false;
  if (scenario === 'praxis' || scenario === 'customer') {
    s.scopeAcked = false;
    s.scopeWarning = praxisWarning();
    s.next = { ...s.next, clarify: [...praxisClarify(), ...s.next.clarify] };
    s.next = { ...s.next, open: s.next.clarify.length };
    s.scope = { ...s.scope, exclude: ['192.168.56.1'], windows: [{ days: 'mon-fri', from: '08:00', to: '18:00', tz: 'Europe/Zurich' }] };
  }
  if (scenario === 'customer') s.profile = 'customer';
  if (scenario === 'local') s.origin = 'local';
  if (scenario === 'budget') {
    s.terminals = s.terminals.map((x) =>
      x.terminal_id === base.T2 ? { ...x, web_pause_left_s: null } : x.terminal_id === base.T3 ? { ...x, web_pause_left_s: 300 } : x,
    );
  }
  if (scenario === 'versions' || scenario === 'ki') {
    const rest = s.next.suggestions.filter((x) => x.rule_id !== 'R-VERSION-RECHERCHE');
    s.next = { ...s.next, suggestions: [...rest, e4.versionsSuggestion()] };
  }
  if (scenario === 'held') s.terminals = [...s.terminals, base.heldTerminal()];
  if (scenario === 'hostile') {
    s.next = { ...s.next, suggestions: [map.hostileSuggestion(), ...s.next.suggestions] };
    s.findings = [...s.findings, history.findingHostile()];
  }
  if (scenario === 'empty') {
    s.graph = { ...graph, nodes: graph.nodes.filter((n) => n.kind !== 'host'), edges: [], oos: { total: 0, items: [] }, summary: { hosts: 0, fog: 0, with_access: 0, services: 0, conflicts: 0 } };
    s.next = { clarify: [], confirm: [], suggestions: [], suggestions_available: true, quiet: { heuristic: 0, out_of_scope: 0, mentions: 0, system_accounts: 0 }, open: 0 };
    s.seen = { seen_at: null, new: null };
    s.timeline = s.timeline.filter((i) => i.type === 'project');
    s.findings = [];
    s.pending = { files: [], truncated: false };
    s.services = [];
    s.hosts = {};
  }
  if (scenario === 'many') {
    const hs = manyHosts();
    s.graph = {
      ...graph,
      nodes: [...graph.nodes.filter((n) => n.kind !== 'host'), ...hs],
      edges: [],
      summary: { hosts: 250, fog: 0, with_access: 0, services: 450, conflicts: 2 },
      table_only: true,
    };
  }
  return s;
}

/** Ein Handler eines Bereichs: Ergebnis, oder `null`, wenn er die Art nicht kennt. */
export type DecisionHandler = (s: MockState, d: DecisionInput, decisionId: string) => DecisionResult | null;

let counter = 0x100;
export function newDecisionId(): string {
  counter++;
  return `0199a3c2-ffff-7000-8000-${counter.toString(16).padStart(12, '0')}`;
}
