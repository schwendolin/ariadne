/**
 * Mock-Entscheide für Karte, «Als Nächstes» und Host-Detail (Besitzer: ui-karte), wie der Daemon:
 * d.claim.confirm/reject/edit, d.conflict.resolve, d.entity.merge/split, d.status.work/access,
 * d.note.set, d.tag.add/remove, d.keystep.mark, d.suggestion.done/dismiss und d.revoke auf genau
 * diese Entscheide (Rückgängig in der Spalte). Andere d.revoke gehen an handlers/history.ts.
 * Jeder Entscheid ändert den Mock-Zustand und löst die Ereignisse aus (`inbox`, `suggestion`; das
 * `changes` sendet MockBackend.decide).
 */
import type { DecisionInput, DecisionResult, GraphView, HostDetail, HostNode, ThreadEdge } from '../../api/types';
import type { MockState } from '../state';

type Undo = (s: MockState) => void;
const undos = new WeakMap<MockState, Map<string, Undo>>();

function undoMap(s: MockState): Map<string, Undo> {
  let m = undos.get(s);
  if (!m) {
    m = new Map();
    undos.set(s, m);
  }
  return m;
}

function ok(id: string, d: DecisionInput): DecisionResult {
  return { decision_id: id, seq: null, client_ref: d.client_ref ?? null, effect: null };
}

const CONFLICT: DecisionResult = { decision_id: null, seq: null, client_ref: null, effect: null };

function emitInbox(s: MockState): void {
  s.next = { ...s.next, open: s.next.clarify.length };
  s.emit({ name: 'inbox', id: null, data: { project_id: s.graph.project_id, open: s.next.open } });
}

function emitSuggestion(s: MockState): void {
  s.emit({ name: 'suggestion', id: null, data: { project_id: s.graph.project_id, open: s.next.suggestions.length } });
}

function summarize(g: GraphView): GraphView['summary'] {
  const hosts = g.nodes.filter((n) => n.kind === 'host') as HostNode[];
  return {
    hosts: hosts.length,
    fog: hosts.filter((h) => h.claim_state === 'candidate').length,
    with_access: hosts.filter((h) => h.access !== 'none').length,
    services: hosts.reduce((n, h) => n + h.services_total, 0),
    conflicts: hosts.reduce((n, h) => n + h.conflicts, 0),
  };
}

/** Host in Graph und Detail ändern. */
function patchHost(s: MockState, id: string, patch: Partial<HostNode> & Partial<Pick<HostDetail, 'note'>>): boolean {
  const node = s.graph.nodes.find((n) => n.kind === 'host' && n.id === id) as HostNode | undefined;
  if (!node) return false;
  const { note, ...nodePatch } = patch;
  s.graph = { ...s.graph, nodes: s.graph.nodes.map((n) => (n.kind === 'host' && n.id === id ? { ...n, ...nodePatch } : n)) };
  s.graph = { ...s.graph, summary: summarize(s.graph) };
  const d = s.hosts[id];
  const { kind: _kind, conflicts: _conflicts, ...detailPatch } = nodePatch;
  if (d) s.hosts = { ...s.hosts, [id]: { ...d, ...detailPatch, ...(note !== undefined ? { note } : {}) } };
  return true;
}

function hostOf(s: MockState, subject: unknown): string | null {
  const id = String(subject ?? '');
  return s.graph.nodes.some((n) => n.kind === 'host' && n.id === id) ? id : null;
}

export function applyMapDecision(s: MockState, d: DecisionInput, id: string): DecisionResult | null {
  const p = d.payload as Record<string, unknown>;
  const undo = undoMap(s);
  switch (d.kind) {
    case 'd.suggestion.done':
    case 'd.suggestion.dismiss': {
      const key = String(p.suggestion_key ?? '');
      const sug = s.next.suggestions.find((x) => x.suggestion_key === key);
      if (!sug) return CONFLICT;
      if (d.kind === 'd.suggestion.done' && typeof p.basis !== 'string') return null;
      const at = s.next.suggestions.indexOf(sug);
      s.next = { ...s.next, suggestions: s.next.suggestions.filter((x) => x.suggestion_key !== key) };
      // wie der Server: der Denkanstoss bleibt mit Zustand und Entscheid in `/suggestions?state=all`
      const decided = { ...sug, state: d.kind === 'd.suggestion.done' ? ('done' as const) : ('dismissed' as const), decision_id: id };
      s.suggestionsDecided = [...s.suggestionsDecided.filter((x) => x.suggestion_key !== key), decided];
      emitSuggestion(s);
      undo.set(id, (st) => {
        const list = [...st.next.suggestions];
        list.splice(Math.min(at, list.length), 0, sug);
        st.next = { ...st.next, suggestions: list };
        st.suggestionsDecided = st.suggestionsDecided.filter((x) => x.suggestion_key !== key);
        emitSuggestion(st);
      });
      return ok(id, d);
    }
    case 'd.entity.merge':
    case 'd.entity.split': {
      const ids = Array.isArray(p.identifiers) ? p.identifiers.map(String) : [];
      const item = s.next.clarify.find(
        (i) => i.kind === 'merge_suggestion' && ids.every((x) => i.identifiers.some((k) => k.key === x)),
      );
      if (!item || ids.length < 2) return CONFLICT;
      const at = s.next.clarify.indexOf(item);
      const oosBefore = s.graph.oos;
      s.next = { ...s.next, clarify: s.next.clarify.filter((i) => i !== item) };
      if (d.kind === 'd.entity.merge') {
        const gone = new Set(ids);
        const items = s.graph.oos.items.filter((o) => !gone.has(o.identifier));
        s.graph = { ...s.graph, oos: { total: s.graph.oos.total - (s.graph.oos.items.length - items.length), items } };
      }
      emitInbox(s);
      undo.set(id, (st) => {
        const list = [...st.next.clarify];
        list.splice(Math.min(at, list.length), 0, item);
        st.next = { ...st.next, clarify: list };
        st.graph = { ...st.graph, oos: oosBefore };
        emitInbox(st);
      });
      return ok(id, d);
    }
    case 'd.claim.confirm':
    case 'd.claim.reject':
    case 'd.claim.edit': {
      const key = String(p.claim_key ?? '');
      if (d.kind === 'd.claim.edit' && typeof p.value !== 'string') return null;
      // Host im Nebel: Claims, die ihn einfärben (candidate_claims)
      const fog = Object.values(s.hosts).find((h) => h.candidate_claims.includes(key));
      if (fog) {
        if (d.kind === 'd.claim.reject') {
          s.graph = { ...s.graph, nodes: s.graph.nodes.filter((n) => n.id !== fog.id), edges: s.graph.edges.filter((e) => e.source !== fog.id && e.target !== fog.id) };
          s.graph = { ...s.graph, summary: summarize(s.graph) };
          const { [fog.id]: _gone, ...rest } = s.hosts;
          s.hosts = rest;
        } else {
          patchHost(s, fog.id, { claim_state: 'confirmed', knowledge: 'discovered' });
          const det = s.hosts[fog.id];
          if (det) s.hosts = { ...s.hosts, [fog.id]: { ...det, candidate_claims: [] } };
        }
        return ok(id, d);
      }
      const item = s.next.clarify.find((i) => i.kind === 'decide_value' && i.fact.claim_key === key);
      if (!item) return CONFLICT;
      s.next = { ...s.next, clarify: s.next.clarify.filter((i) => i !== item) };
      emitInbox(s);
      return ok(id, d);
    }
    case 'd.conflict.resolve': {
      const key = String(p.conflict_key ?? '');
      const item = s.next.clarify.find((i) => i.kind === 'conflict' && i.conflict.conflict_key === key);
      if (!item) return CONFLICT;
      s.next = { ...s.next, clarify: s.next.clarify.filter((i) => i !== item) };
      emitInbox(s);
      return ok(id, d);
    }
    case 'd.status.work': {
      const host = hostOf(s, p.subject);
      if (!host) return CONFLICT;
      const value = String(p.value) as HostNode['work'];
      return patchHost(s, host, { work: value, work_reason: value === 'dead_end' ? (typeof p.reason === 'string' ? p.reason : null) : null }) ? ok(id, d) : CONFLICT;
    }
    case 'd.status.access': {
      const host = hostOf(s, p.subject);
      if (!host) return CONFLICT;
      patchHost(s, host, { access: String(p.value) as HostNode['access'] });
      const det = s.hosts[host];
      if (det) s.hosts = { ...s.hosts, [host]: { ...det, access_by: { source: 'decision', decision_id: id, ts: new Date().toISOString() } } };
      return ok(id, d);
    }
    case 'd.note.set': {
      const host = hostOf(s, p.subject);
      if (!host) return CONFLICT;
      patchHost(s, host, { note: typeof p.text === 'string' && p.text ? p.text : null });
      return ok(id, d);
    }
    case 'd.tag.add':
    case 'd.tag.remove': {
      const host = hostOf(s, p.subject);
      const node = host ? (s.graph.nodes.find((n) => n.id === host) as HostNode) : null;
      if (!host || !node) return CONFLICT;
      const tag = String(p.tag ?? '');
      const tags = d.kind === 'd.tag.add' ? [...new Set([...node.tags, tag])] : node.tags.filter((x) => x !== tag);
      patchHost(s, host, { tags });
      return ok(id, d);
    }
    case 'd.keystep.mark': {
      const host = typeof p.host === 'string' ? hostOf(s, p.host) : null;
      const thread = s.graph.edges.filter((e) => e.kind === 'thread') as ThreadEdge[];
      const last = thread[thread.length - 1];
      const edge: ThreadEdge = {
        kind: 'thread', id: `k:${id.slice(-6)}`, seq: thread.length + 1, step: String(p.step) as ThreadEdge['step'],
        source: last?.target ?? 'kali', target: host ?? last?.target ?? 'kali', ts: new Date().toISOString(),
        note: typeof p.note === 'string' ? p.note : null, decision_id: id,
      };
      s.graph = { ...s.graph, edges: [...s.graph.edges, edge] };
      if (host) {
        const det = s.hosts[host];
        if (det) s.hosts = { ...s.hosts, [host]: { ...det, thread: [...det.thread, edge] } };
      }
      return ok(id, d);
    }
    case 'd.revoke': {
      const target = String(p.decision_id ?? '');
      const fn = undo.get(target);
      if (!fn) return null;
      undo.delete(target);
      fn(s);
      return ok(id, d);
    }
    default:
      return null;
  }
}
