/** Baut die Graph-Projektion aus dem Mock-Zustand, so wie der Server sie liefern soll. */
import type { GraphEdge, GraphLayer, GraphNode, GraphView, HostNode, HostSummary, Lens, ServiceNode, ServiceView } from '../api/types';
import type { MockFixture } from './fixture';

export function hostNode(h: HostSummary): HostNode {
  const { first_seen: _f, last_seen: _l, ...rest } = h;
  return { kind: 'host', ...rest };
}

export function serviceNode(s: ServiceView): ServiceNode {
  return {
    kind: 'service', id: s.service_id, host: s.host_id, proto: s.proto, port: s.port, name: s.name, product: s.product,
    version: s.version, class: s.class, state: s.state, claim_state: s.claim_state, confidence: s.confidence_level,
    work: s.work, conflicts: s.conflicts, ai: s.ai, cves: s.cves,
  };
}

export function buildGraph(fx: MockFixture, layers: GraphLayer[], lens: Lens): GraphView {
  const on = (l: GraphLayer) => layers.includes(l);
  const nodes: GraphNode[] = [fx.kali, ...fx.segments];
  const shownHosts = fx.hosts.filter(
    (h) => h.scope === 'in' && h.claim_state !== 'rejected' && h.work !== 'out_of_scope' && (h.claim_state !== 'candidate' || on('fog')),
  );
  const hostIds = new Set(shownHosts.map((h) => h.id));
  nodes.push(...shownHosts.map(hostNode));
  if (on('services')) {
    for (const s of fx.services) {
      if (!hostIds.has(s.host_id) || s.claim_state === 'rejected') continue;
      if (s.claim_state === 'candidate' && !on('fog')) continue;
      nodes.push(serviceNode(s));
    }
  }
  const ids = new Set(nodes.map((n) => n.id));
  const edges: GraphEdge[] = fx.reach.filter((e) => ids.has(e.source) && ids.has(e.target));
  if (on('attack')) edges.push(...fx.thread.filter((e) => ids.has(e.source) && ids.has(e.target)));
  const outOfScope = fx.oos;
  return {
    project_id: fx.project.id,
    generation: fx.generation,
    lens,
    layers,
    nodes,
    edges,
    oos: {
      out: outOfScope.filter((o) => o.verdict === 'out').length,
      excluded: outOfScope.filter((o) => o.verdict === 'excluded').length,
      unknown: outOfScope.filter((o) => o.verdict === 'unknown').length,
      items: outOfScope,
    },
  };
}
