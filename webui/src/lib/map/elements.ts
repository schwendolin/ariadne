/**
 * Graph-Projektion -> Cytoscape-Elemente.
 *
 * Alle Beschriftungen laufen durch displaySafe() (Zieldaten sind feindlich) und
 * werden auf dem Canvas als Text gezeichnet. Status steht nie nur in der Farbe:
 * Zugriff trägt `#` (admin/root) bzw. `$` (user), Arbeitsstand und Konflikte
 * stehen zusätzlich als Wort im Label.
 */
import type { ElementDefinition } from 'cytoscape';
import type { GraphLayer, GraphView, HostNode, ServiceClass, ServiceNode } from '../api/types';
import { t } from '../i18n';
import { displaySafe } from '../safe/displaySafe';

export const OOS_ID = '__oos__';
const CLASS_ORDER: ServiceClass[] = ['web', 'smb', 'db', 'remote', 'file', 'mail', 'other'];

export interface ElementOptions {
  layers: GraphLayer[];
  /** Hosts mit ausgeklappten Services */
  expanded: ReadonlySet<string>;
  /** neu seit dem letzten «Gesehen» */
  fresh: ReadonlySet<string>;
}

function accessPrefix(h: HostNode): string {
  if (h.access === 'admin') return '# ';
  if (h.access === 'user') return '$ ';
  return '';
}

export function hostLabel(h: HostNode, showServiceBadges: boolean): string {
  const lines: string[] = [];
  lines.push(accessPrefix(h) + displaySafe(h.label, 30));
  const addr = h.addresses[0];
  if (addr && addr !== h.label) lines.push(displaySafe(addr, 40));
  const status: string[] = [];
  if (h.access !== 'none') status.push(t(`access.${h.access}`));
  if (h.work !== 'open') status.push(t(`work.${h.work}`));
  if (h.conflicts > 0) status.push(t('map.conflicts', { n: h.conflicts }));
  if (h.ai) status.push(t('map.ai'));
  if (status.length) lines.push(status.join(' · '));
  if (showServiceBadges && h.services_total > 0) {
    const parts = CLASS_ORDER.filter((c) => h.service_counts[c] > 0).map((c) => `${t(`svcClass.${c}`)} ${h.service_counts[c]}`);
    lines.push(parts.join(' · '));
  }
  return lines.join('\n');
}

export function serviceLabel(s: ServiceNode): string {
  const head = `${s.port}/${s.proto} ${s.name ?? ''}`.trim();
  const prod = [s.product, s.version].filter(Boolean).join(' ');
  const flags = [s.conflicts ? '[!]' : '', s.ai ? t('map.ai') : ''].filter(Boolean).join(' ');
  return [displaySafe(head, 28), prod ? displaySafe(prod, 32) : '', flags].filter(Boolean).join('\n');
}

/** true, wenn die Services eines Hosts als Satelliten gezeigt werden. */
export function showSatellites(h: HostNode, opts: ElementOptions): boolean {
  return opts.layers.includes('services') && opts.expanded.has(h.id);
}

export function toElements(g: GraphView, opts: ElementOptions): ElementDefinition[] {
  const els: ElementDefinition[] = [];
  const hosts = new Map<string, HostNode>();
  for (const n of g.nodes) if (n.kind === 'host') hosts.set(n.id, n);
  const segmentIds = new Set(g.nodes.filter((n) => n.kind === 'segment').map((n) => n.id));

  for (const n of g.nodes) {
    switch (n.kind) {
      case 'kali':
        els.push({
          group: 'nodes',
          data: { id: n.id, kind: 'kali', label: [displaySafe(n.label, 20), ...n.addresses.map((a) => displaySafe(a, 40))].join('\n') },
          classes: 'kali',
        });
        break;
      case 'segment':
        els.push({ group: 'nodes', data: { id: n.id, kind: 'segment', label: displaySafe(n.label, 40) }, classes: 'segment' });
        break;
      case 'host': {
        const sat = showSatellites(n, opts);
        const classes = [
          'host', `p${n.progress}`, `access-${n.access}`, `work-${n.work}`,
          n.claim_state === 'candidate' ? 'fog' : '', n.conflicts > 0 ? 'conflict' : '', n.ai ? 'ai' : '',
          opts.fresh.has(n.id) ? 'fresh' : '', n.on_thread ? 'onthread' : '',
        ];
        els.push({
          group: 'nodes',
          data: {
            id: n.id, kind: 'host', label: hostLabel(n, !sat),
            ...(n.segment && segmentIds.has(n.segment) ? { parent: n.segment } : {}),
          },
          classes: classes.filter(Boolean).join(' '),
        });
        break;
      }
      case 'service': {
        const h = hosts.get(n.host);
        if (!h || !showSatellites(h, opts)) break;
        const classes = ['service', `work-${n.work}`, n.claim_state === 'candidate' ? 'fog' : '', n.conflicts ? 'conflict' : '', opts.fresh.has(n.id) ? 'fresh' : ''];
        els.push({
          group: 'nodes',
          data: { id: n.id, kind: 'service', host: n.host, label: serviceLabel(n), ...(h.segment && segmentIds.has(h.segment) ? { parent: h.segment } : {}) },
          classes: classes.filter(Boolean).join(' '),
        });
        els.push({ group: 'edges', data: { id: `svc-edge:${n.id}`, source: n.host, target: n.id, kind: 'svc' }, classes: 'svc' });
        break;
      }
    }
  }

  for (const e of g.edges) {
    if (e.kind === 'thread') {
      els.push({
        group: 'edges',
        data: { id: e.id, source: e.source, target: e.target, kind: 'thread', label: `${e.seq} ${t(`keystep.${e.step}`)}`, fact: e.evidence?.fact_id ?? null },
        classes: 'thread',
      });
    } else {
      els.push({ group: 'edges', data: { id: e.id, source: e.source, target: e.target, kind: 'reach' }, classes: 'reach' });
    }
  }

  const oosTotal = g.oos.out + g.oos.excluded + g.oos.unknown;
  if (opts.layers.includes('oos') && oosTotal > 0) {
    const lines = [t('map.oos', { n: oosTotal })];
    if (g.oos.excluded) lines.push(t('map.oosExcluded', { n: g.oos.excluded }));
    els.push({ group: 'nodes', data: { id: OOS_ID, kind: 'oos', label: lines.join('\n') }, classes: 'oos', locked: false });
  }
  return els;
}
