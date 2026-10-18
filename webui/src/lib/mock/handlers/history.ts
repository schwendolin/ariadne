/**
 * Mock-Entscheide für Zeitachse, Terminals und Findings (Besitzer: ui-verlauf):
 * d.unit.distrust, d.revoke (auf «Rückgängig pro Befehl» und Findings), d.terminal.label,
 * d.finding.create|update|evidence.add|evidence.remove|delete.
 *
 * Verhalten wie der Daemon (web-api.md 12, 18.5, 18.12): unbekannter Befehl 404, Befehl ohne Werte
 * 409, Finding gelöscht oder unbekannt 409, «final» ohne Schwere 422, gleicher Beleg zweimal 409,
 * Änderungen erscheinen in der Zeitachse als Entscheid. Rückgabe `decision_id: null` heisst 409.
 */
import { ApiError } from '../../api/client';
import type { DecisionInput, DecisionResult, EvidenceRefIn, FindingDetail, FindingEvidence, Severity, TimelineItem } from '../../api/types';
import { nsOf, TERM } from '../data/base';
import { evidenceLabel, unitView } from '../data/history';
import type { MockState } from '../state';

type CommandItem = Extract<TimelineItem, { type: 'command' }>;

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const ATTACK_RE = /^T\d{4}(\.\d{3})?$/;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

/** gelöschte Findings (für d.revoke) und vergebene Nummern je Mock-Zustand */
const deleted = new WeakMap<MockState, Map<string, FindingDetail>>();
const ordinals = new WeakMap<MockState, number>();
const revoked = new WeakMap<MockState, Set<string>>();

function invalid(): ApiError {
  return new ApiError('validation', 422, 'validation');
}

function notFound(): ApiError {
  return new ApiError('not_found', 404, 'not_found');
}

function nowIso(): string {
  return new Date().toISOString().replace(/\.(\d{3})Z$/, '.$1000Z');
}

function hash16(s: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (const ch of s) {
    h1 = Math.imul(h1 ^ ch.charCodeAt(0), 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ ch.charCodeAt(0), 0x811c9dc5) >>> 0;
  }
  return (h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0')).slice(0, 16);
}

function decisionItem(id: string, kind: string, summary: string, extra: Partial<Extract<TimelineItem, { type: 'decision' }>> = {}): TimelineItem {
  const ts = nowIso();
  return {
    id, ts, ts_ns: nsOf(ts), terminal_id: null, context_label: null, host_id: null, ctrl: false, terminal: null,
    type: 'decision', decision_id: id, kind, summary, detail: null, reason: null, ref: null, effect: null, ...extra,
  };
}

function findCommand(s: MockState, ref: string): CommandItem | null {
  for (const it of s.timeline) if (it.type === 'command' && (it.cmd.cmd_id === ref || it.cmd.cmd_ref === ref)) return it;
  return null;
}

function nextOrdinal(s: MockState): number {
  const used = Math.max(ordinals.get(s) ?? 0, ...s.findings.map((f) => f.ordinal));
  ordinals.set(s, used + 1);
  return used + 1;
}

function refs(list: unknown, re: RegExp): { id: string; supported: boolean; hypothesis: boolean }[] {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list) || list.length > 20) throw invalid();
  return list.map((x) => {
    const id = typeof x === 'object' && x && typeof (x as { id?: unknown }).id === 'string' ? (x as { id: string }).id : '';
    if (!re.test(id)) throw invalid();
    return { id, supported: (x as { supported?: unknown }).supported === true, hypothesis: true };
  });
}

function checkRef(p: Record<string, unknown>): EvidenceRefIn {
  const ref: EvidenceRefIn = {};
  if (typeof p.claim_key === 'string') ref.claim_key = p.claim_key;
  if (typeof p.unit_id === 'string') ref.unit_id = p.unit_id;
  if (Array.isArray(p.lines)) {
    const [a, b] = p.lines as unknown[];
    if (typeof a !== 'number' || typeof b !== 'number' || a < 0 || b < a) throw invalid();
    ref.lines = [a, b];
  }
  if (!ref.claim_key && !ref.unit_id) throw invalid();
  return ref;
}

function evidenceOf(ref: EvidenceRefIn, decisionId: string): FindingEvidence {
  const key = `${ref.claim_key ?? ''}|${ref.unit_id ?? ''}|${(ref.lines ?? []).join('-')}`;
  const label = evidenceLabel(ref);
  const u = ref.unit_id ? unitView(ref.unit_id) : null;
  return {
    evidence_id: `ev:${hash16(key)}`,
    ref: { claim_key: ref.claim_key ?? null, unit_id: ref.unit_id ?? null, lines: ref.lines ?? null, label },
    label,
    ctrl: false,
    terminal: u?.terminal_id ? (TERM[u.terminal_id] ?? null) : null,
    ts: u?.ts ?? null,
    state: 'ok',
    added_at: nowIso(),
    decision_id: decisionId,
  };
}

/** Warnungen und Hypothesen neu berechnen (wie die Projektion, 18.5). */
function recompute(f: FindingDetail, s: MockState): FindingDetail {
  const evidence = f.evidence.map((e) => {
    const cmd = e.ref.unit_id ? findCommand(s, unitView(e.ref.unit_id)?.cmd_id ?? '') : null;
    return { ...e, state: cmd?.distrusted ? ('distrusted' as const) : e.state === 'missing' ? ('missing' as const) : ('ok' as const) };
  });
  const ok = evidence.some((e) => e.state === 'ok');
  const warnings: FindingDetail['warnings'] = [];
  if (evidence.some((e) => e.state === 'distrusted')) warnings.push('evidence_distrusted');
  if (evidence.some((e) => e.state === 'missing')) warnings.push('evidence_missing');
  if (evidence.length === 0) warnings.push('no_evidence');
  if (f.severity === null) warnings.push('no_severity');
  const hyp = (x: { id: string; supported: boolean }) => ({ ...x, hypothesis: !(x.supported && ok) });
  return { ...f, evidence, evidence_count: evidence.length, warnings, attack: f.attack.map(hyp), cves: f.cves.map(hyp) };
}

function affected(list: unknown, s: MockState): FindingDetail['affected'] {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list) || list.length > 50) throw invalid();
  return list.map((x) => {
    if (typeof x !== 'string') throw invalid();
    const svc = s.services.find((v) => v.service_id === x);
    if (svc) return { subject: x, label: `${svc.host_label}:${svc.port}${svc.name ? ` ${svc.name}` : ''}`, ctrl: svc.ctrl };
    const host = s.graph.nodes.find((n) => n.kind === 'host' && n.id === x);
    if (host && host.kind === 'host') return { subject: x, label: host.label, ctrl: host.ctrl };
    if (s.findings.some((f) => f.affected.some((a) => a.subject === x))) return { subject: x, label: x.replace(/^name:/, ''), ctrl: false };
    throw new ApiError('conflict', 409, 'conflict');
  });
}

function text(v: unknown, max: number): string {
  if (v === undefined || v === null) return '';
  if (typeof v !== 'string' || v.length > max) throw invalid();
  return v;
}

function title(v: unknown): string {
  if (typeof v !== 'string') throw invalid();
  const t = v.trim();
  if (!t || [...t].length > 200 || /[\r\n]/.test(t)) throw invalid();
  return t;
}

function severity(v: unknown): Severity | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== 'string' || !SEVERITIES.has(v)) throw invalid();
  return v as Severity;
}

function replaceFinding(s: MockState, f: FindingDetail): void {
  s.findings = s.findings.map((x) => (x.finding_id === f.finding_id ? recompute(f, s) : x));
}

export function applyHistoryDecision(s: MockState, d: DecisionInput, id: string): DecisionResult | null {
  const p = d.payload as Record<string, unknown>;
  const result: DecisionResult = { decision_id: id, seq: null, client_ref: d.client_ref ?? null, effect: null };
  const conflict: DecisionResult = { ...result, decision_id: null };
  switch (d.kind) {
    case 'd.unit.distrust': {
      if (typeof p.cmd_id !== 'string') throw invalid();
      const c = findCommand(s, p.cmd_id);
      if (!c) throw notFound();
      if (c.distrusted || (c.adopted === 0 && c.result.values === 0)) return conflict;
      const effect = { rejected: c.adopted || c.result.values, weakened: 0 };
      const reason = typeof p.reason === 'string' && p.reason ? p.reason : null;
      s.timeline = [
        decisionItem(id, 'd.unit.distrust', 'Rückgängig pro Befehl', { ref: c.cmd.cmd_ref, reason, effect }),
        ...s.timeline.map((x) => (x.id === c.id ? { ...c, adopted: 0, distrusted: { decision_id: id, ...effect } } : x)),
      ];
      s.findings = s.findings.map((f) => recompute(f, s));
      return { ...result, effect };
    }
    case 'd.revoke': {
      const target = typeof p.decision_id === 'string' ? p.decision_id : '';
      const c = s.timeline.find((x): x is CommandItem => x.type === 'command' && x.distrusted?.decision_id === target);
      if (c && c.distrusted) {
        const back = c.distrusted.rejected;
        s.timeline = [
          decisionItem(id, 'd.revoke', 'Rückgängig gemacht'),
          ...s.timeline.map((x) => (x.id === c.id ? { ...c, adopted: back, distrusted: null } : x)),
        ];
        s.findings = s.findings.map((f) => recompute(f, s));
        return result;
      }
      const gone = deleted.get(s)?.get(target);
      if (gone) {
        deleted.get(s)?.delete(target);
        s.findings = [...s.findings, gone].sort((a, b) => a.ordinal - b.ordinal);
        s.timeline = [decisionItem(id, 'd.revoke', 'Rückgängig gemacht'), ...s.timeline];
        return result;
      }
      // Andere Entscheide (etwa verwaiste aus «Als Nächstes») kennt der Mock nicht im Einzelnen:
      // ein einmaliges Widerrufen gilt, ein zweites ergibt 409 wie beim Daemon.
      if (!target || revoked.get(s)?.has(target)) return conflict;
      if (!revoked.has(s)) revoked.set(s, new Set());
      revoked.get(s)?.add(target);
      s.timeline = [decisionItem(id, 'd.revoke', 'Rückgängig gemacht'), ...s.timeline];
      return result;
    }
    case 'd.terminal.label': {
      const tid = typeof p.terminal_id === 'string' ? p.terminal_id : '';
      const label = typeof p.label === 'string' ? p.label.trim() : '';
      if (!label || [...label].length > 64) throw invalid();
      const term = s.terminals.find((x) => x.terminal_id === tid);
      if (!term) return conflict;
      s.terminals = s.terminals.map((x) => (x.terminal_id === tid ? { ...x, label } : x));
      s.timeline = [decisionItem(id, 'd.terminal.label', 'Terminal benannt', { terminal_id: tid, terminal: { terminal_id: tid, ordinal: term.ordinal, label } }), ...s.timeline];
      return result;
    }
    case 'd.finding.create': {
      const sev = severity(p.severity);
      const status = p.status === undefined ? 'draft' : p.status;
      if (status !== 'draft' && status !== 'final') throw invalid();
      if (status === 'final' && sev === null) throw invalid();
      const evidence = (Array.isArray(p.evidence) ? p.evidence : []).map((x) => evidenceOf(checkRef(x as Record<string, unknown>), id));
      const createdFrom = p.created_from ? checkRef(p.created_from as Record<string, unknown>) : null;
      const now = nowIso();
      // erst alles prüfen, dann die Nummer vergeben (ein abgelehntes Anlegen verbraucht keine)
      const fields = {
        title: title(p.title), affected: affected(p.affected, s), description: text(p.description, 20000), remediation: text(p.remediation, 20000),
        attack: refs(p.attack, ATTACK_RE), cves: refs(p.cves, CVE_RE),
      };
      const f: FindingDetail = {
        finding_id: id, ordinal: nextOrdinal(s), title: fields.title, ctrl: false, severity: sev, status,
        affected: fields.affected, evidence_count: evidence.length, warnings: [], created_at: now, updated_at: now,
        description: fields.description, remediation: fields.remediation,
        attack: fields.attack, cves: fields.cves, evidence,
        created_from: createdFrom ? { claim_key: createdFrom.claim_key ?? null, unit_id: createdFrom.unit_id ?? null, lines: createdFrom.lines ?? null, label: evidenceLabel(createdFrom) } : null,
        history: [{ decision_id: id, kind: d.kind, ts: now }],
      };
      s.findings = [...s.findings, recompute(f, s)];
      s.timeline = [decisionItem(id, d.kind, 'Finding angelegt', { detail: `F${f.ordinal} · ${f.title}` }), ...s.timeline];
      return result;
    }
    case 'd.finding.update': {
      const f = s.findings.find((x) => x.finding_id === p.finding_id);
      if (!f) return conflict;
      const next: FindingDetail = { ...f, updated_at: nowIso(), history: [...f.history, { decision_id: id, kind: d.kind, ts: nowIso() }] };
      if (p.title !== undefined && p.title !== null) next.title = title(p.title);
      if (p.severity !== undefined && p.severity !== null) next.severity = severity(p.severity);
      if (p.status !== undefined && p.status !== null) {
        if (p.status !== 'draft' && p.status !== 'final') throw invalid();
        next.status = p.status;
      }
      if (next.status === 'final' && next.severity === null) throw invalid();
      if (p.affected !== undefined && p.affected !== null) next.affected = affected(p.affected, s);
      if (p.description !== undefined && p.description !== null) next.description = text(p.description, 20000);
      if (p.remediation !== undefined && p.remediation !== null) next.remediation = text(p.remediation, 20000);
      if (p.attack !== undefined && p.attack !== null) next.attack = refs(p.attack, ATTACK_RE);
      if (p.cves !== undefined && p.cves !== null) next.cves = refs(p.cves, CVE_RE);
      replaceFinding(s, next);
      s.timeline = [decisionItem(id, d.kind, 'Finding geändert', { detail: `F${next.ordinal} · ${next.title}` }), ...s.timeline];
      return result;
    }
    case 'd.finding.evidence.add': {
      const f = s.findings.find((x) => x.finding_id === p.finding_id);
      if (!f) return conflict;
      const ev = evidenceOf(checkRef(p), id);
      if (f.evidence.some((e) => e.evidence_id === ev.evidence_id)) return conflict;
      replaceFinding(s, { ...f, evidence: [...f.evidence, ev], updated_at: nowIso(), history: [...f.history, { decision_id: id, kind: d.kind, ts: nowIso() }] });
      return result;
    }
    case 'd.finding.evidence.remove': {
      const f = s.findings.find((x) => x.finding_id === p.finding_id);
      if (!f || !f.evidence.some((e) => e.evidence_id === p.evidence_id)) return conflict;
      replaceFinding(s, {
        ...f,
        evidence: f.evidence.filter((e) => e.evidence_id !== p.evidence_id),
        updated_at: nowIso(),
        history: [...f.history, { decision_id: id, kind: d.kind, ts: nowIso() }],
      });
      return result;
    }
    case 'd.finding.delete': {
      const f = s.findings.find((x) => x.finding_id === p.finding_id);
      if (!f) return conflict;
      if (!deleted.has(s)) deleted.set(s, new Map());
      deleted.get(s)?.set(id, f);
      ordinals.set(s, Math.max(ordinals.get(s) ?? 0, ...s.findings.map((x) => x.ordinal)));
      s.findings = s.findings.filter((x) => x.finding_id !== f.finding_id);
      s.timeline = [decisionItem(id, d.kind, 'Finding gelöscht', { detail: `F${f.ordinal} · ${f.title}`, reason: typeof p.reason === 'string' ? p.reason : null }), ...s.timeline];
      return result;
    }
    default:
      return null;
  }
}
