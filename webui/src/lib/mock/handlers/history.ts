/**
 * Mock-Entscheide für Zeitachse, Terminals und Findings (Besitzer: ui-verlauf):
 * d.unit.distrust, d.revoke, d.terminal.label, d.finding.*. Gerüst aus Phase 1.
 */
import type { DecisionInput, DecisionResult, FindingDetail } from '../../api/types';
import type { MockState } from '../state';

export function applyHistoryDecision(s: MockState, d: DecisionInput, id: string): DecisionResult | null {
  const p = d.payload as Record<string, unknown>;
  const result: DecisionResult = { decision_id: id, seq: null, client_ref: d.client_ref ?? null, effect: null };
  switch (d.kind) {
    case 'd.unit.distrust':
      return { ...result, effect: { rejected: 18, weakened: 0 } };
    case 'd.revoke':
    case 'd.terminal.label':
      return result;
    case 'd.finding.create': {
      const f: FindingDetail = {
        finding_id: id, ordinal: s.findings.length + 1, title: String(p.title ?? ''), ctrl: false,
        severity: (p.severity as FindingDetail['severity']) ?? null, status: (p.status as FindingDetail['status']) ?? 'draft',
        affected: [], evidence_count: 0, warnings: ['no_evidence'], created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
        description: String(p.description ?? ''), remediation: String(p.remediation ?? ''), attack: [], cves: [], evidence: [],
        created_from: null, history: [{ decision_id: id, kind: d.kind, ts: new Date().toISOString() }],
      };
      s.findings = [...s.findings, f];
      return result;
    }
    case 'd.finding.update':
    case 'd.finding.evidence.add':
    case 'd.finding.evidence.remove':
      return result;
    case 'd.finding.delete':
      s.findings = s.findings.filter((f) => f.finding_id !== p.finding_id);
      return result;
    default:
      return null;
  }
}
