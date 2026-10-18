/**
 * Formular eines Findings (Screen 8, E113, web-api.md 18.5). Besitzer: ui-verlauf.
 *
 * Reine Hilfen: Formular aus einem Finding, Prüfung wie der Server (Titel 1 bis 200 Zeichen ohne
 * Zeilenumbruch, Texte bis 20 000 Zeichen, höchstens 50 Betroffene, ATT&CK und CVE je höchstens 20
 * mit fester Form, «final» nur mit Schwere), und die Entscheide fürs Speichern: neu mit
 * `d.finding.create` (Belege und «angelegt aus» vorgefüllt aus der Belegansicht), sonst nur die
 * geänderten Felder mit `d.finding.update` und Belege mit `d.finding.evidence.add|remove`, alles in
 * einer Anfrage (alle oder keiner). Die Schwere setzt nur der Mensch; eine gesetzte Schwere lässt
 * sich ändern, aber nicht entfernen (web-api.md 18.12).
 */
import type { DecisionInput, EvidenceRefIn, FindingDetail, FindingStatus, Severity } from '../api/types';
import type { MessageKey } from '../i18n';

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const TITLE_MAX = 200;
export const TEXT_MAX = 20000;
export const AFFECTED_MAX = 50;
export const IDS_MAX = 20;
export const ATTACK_RE = /^T\d{4}(\.\d{3})?$/;
export const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

export interface RefEntry {
  id: string;
  supported: boolean;
}

export interface AffectedEntry {
  subject: string;
  label: string;
  ctrl: boolean;
}

export interface NewEvidence {
  ref: EvidenceRefIn;
  label: string;
}

export interface FindingForm {
  title: string;
  severity: Severity | null;
  status: FindingStatus;
  affected: AffectedEntry[];
  description: string;
  remediation: string;
  attack: RefEntry[];
  cves: RefEntry[];
  evidenceAdd: NewEvidence[];
  evidenceRemove: string[];
}

export function emptyForm(): FindingForm {
  return {
    title: '',
    severity: null,
    status: 'draft',
    affected: [],
    description: '',
    remediation: '',
    attack: [],
    cves: [],
    evidenceAdd: [],
    evidenceRemove: [],
  };
}

export function formFrom(d: FindingDetail): FindingForm {
  return {
    title: d.title,
    severity: d.severity,
    status: d.status,
    affected: d.affected.map((a) => ({ subject: a.subject, label: a.label, ctrl: a.ctrl })),
    description: d.description,
    remediation: d.remediation,
    attack: d.attack.map((a) => ({ id: a.id, supported: a.supported })),
    cves: d.cves.map((c) => ({ id: c.id, supported: c.supported })),
    evidenceAdd: [],
    evidenceRemove: [],
  };
}

/** Normalisiert eine eingegebene ID (Gross, ohne Leerraum). */
export function normId(raw: string): string {
  return raw.trim().toUpperCase();
}

export function checkId(kind: 'attack' | 'cve', raw: string, list: RefEntry[]): MessageKey | null {
  const id = normId(raw);
  if (!(kind === 'attack' ? ATTACK_RE : CVE_RE).test(id)) return kind === 'attack' ? 'fd.err.attack' : 'fd.err.cve';
  if (list.some((x) => x.id === id)) return 'fd.err.dupe';
  if (list.length >= IDS_MAX) return 'fd.err.tooMany';
  return null;
}

export type FormErrors = Partial<Record<'title' | 'status' | 'description' | 'remediation' | 'affected', MessageKey>>;

export function validate(f: FindingForm): FormErrors {
  const e: FormErrors = {};
  const title = f.title.trim();
  if (!title) e.title = 'fd.err.title';
  else if ([...title].length > TITLE_MAX) e.title = 'fd.err.titleLong';
  if (f.status === 'final' && f.severity === null) e.status = 'fd.err.finalNeedsSeverity';
  if (f.description.length > TEXT_MAX) e.description = 'fd.err.textLong';
  if (f.remediation.length > TEXT_MAX) e.remediation = 'fd.err.textLong';
  if (f.affected.length > AFFECTED_MAX) e.affected = 'fd.f.affectedMax';
  return e;
}

/**
 * Titel ohne Zeilenumbrüche (das Feld ist einzeilig; eingefügter Text wird geglättet) und ohne
 * Steuer-, Format- und nicht zugewiesene Zeichen, die der Server ablehnt (Korrektur SEC-FIND-1).
 */
export function cleanTitle(s: string): string {
  return s.replace(/[\r\n\u0085\u2028\u2029]+/g, ' ').replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}]/gu, '');
}

export { hasVisibleMarkers } from '../safe/displaySafe';

function sameRefs(a: RefEntry[], b: RefEntry[]): boolean {
  return a.length === b.length && a.every((x, i) => x.id === b[i]?.id && x.supported === b[i]?.supported);
}

function refsIn(list: RefEntry[]): { id: string; supported: boolean }[] {
  return list.map((x) => ({ id: x.id, supported: x.supported }));
}

function sameAffected(a: AffectedEntry[], b: AffectedEntry[]): boolean {
  return a.length === b.length && a.every((x, i) => x.subject === b[i]?.subject);
}

/** Geänderte Felder gegenüber dem gespeicherten Stand (für d.finding.update). */
export function changedFields(f: FindingForm, base: FindingDetail): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const title = cleanTitle(f.title).trim();
  if (title !== base.title) out.title = title;
  if (f.severity !== null && f.severity !== base.severity) out.severity = f.severity;
  if (f.status !== base.status) out.status = f.status;
  if (!sameAffected(f.affected, base.affected)) out.affected = f.affected.map((a) => a.subject);
  if (f.description !== base.description) out.description = f.description;
  if (f.remediation !== base.remediation) out.remediation = f.remediation;
  if (!sameRefs(f.attack, base.attack)) out.attack = refsIn(f.attack);
  if (!sameRefs(f.cves, base.cves)) out.cves = refsIn(f.cves);
  return out;
}

export function isDirty(f: FindingForm, base: FindingDetail | null): boolean {
  if (!base) return f.title.trim() !== '' || f.evidenceAdd.length > 0;
  return Object.keys(changedFields(f, base)).length > 0 || f.evidenceAdd.length > 0 || f.evidenceRemove.length > 0;
}

function evidencePayload(ref: EvidenceRefIn): Record<string, unknown> {
  const p: Record<string, unknown> = {};
  if (ref.claim_key) p.claim_key = ref.claim_key;
  if (ref.unit_id) p.unit_id = ref.unit_id;
  if (ref.lines) p.lines = [ref.lines[0], ref.lines[1]];
  return p;
}

/** Entscheide fürs Speichern; leer, wenn sich nichts geändert hat. */
export function buildDecisions(f: FindingForm, base: FindingDetail | null, createdFrom: EvidenceRefIn | null): DecisionInput[] {
  if (!base) {
    const p: Record<string, unknown> = { title: cleanTitle(f.title).trim(), status: f.status };
    if (f.severity !== null) p.severity = f.severity;
    if (f.affected.length) p.affected = f.affected.map((a) => a.subject);
    if (f.description) p.description = f.description;
    if (f.remediation) p.remediation = f.remediation;
    if (f.attack.length) p.attack = refsIn(f.attack);
    if (f.cves.length) p.cves = refsIn(f.cves);
    if (f.evidenceAdd.length) p.evidence = f.evidenceAdd.map((e) => evidencePayload(e.ref));
    if (createdFrom && (createdFrom.claim_key || createdFrom.unit_id)) p.created_from = evidencePayload(createdFrom);
    return [{ kind: 'd.finding.create', payload: p }];
  }
  const out: DecisionInput[] = [];
  const fields = changedFields(f, base);
  if (Object.keys(fields).length) out.push({ kind: 'd.finding.update', payload: { finding_id: base.finding_id, ...fields } });
  for (const e of f.evidenceAdd) out.push({ kind: 'd.finding.evidence.add', payload: { finding_id: base.finding_id, ...evidencePayload(e.ref) } });
  for (const id of f.evidenceRemove) out.push({ kind: 'd.finding.evidence.remove', payload: { finding_id: base.finding_id, evidence_id: id } });
  return out;
}

/** Text eines Belegs für die Liste (aus der Belegansicht vorgefüllt). */
export function sameRef(a: EvidenceRefIn, b: EvidenceRefIn): boolean {
  return (a.claim_key ?? null) === (b.claim_key ?? null) && (a.unit_id ?? null) === (b.unit_id ?? null) && (a.lines ?? []).join('-') === (b.lines ?? []).join('-');
}
