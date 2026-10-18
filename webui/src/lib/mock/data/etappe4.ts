/**
 * Beispieldaten Etappe 4 (KI, Export, Screenshots, E119, E120) für den Mock. Besitzer: ui.
 *
 * - KI: Status je Szenario (aus, eingerichtet, Budgetwarnung, Budget voll, Anbieter weg, Ablehnung,
 *   Injection-Verdacht) und ein KI-Denkanstoss wie D3 im Design (Kriterien als Modelltext).
 * - Export: frühere Exporte mit Warnungen, Phasen der Vorlagen cys und htb.
 * - Screenshots: zwei kanonische PNGs (nur IHDR, IDAT, IEND), im Mock als Bytes.
 * - E119: «Versionen recherchieren» als ein Denkanstoss pro Host mit Liste pro Dienst.
 */
import type { AiJob, AiStatus, ExportEntry, ExportTemplate, Screenshot, Suggestion, SuggestionItemView } from '../../api/types';
import { at, hex64, hostId, PID, serviceId, T1, T2 } from './base';
import { HOSTILE_IMG, INJECTION_TITLE } from './hostile';
import { tpl } from './map';

const IP101 = '192.168.56.101';

export const MOCK_MODEL = 'test-model';

export type AiMode = 'off' | 'ready' | 'warn' | 'over' | 'gone' | 'refuse' | 'inject' | 'run' | 'notallowed';

export function aiStatus(mode: AiMode, job: AiJob | null): AiStatus {
  const pct = mode === 'warn' ? 86 : mode === 'over' ? 100 : 12;
  const level = mode === 'warn' ? 'warn' : mode === 'over' ? 'over' : 'ok';
  const budget = { month: '2026-10', limit_usd: 10, used_usd: pct / 10, pct, level } as const;
  if (mode === 'off') return { provider: 'off', model: null, ready: false, reason: 'off', reason_text: 'KI ist aus. Einrichten im Terminal: ariadne ai setup', budget, job: null };
  if (mode === 'notallowed') {
    return { provider: 'cloud', model: MOCK_MODEL, ready: false, reason: 'cloud_not_allowed', reason_text: 'Cloud-KI für dieses Projekt nicht freigegeben. Im Terminal: ariadne ai allow-cloud', budget, job: null };
  }
  const busy = job !== null && (job.status === 'queued' || job.status === 'running');
  return {
    provider: mode === 'gone' ? 'local' : 'cloud',
    model: MOCK_MODEL,
    ready: !busy,
    reason: busy ? 'busy' : null,
    reason_text: busy ? 'Ein Auftrag läuft schon.' : null,
    budget,
    job,
  };
}

let jobCounter = 0xa10;
export function newJob(mode: AiMode): AiJob {
  jobCounter++;
  return {
    job_id: `ai-${jobCounter.toString(16).padStart(12, '0')}`,
    status: 'queued', step: 'lagebild', message: 'Lagebild wird erstellt',
    started_at: new Date().toISOString(), ended_at: null,
    provider: mode === 'gone' ? 'local' : 'cloud', model: MOCK_MODEL,
    tokens_in: null, tokens_out: null, tokens_estimate: 4180, masked: 3, cost_usd: null,
    budget_level: mode === 'warn' ? 'warn' : mode === 'over' ? 'over' : 'ok',
    created: 0, dropped: 0, injection_suspect: 0, refusal: null, error: null,
  };
}

/** Endzustand eines Auftrags je Szenario. */
export function finishJob(job: AiJob, mode: AiMode): AiJob {
  const ended_at = new Date().toISOString();
  const base = { ...job, ended_at, step: 'fertig' as const, tokens_in: 4212, tokens_out: 388, cost_usd: 0.018 };
  if (mode === 'gone') return { ...base, status: 'failed', message: 'Ollama auf 127.0.0.1 nicht erreichbar: Verbindung abgelehnt', tokens_in: null, tokens_out: null, cost_usd: null, error: 'unreachable' };
  if (mode === 'refuse') {
    return { ...base, status: 'refused', message: 'Das Modell hat die Anfrage abgelehnt.', refusal: { category: 'policy', text: 'I can’t help with planning attacks against systems.\n<b>Kein HTML</b> ‮' } };
  }
  if (mode === 'inject') return { ...base, status: 'done', message: 'Fertig: 1 Denkanstoss, 2 verworfen', created: 1, dropped: 2, injection_suspect: 1 };
  return { ...base, status: 'done', message: 'Fertig: 1 Denkanstoss', created: 1 };
}

export function aiSuggestion(jobId: string, inject = false): Suggestion {
  const title = inject ? INJECTION_TITLE : 'Hypothese: Samba 3.0.20 auf 192.168.56.101 ist für usermap_script anfällig';
  return {
    suggestion_key: `ai:${hex64(`ai-${jobId}`).slice(0, 24)}`,
    origin: 'ai', rule_id: 'KI', goal_id: 'PZ-VULN-RECHERCHE', kind: 'hypothesis',
    title, ctrl: false,
    title_parts: inject ? [{ text: title, target: true }] : [{ text: 'Hypothese: Samba 3.0.20 auf ', target: false }, { text: IP101, target: true }, { text: ' ist für usermap_script anfällig', target: false }],
    host_id: hostId(IP101), service_id: serviceId(IP101, 445), host_label: IP101,
    reason: 'Samba-Version aus nmap -sV liegt im bekannten anfälligen Bereich.', ctrl_reason: false,
    evidence: [{ claim_key: hex64('smb-445-version'), unit_id: `${T1}@18432`, lines: [14, 14], label: 'nmap -sV · Zeile 14', ts: at('14:02:11.204') }],
    stages: { question: 'Welche Samba-Version läuft genau?', direction: 'Version mit einem zweiten Werkzeug bestätigen, dann Exploit-Datenbanken prüfen.' },
    templates: [
      tpl('smbclient-list', 'smbclient', 'smbclient', [['smbclient -N -L //', false], [IP101, true]], [{ slot: 'host.ip', type: 'ip', label: 'IP', value: IP101, ctrl: false, target: true, safe: true }]),
    ],
    state: 'open', decision_id: null, basis: `ai-${jobId}`,
    flags: inject ? ['ai', 'injection_suspect'] : ['ai'],
    ts: new Date().toISOString(),
    ai: {
      model: MOCK_MODEL,
      confirmed_if: inject ? HOSTILE_IMG : 'smbclient meldet «Samba 3.0.20-Debian» oder ein Skript bestätigt die Version.',
      refuted_if: 'Die Version ist 3.0.25 oder neuer, oder der Dienst ist nicht Samba.',
      job_id: jobId,
      created_at: new Date().toISOString(),
    },
    items: [],
  };
}

/** E119: ein Denkanstoss «Versionen recherchieren» für den ganzen Host. */
export function versionsSuggestion(): Suggestion {
  const rows: [number, string, string][] = [
    [21, 'vsftpd', '2.3.4'],
    [22, 'OpenSSH', '4.7p1'],
    [53, 'ISC BIND', '9.4.2'],
    [80, 'Apache httpd', '2.2.8'],
    [139, 'Samba smbd', '3.0.20'],
    [3306, 'MySQL', '5.0.51a'],
    [5432, 'PostgreSQL', '8.3.0'],
    [8180, 'Apache Tomcat', '5.5'],
  ];
  const items: SuggestionItemView[] = rows.map(([port, product, version]) => ({
    service_id: serviceId(IP101, port), port, proto: 'tcp',
    label: `${product} ${version} · ${port}/tcp`, ctrl: false,
    label_parts: [{ text: `${product} ${version}`, target: true }, { text: ` · ${port}/tcp`, target: false }],
    template: tpl(`searchsploit-${port}`, 'searchsploit', 'searchsploit', [['searchsploit ', false], [`${product} ${version}`, true]], [
      { slot: 'service.product', type: 'word', label: 'Produkt', value: product, ctrl: false, target: true, safe: true },
      { slot: 'service.version', type: 'word', label: 'Version', value: version, ctrl: false, target: true, safe: true },
    ]),
  }));
  return {
    suggestion_key: 'sg:9d3c2b1a0f8e7d6c5b4a3928', origin: 'rule', rule_id: 'R-VERSION-RECHERCHE', goal_id: 'PZ-VULN-RECHERCHE', kind: 'goal',
    title: `Versionen recherchieren: ${IP101} (${items.length} Dienste)`, ctrl: false,
    title_parts: [{ text: 'Versionen recherchieren: ', target: false }, { text: IP101, target: true }, { text: ` (${items.length} Dienste)`, target: false }],
    host_id: hostId(IP101), service_id: null, host_label: IP101,
    reason: `Produkt und Version für ${items.length} Dienste bekannt`, ctrl_reason: false,
    evidence: [{ claim_key: hex64('ftp-21-version'), unit_id: `${T1}@18432`, lines: [6, 6], label: 'nmap -sV · Zeile 6', ts: at('14:02:11.204') }],
    stages: { question: 'Gibt es für diese Versionen bekannte Schwachstellen?', direction: 'Exploit-Datenbanken pro Dienst nach Produkt und Version durchsuchen.' },
    templates: items.slice(0, 4).map((i) => i.template),
    state: 'open', decision_id: null, basis: 'b1e4c7d0a3f69258', flags: [], ts: at('14:02:11.204'), ai: null,
    items,
  };
}

export function exportsList(): ExportEntry[] {
  return [
    {
      export_id: '20261008T143012Z-cys', template: 'cys', created_at: at('16:30:12.000'), path: 'exports/20261008T143012Z-cys', files: 23, klartext: false,
      warnings: ['sync_folder'], chain: { seq: 4182, hash: hex64('chain-4182') },
    },
  ];
}

export function newExport(template: ExportTemplate, n: number): ExportEntry {
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  return {
    export_id: `${stamp}-${template}${n > 1 ? `-${n}` : ''}`, template, created_at: new Date().toISOString(), path: `exports/${stamp}-${template}`,
    files: 24, klartext: false, warnings: ['generic_secret'], chain: { seq: 4200 + n, hash: hex64(`chain-${n}`) },
  };
}

export const PHASES: Record<ExportTemplate, { key: string; label: string }[]> = {
  cys: [
    { key: 'recon', label: 'Reconnaissance' },
    { key: 'scanning', label: 'Scanning und Enumeration' },
    { key: 'exploitation', label: 'Exploitation' },
    { key: 'post', label: 'Post-Exploitation' },
    { key: 'reporting', label: 'Reporting' },
    { key: 'omit', label: 'Nicht im Writeup' },
  ],
  htb: [
    { key: 'enumeration', label: 'Enumeration' },
    { key: 'foothold', label: 'Foothold' },
    { key: 'privesc', label: 'Privilege Escalation' },
    { key: 'pivot', label: 'Pivot' },
    { key: 'loot', label: 'Loot' },
    { key: 'lessons', label: 'Lessons Learned' },
    { key: 'omit', label: 'Nicht im Writeup' },
  ],
};

/** Phase nach dem Werkzeug wie die Regeln des Servers (vereinfacht). */
export function rulePhase(template: ExportTemplate, text: string): string | null {
  const tool = text.trim().split(/\s+/)[0] ?? '';
  if (/^(nmap|masscan|gobuster|nikto|enum4linux|smbclient|searchsploit)$/.test(tool)) return template === 'cys' ? 'scanning' : 'enumeration';
  if (/^(msfconsole|nc|ncat|ftp|ssh|hydra)$/.test(tool)) return template === 'cys' ? 'exploitation' : 'foothold';
  if (/^(sudo|su|linpeas\.sh)$/.test(tool)) return template === 'cys' ? 'post' : 'privesc';
  return null;
}

const PNG_A = 'iVBORw0KGgoAAAANSUhEUgAAAUAAAADICAIAAAAWZq/8AAACgUlEQVR42u3dsQnCABRF0YwhFg4iVpnA2kneiL+xsXYYC8sQiGIg3xw4nZ3mNi98HM6XEWhq8BWAgAEBAwIGAY/P23XKVwYCBgQMAhYwCBiwQgMCBgEDAgZWCvhwPAFNCRgEDGwt4FRgSjYCRsAIGAELWMAIWMAIGCs0IGAQMCBgQMDABwHX/QH/QcAgYAGDgAUMAhYwArZCAwIGBAwCBgQMWKGtoyBgASNgBIyAETACFjACBgQMCBgQMAgYsEKDNwUCBgELGAQMAhYwCNgKDVZoQMCAgAEBw24DToU3DwoCFjAIWMAgYAEjYAGDFRoQMAgYEDAgYODLgB2C4vJWwCBgASNgBIyABQwCtkIDAgYBAwIGBAxYoS26CBgBI2AEjIARMAIWMFZoQMCAgEHAgIABKzR4FyBgEDAgYBCwgEHAVmjwGgkQMCBgEDDQPeBUevFzImABg4AFDAIWMAgYrNCAgAEBAwIGAQObC9gxJ/4vQsAgYAEjYASMgAUMArZCAwIGAQMCBgQMWKGxFQsYASNgBIyAETACRsBWaEDAgIBBwICAASs0WM4FjIAFDAIWMAhYwCBgKzQIGBAwIGAQMNA94FRYwmOEgAUMAhYwAhawgBGwgMEKDQgYBAwIGBAwCHj2MyemuCUWMAhYwCBgAYOAQcBWaEDAIGBAwICAASu07RQBI2AEjIARMAJGwALGCg0IGBAwCBgQMGCFxjaOgBGwgEHAAkbACBgBY4UGAQMCBgQMAga6B5zKfngUELCAQcACBgELGAELGKzQgIABAYOAAQEDqwTstBWXxgIGAQsYAStWwAhYwCBgKzQgYBAwIGBAwIAVGmuwgEHAAkbA/NwL5xuwpPcQLkgAAAAASUVORK5CYII=';
const PNG_B = 'iVBORw0KGgoAAAANSUhEUgAAAUAAAADICAIAAAAWZq/8AAAC+0lEQVR42u3dQW3DUBBAweCKeiqCnIupSIwkIALBh0Iog6hJJVtv/0hDYHf95IuVXK4fn0DUxQpAwICAAQGDgAEBAwIGBAwCBgQMCBgEDAgYODTgff8BogQMAgYEDAgYBAwIGBAwIGAQMCBgQMAgYEDAgIABAYOAAQEDAgYEDAIGBAwIGAQMCBgQMCBgEDAgYEDAgIBBwICAAQGDgAEBAwIGBAwCBgQMCBgE3J/hvt2ec2YEnExXxgg4n66MEfCEejWMgNv1ahgBt+vVMAJu16thBCxgEPBJ9WoYAQsYBHxSvRpGwAIGAQsYBCxgBCxgELCAQcACBgELGAELGAQsYBCwgBGwb6FBwAIGAR/asPMjYAGDgA9v2O0RcLXhkbf8+n78nUdfwNWGV+5WyQJuN6xbJQs4mbG3roYFnMxYujIWMEvUq2EBE05XxgJmQr0aFjDtejUsYNr1aljAtOvVsIARMAJWr4YRsHo1LGAEjIDp1KthAdOuV8MCRsAIWMACRsDq1bCAETACFrCAEbB6NSxgBCxgASNgBCxgASNgAQtYwAhYwAJGwAhYwAIWMAIWsIARMAIWsIARsIAFLGAELGABI2AELGABI2ANq1fACBgBI2AErGH1ChgBC1jACBgBa1i9CFjD6hUwAhawgEk37CgCptqwcwgYASNgDasXAWtYvQJmeMOWL2CqDVu7gElmbNUCptrwpHXdt9tzAmZOxkulOyNjAWt4Wr0vpVvPWMCrlzxsG2/XG21YwIuWPHID/6y32LCAUW+4YQGj3nDDAkbAAoZB9YYaFjACFjDMqrfSsIARsIBBwAIGAQsYAQsYBCxgELCAQcACRsACBgELGAQsYDTsW2gQsIBhSMOVwQWMgAUMgxoOTS1gNOxXKWFEw7l5BYyG/TMDlDPujilgls64PqCAQcCAgAEBg4ABAQMCBgQMAgYEDAgYBAwIGBAwIGAQMCBgQMCAgEHAgIABAYOAAQEDAgYEDAIGBAwIGBAwCBgQMCBgEDDQ8AsuNsuOj9yD0gAAAABJRU5ErkJggg==';

export function pngBytes(which: 'a' | 'b'): Uint8Array<ArrayBuffer> {
  const bin = atob(which === 'a' ? PNG_A : PNG_B);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const SHOT_BLOBS: Record<string, 'a' | 'b'> = {
  '0199a3c2-b10b-7000-8000-00000000000a': 'a',
  '0199a3c2-b10b-7000-8000-00000000000b': 'b',
};

export function screenshots(): Screenshot[] {
  const mk = (id: string, blob: string, ts: string, extra: Partial<Screenshot>): Screenshot => ({
    id, seq: 0, ts, blob_id: blob, url: `/api/v1/p/${PID}/blobs/${blob}`, mime: 'image/png', mode: 'window', trigger: 'hotkey',
    width: 320, height: 200, sha256: hex64(blob), dhash: hex64(blob).slice(0, 16), window_title: null, wm_class: null,
    terminal_id: null, stream_off: null, host: null, note: null, ...extra,
  });
  return [
    mk('0199a3c2-5c07-7000-8000-000000000b02', '0199a3c2-b10b-7000-8000-00000000000b', at('16:41:07.512'), {
      seq: 5121, mode: 'monitor', trigger: 'webui', window_title: 'Mozilla Firefox', wm_class: 'firefox', terminal_id: T2, host: IP101, note: 'Login-Seite von Tomcat',
    }),
    mk('0199a3c2-5c07-7000-8000-000000000b01', '0199a3c2-b10b-7000-8000-00000000000a', at('15:12:44.031'), {
      seq: 4410, trigger: 'hotkey', window_title: `root@kali: ~ — ${HOSTILE_IMG}`, wm_class: 'xfce4-terminal', terminal_id: T1, stream_off: 18432, host: IP101,
    }),
  ];
}
