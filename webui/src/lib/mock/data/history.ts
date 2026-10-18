/**
 * Mock-Daten, Teil Verlauf: Zeitachse (Anhang A.6), Eingaben, Einheiten mit Logzeilen, Belege,
 * Finding F1 (A.9), Warteliste (Screen 10). Form genau wie docs/web-api.md 10, 11, 13, 18.5.
 * Besitzer: ui-verlauf.
 */
import type {
  FactSources,
  FindingDetail,
  InputView,
  LinesPage,
  LogLine,
  PendingResponse,
  TimelineItem,
  UnitView,
} from '../../api/types';
import { at, hex64, hostId, KALI_IP, KALI_STAGE, nsOf, T1, T2, T3, TERM } from './base';
import { FAKE_CALLBACK } from './hostile';

const IP101 = '192.168.56.101';

function cmd(tid: string, off: number, text: string, start: string, end: string | null, exit: number | null) {
  return { cmd_id: `${tid}@${off}`, cmd_ref: `${tid.slice(-8)}@${off}`, text, started_at: at(start), ended_at: end ? at(end) : null, exit, src_ip: KALI_IP, origin: 'local' as const };
}

function base(id: string, tid: string | null, local: string, extra: Partial<{ context_label: string; host_id: string }> = {}) {
  const ts = at(local);
  return { id, ts, ts_ns: nsOf(ts), terminal_id: tid, context_label: extra.context_label ?? (tid ? 'Kali' : null), host_id: extra.host_id ?? null, ctrl: false, terminal: tid ? (TERM[tid] ?? null) : null };
}

const NO_RESULT = { hosts_new: 0, services: 0, values: 0, out_of_scope: 0, conflicts: 0 };

export function timeline(): TimelineItem[] {
  const items: TimelineItem[] = [
    { ...base(`${T3}@64`, T3, '16:52:31.447'), type: 'command', cmd: cmd(T3, 64, 'nc -lvnp 4445', '16:51:52.004', null, null), unit_id: `${T3}@64`, adopted: 0, distrusted: null, scope_warning: null, flags: ['partial'], files: [], lines: 4, result: NO_RESULT },
    { ...base('g:48001', T1, '16:50:05.218'), type: 'gap', reason: 'pause', until: at('17:00:05.218'), bytes_lost: 0 },
    { ...base('k:31877', T2, '16:48:31.902', { host_id: hostId(IP101) }), type: 'keystep', step: 'loot', host_label: IP101, note: '/etc/shadow', ordinal: 2, decision_id: '0199a3c2-9a02-7000-8000-00000000d002' },
    { ...base('0199a3c2-9a03-7000-8000-00000000d003', null, '16:46:41.870', { host_id: hostId(IP101) }), type: 'decision', decision_id: '0199a3c2-9a03-7000-8000-00000000d003', kind: 'd.status.access', summary: 'Zugriff gesetzt', detail: 'Zugriff root auf 192.168.56.101', reason: null, ref: null, effect: null },
    { ...base('k:31001', T2, '16:45:40.118', { host_id: hostId(IP101) }), type: 'keystep', step: 'foothold', host_label: IP101, note: 'vsftpd 2.3.4 Backdoor', ordinal: 1, decision_id: '0199a3c2-9a01-7000-8000-00000000d001' },
    { ...base(`${T2}@20480`, T2, '16:45:12.384', { context_label: 'Kali › 192.168.56.101 [msf] (auto)', host_id: hostId(IP101) }), type: 'segment', unit_id: `${T2}@20480`, lines: 41, state: 'open', evaluate_after: at('16:58:31.000') },
    { ...base(`a:${T2}@20480`, T2, '16:45:12.384', { host_id: hostId(IP101) }), type: 'context', change: 'auto', stack_label: 'Kali › 192.168.56.101 [msf] (auto)', source: 'auto' },
    { ...base('0199a3c2-9a00-7000-8000-00000000d000', null, '16:04:31.268'), type: 'decision', decision_id: '0199a3c2-9a00-7000-8000-00000000d000', kind: 'd.unit.distrust', summary: 'Rückgängig pro Befehl', detail: null, reason: 'Banner manipuliert, vermutlich Honeypot', ref: `${T1.slice(-8)}@51200`, effect: { rejected: 18, weakened: 0 } },
    { ...base(`${T1}@51200`, T1, '16:01:07.540'), type: 'command', cmd: cmd(T1, 51200, 'nmap -sV -sC 192.168.56.110', '16:01:07.540', '16:01:31.002', 0), unit_id: `${T1}@51200`, adopted: 18, distrusted: { decision_id: '0199a3c2-9a00-7000-8000-00000000d000', rejected: 18, weakened: 0 }, scope_warning: null, flags: [], files: [], lines: 40, result: { hosts_new: 1, services: 3, values: 18, out_of_scope: 0, conflicts: 0 } },
    { ...base(`${T1}@40960`, T1, '15:20:44.317'), type: 'command', cmd: cmd(T1, 40960, 'nmap -6 -sV -oX scans/v6.xml fd00:56::101', '15:20:44.317', '15:21:02.100', 0), unit_id: `${T1}@40960`, adopted: 0, distrusted: null, scope_warning: { targets: [{ value: 'fd00:56::101', verdict: 'out' }] }, flags: [], files: [{ unit_id: 'f:v6', path: 'scans/v6.xml' }], lines: 22, result: { hosts_new: 0, services: 0, values: 0, out_of_scope: 17, conflicts: 0 } },
    { ...base('0199a3c2-99ff-7000-8000-00000000cfff', null, '15:12:47.390', { host_id: hostId(IP101) }), type: 'decision', decision_id: '0199a3c2-99ff-7000-8000-00000000cfff', kind: 'd.conflict.resolve', summary: 'Widerspruch gelöst', detail: 'tcp/445 · netbios-ssn', reason: null, ref: null, effect: null },
    { ...base(`${T1}@30720`, T1, '15:10:02.031'), type: 'command', cmd: cmd(T1, 30720, 'nmap -O -v -oX scans/sweep.xml 192.168.56.100-104', '15:10:02.031', '15:10:40.512', 0), unit_id: `${T1}@30720`, adopted: 15, distrusted: null, scope_warning: null, flags: [], files: [{ unit_id: 'f:sweep', path: 'scans/sweep.xml' }], lines: 60, result: { hosts_new: 1, services: 0, values: 15, out_of_scope: 0, conflicts: 1 } },
    { ...base(`${T1}@18432`, T1, '14:02:11.204'), type: 'command', cmd: cmd(T1, 18432, 'nmap -sV -sC -oA scans/ms2 192.168.56.101', '14:02:11.204', '14:04:02.880', 0), unit_id: `${T1}@18432`, adopted: 141, distrusted: null, scope_warning: null, flags: [], files: [{ unit_id: 'f:ms2', path: 'scans/ms2.xml' }], lines: 120, result: { hosts_new: 1, services: 23, values: 141, out_of_scope: 2, conflicts: 0 } },
    { ...base('p:1', T1, '13:58:40.112'), type: 'project', change: 'start', reason: null, detail: 'Vorlauf übernommen (1 Terminal)' },
  ];
  return items;
}

export function inputs(): InputView[] {
  const ts = at('16:47:10.000');
  return [
    { seq: 47001, terminal_id: T2, stream_off: 30000, out_end: 30010, ts, ts_ns: nsOf(ts), length: null, paste: false, redacted: false, hidden: true, reason: 'no_echo_seen', revealed: false, text: '••••••••' },
  ];
}

function line(n: number, text: string, extra: Partial<LogLine> = {}): LogLine {
  return { n, text, ctrl: false, sgr: [], prompt_echo: false, concealed: false, overwritten: false, masked: [], ...extra };
}

const MSF_LINES = [
  'msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run',
  '[*] 192.168.56.101:21 - Banner: 220 (vsFTPd 2.3.4)',
  '[*] 192.168.56.101:21 - USER: 331 Please specify the password.',
  '[+] 192.168.56.101:21 - Backdoor service has been spawned, handling...',
  '[+] 192.168.56.101:21 - UID: uid=0(root) gid=0(root)',
  '[*] Found shell.',
  '[*] Command shell session 1 opened (192.168.56.102:4444 -> 192.168.56.101:6200)',
  '· remote, rekonstruiert ab hier ·',
];

export function unitView(unitId: string): UnitView | null {
  const ctx = [KALI_STAGE];
  if (unitId === `${T2}@1024`) {
    return {
      unit_id: unitId, kind: 'command', cmd_id: unitId, cmd_ref: `${T2.slice(-8)}@1024`, title: 'msfconsole -q', ctrl: false, terminal_id: T2, parser: null,
      ts: at('16:45:12.384'), exit: null, started_at: at('16:43:55.410'), ended_at: null, duration_ms: null, src_ip: KALI_IP,
      context: [...ctx, { depth: 1, kind: 'msf', host_id: hostId(IP101), host_label: IP101, user: null, state: 'active', source: 'auto', auto: true, candidate: null, opened_at: 20480 }],
      line_count: 48, flags: [], chain_ok: true, terminal: TERM[T2] ?? null, chain_break_line: null,
    };
  }
  if (unitId === `${T1}@18432`) {
    return {
      unit_id: unitId, kind: 'command', cmd_id: unitId, cmd_ref: `${T1.slice(-8)}@18432`, title: 'nmap -sV -sC -oA scans/ms2 192.168.56.101', ctrl: false,
      terminal_id: T1, parser: 'nmap.text', ts: at('14:02:11.204'), exit: 0, started_at: at('14:02:11.204'), ended_at: at('14:04:02.880'), duration_ms: 111676,
      src_ip: KALI_IP, context: ctx, line_count: 120, flags: [], chain_ok: true, terminal: TERM[T1] ?? null, chain_break_line: null,
    };
  }
  if (unitId === `${T3}@64`) {
    return {
      unit_id: unitId, kind: 'command', cmd_id: unitId, cmd_ref: `${T3.slice(-8)}@64`, title: 'nc -lvnp 4445', ctrl: false, terminal_id: T3, parser: 'listener.callback',
      ts: at('16:52:31.447'), exit: null, started_at: at('16:51:52.004'), ended_at: null, duration_ms: null, src_ip: KALI_IP, context: ctx, line_count: 4,
      flags: ['partial'], chain_ok: true, terminal: TERM[T3] ?? null, chain_break_line: null,
    };
  }
  // Übrige Befehle und Segmente der Zeitachse: allgemeine Einheit, damit jede Zeile eine Belegansicht hat.
  const item = timeline().find((x) => (x.type === 'command' || x.type === 'segment') && x.unit_id === unitId);
  if (!item || (item.type !== 'command' && item.type !== 'segment')) return null;
  const c = item.type === 'command' ? item.cmd : null;
  return {
    unit_id: unitId, kind: item.type === 'command' ? 'command' : 'segment', cmd_id: c ? c.cmd_id : null, cmd_ref: c ? c.cmd_ref : null,
    title: (c ? c.text : item.context_label) ?? 'Segment', ctrl: false, terminal_id: item.terminal_id ?? T1, parser: null, ts: item.ts,
    exit: c ? c.exit : null, started_at: c ? c.started_at : item.ts, ended_at: c ? c.ended_at : null, duration_ms: null, src_ip: KALI_IP,
    context: ctx, line_count: item.lines, flags: [], chain_ok: true, terminal: item.terminal, chain_break_line: null,
  };
}

export function lines(unitId: string, from: number, count: number): LinesPage | null {
  let all: LogLine[];
  if (unitId === `${T2}@1024`) {
    all = Array.from({ length: 41 }, (_, i) => line(i, i === 0 ? 'msf6 > use exploit/unix/ftp/vsftpd_234_backdoor' : `[*] Modul geladen (${i})`));
    MSF_LINES.forEach((text, i) => all.push(line(41 + i, text)));
  } else if (unitId === `${T1}@18432`) {
    all = [
      line(0, 'Starting Nmap 7.94 ( https://nmap.org )'),
      line(1, 'Nmap scan report for 192.168.56.101'),
      line(2, 'Host is up (0.00041s latency).'),
      line(3, 'Not shown: 977 closed tcp ports (reset)'),
      line(4, 'PORT     STATE SERVICE     VERSION'),
      line(5, '21/tcp   open  ftp         vsftpd 2.3.4'),
      line(6, '|_ftp-anon: Anonymous FTP login allowed (FTP code 230)'),
      line(7, '22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)'),
    ];
  } else if (unitId === `${T3}@64`) {
    all = [
      line(0, 'listening on [any] 4445 ...'),
      line(1, 'connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 49158'),
      line(2, 'id'),
      line(3, FAKE_CALLBACK, { sgr: [{ col_start: 0, col_end: 10, fg: 'yellow', bg: null, bold: false }] }),
    ];
  } else {
    const unit = unitView(unitId);
    if (!unit) return null;
    all = Array.from({ length: unit.line_count }, (_, i) => line(i, i === 0 ? unit.title : `Ausgabe Zeile ${i}`));
  }
  return { unit_id: unitId, total: all.length, from, lines: all.slice(from, from + count) };
}

export function factSources(claimKey: string): FactSources | null {
  if (claimKey !== hex64('ftp-21') && claimKey !== hex64('ftp-21-version')) return null;
  return {
    fact: {
      claim_key: claimKey, subject: `svc:ip:default/${IP101}|tcp/21`, subject_label: '192.168.56.101:21', predicate: 'service.version', value: '2.3.4', ctrl: false,
      is_secret: false, state: 'auto', lane: 'auto', lane_reason: 'parser_in_scope', confidence: 'high', trust: 'structured', parser: 'nmap.xml', from_target: false,
      suspect: false, verdict: 'in', sources: 2, first_seen: at('14:02:11.204'), last_seen: at('14:04:02.880'), conflict_key: null, history: false,
    },
    sources: [
      { t: 'stream', unit_id: `${T1}@18432`, terminal_id: T1, cmd: cmd(T1, 18432, 'nmap -sV -sC -oA scans/ms2 192.168.56.101', '14:02:11.204', '14:04:02.880', 0), context: [KALI_STAGE], lines: [5, 6], parser: 'nmap.text', trust: 'tool_text', confidence: 'high', flags: [], distrusted: false },
      { t: 'file', unit_id: 'f:ms2', path: 'scans/ms2.xml', sha256: '9f2c41e0a1b7a3d18c5e2f7a90b1c3d4e5f60718293a4b5c6d7e8f9012345678', lines: [12, 13], parser: 'nmap.xml', trust: 'structured', produced_by_cmd: `${T1}@18432` },
    ],
  };
}

export function findingF1(): FindingDetail {
  return {
    finding_id: '0199a3c2-9b10-7000-8000-00000000f001', ordinal: 1,
    title: 'vsftpd 2.3.4 mit Hintertür: Root-Shell ohne Anmeldung', ctrl: false, severity: 'critical', status: 'draft',
    affected: [{ subject: `svc:ip:default/${IP101}|tcp/21`, label: '192.168.56.101:21 ftp', ctrl: false }],
    evidence_count: 3, warnings: [], created_at: at('16:50:00.000'), updated_at: at('16:52:00.000'),
    description: 'Der FTP-Dienst meldet vsftpd 2.3.4. Über die bekannte Hintertür öffnete sich eine Shell mit uid=0.', remediation: '',
    attack: [], cves: [{ id: 'CVE-2011-2523', supported: false, hypothesis: true }],
    evidence: [
      { evidence_id: 'ev:1a2b3c4d5e6f7081', ref: { claim_key: hex64('ftp-21-version'), unit_id: `${T1}@18432`, lines: [5, 5], label: 'nmap 14:02 · Zeile 6 · vsftpd 2.3.4' }, label: 'nmap 14:02 · Zeile 6 · vsftpd 2.3.4', ctrl: false, terminal: TERM[T1] ?? null, ts: at('14:02:11.204'), state: 'ok', added_at: at('16:50:00.000'), decision_id: '0199a3c2-9b10-7000-8000-00000000f001' },
      { evidence_id: 'ev:2b3c4d5e6f708192', ref: { claim_key: null, unit_id: `${T2}@1024`, lines: [44, 47], label: 'T2 msf 16:45:12 · Zeilen 44 bis 47' }, label: 'T2 msf 16:45:12 · Zeilen 44 bis 47', ctrl: false, terminal: TERM[T2] ?? null, ts: at('16:45:12.384'), state: 'ok', added_at: at('16:50:00.000'), decision_id: '0199a3c2-9b10-7000-8000-00000000f001' },
    ],
    created_from: { claim_key: null, unit_id: `${T2}@1024`, lines: [44, 47], label: 'T2 16:45:12' },
    history: [{ decision_id: '0199a3c2-9b10-7000-8000-00000000f001', kind: 'd.finding.create', ts: at('16:50:00.000') }],
  };
}

export function pending(): PendingResponse {
  return {
    files: [
      { path: 'scans/udp.xml', reason: 'outside_workspace', cmd_id: `${T1}@30720`, terminal_id: T1, ts: at('16:49:00.000'), ctrl: false, size: 41 * 1024 },
      { path: 'loot/shadow.lnk', reason: 'symlink', cmd_id: null, terminal_id: T2, ts: at('16:49:00.000'), ctrl: false, size: null },
      { path: '~/privat/notizen.txt', reason: 'outside_workspace', cmd_id: null, terminal_id: T1, ts: at('15:44:00.000'), ctrl: false, size: 2048 },
    ],
    truncated: false,
  };
}
