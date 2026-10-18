/**
 * Mock-Daten, Teil Verlauf: Zeitachse (Anhang A.6), Eingaben, Einheiten mit Logzeilen, Belege,
 * Finding F1 (A.9), Warteliste (Screen 10). Form genau wie docs/web-api.md 10, 11, 13, 18.5.
 * Besitzer: ui-verlauf.
 *
 * Im Szenario `hostile` (Query `?mock=hostile`, nur im Browser) kommen feindliche Werte dazu:
 * ein Befehl mit Steuer- und Bidi-Zeichen und HTML, Dateien mit Shell-Sonderzeichen in der
 * Warteliste, ein Finding mit HTML im Titel und Markdown mit Bild und Link, Logzeilen mit
 * sichtbar gemachten Escapes.
 */
import type {
  CommandRef,
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
import { ESC_VERSION_VISIBLE, FAKE_CALLBACK, FAKE_SCAN_TITLE, HOSTILE_IMG, RLO_VERSION_RAW } from './hostile';

const IP101 = '192.168.56.101';
const IP110 = '192.168.56.110';

/** feindliche Zusatzdaten nur im Browser mit `?mock=hostile` */
export function hostileMode(): boolean {
  return typeof location !== 'undefined' && new URLSearchParams(location.search).get('mock') === 'hostile';
}

export const HOSTILE_CMD_TEXT = `curl -A "<script>alert(1)</script>" http://${IP101}/<ESC>]0;REC aus<BEL>`;
export const HOSTILE_PATH = 'scans/$(id)`whoami`.xml';
export const HOSTILE_FINDING_TITLE = '<b>fett</b> <img src=x onerror=alert(1)> Titel';

function cmd(tid: string, off: number, text: string, start: string, end: string | null, exit: number | null): CommandRef {
  return { cmd_id: `${tid}@${off}`, cmd_ref: `${tid.slice(-8)}@${off}`, text, started_at: at(start), ended_at: end ? at(end) : null, exit, src_ip: KALI_IP, origin: 'local' as const };
}

function base(id: string, tid: string | null, local: string, extra: Partial<{ context_label: string; host_id: string }> = {}) {
  const ts = at(local);
  return { id, ts, ts_ns: nsOf(ts), terminal_id: tid, context_label: extra.context_label ?? (tid ? 'Kali' : null), host_id: extra.host_id ?? null, ctrl: false, terminal: tid ? (TERM[tid] ?? null) : null };
}

const NO_RESULT = { hosts_new: 0, services: 0, values: 0, out_of_scope: 0, conflicts: 0 };

export const DISTRUST_ID = '0199a3c2-9a00-7000-8000-00000000d000';

export function inputs(): InputView[] {
  const ts = at('16:47:10.000');
  return [
    { seq: 47001, terminal_id: T2, stream_off: 30000, out_end: 30010, ts, ts_ns: nsOf(ts), length: null, paste: false, redacted: false, hidden: true, reason: 'no_echo_seen', revealed: false, text: '••••••••' },
  ];
}

export function timeline(): TimelineItem[] {
  const input = inputs()[0] as InputView;
  const items: TimelineItem[] = [
    { ...base(`${T3}@64`, T3, '16:52:31.447'), type: 'command', cmd: cmd(T3, 64, 'nc -lvnp 4445', '16:51:52.004', null, null), unit_id: `${T3}@64`, adopted: 0, distrusted: null, scope_warning: null, flags: ['partial'], files: [], lines: 4, result: NO_RESULT },
    { ...base('g:48001', T1, '16:50:05.218'), type: 'gap', reason: 'pause', until: at('17:00:05.218'), bytes_lost: 0 },
    { ...base('k:31877', T2, '16:48:31.902', { host_id: hostId(IP101) }), type: 'keystep', step: 'loot', host_label: IP101, note: '/etc/shadow', ordinal: 2, decision_id: '0199a3c2-9a02-7000-8000-00000000d002' },
    { ...base(`i:${input.seq}`, T2, '16:47:10.000', { context_label: 'Kali › 192.168.56.101 [msf] (auto)', host_id: hostId(IP101) }), type: 'input', input },
    { ...base('0199a3c2-9a03-7000-8000-00000000d003', null, '16:46:41.870', { host_id: hostId(IP101) }), type: 'decision', decision_id: '0199a3c2-9a03-7000-8000-00000000d003', kind: 'd.status.access', summary: 'Zugriff: Administrator', detail: 'Zugriff root auf 192.168.56.101', reason: null, ref: null, effect: null },
    { ...base('k:31001', T2, '16:45:40.118', { host_id: hostId(IP101) }), type: 'keystep', step: 'foothold', host_label: IP101, note: 'vsftpd 2.3.4 Backdoor', ordinal: 1, decision_id: '0199a3c2-9a01-7000-8000-00000000d001' },
    { ...base(`${T2}@20480`, T2, '16:45:12.384', { context_label: 'Kali › 192.168.56.101 [msf] (auto)', host_id: hostId(IP101) }), type: 'segment', unit_id: `${T2}@20480`, lines: 41, state: 'open', evaluate_after: at('16:58:31.000') },
    { ...base(`a:${T2}@20480`, T2, '16:45:12.384', { host_id: hostId(IP101) }), type: 'context', change: 'auto', stack_label: 'Kali › 192.168.56.101 [msf] (auto)', source: 'auto', host_label: IP101, stage_kind: 'msf', user: null, session: '1' },
    { ...base(`${T2}@1024`, T2, '16:43:55.410'), type: 'command', cmd: cmd(T2, 1024, 'msfconsole -q', '16:43:55.410', null, null), unit_id: `${T2}@1024`, adopted: 0, distrusted: null, scope_warning: null, flags: [], files: [], lines: 48, result: NO_RESULT },
    { ...base(DISTRUST_ID, null, '16:04:31.268'), type: 'decision', decision_id: DISTRUST_ID, kind: 'd.unit.distrust', summary: 'Rückgängig pro Befehl', detail: null, reason: 'Banner manipuliert, vermutlich Honeypot', ref: `${T1.slice(-8)}@51200`, effect: { rejected: 18, weakened: 0 } },
    { ...base(`${T1}@51200`, T1, '16:01:07.540'), type: 'command', cmd: cmd(T1, 51200, `nmap -sV -sC ${IP110}`, '16:01:07.540', '16:01:31.002', 0), unit_id: `${T1}@51200`, adopted: 0, distrusted: { decision_id: DISTRUST_ID, rejected: 18, weakened: 0 }, scope_warning: null, flags: [], files: [], lines: 40, result: { hosts_new: 1, services: 3, values: 18, out_of_scope: 0, conflicts: 0 } },
    { ...base(`${T1}@40960`, T1, '15:20:44.317'), type: 'command', cmd: cmd(T1, 40960, 'nmap -6 -sV -oX scans/v6.xml fd00:56::101', '15:20:44.317', '15:21:02.100', 0), unit_id: `${T1}@40960`, adopted: 0, distrusted: null, scope_warning: { targets: [{ value: 'fd00:56::101', verdict: 'out' }] }, flags: [], files: [{ unit_id: 'f:v6', path: 'scans/v6.xml' }], lines: 22, result: { hosts_new: 0, services: 0, values: 0, out_of_scope: 17, conflicts: 0 } },
    { ...base('0199a3c2-99ff-7000-8000-00000000cfff', null, '15:12:47.390', { host_id: hostId(IP101) }), type: 'decision', decision_id: '0199a3c2-99ff-7000-8000-00000000cfff', kind: 'd.conflict.resolve', summary: 'Widerspruch gelöst', detail: 'tcp/445 · netbios-ssn', reason: null, ref: null, effect: null },
    { ...base(`${T1}@30720`, T1, '15:10:02.031'), type: 'command', cmd: cmd(T1, 30720, 'nmap -O -v -oX scans/sweep.xml 192.168.56.100-104', '15:10:02.031', '15:10:40.512', 0), unit_id: `${T1}@30720`, adopted: 15, distrusted: null, scope_warning: null, flags: [], files: [{ unit_id: 'f:sweep', path: 'scans/sweep.xml' }], lines: 60, result: { hosts_new: 1, services: 0, values: 15, out_of_scope: 0, conflicts: 1 } },
    { ...base('f:ms2', null, '14:04:02.880'), type: 'file', unit_id: 'f:ms2', path: 'scans/ms2.xml', cmd_id: `${T1}@18432` },
    { ...base(`${T1}@18432`, T1, '14:02:11.204'), type: 'command', cmd: cmd(T1, 18432, 'nmap -sV -sC -oA scans/ms2 192.168.56.101', '14:02:11.204', '14:04:02.880', 0), unit_id: `${T1}@18432`, adopted: 141, distrusted: null, scope_warning: null, flags: [], files: [{ unit_id: 'f:ms2', path: 'scans/ms2.xml' }], lines: 120, result: { hosts_new: 1, services: 23, values: 141, out_of_scope: 2, conflicts: 0 } },
    { ...base('p:1', T1, '13:58:40.112'), type: 'project', change: 'start', reason: null, detail: 'Vorlauf übernommen (1 Terminal)' },
  ];
  if (hostileMode()) {
    items.unshift({
      ...base(`${T1}@60000`, T1, '16:53:40.000'),
      ctrl: true,
      type: 'command',
      cmd: cmd(T1, 60000, `${HOSTILE_CMD_TEXT} ${RLO_VERSION_RAW}`, '16:53:40.000', '16:53:41.000', 0),
      unit_id: `${T1}@60000`,
      adopted: 2,
      distrusted: null,
      scope_warning: null,
      flags: ['marker_forged'],
      files: [{ unit_id: 'f:hostile', path: HOSTILE_PATH }],
      lines: 3,
      result: { hosts_new: 0, services: 0, values: 2, out_of_scope: 0, conflicts: 0 },
    });
  }
  return items;
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

const NMAP_101 = [
  'Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-08 14:02 CEST',
  'Nmap scan report for 192.168.56.101',
  'Host is up (0.00041s latency).',
  'Not shown: 977 closed tcp ports (reset)',
  'PORT     STATE SERVICE     VERSION',
  '21/tcp   open  ftp         vsftpd 2.3.4',
  '|_ftp-anon: Anonymous FTP login allowed (FTP code 230)',
  '22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)',
  '23/tcp   open  telnet      Linux telnetd',
  '25/tcp   open  smtp        Postfix smtpd',
  '53/tcp   open  domain      ISC BIND 9.4.2',
  '80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)',
  '|_http-title: Metasploitable2 - Linux',
  '111/tcp  open  rpcbind     2 (RPC #100000)',
  '139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)',
  '445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)',
];

const XML_MS2 = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<!DOCTYPE nmaprun>',
  '<nmaprun scanner="nmap" args="nmap -sV -sC -oA scans/ms2 192.168.56.101" start="1791461331">',
  '<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>',
  '<verbose level="0"/>',
  '<debugging level="0"/>',
  '<host starttime="1791461331" endtime="1791461442"><status state="up" reason="arp-response"/>',
  '<address addr="192.168.56.101" addrtype="ipv4"/>',
  '<address addr="08:00:27:63:7E:E7" addrtype="mac" vendor="Oracle VirtualBox virtual NIC"/>',
  '<hostnames>',
  '</hostnames>',
  '<ports><extraports state="closed" count="977"/>',
  '<port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/>',
  '<service name="ftp" product="vsftpd" version="2.3.4" ostype="Unix" method="probed" conf="10"/>',
  '<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>',
  '</port>',
];

function fileUnit(unitId: string, path: string, cmdId: string, local: string, lineCount: number, parser: string): UnitView {
  return {
    unit_id: unitId, kind: 'file', cmd_id: cmdId, cmd_ref: `${cmdId.split('@')[0]?.slice(-8)}@${cmdId.split('@')[1]}`, title: path, ctrl: false, terminal_id: null,
    parser, ts: at(local), exit: null, started_at: at(local), ended_at: null, duration_ms: null, src_ip: null, context: [KALI_STAGE], line_count: lineCount,
    flags: [], chain_ok: true, terminal: null, chain_break_line: null, tty: null,
  };
}

export function unitView(unitId: string): UnitView | null {
  const ctx = [KALI_STAGE];
  if (unitId === `${T2}@1024`) {
    return {
      unit_id: unitId, kind: 'command', cmd_id: unitId, cmd_ref: `${T2.slice(-8)}@1024`, title: 'msfconsole -q', ctrl: false, terminal_id: T2, parser: null,
      ts: at('16:45:12.384'), exit: null, started_at: at('16:43:55.410'), ended_at: null, duration_ms: null, src_ip: KALI_IP,
      context: [...ctx, { depth: 1, kind: 'msf', host_id: hostId(IP101), host_label: IP101, user: null, state: 'active', source: 'auto', auto: true, candidate: null, opened_at: 20480 }],
      line_count: 48, flags: [], chain_ok: true, terminal: TERM[T2] ?? null, chain_break_line: null, tty: '/dev/pts/2',
    };
  }
  if (unitId === `${T1}@18432`) {
    return {
      unit_id: unitId, kind: 'command', cmd_id: unitId, cmd_ref: `${T1.slice(-8)}@18432`, title: 'nmap -sV -sC -oA scans/ms2 192.168.56.101', ctrl: false,
      terminal_id: T1, parser: 'nmap.text', ts: at('14:02:11.204'), exit: 0, started_at: at('14:02:11.204'), ended_at: at('14:04:02.880'), duration_ms: 111676,
      src_ip: KALI_IP, context: ctx, line_count: 120, flags: [], chain_ok: true, terminal: TERM[T1] ?? null, chain_break_line: null, tty: '/dev/pts/1',
    };
  }
  if (unitId === `${T3}@64`) {
    return {
      unit_id: unitId, kind: 'command', cmd_id: unitId, cmd_ref: `${T3.slice(-8)}@64`, title: 'nc -lvnp 4445', ctrl: false, terminal_id: T3, parser: 'listener.callback',
      ts: at('16:52:31.447'), exit: null, started_at: at('16:51:52.004'), ended_at: null, duration_ms: null, src_ip: KALI_IP, context: ctx, line_count: 4,
      flags: ['partial'], chain_ok: true, terminal: TERM[T3] ?? null, chain_break_line: null, tty: '/dev/pts/3',
    };
  }
  if (unitId === 'f:ms2') return fileUnit(unitId, 'scans/ms2.xml', `${T1}@18432`, '14:04:02.880', 131, 'nmap.xml');
  if (unitId === 'f:sweep') return fileUnit(unitId, 'scans/sweep.xml', `${T1}@30720`, '15:10:40.512', 80, 'nmap.xml');
  if (unitId === 'f:v6') return fileUnit(unitId, 'scans/v6.xml', `${T1}@40960`, '15:21:02.100', 40, 'nmap.xml');
  if (unitId === 'f:hostile' && hostileMode()) return { ...fileUnit(unitId, HOSTILE_PATH, `${T1}@60000`, '16:53:41.000', 3, 'nmap.xml'), ctrl: true };
  // Übrige Befehle und Segmente der Zeitachse: allgemeine Einheit, damit jede Zeile eine Belegansicht hat.
  const item = timeline().find((x) => (x.type === 'command' || x.type === 'segment') && x.unit_id === unitId);
  if (!item || (item.type !== 'command' && item.type !== 'segment')) return null;
  const c = item.type === 'command' ? item.cmd : null;
  return {
    unit_id: unitId, kind: item.type === 'command' ? 'command' : 'segment', cmd_id: c ? c.cmd_id : null, cmd_ref: c ? c.cmd_ref : null,
    title: (c ? c.text : item.context_label) ?? 'Segment', ctrl: item.ctrl, terminal_id: item.terminal_id ?? T1, parser: null, ts: item.ts,
    exit: c ? c.exit : null, started_at: c ? c.started_at : item.ts, ended_at: c ? c.ended_at : null, duration_ms: c?.ended_at ? Date.parse(c.ended_at) - Date.parse(c.started_at) : null,
    src_ip: KALI_IP, context: item.type === 'segment'
      ? [...ctx, { depth: 1, kind: 'msf', host_id: hostId(IP101), host_label: IP101, user: null, state: 'active', source: 'auto', auto: true, candidate: null, opened_at: 20480 }]
      : ctx,
    line_count: item.lines, flags: item.type === 'segment' ? ['remote_reconstructed'] : [], chain_ok: true, terminal: item.terminal, chain_break_line: null, tty: null,
  };
}

export function lines(unitId: string, from: number, count: number): LinesPage | null {
  let all: LogLine[];
  if (unitId === `${T2}@1024`) {
    all = Array.from({ length: 40 }, (_, i) => line(i, i === 0 ? 'msf6 > use exploit/unix/ftp/vsftpd_234_backdoor' : `[*] Modul geladen (${i})`, { prompt_echo: i === 0 }));
    MSF_LINES.forEach((text, i) => all.push(line(40 + i, text)));
  } else if (unitId === `${T1}@18432`) {
    all = NMAP_101.map((text, i) => line(i, text));
    for (let i = all.length; i < 120; i++) all.push(line(i, `${1000 + i}/tcp closed unknown`));
  } else if (unitId === `${T3}@64`) {
    all = [
      line(0, 'listening on [any] 4445 ...'),
      line(1, 'connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 49158'),
      line(2, 'id'),
      line(3, FAKE_CALLBACK, { sgr: [{ col_start: 0, col_end: 10, fg: 'yellow', bg: null, bold: false }] }),
    ];
  } else if (unitId === `${T1}@51200`) {
    // Honeypot .110 (Anhang A.10): Titel und Bannerzeile nur Text, nie Host oder Service
    all = [
      line(0, `Nmap scan report for ${IP110}`),
      line(1, 'PORT   STATE SERVICE VERSION'),
      line(2, '21/tcp open  ftp     evil 1.0'),
      line(3, `|_http-title: ${FAKE_SCAN_TITLE}`),
      line(4, '22/tcp open  ssh     OpenSSH 7.4', { ctrl: true }),
    ];
    for (let i = all.length; i < 40; i++) all.push(line(i, `Ausgabe Zeile ${i}`));
  } else if (unitId === 'f:ms2') {
    all = XML_MS2.map((text, i) => line(i, text));
    for (let i = all.length; i < 131; i++) all.push(line(i, `<port protocol="tcp" portid="${i}"><state state="closed"/></port>`));
  } else if (unitId === `${T1}@60000` && hostileMode()) {
    all = [
      line(0, `$ ${HOSTILE_CMD_TEXT}`, { prompt_echo: true, ctrl: true }),
      line(1, `Server: ${ESC_VERSION_VISIBLE} ${RLO_VERSION_RAW}`, { ctrl: true }),
      line(2, `<title>${HOSTILE_IMG}</title> passwort=•••••••• ende`, { masked: [{ col_start: 47, col_end: 55, kind: 'secret' }] }),
    ];
  } else {
    const unit = unitView(unitId);
    if (!unit) return null;
    all = Array.from({ length: unit.line_count }, (_, i) => line(i, i === 0 ? unit.title : `Ausgabe Zeile ${i}`));
  }
  return { unit_id: unitId, total: all.length, from, lines: all.slice(from, from + count) };
}

const FACT_SOURCES: Record<string, { subject: string; label: string; predicate: string; value: string; unit: string; lines: [number, number]; file?: boolean }> = {
  'ftp-21': { subject: `svc:ip:default/${IP101}|tcp/21`, label: '192.168.56.101:21', predicate: 'service.product', value: 'vsftpd', unit: `${T1}@18432`, lines: [5, 6], file: true },
  'ftp-21-version': { subject: `svc:ip:default/${IP101}|tcp/21`, label: '192.168.56.101:21', predicate: 'service.version', value: '2.3.4', unit: `${T1}@18432`, lines: [5, 5], file: true },
  'cb-101': { subject: hostId(IP101), label: IP101, predicate: 'access.callback', value: `${IP101}:49158`, unit: `${T3}@64`, lines: [1, 1] },
  '445-open': { subject: `svc:ip:default/${IP101}|tcp/445`, label: '192.168.56.101:445', predicate: 'service.state', value: 'open', unit: `${T1}@18432`, lines: [15, 15] },
  'cand-ip:default/192.168.56.103': { subject: hostId('192.168.56.103'), label: '192.168.56.103', predicate: 'host.address', value: '192.168.56.103', unit: `${T1}@30720`, lines: [8, 8] },
};

export function factSources(claimKey: string): FactSources | null {
  const name = Object.keys(FACT_SOURCES).find((k) => hex64(k) === claimKey);
  const f = name ? FACT_SOURCES[name] : undefined;
  if (!f) return null;
  const unit = unitView(f.unit);
  const c = unit?.cmd_id ? (timeline().find((x) => x.type === 'command' && x.unit_id === f.unit) as Extract<TimelineItem, { type: 'command' }> | undefined)?.cmd ?? null : null;
  const sources: FactSources['sources'] = [
    { t: 'stream', unit_id: f.unit, terminal_id: unit?.terminal_id ?? T1, cmd: c, context: unit?.context ?? [KALI_STAGE], lines: f.lines, parser: unit?.parser ?? 'nmap.text', trust: 'tool_text', confidence: 'high', flags: [], distrusted: false },
  ];
  if (f.file) {
    sources.push({ t: 'file', unit_id: 'f:ms2', path: 'scans/ms2.xml', sha256: '9f2c41e0a1b7a3d18c5e2f7a90b1c3d4e5f60718293a4b5c6d7e8f90b7a3d18c', lines: [12, 13], parser: 'nmap.xml', trust: 'structured', produced_by_cmd: `${T1}@18432` });
  }
  return {
    fact: {
      claim_key: claimKey, subject: f.subject, subject_label: f.label, predicate: f.predicate, value: f.value, ctrl: false,
      is_secret: false, state: 'auto', lane: 'auto', lane_reason: 'parser_in_scope', confidence: 'high', trust: 'structured', parser: 'nmap.xml', from_target: false,
      suspect: false, verdict: 'in', sources: sources.length, first_seen: at('14:02:11.204'), last_seen: at('14:04:02.880'), conflict_key: null, history: false,
    },
    sources,
  };
}

/** Beschriftung eines Belegs wie der Server (18.12): Terminal, Befehl bzw. Datei, Zeilen, Wert. */
export function evidenceLabel(ref: { claim_key?: string | null; unit_id?: string | null; lines?: [number, number] | null }): string {
  if (ref.claim_key) {
    const s = factSources(ref.claim_key);
    const src = s?.sources[0];
    const unitId = src && src.t !== 'user' ? src.unit_id : null;
    const u = unitId ? unitView(unitId) : null;
    const term = u?.terminal ? `T${u.terminal.ordinal} ${u.terminal.label ?? ''}`.trim() : null;
    const ln = src && src.t !== 'user' && src.lines ? linesText(src.lines) : null;
    return [term, u?.title, ln, s?.fact.value].filter(Boolean).join(' · ');
  }
  const u = ref.unit_id ? unitView(ref.unit_id) : null;
  if (!u) return ref.unit_id ?? '?';
  const term = u.terminal ? `T${u.terminal.ordinal} ${u.terminal.label ?? ''}`.trim() : null;
  return [term, u.title, ref.lines ? linesText(ref.lines) : null].filter(Boolean).join(' · ');
}

function linesText([a, b]: [number, number]): string {
  return a === b ? `Zeile ${a + 1}` : `Zeilen ${a + 1} bis ${b + 1}`;
}

export function findingF1(): FindingDetail {
  return {
    finding_id: '0199a3c2-9b10-7000-8000-00000000f001', ordinal: 1,
    title: 'vsftpd 2.3.4 mit Hintertür: Root-Shell ohne Anmeldung', ctrl: false, severity: 'critical', status: 'draft',
    affected: [{ subject: `svc:ip:default/${IP101}|tcp/21`, label: '192.168.56.101:21 ftp', ctrl: false }],
    evidence_count: 2, warnings: [], created_at: at('16:50:00.000'), updated_at: at('16:52:00.000'),
    description: 'Der FTP-Dienst meldet vsftpd 2.3.4. Über die bekannte Hintertür öffnete sich eine Shell mit uid=0.', remediation: '',
    attack: [], cves: [{ id: 'CVE-2011-2523', supported: false, hypothesis: true }],
    evidence: [
      { evidence_id: 'ev:1a2b3c4d5e6f7081', ref: { claim_key: hex64('ftp-21-version'), unit_id: null, lines: null, label: 'T1 scan · nmap -sV -sC -oA scans/ms2 192.168.56.101 · Zeile 6 · 2.3.4' }, label: 'T1 scan · nmap -sV -sC -oA scans/ms2 192.168.56.101 · Zeile 6 · 2.3.4', ctrl: false, terminal: TERM[T1] ?? null, ts: at('14:02:11.204'), state: 'ok', added_at: at('16:50:00.000'), decision_id: '0199a3c2-9b10-7000-8000-00000000f001' },
      { evidence_id: 'ev:2b3c4d5e6f708192', ref: { claim_key: null, unit_id: `${T2}@1024`, lines: [43, 46], label: 'T2 msf · msfconsole -q · Zeilen 44 bis 47' }, label: 'T2 msf · msfconsole -q · Zeilen 44 bis 47', ctrl: false, terminal: TERM[T2] ?? null, ts: at('16:45:12.384'), state: 'ok', added_at: at('16:50:00.000'), decision_id: '0199a3c2-9b10-7000-8000-00000000f001' },
    ],
    created_from: { claim_key: null, unit_id: `${T2}@1024`, lines: [43, 46], label: 'T2 msf · msfconsole -q · Zeilen 44 bis 47' },
    history: [{ decision_id: '0199a3c2-9b10-7000-8000-00000000f001', kind: 'd.finding.create', ts: at('16:50:00.000') }],
  };
}

/** Feindliches Finding (nur `?mock=hostile`). */
export function findingHostile(): FindingDetail {
  return {
    ...findingF1(),
    finding_id: '0199a3c2-9b10-7000-8000-00000000f0ee', ordinal: 2, title: HOSTILE_FINDING_TITLE, ctrl: true, severity: null,
    description: '![bild](https://evil.example/x.png) [klick](https://evil.example) <img src=x onerror=alert(1)> **fett**',
    affected: [{ subject: `name:${HOSTILE_IMG}`, label: HOSTILE_IMG, ctrl: false }],
    evidence: [], evidence_count: 0, warnings: ['no_evidence', 'no_severity'], created_from: null,
    cves: [], attack: [{ id: 'T1190', supported: false, hypothesis: true }],
  };
}

export function pending(): PendingResponse {
  const files: PendingResponse['files'] = [
    { path: 'scans/udp.xml', reason: 'outside_workspace', cmd_id: `${T1}@30720`, terminal_id: T1, ts: at('16:49:00.000'), ctrl: false, size: 41 * 1024 },
    { path: 'loot/shadow.lnk', reason: 'symlink', cmd_id: null, terminal_id: T2, ts: at('16:49:00.000'), ctrl: false, size: null },
    { path: '~/privat/notizen.txt', reason: 'outside_workspace', cmd_id: null, terminal_id: T1, ts: at('15:44:00.000'), ctrl: false, size: 2048 },
  ];
  if (hostileMode()) {
    files.unshift(
      { path: HOSTILE_PATH, reason: 'owner', cmd_id: null, terminal_id: T1, ts: at('16:53:41.000'), ctrl: false, size: 12 },
      { path: `loot/${HOSTILE_IMG}<ESC>[2J.txt`, reason: 'path', cmd_id: null, terminal_id: T1, ts: at('16:53:42.000'), ctrl: true, size: 1 },
    );
  }
  return { files, truncated: false };
}
