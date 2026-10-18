/**
 * Mock-Daten, Teil Karte: Graph, Hosts, Services, Host-Detail, «Als Nächstes» mit K2, K3 und den
 * Denkanstössen D1, D2 (Briefing Anhang A.2 bis A.8), «Neu seit 16:40». Form genau wie
 * docs/web-api.md 7, 8, 9, 18.3, 18.6. Besitzer: ui-karte.
 */
import type {
  CommandTemplate,
  GraphView,
  HostDetail,
  HostNode,
  ServiceNode,
  NextView,
  SeenView,
  ServiceClass,
  ServiceView,
  Suggestion,
  ThreadEdge,
} from '../../api/types';
import { at, hex64, hostId, KALI_IP, PID, SCOPE, serviceId, T1, T2, T3, TERM } from './base';
import { HOSTILE_IMG, INJECTION_TITLE, SHELL_PRODUCT } from './hostile';

const IP101 = '192.168.56.101';
const IP103 = '192.168.56.103';
const IP104 = '192.168.56.104';

type Svc = [port: number, name: string, product: string | null, version: string | null, cls: ServiceClass];
/** Services von .101 (Anhang A.4) */
export const SERVICES_101: Svc[] = [
  [21, 'ftp', 'vsftpd', '2.3.4', 'file'],
  [22, 'ssh', 'OpenSSH', '4.7p1 Debian 8ubuntu1', 'remote'],
  [23, 'telnet', 'Linux telnetd', null, 'remote'],
  [25, 'smtp', 'Postfix smtpd', null, 'mail'],
  [53, 'domain', 'ISC BIND', '9.4.2', 'other'],
  [80, 'http', 'Apache httpd', '2.2.8', 'web'],
  [111, 'rpcbind', null, null, 'other'],
  [139, 'netbios-ssn', 'Samba smbd', '3.X - 4.X', 'smb'],
  [445, 'netbios-ssn', 'Samba smbd', null, 'smb'],
  [512, 'exec', null, null, 'remote'],
  [513, 'login', null, null, 'remote'],
  [514, 'shell', null, null, 'remote'],
  [1099, 'java-rmi', null, null, 'other'],
  [1524, 'bindshell', 'Metasploitable root shell', null, 'remote'],
  [2049, 'nfs', null, null, 'file'],
  [2121, 'ftp', 'ProFTPD', '1.3.1', 'file'],
  [3306, 'mysql', 'MySQL', '5.0.51a-3ubuntu5', 'db'],
  [5432, 'postgresql', 'PostgreSQL DB', '8.3.0 - 8.3.7', 'db'],
  [5900, 'vnc', null, null, 'remote'],
  [6000, 'X11', null, null, 'remote'],
  [6667, 'irc', 'UnrealIRCd', null, 'other'],
  [8009, 'ajp13', null, null, 'web'],
  [8180, 'http', 'Apache Tomcat/Coyote', '1.1', 'web'],
];

function classes(svcs: Svc[]): Record<ServiceClass, number> {
  const out: Record<ServiceClass, number> = { web: 0, smb: 0, db: 0, remote: 0, file: 0, mail: 0, other: 0 };
  for (const s of svcs) out[s[4]]++;
  return out;
}

export function hostNodes(): HostNode[] {
  const base = {
    kind: 'host' as const, segment: `seg:${SCOPE}`, ctrl: false, conflicts: 0, auto: true, ai: false, tags: [] as string[],
    conflict_brief: null,
  };
  return [
    {
      ...base, id: hostId(IP101), label: IP101, addresses: [IP101], names: [], claim_state: 'auto', knowledge: 'versions',
      access: 'admin', work: 'in_progress', work_reason: null, progress: 5, os: 'Linux 2.6.9 - 2.6.33', services_total: 23,
      service_classes: classes(SERVICES_101), on_thread: true, hint: 'services', tags: ['linux'],
      ports: SERVICES_101.slice(0, 12).map((s) => s[0]),
    },
    {
      ...base, id: hostId(IP103), label: IP103, addresses: [IP103], names: [], claim_state: 'candidate', knowledge: 'mentioned',
      access: 'none', work: 'open', work_reason: null, progress: 0, os: null, services_total: 0,
      service_classes: classes([]), on_thread: false, hint: null, auto: false, ports: [],
    },
    {
      ...base, id: hostId(IP104), label: IP104, addresses: [IP104], names: [], claim_state: 'auto', knowledge: 'scanned',
      access: 'none', work: 'dead_end', work_reason: 'nur RDP', progress: 1, os: 'Windows 10 1709 - 1909', services_total: 1,
      service_classes: { ...classes([]), remote: 1 }, on_thread: false, hint: 'services', ports: [3389],
    },
  ];
}

export function thread(): ThreadEdge[] {
  return [
    { kind: 'thread', id: 'k:31001', seq: 1, step: 'foothold', source: 'kali', target: hostId(IP101), ts: at('16:45:40.118'), note: 'vsftpd 2.3.4 Backdoor', decision_id: '0199a3c2-9a01-7000-8000-00000000d001' },
    { kind: 'thread', id: 'k:31877', seq: 2, step: 'loot', source: hostId(IP101), target: hostId(IP101), ts: at('16:48:31.902'), note: '/etc/shadow', decision_id: '0199a3c2-9a02-7000-8000-00000000d002' },
  ];
}

export function graph(generation: number): GraphView {
  const hosts = hostNodes();
  return {
    project_id: PID,
    generation,
    nodes: [
      { kind: 'kali', id: 'kali', label: 'Kali', addresses: [KALI_IP] },
      { kind: 'segment', id: `seg:${SCOPE}`, cidr: SCOPE, label: SCOPE, origin: 'scope' },
      ...hosts,
      ...serviceNodes(),
    ],
    edges: [...hosts.map((h) => ({ kind: 'member' as const, id: `m:${h.id}`, source: `seg:${SCOPE}`, target: h.id })), ...thread()],
    oos: {
      total: 4,
      items: [
        { identifier: 'ip:default/fd00:56::101', label: 'fd00:56::101', ctrl: false, verdict: 'out', rule: null, mentions: 17, first_unit: `${T1}@40960`, source: { unit_id: `${T1}@40960`, kind: 'command', cmd_id: `${T1}@40960`, cmd_ref: `${T1.slice(-8)}@40960`, title: 'nmap -6 -sV -oX scans/v6.xml fd00:56::101', ctrl: false, terminal_id: T1, parser: 'nmap.xml', ts: at('15:20:44.317') }, punycode: null, note: 'same_mac', related: hostId(IP101) },
        { identifier: 'name:ms2.lab', label: 'ms2.lab · metasploitable.lab', ctrl: false, verdict: 'out', rule: null, mentions: 2, first_unit: `${T1}@18432`, source: { unit_id: `${T1}@18432`, kind: 'command', cmd_id: `${T1}@18432`, cmd_ref: `${T1.slice(-8)}@18432`, title: 'nmap -sV -sC -oA scans/ms2 192.168.56.101', ctrl: false, terminal_id: T1, parser: 'nmap.xml', ts: at('14:02:11.204') }, punycode: null, note: null, related: hostId(IP101) },
        { identifier: 'ip:default/10.66.66.66', label: '10.66.66.66', ctrl: false, verdict: 'out', rule: null, mentions: 1, first_unit: `${T3}@64`, source: { unit_id: `${T3}@64`, kind: 'command', cmd_id: `${T3}@64`, cmd_ref: `${T3.slice(-8)}@64`, title: 'nc -lvnp 4445', ctrl: false, terminal_id: T3, parser: 'listener.callback', ts: at('16:53:02.000') }, punycode: null, note: 'forged_callback', related: null },
        { identifier: `name:${HOSTILE_IMG}`, label: HOSTILE_IMG, ctrl: false, verdict: 'out', rule: null, mentions: 1, first_unit: `${T1}@18432`, source: null, punycode: null, note: null, related: null },
      ],
    },
    summary: { hosts: 3, fog: 1, with_access: 1, services: 24, conflicts: 0 },
    table_only: false,
    as_of: at('16:54:00.000'),
  };
}

/** Service-Knoten des Graphs (Ebene «services»; die Karte zeigt sie als Zahl, die Palette sucht darin). */
export function serviceNodes(): ServiceNode[] {
  const one = (ip: string, [port, name, product, version, cls]: Svc): ServiceNode => ({
    kind: 'service', id: serviceId(ip, port), host: hostId(ip), proto: 'tcp', port, name, product, version, ctrl: false,
    class: cls, state: port === 445 ? 'filtered' : 'open', claim_state: 'auto', conflicts: 0,
  });
  return [...SERVICES_101.map((s) => one(IP101, s)), one(IP104, [3389, 'ms-wbt-server', null, null, 'remote'])];
}

function serviceView(ip: string, s: Svc): ServiceView {
  const [port, name, product, version, cls] = s;
  const tomcat = port === 8180;
  return {
    service_id: serviceId(ip, port), host_id: hostId(ip), host_label: ip, proto: 'tcp', port, name, product, version, ctrl: false,
    class: cls, state: port === 445 ? 'filtered' : 'open', claim_state: 'auto', verdict: 'in', work: null, conflicts: 0, cves: [],
    history: port === 445 ? [{ predicate: 'service.state', value: 'open', ctrl: false, until: at('15:10:02.031'), claim_key: hex64('445-open') }] : [],
    banner: tomcat ? `Titel «${INJECTION_TITLE}»` : null, from_target: tomcat, suspect: tomcat,
  };
}

export function services(): ServiceView[] {
  return [...SERVICES_101.map((s) => serviceView(IP101, s)), serviceView(IP104, [3389, 'ms-wbt-server', null, null, 'remote'])];
}

export function hostDetail(id: string): HostDetail | null {
  const node = hostNodes().find((h) => h.id === id);
  if (!node) return null;
  const { kind: _k, ...rest } = node;
  const svcs = services().filter((s) => s.host_id === id);
  return {
    ...rest,
    conflicts: [],
    first_seen: at('14:02:11.204'),
    last_seen: at('16:48:31.902'),
    quiet: { heuristic: 0, out_of_scope: id === hostId(IP101) ? 2 : 0, mentions: 0, system_accounts: id === hostId(IP101) ? 27 : 0 },
    identifiers: [
      { key: id, label: node.label, type: 'ip', verdict: 'in', rule: SCOPE, ctrl: false, punycode: null },
      ...(id === hostId(IP104) ? [{ key: `name:${HOSTILE_IMG}`, label: HOSTILE_IMG, type: 'name', verdict: 'out' as const, rule: null, ctrl: false, punycode: null }] : []),
    ],
    services: svcs,
    facts: [],
    facts_truncated: false,
    open_items: id === hostId(IP101) ? [`ctx:${T3}@412`, `merge:${hex64('merge-101').slice(0, 16)}`] : [],
    thread: id === hostId(IP101) ? thread() : [],
    note: id === hostId(IP101) ? 'vsftpd-Backdoor geht, Samba noch prüfen' : null,
    commands: [],
    candidate_claims: node.claim_state === 'candidate' ? [hex64(`cand-${id}`)] : [],
    access_by: node.access === 'admin' ? { source: 'decision', decision_id: '0199a3c2-9a03-7000-8000-00000000d003', ts: at('16:46:41.870') } : null,
    first_source: node.claim_state === 'candidate' ? { unit_id: `${T1}@30720`, kind: 'command', cmd_id: `${T1}@30720`, cmd_ref: `${T1.slice(-8)}@30720`, title: 'nmap -O -v -oX scans/sweep.xml 192.168.56.100-104', ctrl: false, terminal_id: T1, parser: 'nmap.xml', ts: at('15:10:02.031') } : null,
  };
}

export function tpl(id: string, tool: string, label: string, parts: [string, boolean][], values: CommandTemplate['values']): CommandTemplate {
  return {
    template_id: id, tool, label, rendered: true, command: parts.map((p) => p[0]).join(''), parts: parts.map(([text, target]) => ({ text, target })),
    values, blocked_reason: null,
  };
}

export function suggestions(): Suggestion[] {
  // wie der Server (18.12): Label ohne Uhrzeit, die Zeit der Quelle in `ts`
  const ev = (claim: string, label: string) => ({ claim_key: hex64(claim), unit_id: `${T1}@18432`, lines: [6, 6] as [number, number], label, ts: at('14:02:11.204') });
  const d1: Suggestion = {
    suggestion_key: 'sg:5a1f0c3e9b27d4a8c6e2f013', origin: 'rule', rule_id: 'R-ANON-ZUGRIFF', goal_id: 'PZ-AUTH-ANON', kind: 'goal',
    title: 'Unauthentisierten Zugriff auf 192.168.56.101:21 prüfen', ctrl: false,
    title_parts: [{ text: 'Unauthentisierten Zugriff auf ', target: false }, { text: '192.168.56.101:21', target: true }, { text: ' prüfen', target: false }],
    host_id: hostId(IP101), service_id: serviceId(IP101, 21), host_label: IP101,
    reason: 'FTP-Dienst ohne geprüfte anonyme Anmeldung', ctrl_reason: false,
    evidence: [ev('ftp-21', 'nmap -sV · Zeile 6')],
    stages: { question: 'Welche Daten gibt dieser Dienst ohne Anmeldung preis?', direction: 'Viele vsftpd-Installationen erlauben Gast- oder anonyme Logins.' },
    templates: [
      tpl('nmap-ftp-anon', 'nmap', 'nmap-Skript ftp-anon', [['nmap -p ', false], ['21', true], [' --script ftp-anon ', false], [IP101, true]], [
        { slot: 'service.port', type: 'port', label: 'Port', value: '21', ctrl: false, target: true, safe: true },
        { slot: 'host.ip', type: 'ip', label: 'IP', value: IP101, ctrl: false, target: true, safe: true },
      ]),
      tpl('ftp-anon-login', 'ftp', 'ftp-Client', [['ftp ', false], [IP101, true]], [{ slot: 'host.ip', type: 'ip', label: 'IP', value: IP101, ctrl: false, target: true, safe: true }]),
    ],
    state: 'open', decision_id: null, basis: '3c9f1a2b7d4e6f80', flags: [], ts: at('14:02:11.204'), ai: null,
  };
  const d2: Suggestion = {
    suggestion_key: 'sg:8e2d71b04c9a3f5e1d6b0a27', origin: 'rule', rule_id: 'R-VERSION-RECHERCHE', goal_id: 'PZ-VULN-RECHERCHE', kind: 'goal',
    title: 'Version recherchieren: vsftpd 2.3.4 (192.168.56.101:21)', ctrl: false,
    title_parts: [{ text: 'Version recherchieren: ', target: false }, { text: 'vsftpd 2.3.4', target: true }, { text: ' (', target: false }, { text: '192.168.56.101:21', target: true }, { text: ')', target: false }],
    host_id: hostId(IP101), service_id: serviceId(IP101, 21), host_label: IP101,
    reason: 'Produkt und Version bekannt', ctrl_reason: false,
    evidence: [ev('ftp-21-version', 'nmap -sV · Zeile 6')],
    stages: { question: 'Gibt es für diese Version bekannte Schwachstellen?', direction: 'Exploit-Datenbanken nach Produkt und Version durchsuchen.' },
    templates: [
      tpl('searchsploit', 'searchsploit', 'searchsploit', [['searchsploit ', false], ['vsftpd 2.3.4', true]], [
        { slot: 'service.product', type: 'word', label: 'Produkt', value: 'vsftpd', ctrl: false, target: true, safe: true },
        { slot: 'service.version', type: 'word', label: 'Version', value: '2.3.4', ctrl: false, target: true, safe: true },
      ]),
    ],
    state: 'open', decision_id: null, basis: '7a0e5d3c1b9f2e64', flags: [], ts: at('14:02:11.204'), ai: null,
  };
  return [d1, d2];
}

/** D2-Variante mit Shell-Sonderzeichen: keine fertige Vorlage, nur Einzelwerte (Szenario `hostile`). */
export function hostileSuggestion(): Suggestion {
  const d2 = suggestions()[1] as Suggestion;
  return {
    ...d2,
    suggestion_key: 'sg:0f9e8d7c6b5a493827161504',
    title: `Version recherchieren: ${SHELL_PRODUCT}`,
    title_parts: [{ text: 'Version recherchieren: ', target: false }, { text: SHELL_PRODUCT, target: true }],
    templates: [
      {
        template_id: 'searchsploit', tool: 'searchsploit', label: 'searchsploit', rendered: false, command: null, parts: [],
        values: [
          { slot: 'tool', type: 'word', label: 'Werkzeug', value: 'searchsploit', ctrl: false, target: false, safe: true },
          { slot: 'service.product', type: 'word', label: 'Produkt', value: SHELL_PRODUCT, ctrl: false, target: true, safe: false },
        ],
        blocked_reason: 'shell_meta',
      },
    ],
    flags: ['from_target'],
  };
}

export function next(): NextView {
  return {
    clarify: [
      {
        kind: 'ctx_suggestion', ordinal: 2, item_key: `ctx:${T3}@412`, ts: at('16:52:31.447'), terminal_id: T3, from_off: 412, stage_kind: 'revshell', units: 1,
        suggested_host: hostId(IP101), suggested_label: IP101, reason: 'Callback von 192.168.56.101 (nc:4445)', claim_key: hex64('cb-101'),
        terminal: TERM[T3] ?? null, from_ts: at('16:52:31.447'), reason_ts: at('16:52:31.447'),
        excerpt: { unit_id: `${T3}@64`, lines: [3, 3], text: ['connect to [192.168.56.102] from (UNKNOWN) [10.66.66.66] 31337'], ctrl: false, note: 'second_callback', ts: at('16:53:02.118') },
      },
      {
        kind: 'merge_suggestion', ordinal: 3, item_key: `merge:${hex64('merge-101').slice(0, 16)}`, ts: at('15:20:44.317'),
        identifiers: [
          { key: hostId(IP101), label: IP101, verdict: 'in' },
          { key: 'ip:default/fd00:56::101', label: 'fd00:56::101', verdict: 'out' },
          { key: 'mac:08:00:27:63:7e:e7', label: '08:00:27:63:7e:e7', verdict: null },
        ],
        shared: 'mac:08:00:27:63:7e:e7', reason: 'gleiche MAC-Adresse 08:00:27:63:7e:e7 auf fd00:56::101 (ausserhalb) und 192.168.56.101 (im Scope)',
      },
    ],
    confirm: [],
    suggestions: suggestions(),
    suggestions_available: true,
    quiet: { heuristic: 0, out_of_scope: 21, mentions: 2, system_accounts: 27, own_address: 3 },
    open: 2,
  };
}

export function seen(): SeenView {
  const since = at('16:40:00.000');
  return { seen_at: since, new: { since, count: 3, hosts: [], access: [hostId(IP101)], services: [], items: [], keysteps: ['k:31001', 'k:31877'] } };
}

export const MAP_IDS = { IP101, IP103, IP104, T2 };
