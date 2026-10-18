/**
 * Mock-Daten, Teil Fundament: Projekt «ms2», Status, Terminals, Sitzung, Vorlieben im Standbild
 * 16:54 (Briefing Anhang A, Datum 2026-10-08, CEST = UTC+2). Form genau wie docs/web-api.md.
 * Besitzer: ui-fundament.
 */
import type { PrefsView, ProjectView, SessionView, Status, StageView, Terminal, TermRef } from '../../api/types';

export const DAY = '2026-10-08';

/** Lokalzeit «16:54:00.000» (CEST) als ISO-UTC mit Mikrosekunden. */
export function at(local: string): string {
  const [hms, frac = '0'] = local.split('.');
  const [h = '0', m = '0', s = '0'] = (hms ?? '0:0:0').split(':');
  const utcH = String(Number(h) - 2).padStart(2, '0');
  return `${DAY}T${utcH}:${m.padStart(2, '0')}:${s.padStart(2, '0')}.${frac.padEnd(6, '0').slice(0, 6)}Z`;
}

/** ts_ns als Dezimalstring zu `at()`. */
export function nsOf(iso: string): string {
  const ms = Date.parse(iso);
  const micro = Number(/\.(\d{6})Z$/.exec(iso)?.[1] ?? '0') % 1000;
  return `${BigInt(ms) * 1000000n + BigInt(micro) * 1000n}`;
}

/** Deterministische 64-Hex-Schlüssel (claim_key) aus einem Namen. */
export function hex64(name: string): string {
  let out = '';
  let h = 0x811c9dc5;
  for (let round = 0; out.length < 64; round++) {
    for (const ch of `${name}#${round}`) {
      h ^= ch.charCodeAt(0);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    out += h.toString(16).padStart(8, '0');
  }
  return out.slice(0, 64);
}

export const PID = '0199a3c2-7e10-7000-8000-0000000000a1';
export const NOW = at('16:54:00.000');
export const KALI_IP = '192.168.56.102';
export const SCOPE = '192.168.56.0/24';

export const T1 = '0199a3c2-7e11-7000-8000-00000000c011';
export const T2 = '0199a3c2-7e12-7000-8000-00000000c022';
export const T3 = '0199a3c2-7e13-7000-8000-00000000c033';
export const T4 = '0199a3c2-7e14-7000-8000-00000000c044';

export const TERM: Record<string, TermRef> = {
  [T1]: { terminal_id: T1, ordinal: 1, label: 'scan' },
  [T2]: { terminal_id: T2, ordinal: 2, label: 'msf' },
  [T3]: { terminal_id: T3, ordinal: 3, label: 'listener' },
};

export function hostId(ip: string): string {
  return `ip:default/${ip}`;
}
export function serviceId(ip: string, port: number, proto: 'tcp' | 'udp' = 'tcp'): string {
  return `svc:ip:default/${ip}|${proto}/${port}`;
}

export function session(origin: 'sshd' | 'local' = 'sshd'): SessionView {
  return { session_id: 's-7f3a21', origin, created_at: at('16:40:02.000'), expires_at: '2026-10-09T02:40:02.000000Z' };
}

export const KALI_STAGE: StageView = {
  depth: 0, kind: 'local', host_id: null, host_label: null, user: 'kali', state: 'active', source: 'auto', auto: false, candidate: null, opened_at: 0,
};

export function project(): ProjectView {
  return {
    id: PID,
    slug: 'ms2',
    name: 'Metasploitable2 Lab',
    profile: 'lab',
    chain_head_ok: true,
    created_at: at('13:58:40.112'),
    scope: { include: [SCOPE], exclude: [], version: 1 },
    lab_guard: { public_targets: false, confirmed_not_customer: false },
    started_at: at('13:57:02.512'),
    chain: { head_seq: 48211, head_hash: '9f2c41e0a1b7a3d18c', head_ok: true },
    ctrl: false,
  };
}

export function terminals(): Terminal[] {
  const t1: Terminal = {
    terminal_id: T1, short_id: T1.slice(-8), tty: '/dev/pts/1', state: 'paused', pause_until: at('17:00:05.218'),
    held_slug: null, preroll_s: 0, mux: false, context_label: 'Kali', ctrl: false, ordinal: 1, label: 'scan',
    opened_at: at('13:57:02.512'), web_pause_left_s: 1200, shell: 'zsh', connected: true, stack: [KALI_STAGE],
    last_command: {
      cmd_id: `${T1}@51200`, cmd_ref: `${T1.slice(-8)}@51200`, text: 'nmap -sV -sC 192.168.56.110', started_at: at('16:01:07.540'),
      ended_at: at('16:01:31.002'), exit: 0, src_ip: KALI_IP, origin: 'local',
    },
    remote_segment: null, suggestion: null,
  };
  const t2: Terminal = {
    terminal_id: T2, short_id: T2.slice(-8), tty: '/dev/pts/2', state: 'on', pause_until: null, held_slug: null, preroll_s: 0,
    mux: false, context_label: 'Kali › 192.168.56.101 [msf] (auto)', ctrl: false, ordinal: 2, label: 'msf', opened_at: at('16:43:51.077'),
    web_pause_left_s: 1800, shell: 'zsh', connected: true,
    stack: [KALI_STAGE, { depth: 1, kind: 'msf', host_id: hostId('192.168.56.101'), host_label: '192.168.56.101', user: null, state: 'active', source: 'auto', auto: true, candidate: null, opened_at: 20480 }],
    last_command: { cmd_id: `${T2}@1024`, cmd_ref: `${T2.slice(-8)}@1024`, text: 'msfconsole -q', started_at: at('16:43:55.410'), ended_at: null, exit: null, src_ip: KALI_IP, origin: 'local' },
    remote_segment: { since: at('16:45:12.384'), lines: 41 }, suggestion: null,
  };
  const t3: Terminal = {
    terminal_id: T3, short_id: T3.slice(-8), tty: '/dev/pts/3', state: 'on', pause_until: null, held_slug: null, preroll_s: 0,
    mux: false, context_label: 'Kali › ? [Reverse Shell]', ctrl: false, ordinal: 3, label: 'listener', opened_at: at('16:51:48.630'),
    web_pause_left_s: 1800, shell: 'zsh', connected: true,
    stack: [KALI_STAGE, { depth: 1, kind: 'revshell', host_id: null, host_label: null, user: null, state: 'active', source: 'auto', auto: false, candidate: null, opened_at: 412 }],
    last_command: { cmd_id: `${T3}@64`, cmd_ref: `${T3.slice(-8)}@64`, text: 'nc -lvnp 4445', started_at: at('16:51:52.004'), ended_at: null, exit: null, src_ip: KALI_IP, origin: 'local' },
    remote_segment: null,
    suggestion: { item_key: `ctx:${T3}@412`, from_off: 412, host_id: hostId('192.168.56.101'), host_label: '192.168.56.101', reason: 'Callback von 192.168.56.101 (nc:4445)' },
  };
  return [t1, t2, t3];
}

/** held-Variante (T4 bei lame), für Szenario `held`. */
export function heldTerminal(): Terminal {
  return {
    terminal_id: T4, short_id: T4.slice(-8), tty: '/dev/pts/4', state: 'held', pause_until: null, held_slug: 'lame', preroll_s: 0,
    mux: false, context_label: null, ctrl: false, ordinal: null, label: null, opened_at: at('16:30:00.000'), web_pause_left_s: null,
    shell: 'zsh', connected: true, stack: [], last_command: null, remote_segment: null, suggestion: null,
  };
}

export function status(terms: Terminal[], generation: number, presentation: boolean, origin: 'sshd' | 'local'): Status {
  const states = terms.map(({ shell: _s, connected: _c, stack: _st, last_command: _l, remote_segment: _r, suggestion: _g, ...ts }) => ts);
  return {
    version: '0.1.0',
    api_version: 2,
    server_time: NOW,
    session: session(origin),
    operator: { exists: true, unlocked: true, own_secrets: 2 },
    project: { id: PID, slug: 'ms2', name: 'Metasploitable2 Lab', profile: 'lab', chain_head_ok: true },
    active: { slug: 'ms2', stopped: false, end_reason: null },
    locked: false,
    recording: {
      connected: states.length,
      on: states.filter((s) => s.state === 'on').length,
      paused: states.filter((s) => s.state === 'paused').length,
      held: states.filter((s) => s.state === 'held').length,
      mux: 0,
    },
    terminals: states,
    idle: { idle_s: 60, end_after_s: 12 * 3600 },
    preroll: { terminals: 0, seconds: 0, window_s: 900, ask_terminals: 0, ask_seconds: 0, outage_terminals: 0, outage_seconds: 0 },
    presentation,
    llm: { mode: 'off', model: null, available: false, budget: { month_limit_usd: 20, month_used_usd: 0 } },
    generation,
    ingest: { active: true, last_error: null },
    disk_low: false,
    scope_warning: {
      cmd_id: `${T1}@40960`, cmd_ref: `${T1.slice(-8)}@40960`, terminal_id: T1, ts: at('15:20:44.317'), terminal: TERM[T1] as TermRef,
      text: 'nmap -6 -sV -oX scans/v6.xml fd00:56::101', ctrl: false, targets: [{ value: 'fd00:56::101', verdict: 'out', ctrl: false }],
      scope: [SCOPE], acked: true,
    },
  };
}

export function prefs(): PrefsView {
  return { prefs: { theme: 'system', density: 'comfortable', learning: true }, updated_at: null };
}
