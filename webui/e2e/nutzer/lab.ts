/**
 * Steuerung des echten Durchlaufs als Nutzer (tests/e2e/user_lab.py) aus dem Browsertest.
 *
 * Der Python-Prozess baut ein isoliertes HOME mit XDG-Ordnern, richtet Ariadne mit `setup` und
 * `init` ein, startet den Daemon mit Web-Server auf einem freien Port und öffnet echte zsh-Terminals
 * im PTY (Shim, Marker, F12). Die Werkzeuge (nmap, msfconsole, nc, ip) sind Attrappen mit den
 * Daten aus Anhang A des Briefings; nichts geht ins Netz. Gesteuert wird über JSON-Zeilen auf
 * stdin/stdout: Anfrage `{id, op, args}`, Antwort `{id, ok, result | error}`.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';

export const REPO = resolve(import.meta.dirname, '../../..');
const PYTHON = process.env.ARIADNE_PYTHON ?? resolve(REPO, '.venv/bin/python');

export function freePort(): Promise<number> {
  return new Promise((resolveP, reject) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      s.close(() => (typeof addr === 'object' && addr ? resolveP(addr.port) : reject(new Error('kein Port'))));
    });
  });
}

interface Reply {
  id?: string;
  ok?: boolean;
  result?: unknown;
  error?: string;
  ready?: boolean;
  base?: string;
}

export class UserLab {
  private proc: ChildProcess;
  private waiting = new Map<string, (r: Reply) => void>();
  private seq = 0;
  private stderr = '';
  private ready: Promise<Reply>;
  readonly port: number;

  private constructor(port: number) {
    this.port = port;
    this.proc = spawn(PYTHON, ['-m', 'tests.e2e.user_lab', '--port', String(port)], {
      cwd: REPO,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
    });
    this.proc.stderr?.on('data', (d: Buffer) => {
      this.stderr = (this.stderr + d.toString('utf8')).slice(-6000);
    });
    let onReady: (r: Reply) => void = () => {};
    this.ready = new Promise((r) => (onReady = r));
    const rl = createInterface({ input: this.proc.stdout! });
    rl.on('line', (line) => {
      let msg: Reply;
      try {
        msg = JSON.parse(line) as Reply;
      } catch {
        return;
      }
      if (msg.ready) return onReady(msg);
      const cb = msg.id ? this.waiting.get(msg.id) : undefined;
      if (cb && msg.id) {
        this.waiting.delete(msg.id);
        cb(msg);
      }
    });
  }

  static async start(): Promise<UserLab> {
    const lab = new UserLab(await freePort());
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`user_lab nicht bereit: ${lab.stderr}`)), 60_000),
    );
    await Promise.race([lab.ready, timeout]);
    return lab;
  }

  get base(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  call<T = unknown>(op: string, args: Record<string, unknown> = {}, timeoutMs = 180_000): Promise<T> {
    const id = String(++this.seq);
    return new Promise<T>((resolveP, reject) => {
      const timer = setTimeout(() => {
        this.waiting.delete(id);
        reject(new Error(`user_lab ${op}: keine Antwort (${this.stderr.slice(-800)})`));
      }, timeoutMs);
      this.waiting.set(id, (r) => {
        clearTimeout(timer);
        if (r.ok) resolveP(r.result as T);
        else reject(new Error(`user_lab ${op}: ${r.error ?? 'Fehler'}`));
      });
      this.proc.stdin?.write(`${JSON.stringify({ id, op, args })}\n`);
    });
  }

  /** `ariadne …` als Nutzer (mit der Passphrase über einen Dateideskriptor, wenn verlangt). */
  cli(args: string[], passphrase = false, check = true): Promise<string> {
    return this.call<string>('cli', { args, passphrase, check });
  }

  /** Startadresse mit Einmalcode im Fragment, wie aus der Startdatei von `ariadne ui`. */
  uiUrl(): Promise<string> {
    return this.call<string>('ui_url');
  }

  async close(): Promise<void> {
    const p = this.proc;
    if (p.exitCode !== null) return;
    p.stdin?.write(`${JSON.stringify({ id: 'close', op: 'close' })}\n`);
    p.stdin?.end();
    await new Promise<void>((r) => {
      const kill = setTimeout(() => {
        p.kill('SIGTERM');
        r();
      }, 20_000);
      p.once('exit', () => {
        clearTimeout(kill);
        r();
      });
    });
  }
}
