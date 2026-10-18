// Secrets und Kopieren mit Ziel (E99, E104, E111, Briefing 9.4, 9.5): verdeckt ohne Länge, Aufdecken
// einzeln und nie im Präsentationsmodus, verdeckt sich beim Einschalten, «In die Kali» nur über den
// Daemon und nur im Profil lab, nie in die Zwischenablage des Browsers; jeder Kopierknopf nennt das
// Ziel. Besitzer: ui-fundament.
import { fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as base from '../../src/lib/mock/data/base';
import { MockBackend } from '../../src/lib/mock/backend';
import CopyButton from '../../src/lib/ui/CopyButton.svelte';
import SecretValue from '../../src/lib/ui/SecretValue.svelte';
import { settle } from './helpers';

function backend(scenario: ConstructorParameters<typeof MockBackend>[0] = 'normal'): MockBackend {
  const b = new MockBackend(scenario);
  b.delay = 0;
  return b;
}

const SECRET = { ref: 'input' as const, seq: 47001 };

afterEach(() => {
  vi.restoreAllMocks();
});

describe('SecretValue', () => {
  it('verdeckt ohne Längenangabe; Aufdecken einzeln, Verdecken entfernt den Wert aus dem DOM', async () => {
    const b = backend();
    const reveal = vi.spyOn(b, 'reveal');
    const { container } = render(SecretValue, { props: { secret: SECRET, pid: base.PID, backend: b, presentation: false, profile: 'lab', hint: 'Passwort' } });
    expect(container.textContent).toContain('••••••••');
    expect(container.textContent).toContain('(Passwort)');
    await fireEvent.click(screen.getByRole('button', { name: 'Aufdecken' }));
    await settle();
    expect(reveal).toHaveBeenCalledWith(base.PID, SECRET);
    expect(container.textContent).toContain('mock-Ziel-Passwort');
    await fireEvent.click(screen.getByRole('button', { name: 'Verdecken' }));
    expect(container.textContent).not.toContain('mock-Ziel-Passwort');
  });

  it('im Präsentationsmodus: Aufdecken und «In die Kali» gesperrt, mit Grund', () => {
    const b = backend();
    render(SecretValue, { props: { secret: SECRET, pid: base.PID, backend: b, presentation: true, profile: 'lab' } });
    const reveal = screen.getByRole('button', { name: 'Aufdecken' }) as HTMLButtonElement;
    expect(reveal.disabled).toBe(true);
    expect(reveal.title).toBe('Aufdecken ist im Präsentationsmodus gesperrt');
    const kali = screen.getByRole('button', { name: 'In die Kali' }) as HTMLButtonElement;
    expect(kali.disabled).toBe(true);
    expect(kali.title).toBe('Im Präsentationsmodus gesperrt');
  });

  it('verdeckt sich sofort, wenn der Präsentationsmodus angeht', async () => {
    const b = backend();
    const r = render(SecretValue, { props: { secret: SECRET, pid: base.PID, backend: b, presentation: false, profile: 'lab' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Aufdecken' }));
    await settle();
    expect(r.container.textContent).toContain('mock-Ziel-Passwort');
    await r.rerender({ secret: SECRET, pid: base.PID, backend: b, presentation: true, profile: 'lab' });
    await settle();
    expect(r.container.textContent).not.toContain('mock-Ziel-Passwort');
  });

  it('Korrektur SEC-UI-2: eine verspätete Antwort von «Aufdecken» zeigt im Präsentationsmodus nichts', async () => {
    const b = backend();
    let release: (v: { value: string; ctrl: boolean }) => void = () => undefined;
    vi.spyOn(b, 'reveal').mockImplementation(() => new Promise((res) => (release = res)));
    const r = render(SecretValue, { props: { secret: SECRET, pid: base.PID, backend: b, presentation: false, profile: 'lab' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Aufdecken' }));
    // Der Server hat schon geantwortet (ausgeschaltet), die Antwort ist noch unterwegs; jetzt an:
    await r.rerender({ secret: SECRET, pid: base.PID, backend: b, presentation: true, profile: 'lab' });
    await settle();
    release({ value: 'geheim-731', ctrl: false });
    await settle();
    expect(r.container.textContent).not.toContain('geheim-731');
    expect(r.container.textContent).toContain('••••••••');
    // auch ein Hin und Her während der Anfrage verwirft die Antwort
    await r.rerender({ secret: SECRET, pid: base.PID, backend: b, presentation: false, profile: 'lab' });
    await settle();
    await fireEvent.click(screen.getByRole('button', { name: 'Aufdecken' }));
    await r.rerender({ secret: SECRET, pid: base.PID, backend: b, presentation: true, profile: 'lab' });
    await settle();
    await r.rerender({ secret: SECRET, pid: base.PID, backend: b, presentation: false, profile: 'lab' });
    await settle();
    release({ value: 'geheim-732', ctrl: false });
    await settle();
    expect(r.container.textContent).not.toContain('geheim-732');
  });

  it('eine ältere Antwort von «Aufdecken» überschreibt keine neuere', async () => {
    const b = backend();
    const waiting: ((v: { value: string; ctrl: boolean }) => void)[] = [];
    vi.spyOn(b, 'reveal').mockImplementation(() => new Promise((res) => waiting.push(res)));
    const r = render(SecretValue, { props: { secret: SECRET, pid: base.PID, backend: b, presentation: false, profile: 'lab' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Aufdecken' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Aufdecken' }));
    expect(waiting.length).toBe(2);
    waiting[1]?.({ value: 'neu-2', ctrl: false });
    await settle();
    waiting[0]?.({ value: 'alt-1', ctrl: false });
    await settle();
    expect(r.container.textContent).toContain('neu-2');
    expect(r.container.textContent).not.toContain('alt-1');
  });

  it('nur im Profil lab aufdeckbar', () => {
    render(SecretValue, { props: { secret: SECRET, pid: base.PID, backend: backend(), presentation: false, profile: 'customer' } });
    expect((screen.getByRole('button', { name: 'Aufdecken' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'In die Kali' }) as HTMLButtonElement).title).toBe('Nur im Profil lab');
  });
});

describe('CopyButton', () => {
  it('«In die Kali» geht über den Daemon, nie in die Zwischenablage des Browsers', async () => {
    const b = backend();
    const copy = vi.spyOn(b, 'copyToKali');
    const write = vi.fn();
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: write }, configurable: true });
    render(CopyButton, { props: { target: 'kali', secret: SECRET, pid: base.PID, backend: b, presentation: false, profile: 'lab' } });
    await fireEvent.click(screen.getByRole('button', { name: 'In die Kali' }));
    await settle();
    expect(copy).toHaveBeenCalledWith(base.PID, SECRET);
    expect(write).not.toHaveBeenCalled();
    expect(screen.getByRole('status').textContent).toBe('In der Zwischenablage der Kali, wird nach 30 s geleert');
  });

  it('fehlt das Werkzeug in der Kali: fester Text (503 clipboard_tool)', async () => {
    render(CopyButton, { props: { target: 'kali', secret: SECRET, pid: base.PID, backend: backend('noclip'), presentation: false, profile: 'lab' } });
    await fireEvent.click(screen.getByRole('button', { name: 'In die Kali' }));
    await settle();
    expect(screen.getByRole('status').textContent).toBe(
      'In der Kali fehlt ein Werkzeug für die Zwischenablage: xclip, xsel oder wl-copy installieren',
    );
  });

  it('«Kopieren · Mac» schreibt den Befehl ohne Zeilenumbruch am Ende', async () => {
    const write = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: write }, configurable: true });
    render(CopyButton, { props: { target: 'mac', text: 'nmap -p 21 192.168.56.101\n' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Kopieren · Mac' }));
    await settle();
    expect(write).toHaveBeenCalledWith('nmap -p 21 192.168.56.101');
    expect(screen.getByRole('status').textContent).toBe('In der Zwischenablage des Macs');
  });

  it('ohne Zwischenablage: markiertes Textfeld zum Kopieren von Hand', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    const { container } = render(CopyButton, { props: { target: 'mac', text: 'searchsploit vsftpd 2.3.4' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Kopieren · Mac' }));
    await settle();
    const area = container.querySelector('textarea') as HTMLTextAreaElement;
    expect(area.readOnly).toBe(true);
    expect(area.value).toBe('searchsploit vsftpd 2.3.4');
  });
});
