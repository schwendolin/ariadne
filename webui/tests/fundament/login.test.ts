// Anmeldung (SCREENS 9, Briefing 4.1, A 7.2, R5): ein Feld, alle Fehler unter dem Feld, nie ein
// Passphrase-Feld, Code nie im Speicher; Sitzung beendet führt ohne Grund zur Anmeldung.
// Besitzer: ui-fundament.
import { fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../src/lib/api/client';
import LoginView from '../../src/lib/shell/LoginView.svelte';
import { makeApp, settle, stopAll } from './helpers';

afterEach(stopAll);

async function loginPage() {
  const h = await makeApp('login');
  const r = render(LoginView, { props: { app: h.app } });
  const input = screen.getByLabelText('Anmeldecode') as HTMLInputElement;
  const submit = screen.getByRole('button', { name: 'Anmelden' }) as HTMLButtonElement;
  return { ...h, ...r, input, submit };
}

async function attempt(input: HTMLInputElement, submit: HTMLButtonElement, code: string): Promise<void> {
  await fireEvent.input(input, { target: { value: code } });
  await fireEvent.click(submit);
  await settle(8);
}

describe('Anmeldung', () => {
  it('ein Feld «Anmeldecode», Hinweise, kein Passphrase-Feld', async () => {
    const { container, app } = await loginPage();
    expect(app.phase).toBe('login');
    expect(container.querySelectorAll('input')).toHaveLength(1);
    expect(container.querySelector('input[type="password"]')).toBeNull();
    expect(container.textContent).toContain('Ariadne fragt hier nie nach Passphrasen.');
    expect(container.textContent?.replace(/\s+/g, ' ')).toContain(
      'Code im Terminal holen: ariadne ui --code (oder ariadne ui öffnet den Browser direkt) Vom Mac: ariadne-mac start oder ssh -t kali-sl code',
    );
    // Tippcode: 10 Zeichen (sessions.format_typed, «ABCDE-FGHJK»)
    expect((screen.getByLabelText('Anmeldecode') as HTMLInputElement).placeholder).toBe('XXXXX-XXXXX');
  });

  it('Eingabe ungültig: Fehler ohne Anfrage an den Server', async () => {
    const { input, submit, backend } = await loginPage();
    const spy = vi.spyOn(backend, 'login');
    await attempt(input, submit, 'k7q2 m4');
    expect(screen.getByRole('alert').textContent).toBe('Eingabe ungültig.');
    expect(spy).not.toHaveBeenCalled();
    expect(input.getAttribute('aria-invalid')).toBe('true');
    expect(input.classList.contains('invalid')).toBe(true);
  });

  it('Code unbekannt, abgelaufen oder schon benutzt (401)', async () => {
    const { input, submit, app } = await loginPage();
    await attempt(input, submit, 'FALSCH00');
    expect(screen.getByRole('alert').textContent).toBe('Code unbekannt, abgelaufen oder schon benutzt.');
    expect(app.phase).toBe('login');
  });

  it('zu viele Versuche (429): Feld gesperrt, «gesperrt», neuer Code erst nach «Neuen Code eingeben»', async () => {
    const { input, submit } = await loginPage();
    await attempt(input, submit, 'SPERRE00');
    expect(screen.getByRole('alert').textContent).toBe('Zu viele Versuche. Neuen Code im Terminal holen.');
    expect(input.disabled).toBe(true);
    expect(input.placeholder).toBe('gesperrt');
    expect(submit.disabled).toBe(true);
    await fireEvent.click(screen.getByRole('button', { name: 'Neuen Code eingeben' }));
    await settle();
    expect(input.disabled).toBe(false);
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('Daemon nicht erreichbar', async () => {
    const { input, submit, backend } = await loginPage();
    vi.spyOn(backend, 'login').mockRejectedValueOnce(new ApiError('network', 0, 'x'));
    await attempt(input, submit, 'ABCD-EFGH');
    expect(screen.getByRole('alert').textContent).toBe('Daemon nicht erreichbar.');
  });

  it('gültiger Code (getippt mit Bindestrich und Kleinbuchstaben) meldet an', async () => {
    const { input, submit, app, backend } = await loginPage();
    const spy = vi.spyOn(backend, 'login');
    await attempt(input, submit, 'abcde-fghjk');
    expect(spy).toHaveBeenCalledWith('abcdefghjk');
    expect(app.phase).toBe('project');
  });

  it('Code aus dem Fragment: abgelaufen ergibt den Fehler auf der Anmeldeseite', async () => {
    const { app } = await makeApp('login', { code: 'FALSCH00' });
    expect(app.phase).toBe('login');
    expect(app.loginError).toBe('unauthorized');
  });

  it('Sitzung beendet (401 mitten in der Arbeit): Anmeldung mit allgemeinem Grund, Daten verworfen', async () => {
    const { app, backend } = await makeApp('normal');
    expect(app.phase).toBe('project');
    const project = app.project;
    app.ui.openDialog({ kind: 'help' });
    await backend.logout();
    await app.refreshStatus();
    await settle();
    expect(app.phase).toBe('login');
    expect(app.loginError).toBeNull();
    expect(app.project).toBeNull();
    expect(project?.disposed).toBe(true);
    expect(app.ui.dialog).toBeNull();
    const r = render(LoginView, { props: { app } });
    expect(r.container.querySelector('[role="alert"]')).toBeNull();
    // Praxistest 1: ohne Hinweis aus dem Strom ein allgemeiner Grund
    expect(r.container.querySelector('[data-testid="login-ended"]')?.textContent).toBe('Die Sitzung wurde beendet. Neue Anmeldung: ariadne ui');
  });

  it('Abmelden über das Menü löscht die Sitzung und zeigt die Anmeldung', async () => {
    const { app, backend } = await makeApp('normal');
    const spy = vi.spyOn(backend, 'logout');
    await app.logout();
    expect(spy).toHaveBeenCalledOnce();
    expect(app.phase).toBe('login');
    expect(app.status).toBeNull();
  });
});
