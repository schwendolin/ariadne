// Reiter Findings (Screen 8, E113) gegen den Mock: Liste mit Auswahl, Formular mit nur geänderten
// Feldern, neu aus dem Beleg («Als Finding») mit Beleg und «angelegt aus», final nur mit Schwere,
// ATT&CK und CVE mit Hypothese, Belege öffnen und entfernen, Löschen mit Grund, ⌘↵, Vorschau nur
// über SafeMarkdown, feindliche Titel als Text. Besitzer: ui-verlauf.
import { cleanup, fireEvent, render, screen, within } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../src/lib/api/client';
import type { DecisionInput } from '../../src/lib/api/types';
import FindingsView from '../../src/lib/findings/FindingsView.svelte';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { T2 } from '../../src/lib/mock/data/base';
import { findingF1, findingHostile, HOSTILE_FINDING_TITLE } from '../../src/lib/mock/data/history';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, press, settle, stopAll, until } from '../fundament/helpers';

const F1 = findingF1().finding_id;

beforeAll(() => {
  installKeymap(window);
});

afterEach(() => {
  cleanup();
  resetKeymapForTests();
  stopAll();
  document.body.replaceChildren();
  url.go('karte', {}, { replace: true, keep: false });
});

async function mount(scenario: Parameters<typeof makeApp>[0] = 'normal', patch: Parameters<typeof url.go>[1] = {}, before?: (h: Awaited<ReturnType<typeof makeApp>>) => void) {
  url.go('findings', patch, { replace: true, keep: false });
  const h = await makeApp(scenario);
  const project = h.app.project as ProjectStore;
  await until(() => project.findings.loaded);
  if (before) {
    before(h);
    await project.findings.load();
  }
  const view = render(FindingsView, { props: { app: h.app, project } });
  await settle();
  return { ...h, project, view };
}

const title = () => screen.getByLabelText('Titel') as HTMLInputElement;
const saveBtn = () => screen.getByRole('button', { name: /^Speichern/ });
/** Entscheide eines Aufrufs ohne client_ref (vergibt ProjectStore.decide) */
const decisions = (spy: { mock: { calls: unknown[][] } }, i = 0) =>
  ((spy.mock.calls[i]?.[1] ?? []) as DecisionInput[]).map((d) => {
    const { client_ref: _r, ...rest } = d;
    return rest;
  });

describe('Findings: Liste und Formular', () => {
  it('wählt ohne Auswahl das erste Finding und zeigt es wie im Design', async () => {
    const { view } = await mount();
    await until(() => url.get('finding') === F1 && !!screen.queryByLabelText('Titel'));
    const card = view.container.querySelector('a.card.sel') as HTMLElement;
    expect(card.textContent).toContain('F1');
    expect(card.textContent).toContain('Entwurf');
    expect(card.textContent).toContain('Kritisch');
    expect(card.textContent).toContain('2 Belege');
    expect(title().value).toBe('vsftpd 2.3.4 mit Hintertür: Root-Shell ohne Anmeldung');
    const sev = screen.getByRole('radiogroup', { name: 'Schwere, setzt nur du' });
    expect(within(sev).getByRole('radio', { name: 'Kritisch' }).getAttribute('aria-checked')).toBe('true');
    expect(view.container.textContent).toContain('CVE-2011-2523');
    expect(view.container.textContent).toContain('Hypothese, ohne eigenen Beleg');
    expect(view.container.textContent).toContain('T2 msf · msfconsole -q · Zeilen 44 bis 47');
    expect(view.container.textContent).toContain('Herkunft: von dir');
    expect(view.container.textContent).toContain('angelegt aus dem Beleg');
    expect(view.container.textContent).toContain('Verlauf');
  });

  it('Speichern schickt nur geänderte Felder; ohne Änderung «Keine Änderungen»', async () => {
    const { backend, view } = await mount('normal', { finding: F1 });
    await until(() => !!screen.queryByLabelText('Titel'));
    const spy = vi.spyOn(backend, 'decide');
    await fireEvent.click(saveBtn());
    await settle();
    expect(spy).not.toHaveBeenCalled();
    expect(view.container.textContent).toContain('Keine Änderungen');

    await fireEvent.input(title(), { target: { value: 'vsftpd 2.3.4 Hintertür' } });
    await fireEvent.click(within(screen.getByRole('radiogroup', { name: 'Schwere, setzt nur du' })).getByRole('radio', { name: 'Hoch' }));
    await fireEvent.click(saveBtn());
    await until(() => spy.mock.calls.length === 1);
    expect(decisions(spy)).toEqual([{ kind: 'd.finding.update', payload: { finding_id: F1, title: 'vsftpd 2.3.4 Hintertür', severity: 'high' } }]);
    await until(() => !!view.container.textContent?.includes('Gespeichert'));
    await until(() => !!view.container.querySelector('a.card.sel')?.textContent?.includes('Hoch'));
  });

  it('Titel fehlt wird gemeldet', async () => {
    const { backend } = await mount('normal', { finding: F1 });
    await until(() => !!screen.queryByLabelText('Titel'));
    const spy = vi.spyOn(backend, 'decide');
    await fireEvent.input(title(), { target: { value: '   ' } });
    await fireEvent.click(saveBtn());
    await settle();
    expect(screen.getByRole('alert').textContent).toBe('Titel fehlt');
    expect(spy).not.toHaveBeenCalled();
  });

  it('⌘↵ speichert auch aus einem Textfeld', async () => {
    const { backend } = await mount('normal', { finding: F1 });
    await until(() => !!screen.queryByLabelText('Titel'));
    const spy = vi.spyOn(backend, 'decide');
    const ta = screen.getByLabelText('Massnahme') as HTMLTextAreaElement;
    await fireEvent.input(ta, { target: { value: 'vsftpd aktualisieren' } });
    press('Enter', { metaKey: true }, ta);
    await until(() => spy.mock.calls.length === 1);
    expect(decisions(spy)[0]).toEqual({ kind: 'd.finding.update', payload: { finding_id: F1, remediation: 'vsftpd aktualisieren' } });
  });

  it('ATT&CK in fester Form, ungültig mit Hinweis, neu als Hypothese; CVE doppelt abgelehnt', async () => {
    const { backend } = await mount('normal', { finding: F1 });
    await until(() => !!screen.queryByLabelText('ATT&CK'));
    const attack = screen.getByLabelText('ATT&CK') as HTMLInputElement;
    await fireEvent.input(attack, { target: { value: 't99' } });
    await fireEvent.keyDown(attack, { key: 'Enter' });
    expect(screen.getByRole('alert').textContent).toBe('Form T1234 oder T1234.001');
    await fireEvent.input(attack, { target: { value: 't1190' } });
    await fireEvent.keyDown(attack, { key: 'Enter' });
    await settle();
    expect(screen.queryByRole('alert')).toBeNull();
    const box = attack.closest('.box') as HTMLElement;
    expect(box.textContent).toContain('T1190');
    expect(box.textContent).toContain('Hypothese, ohne eigenen Beleg');
    // als belegt markiert (das Finding hat gültige Belege): keine Hypothese mehr
    await fireEvent.click(within(box).getByRole('checkbox', { name: 'T1190: als belegt markieren' }));
    expect(box.textContent).not.toContain('Hypothese');

    const cve = screen.getByLabelText('CVE') as HTMLInputElement;
    await fireEvent.input(cve, { target: { value: 'cve-2011-2523' } });
    await fireEvent.keyDown(cve, { key: 'Enter' });
    expect(screen.getByRole('alert').textContent).toBe('Steht schon in der Liste');

    const spy = vi.spyOn(backend, 'decide');
    await fireEvent.click(saveBtn());
    await until(() => spy.mock.calls.length === 1);
    expect(decisions(spy)[0]).toEqual({ kind: 'd.finding.update', payload: { finding_id: F1, attack: [{ id: 'T1190', supported: true }] } });
  });

  it('Beleg öffnen setzt `beleg`, entfernen geht mit Speichern als evidence.remove', async () => {
    const { backend, view } = await mount('normal', { finding: F1 });
    await until(() => !!screen.queryByLabelText('Titel'));
    await fireEvent.click(screen.getByRole('button', { name: 'Beleg T2 msf · msfconsole -q · Zeilen 44 bis 47 öffnen' }));
    expect(url.get('beleg')).toBe(`u:${T2}@1024:43-46`);
    url.set({ beleg: null });
    await fireEvent.click(screen.getByRole('button', { name: 'Beleg T2 msf · msfconsole -q · Zeilen 44 bis 47 entfernen' }));
    expect(view.container.textContent).toContain('wird entfernt');
    const spy = vi.spyOn(backend, 'decide');
    await fireEvent.click(saveBtn());
    await until(() => spy.mock.calls.length === 1);
    expect(decisions(spy)).toEqual([{ kind: 'd.finding.evidence.remove', payload: { finding_id: F1, evidence_id: 'ev:2b3c4d5e6f708192' } }]);
    await until(() => !!view.container.querySelector('a.card.sel')?.textContent?.includes('1 Beleg'));
  });

  it('Vorschau nur über SafeMarkdown: kein Bild, kein Link, kein HTML aus dem Text', async () => {
    const { view } = await mount('normal', { finding: F1 });
    await until(() => !!screen.queryByLabelText('Beschreibung'));
    await fireEvent.input(screen.getByLabelText('Beschreibung'), {
      target: { value: '**fett** ![bild](https://evil.example/x.png) [klick](https://evil.example) <img src=x onerror=alert(1)>' },
    });
    const toggles = screen.getAllByRole('button', { name: 'Vorschau' });
    await fireEvent.click(toggles[0] as HTMLElement);
    const md = view.container.querySelector('#fd-description') as HTMLElement;
    expect(md.tagName).toBe('DIV');
    expect(md.querySelector('img, a[href], script')).toBeNull();
    expect(md.textContent).toContain('fett');
    expect(md.textContent).toContain('<img src=x onerror=alert(1)>');
    await fireEvent.click(screen.getByRole('button', { name: 'Bearbeiten' }));
    expect((screen.getByLabelText('Beschreibung') as HTMLTextAreaElement).value).toContain('**fett**');
  });

  it('Löschen mit Grund als d.finding.delete, danach leer', async () => {
    const { app, backend, view } = await mount('normal', { finding: F1 });
    await until(() => !!screen.queryByLabelText('Titel'));
    const spy = vi.spyOn(backend, 'decide');
    await fireEvent.click(screen.getByRole('button', { name: 'Finding löschen' }));
    const group = screen.getByRole('group', { name: 'Finding löschen?' });
    expect(group.textContent).toContain('Rückgängig stellt es wieder her');
    await fireEvent.input(within(group).getByLabelText('Grund (optional)'), { target: { value: 'doppelt' } });
    await fireEvent.click(within(group).getByRole('button', { name: 'Löschen' }));
    await until(() => spy.mock.calls.length === 1);
    expect(decisions(spy)).toEqual([{ kind: 'd.finding.delete', payload: { finding_id: F1, reason: 'doppelt' } }]);
    await until(() => app.ui.notices.some((n) => n.text === 'Finding gelöscht'));
    await until(() => !!view.container.textContent?.includes('Noch keine Findings.'));
  });

  it('Fehler des Servers inline im Formular', async () => {
    const { backend } = await mount('normal', { finding: F1 });
    await until(() => !!screen.queryByLabelText('Titel'));
    vi.spyOn(backend, 'decide').mockRejectedValue(new Error('kaputt'));
    await fireEvent.input(title(), { target: { value: 'Neuer Titel' } });
    await fireEvent.click(saveBtn());
    await until(() => !!document.querySelector('.error-box[role="alert"]'));
    expect(document.querySelector('.error-box')?.textContent).toContain('Speichern fehlgeschlagen');
  });
});

describe('Findings: neu', () => {
  it('aus dem Beleg: vorgefüllter Beleg, «angelegt aus», create mit evidence und created_from', async () => {
    const { project, backend, view } = await mount('normal', {}, undefined);
    project.findings.startFromEvidence({ unit_id: `${T2}@1024`, lines: [43, 46] }, 'T2 msf · msfconsole -q · Zeilen 44 bis 47');
    await until(() => url.get('finding') === 'neu' && !!screen.queryByRole('form', { name: 'Neues Finding' }));
    const form = screen.getByRole('form', { name: 'Neues Finding' });
    expect(form.textContent).toContain('T2 msf · msfconsole -q · Zeilen 44 bis 47');
    expect(form.textContent).toContain('neu');
    expect(form.textContent).toContain('angelegt aus dem Beleg');
    expect(view.container.querySelector('.card.sel')?.textContent).toContain('F?');
    expect(title().value).toBe('');

    // final ohne Schwere geht nicht
    await fireEvent.input(title(), { target: { value: 'Root über vsftpd' } });
    await fireEvent.click(within(screen.getByRole('radiogroup', { name: 'Status' })).getByRole('radio', { name: 'final' }));
    expect(screen.getByRole('alert').textContent).toBe('Für «final» braucht es eine Schwere');
    const spy = vi.spyOn(backend, 'decide');
    await fireEvent.click(saveBtn());
    await settle();
    expect(spy).not.toHaveBeenCalled();
    await fireEvent.click(within(screen.getByRole('radiogroup', { name: 'Schwere, setzt nur du' })).getByRole('radio', { name: 'Kritisch' }));
    await fireEvent.click(saveBtn());
    await until(() => spy.mock.calls.length === 1);
    expect(decisions(spy)).toEqual([
      {
        kind: 'd.finding.create',
        payload: {
          title: 'Root über vsftpd',
          status: 'final',
          severity: 'critical',
          evidence: [{ unit_id: `${T2}@1024`, lines: [43, 46] }],
          created_from: { unit_id: `${T2}@1024`, lines: [43, 46] },
        },
      },
    ]);
    await until(() => !!url.get('finding') && url.get('finding') !== 'neu');
    await until(() => project.findings.list.length === 2 && project.findings.current?.finding_id === url.get('finding'));
    expect(project.findings.current?.ordinal).toBe(2);
    expect(project.findings.current?.created_from?.label).toContain('Zeilen 44 bis 47');
  });

  it('gerade angelegt, Auswertung hinkt nach: kein Abruf des Details, bis die Liste es kennt (keine 404)', async () => {
    const { project, backend } = await mount('normal');
    const orig = backend.findings.bind(backend);
    let lag = 3;
    const old = await orig(project.pid);
    vi.spyOn(backend, 'findings').mockImplementation(async (pid: string) => (lag-- > 0 ? old : orig(pid)));
    // wie der Daemon: solange die Liste es nicht kennt, kennt auch das Detail es nicht (404)
    const origDetail = backend.finding.bind(backend);
    let rejected = 0;
    const detail = vi.spyOn(backend, 'finding').mockImplementation(async (pid: string, fid: string) => {
      if (lag >= 0 && !old.some((f) => f.finding_id === fid)) {
        rejected += 1;
        throw new ApiError('not_found', 404, 'Nicht gefunden.');
      }
      return origDetail(pid, fid);
    });
    project.findings.startFromEvidence({ unit_id: `${T2}@1024`, lines: [43, 46] }, 'T2 msf · Zeilen 44 bis 47');
    await until(() => !!screen.queryByRole('form', { name: 'Neues Finding' }));
    await fireEvent.input(title(), { target: { value: 'Neu und noch nicht ausgewertet' } });
    await fireEvent.click(saveBtn());
    await until(() => !!url.get('finding') && url.get('finding') !== 'neu');
    const id = url.get('finding');
    expect(project.findings.waiting).toBe(true);
    await until(() => project.findings.current?.finding_id === id, 8000);
    // das Detail wurde erst geholt, als die Liste das neue Finding kannte: keine Anfrage mit 404
    expect(rejected).toBe(0);
    expect(detail.mock.calls.filter((c) => c[1] === id).length).toBe(1);
    expect(lag).toBeLessThan(0);
  });

  it('«Neues Finding» ohne Beleg: leeres Formular, entfernter Entwurfsbeleg bleibt weg', async () => {
    const { project, view } = await mount('normal', { finding: F1 });
    await until(() => !!screen.queryByLabelText('Titel'));
    project.findings.startFromEvidence({ claim_key: 'a'.repeat(64) }, 'Wert');
    await until(() => !!screen.queryByRole('form', { name: 'Neues Finding' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Beleg Wert entfernen' }));
    await settle();
    expect(view.container.textContent).toContain('Noch keine Belege');
    await fireEvent.click(screen.getByRole('button', { name: 'Neues Finding' }));
    await settle();
    expect(project.findings.draftFrom).toBeNull();
    expect(view.container.textContent).not.toContain('angelegt aus dem Beleg');
  });

  it('leer: Hinweis, Findings entstehen aus Belegen', async () => {
    const { view } = await mount('empty');
    expect(view.container.textContent).toContain('Noch keine Findings.');
    expect(view.container.textContent).toContain('Findings entstehen aus Belegen.');
  });

  it('unbekanntes Finding: «gibt es nicht mehr»', async () => {
    const { view } = await mount('normal', { finding: '0199a3c2-9b10-7000-8000-0000000000aa' });
    await until(() => !!view.container.textContent?.includes('Dieses Finding gibt es nicht mehr.'));
  });
});

describe('Findings: feindliche Werte', () => {
  it('Titel und Betroffen nur als Text, Warnungen ohne Beleg', async () => {
    const { view } = await mount('normal', {}, (h) => {
      h.backend.state.findings = [findingHostile()];
    });
    await until(() => !!screen.queryByLabelText('Titel'));
    const list = screen.getByRole('list', { name: 'Liste der Findings' });
    expect(list.textContent).toContain('<b>fett</b>');
    expect(list.querySelector('b, img')).toBeNull();
    expect(title().value).toBe(HOSTILE_FINDING_TITLE);
    expect(view.container.querySelector('img, script, a[href^="http"]')).toBeNull();
    expect(view.container.textContent).toContain('ohne Schwere');
    expect(view.container.textContent).toContain('0 Belege');
  });
});

describe('Findings: Korrekturen nach der Prüfung', () => {
  it('A6: neues Finding beginnt im Titelfeld; ein ungespeicherter Entwurf sperrt die Reiterkürzel', async () => {
    const { app } = await mount('normal', { finding: 'neu' });
    const { registerGlobalKeys } = await import('../../src/lib/shell/global');
    const off = registerGlobalKeys(app);
    await until(() => !!screen.queryByLabelText('Titel'));
    await settle();
    expect(document.activeElement).toBe(title());
    // Ziffern im Titelfeld sind Text, keine Reiterkürzel
    press('2', {}, title());
    expect(url.route).toBe('findings');
    await fireEvent.input(title(), { target: { value: 'Backdoor 2' } });
    await settle();
    // auch mit Fokus ausserhalb: kein stilles Verwerfen des Entwurfs
    title().blur();
    press('2');
    expect(url.route).toBe('findings');
    expect(url.get('finding')).toBe('neu');
    expect(app.ui.notices.some((n) => n.text.includes('Ungespeicherte Änderungen'))).toBe(true);
    off();
  });

  it('A6: nach dem Speichern eines neuen Findings zieht das Formular den Fokus nicht ins Titelfeld; Ziffern wechseln den Reiter', async () => {
    const { app, project, backend } = await mount('normal');
    // Auswertung hinkt nach: das gespeicherte Finding lädt noch, das Formular hängt ohne `base` neu ein
    const orig = backend.findings.bind(backend);
    let lag = 3;
    const old = await orig(project.pid);
    vi.spyOn(backend, 'findings').mockImplementation(async (pid: string) => (lag-- > 0 ? old : orig(pid)));
    const { registerGlobalKeys } = await import('../../src/lib/shell/global');
    const off = registerGlobalKeys(app);
    project.findings.startFromEvidence({ unit_id: `${T2}@1024`, lines: [43, 46] }, 'T2 msf · Zeilen 44 bis 47');
    await until(() => !!screen.queryByRole('form', { name: 'Neues Finding' }));
    await settle();
    expect(document.activeElement).toBe(title());
    await fireEvent.input(title(), { target: { value: 'Backdoor ohne Anmeldung' } });
    await fireEvent.click(saveBtn());
    await until(() => !!url.get('finding') && url.get('finding') !== 'neu');
    const id = url.get('finding');
    await settle();
    expect(document.activeElement).not.toBe(screen.queryByLabelText('Titel'));
    await until(() => project.findings.current?.finding_id === id, 8000);
    await until(() => (document.activeElement as HTMLElement | null)?.matches('a.card.sel') === true);
    expect(document.activeElement?.textContent).toContain('Backdoor ohne Anmeldung');
    press('3', {}, document.activeElement as HTMLElement);
    expect(url.route).toBe('zeitachse');
    expect(app.ui.notices.some((n) => n.text.includes('Ungespeicherte Änderungen'))).toBe(false);
    off();
  });

  it('D10: Tastenhinweis «Speichern» nach Plattform (Strg+↵ ausserhalb des Mac)', async () => {
    await mount();
    await until(() => !!screen.queryByLabelText('Titel'));
    expect(saveBtn().textContent).toMatch(/Strg\+↵|⌘↵/);
    expect(saveBtn().textContent).not.toMatch(/Strg ↵/);
  });

  it('SEC-UI-1: mehrzeiliger Text kommt echt an; sichtbar gemachte Steuerzeichen werden genannt', async () => {
    const { project } = await mount('normal', {}, (h) => {
      h.backend.state.findings = h.backend.state.findings.map((f, i) =>
        i === 0 ? { ...f, description: 'Erste Zeile\n\n- Punkt eins\n- Punkt zwei', remediation: 'a<ESC>[31m b' } : f,
      );
    });
    await until(() => !!project.findings.current);
    const desc = screen.getByLabelText('Beschreibung') as HTMLTextAreaElement;
    expect(desc.value).toBe('Erste Zeile\n\n- Punkt eins\n- Punkt zwei');
    const notes = screen.getAllByRole('note').map((n) => n.textContent ?? '');
    expect(notes.some((x) => x.includes('sichtbar gemachte Steuerzeichen'))).toBe(true);
    expect(notes.filter((x) => x.includes('sichtbar gemachte Steuerzeichen'))).toHaveLength(1);
  });
});
