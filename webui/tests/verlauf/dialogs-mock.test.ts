// Export- und Screenshot-Dialog (Etappe 4, Screen 10) und die Mock-Handler des Verlaufs
// (Verhalten wie der Daemon: 404, 409, 422, Widerruf, Zählungen). Besitzer: ui-verlauf, ui.
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../src/lib/api/client';
import type { DecisionInput, TimelineItem } from '../../src/lib/api/types';
import ExportDialog from '../../src/lib/dialogs/ExportDialog.svelte';
import ScreenshotDialog from '../../src/lib/dialogs/ScreenshotDialog.svelte';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { T1, T2 } from '../../src/lib/mock/data/base';
import { findingF1 } from '../../src/lib/mock/data/history';
import { applyHistoryDecision } from '../../src/lib/mock/handlers/history';
import { createState } from '../../src/lib/mock/state';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, press, settle, until } from '../fundament/helpers';
import type { MockBackend } from '../../src/lib/mock/backend';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';

beforeAll(() => {
  installKeymap(window);
});

afterEach(() => {
  cleanup();
  resetKeymapForTests();
  document.body.replaceChildren();
  url.go('karte', {}, { replace: true, keep: false });
});

const disabled = (el: HTMLElement) => (el as HTMLButtonElement).disabled;

describe('Export-Dialog (Etappe 4)', () => {
  async function openExport() {
    const h = await makeApp('normal');
    const project = h.app.project as ProjectStore;
    (h.backend as MockBackend).exportStepMs = 5;
    const onclose = vi.fn();
    render(ExportDialog, { props: { app: h.app, project, onclose } });
    await until(() => project.exports.view !== null);
    await settle();
    return { ...h, project, onclose };
  }

  it('Vorlage, Phasenhinweis, Klartext nur als Hinweis, frühere Exporte mit Warnung', async () => {
    const { onclose } = await openExport();
    const dlg = screen.getByRole('dialog');
    expect(dlg.textContent).toContain('Bericht exportieren');
    expect(dlg.textContent).toContain('Credentials');
    expect(dlg.textContent).toContain('verdeckt');
    expect(dlg.textContent).toContain('ariadne export --klartext');
    await until(() => /Befehle? ohne Phase|alle Befehle zugeordnet/.test(dlg.querySelector('[data-export-phases]')?.textContent ?? ''));
    expect(dlg.querySelectorAll('[data-export-id]').length).toBe(1);
    expect(dlg.querySelector('[data-export-id]')?.textContent).toContain('exports/20261008T143012Z-cys');
    expect(screen.queryByRole('checkbox', { name: /Klartext/ })).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Schliessen' }));
    expect(onclose).toHaveBeenCalledTimes(1);
  });

  it('Exportieren: Fortschritt, Ergebnis mit Ordner und Warnung, Liste wächst', async () => {
    const { project, backend } = await openExport();
    const start = vi.spyOn(backend, 'startExport');
    await fireEvent.click(screen.getByRole('button', { name: /^Exportieren/ }));
    expect(start).toHaveBeenCalledWith(project.pid, 'cys');
    await until(() => document.querySelector('[data-export-result]') !== null, 3000);
    const res = document.querySelector('[data-export-result]') as HTMLElement;
    expect(res.textContent).toContain('Export fertig');
    expect(res.textContent).toMatch(/exports\/\d{8}T\d{6}Z-cys/);
    expect(res.textContent).toContain('Mögliche Secrets');
    expect(document.querySelectorAll('[data-export-id]').length).toBe(2);
  });

  it('htb wählen und «in der Zeitachse prüfen ›» öffnet die Phasen der Vorlage', async () => {
    const { onclose } = await openExport();
    await fireEvent.click(screen.getByRole('radio', { name: 'htb' }));
    await fireEvent.click(screen.getByRole('button', { name: 'in der Zeitachse prüfen ›' }));
    expect(url.route).toBe('zeitachse');
    expect(url.get('phasen')).toBe('htb');
    expect(onclose).toHaveBeenCalled();
  });

  it('Esc schliesst', async () => {
    const { onclose } = await openExport();
    press('Escape');
    expect(onclose).toHaveBeenCalled();
  });
});

describe('Screenshot-Dialog (Etappe 4)', () => {
  async function openShot(scenario: Parameters<typeof makeApp>[0] = 'normal') {
    const h = await makeApp(scenario);
    const project = h.app.project as ProjectStore;
    const onclose = vi.fn();
    render(ScreenshotDialog, { props: { app: h.app, project, onclose } });
    await settle();
    return { ...h, project, onclose };
  }

  it('Modus, Countdown, Auslösen sendet den Auftrag; danach Vorschau und Ansehen', async () => {
    const { project, backend, onclose } = await openShot();
    const dlg = screen.getByRole('dialog');
    expect(dlg.textContent).toContain('hostname, whoami und ip a');
    await fireEvent.click(screen.getByRole('radio', { name: 'Monitor' }));
    await fireEvent.click(screen.getByRole('radio', { name: '0 s' }));
    const take = vi.spyOn(backend, 'takeScreenshot');
    await fireEvent.click(screen.getByRole('button', { name: /^Auslösen/ }));
    expect(take).toHaveBeenCalledWith(project.pid, { mode: 'monitor', delay_s: 0 });
    await until(() => document.querySelector('[data-shot-done]') !== null, 3000);
    await fireEvent.click(screen.getByRole('button', { name: 'Ansehen' }));
    expect(onclose).toHaveBeenCalled();
    expect(url.get('beleg')).toMatch(/^s:/);
  });

  it('Bereich braucht gültige Zahlen; Fehler des Servers als fester Text', async () => {
    const { backend } = await openShot();
    await fireEvent.click(screen.getByRole('radio', { name: 'Bereich' }));
    const w = screen.getByLabelText('Breite') as HTMLInputElement;
    await fireEvent.input(w, { target: { value: 'abc' } });
    expect(disabled(screen.getByRole('button', { name: /^Auslösen/ }))).toBe(true);
    await fireEvent.input(w, { target: { value: '640' } });
    await fireEvent.click(screen.getByRole('radio', { name: '0 s' }));
    vi.spyOn(backend, 'takeScreenshot').mockRejectedValue(new ApiError('shot_wayland', 503, 'x'));
    await fireEvent.click(screen.getByRole('button', { name: /^Auslösen/ }));
    await until(() => screen.queryByRole('alert') !== null);
    expect(screen.getByRole('alert').textContent).toContain('nur unter X11');
  });
});

describe('Mock-Handler des Verlaufs', () => {
  const cmdOf = (items: TimelineItem[], id: string) => items.find((x) => x.type === 'command' && x.id === id) as Extract<TimelineItem, { type: 'command' }>;
  const apply = (s: ReturnType<typeof createState>, d: DecisionInput, id = `d-${Math.random().toString(16).slice(2)}`) => applyHistoryDecision(s, d, id);
  const code = (fn: () => unknown) => {
    try {
      fn();
    } catch (e) {
      return e instanceof ApiError ? e.status : -1;
    }
    return 0;
  };

  it('distrust: Wirkung, misstraut in der Zeile, zweites Mal 409, unbekannt 404, Widerruf stellt her', () => {
    const s = createState('normal');
    const id = `${T1}@18432`;
    expect(cmdOf(s.timeline, id).adopted).toBe(141);
    const r = apply(s, { kind: 'd.unit.distrust', payload: { cmd_id: id, reason: 'Honeypot' } }, 'dist-1');
    expect(r?.effect).toEqual({ rejected: 141, weakened: 0 });
    expect(cmdOf(s.timeline, id).distrusted).toMatchObject({ decision_id: 'dist-1', rejected: 141 });
    expect(s.timeline[0]).toMatchObject({ type: 'decision', kind: 'd.unit.distrust', reason: 'Honeypot' });
    expect(apply(s, { kind: 'd.unit.distrust', payload: { cmd_id: id } })?.decision_id).toBeNull();
    expect(code(() => apply(s, { kind: 'd.unit.distrust', payload: { cmd_id: `${T1}@1` } }))).toBe(404);
    expect(code(() => apply(s, { kind: 'd.unit.distrust', payload: {} }))).toBe(422);
    apply(s, { kind: 'd.revoke', payload: { decision_id: 'dist-1' } });
    expect(cmdOf(s.timeline, id).distrusted).toBeNull();
    expect(cmdOf(s.timeline, id).adopted).toBe(141);
  });

  it('distrust eines Befehls ohne Werte ergibt 409', () => {
    const s = createState('normal');
    expect(apply(s, { kind: 'd.unit.distrust', payload: { cmd_id: `${T2}@1024` } })?.decision_id).toBeNull();
  });

  it('Widerruf eines unbekannten Entscheids gilt einmal, das zweite Mal 409', () => {
    const s = createState('normal');
    expect(apply(s, { kind: 'd.revoke', payload: { decision_id: 'x' } })?.decision_id).not.toBeNull();
    expect(apply(s, { kind: 'd.revoke', payload: { decision_id: 'x' } })?.decision_id).toBeNull();
  });

  it('Terminal benennen: höchstens 64 Zeichen, unbekanntes Terminal 409', () => {
    const s = createState('normal');
    expect(apply(s, { kind: 'd.terminal.label', payload: { terminal_id: T1, label: ' recon ' } })?.decision_id).not.toBeNull();
    expect(s.terminals.find((x) => x.terminal_id === T1)?.label).toBe('recon');
    expect(code(() => apply(s, { kind: 'd.terminal.label', payload: { terminal_id: T1, label: 'x'.repeat(65) } }))).toBe(422);
    expect(apply(s, { kind: 'd.terminal.label', payload: { terminal_id: 'nope', label: 'a' } })?.decision_id).toBeNull();
  });

  it('Findings: final ohne Schwere 422, neue Nummer, Beleg doppelt 409, löschen und wiederherstellen', () => {
    const s = createState('normal');
    expect(code(() => apply(s, { kind: 'd.finding.create', payload: { title: 'x', status: 'final' } }))).toBe(422);
    expect(code(() => apply(s, { kind: 'd.finding.create', payload: { title: '', status: 'draft' } }))).toBe(422);
    apply(s, { kind: 'd.finding.create', payload: { title: 'Neu', status: 'draft', evidence: [{ unit_id: `${T2}@1024`, lines: [43, 46] }] } }, 'f-new');
    const f = s.findings.find((x) => x.finding_id === 'f-new');
    expect(f?.ordinal).toBe(2);
    expect(f?.evidence[0]?.label).toBe('T2 msf · msfconsole -q · Zeilen 44 bis 47');
    expect(apply(s, { kind: 'd.finding.evidence.add', payload: { finding_id: 'f-new', unit_id: `${T2}@1024`, lines: [43, 46] } })?.decision_id).toBeNull();
    const F1 = findingF1().finding_id;
    expect(apply(s, { kind: 'd.finding.update', payload: { finding_id: F1, severity: 'high', attack: [{ id: 'T1190', supported: true }] } })?.decision_id).not.toBeNull();
    const f1 = s.findings.find((x) => x.finding_id === F1);
    expect(f1?.severity).toBe('high');
    expect(f1?.attack).toEqual([{ id: 'T1190', supported: true, hypothesis: false }]);
    expect(code(() => apply(s, { kind: 'd.finding.update', payload: { finding_id: F1, attack: [{ id: 'T99', supported: false }] } }))).toBe(422);
    apply(s, { kind: 'd.finding.delete', payload: { finding_id: F1, reason: 'doppelt' } }, 'del-1');
    expect(s.findings.some((x) => x.finding_id === F1)).toBe(false);
    expect(apply(s, { kind: 'd.finding.update', payload: { finding_id: F1, title: 'y' } })?.decision_id).toBeNull();
    apply(s, { kind: 'd.revoke', payload: { decision_id: 'del-1' } });
    expect(s.findings.map((x) => x.ordinal)).toEqual([1, 2]);
  });

  it('ein Beleg aus einem misstrauten Befehl macht das Finding zur Warnung', () => {
    const s = createState('normal');
    const F1 = findingF1().finding_id;
    apply(s, { kind: 'd.finding.evidence.add', payload: { finding_id: F1, unit_id: `${T1}@18432`, lines: [5, 6] } });
    apply(s, { kind: 'd.unit.distrust', payload: { cmd_id: `${T1}@18432` } });
    const f1 = s.findings.find((x) => x.finding_id === F1);
    expect(f1?.warnings).toContain('evidence_distrusted');
  });
});
