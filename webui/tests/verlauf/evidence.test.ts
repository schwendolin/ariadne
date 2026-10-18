// Belegansicht (Screen 7) gegen den Mock: Kopf, Raster, Log als virtuelle Liste mit markiertem
// Bereich und «N Zeilen davor ausgeblendet · zeigen», Wert mit mehreren Quellen (Terminal, Datei
// mit SHA-256), Hash-Kette verletzt (Knöpfe gesperrt, Meldung nicht wegklickbar), Beleg nicht mehr
// vorhanden, Präsentationsmodus, Als Finding, Zu Finding hinzufügen, Als Beleg kopieren (Ziel Mac,
// Ersatz ohne Zwischenablage), Ganzes Log (Dateiname ohne Zieldaten), feindliche Werte nur Text.
// Besitzer: ui-verlauf.
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { DecisionInput } from '../../src/lib/api/types';
import EvidencePanel from '../../src/lib/evidence/EvidencePanel.svelte';
import { evidenceMarkdown, logFileName } from '../../src/lib/evidence/text';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { hex64, T1, T2 } from '../../src/lib/mock/data/base';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import { url, type EvidenceTarget } from '../../src/lib/url/state.svelte';
import { makeApp, press, settle, stopAll, until } from '../fundament/helpers';

const MSF = `${T2}@1024`;
const NMAP = `${T1}@18432`;

beforeAll(() => {
  installKeymap(window);
});

afterEach(() => {
  cleanup();
  resetKeymapForTests();
  stopAll();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  Reflect.deleteProperty(navigator, 'clipboard');
  document.body.replaceChildren();
  url.go('karte', {}, { replace: true, keep: false });
});

async function open(target: EvidenceTarget, scenario: Parameters<typeof makeApp>[0] = 'normal', before?: () => void) {
  url.go('zeitachse', {}, { replace: true, keep: false });
  const h = await makeApp(scenario);
  const project = h.app.project as ProjectStore;
  await until(() => project.timeline.loaded && project.findings.loaded);
  before?.();
  const view = render(EvidencePanel, { props: { app: h.app, project, target } });
  await until(() => !project.evidence.loading && (project.evidence.unit !== null || project.evidence.error !== null), 3000);
  await settle();
  return { ...h, project, view };
}

const panel = () => screen.getByRole('region', { name: 'Beleg' });
// gesperrte Knöpfe nennen den Grund im Namen (Bildschirmleser), daher Anfang des Namens
const btn = (name: string) => screen.getByRole('button', { name: new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`) });
const isDisabled = (el: HTMLElement) => el.getAttribute('aria-disabled') === 'true' || (el as HTMLButtonElement).disabled;
const rowsShown = (c: HTMLElement) => Array.from(c.querySelectorAll<HTMLElement>('.lr[data-n]')).map((x) => Number(x.dataset.n));

describe('Belegansicht: Einheit mit Zeilen', () => {
  it('Kopf, Raster, Ausschnitt ab kurz vor der Markierung, ganz zeigen', async () => {
    const { view } = await open({ kind: 'unit', unit_id: MSF, lines: [43, 46] });
    const p = panel();
    // Zeiten in Lokalzeit (die Tests laufen in UTC, der Mock in +02:00)
    expect(p.querySelector('h2')?.textContent).toMatch(/^Beleg · T2 msf · \d\d:45:12$/);
    const dl = p.querySelector('dl.meta') as HTMLElement;
    expect(dl.textContent).toContain('msfconsole -q');
    expect(dl.textContent).toContain('Kali');
    expect(dl.textContent).toContain('192.168.56.101');
    expect(dl.textContent).toContain(':45:12.384');
    expect(dl.textContent).toContain('Quell-IP');
    expect(dl.textContent).toContain('läuft');
    expect(dl.textContent).toContain('✓ geprüft');

    expect(p.textContent).toContain('40 Zeilen davor ausgeblendet');
    await until(() => view.container.querySelectorAll('.line.marked').length === 4);
    const marked = Array.from(view.container.querySelectorAll('.line.marked .ln')).map((x) => x.textContent);
    expect(marked).toEqual(['44', '45', '46', '47']);
    expect(rowsShown(view.container)[0]).toBe(40);

    await fireEvent.click(screen.getByRole('button', { name: 'zeigen' }));
    await settle();
    expect(p.textContent).not.toContain('Zeilen davor ausgeblendet');
  });

  it('ohne Markierung beginnt das Log bei Zeile 1, Kopf ohne Ausschnitt-Hinweis', async () => {
    const { view } = await open({ kind: 'unit', unit_id: NMAP, lines: null });
    expect(panel().textContent).not.toContain('davor ausgeblendet');
    await until(() => view.container.querySelectorAll('.line').length > 0);
    expect(rowsShown(view.container)[0]).toBe(0);
    expect(view.container.querySelector('.line .ln')?.textContent).toBe('1');
    expect(panel().textContent).toContain('Exit 0');
  });

  it('Esc und «Schliessen» schliessen die Tafel über die URL', async () => {
    await open({ kind: 'unit', unit_id: MSF, lines: [43, 46] });
    url.set({ beleg: `u:${MSF}:43-46` }, { push: false });
    press('Escape');
    expect(url.get('beleg')).toBeNull();
    url.set({ beleg: `u:${MSF}:43-46` }, { push: false });
    await fireEvent.click(btn('Schliessen'));
    expect(url.get('beleg')).toBeNull();
  });

  it('Beleg nicht mehr vorhanden: Hinweis, keine Knöpfe aktiv', async () => {
    await open({ kind: 'unit', unit_id: `${T1}@999999`, lines: null });
    expect(panel().textContent).toContain('Beleg nicht mehr vorhanden');
    expect(isDisabled(btn('Als Finding'))).toBe(true);
    expect(isDisabled(btn('Als Beleg kopieren · Mac'))).toBe(true);
  });
});

describe('Belegansicht: Laden', () => {
  it('ein 404 lädt nicht in einer Schleife nach (einmal fragen, dann Hinweis)', async () => {
    const h = await open({ kind: 'unit', unit_id: `${T1}@424242`, lines: null }, 'normal');
    const spy = vi.spyOn(h.backend, 'unit');
    await h.project.evidence.open({ kind: 'unit', unit_id: `${T1}@424242`, lines: null });
    await new Promise((r) => setTimeout(r, 100));
    await settle();
    expect(spy).not.toHaveBeenCalled();
    expect(panel().textContent).toContain('Beleg nicht mehr vorhanden');
    // anderes Ziel lädt wieder
    await h.project.evidence.open({ kind: 'unit', unit_id: MSF, lines: null });
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('Zeilen laden in Blöcken zu 200, erst wenn sichtbar', async () => {
    const h = await open({ kind: 'unit', unit_id: NMAP, lines: null }, 'normal', undefined);
    const spy = vi.spyOn(h.backend, 'lines');
    await until(() => h.project.evidence.hasLines(0, 5));
    expect(spy.mock.calls.every((c) => c[2].count === 200)).toBe(true);
    expect(await h.project.evidence.ensureRange(0, 119)).toBe(true);
    expect(h.project.evidence.line(119)?.n).toBe(119);
  });
});

describe('Belegansicht: Wert mit Quellen', () => {
  it('Wert, Quellen umschalten, Datei mit SHA-256 und erzeugendem Befehl', async () => {
    const { project } = await open({ kind: 'claim', claim_key: hex64('ftp-21') });
    const p = panel();
    const dl = p.querySelector('dl.meta') as HTMLElement;
    expect(dl.textContent).toContain('192.168.56.101:21');
    expect(dl.textContent).toContain('service.product');
    expect(dl.textContent).toContain('vsftpd');
    const group = screen.getByRole('radiogroup', { name: 'Quellen' });
    const radios = Array.from(group.querySelectorAll<HTMLElement>('[role="radio"]'));
    expect(radios).toHaveLength(2);
    expect(radios[0]?.getAttribute('aria-checked')).toBe('true');
    expect(radios[1]?.textContent).toContain('scans/ms2.xml');
    expect(dl.textContent).toContain('nmap -sV -sC -oA scans/ms2 192.168.56.101');

    await fireEvent.click(radios[1] as HTMLElement);
    await until(() => project.evidence.unit?.kind === 'file');
    await settle();
    const dl2 = panel().querySelector('dl.meta') as HTMLElement;
    expect(dl2.textContent).toContain('Pfad');
    expect(dl2.textContent).toContain('scans/ms2.xml');
    expect(dl2.textContent).toContain('SHA-256');
    expect(dl2.textContent).toContain('9f2c41e0…b7a3d18c');
    expect(dl2.textContent).toContain('nmap.xml');
    // erzeugender Befehl aus der Zeitachse
    expect(dl2.textContent).toMatch(/nmap .*\d\d:02/);
    expect(panel().querySelector('h2')?.textContent).toContain('Beleg · Datei');
  });
});

describe('Belegansicht: Varianten', () => {
  it('Hash-Kette verletzt: Meldung bleibt, Kopieren und Finding gesperrt, Zeilen ab dem Bruch markiert', async () => {
    const { view } = await open({ kind: 'unit', unit_id: NMAP, lines: null }, 'chain');
    const alert = screen.getAllByRole('alert').find((a) => a.textContent?.includes('Hash-Kette verletzt'));
    expect(alert).toBeTruthy();
    expect(alert?.textContent).toContain('ab Zeile 4');
    expect(alert?.querySelector('button')).toBeNull();
    expect(isDisabled(btn('Als Finding'))).toBe(true);
    expect(isDisabled(btn('Zu Finding hinzufügen'))).toBe(true);
    expect(isDisabled(btn('Als Beleg kopieren · Mac'))).toBe(true);
    expect(panel().querySelector('dl.meta')?.textContent).toContain('verletzt ab Zeile 4');
    await until(() => view.container.querySelectorAll('.lr.broken').length > 0);
    const firstBroken = Number(view.container.querySelector<HTMLElement>('.lr.broken')?.dataset.n);
    expect(firstBroken).toBe(3);
  });

  it('Präsentationsmodus: Kennzeichen und Hinweis, Aufdecken gesperrt', async () => {
    const { project } = await open({ kind: 'unit', unit_id: MSF, lines: [43, 46] }, 'present');
    expect(panel().querySelector('.head')?.textContent).toContain('Präsentation');
    expect(panel().textContent).toContain('kopiert maskiert');
    project.evidence.setRevealHidden(true);
    expect(project.evidence.revealHidden).toBe(false);
  });

  it('feindliche Werte bleiben Text: kein Element, kein Link, Steuerzeichen sichtbar', async () => {
    const { view } = await open({ kind: 'unit', unit_id: `${T1}@60000`, lines: null }, 'normal', () => {
      window.history.replaceState(null, '', '/zeitachse?mock=hostile');
    });
    await until(() => view.container.querySelectorAll('.line').length >= 3);
    const p = panel();
    expect(p.querySelector('img, script, a[href], iframe, object')).toBeNull();
    // style nur aus CSSOM mit CSS-Variablen (virtuelle Liste), nie aus Zieldaten
    for (const el of Array.from(p.querySelectorAll('[style]'))) expect(el.getAttribute('style')).toMatch(/^(\s*--[a-z-]+:[^;]*;)*\s*$/);
    for (const el of Array.from(p.querySelectorAll('*'))) {
      for (const a of Array.from(el.attributes)) expect(a.name.startsWith('on')).toBe(false);
    }
    expect(p.textContent).toContain('<script>alert(1)</script>');
    expect(p.textContent).toContain('<ESC>');
    expect(p.textContent).toContain('<U+202E>');
    expect(p.textContent).not.toContain('\u202e');
    expect(p.textContent).toContain('••••••••');
  });
});

describe('Belegansicht: Aktionen', () => {
  it('Als Finding: Reiter Findings mit Entwurf und Bezug auf die Zeilen', async () => {
    const { project } = await open({ kind: 'unit', unit_id: MSF, lines: [43, 46] });
    await fireEvent.click(btn('Als Finding'));
    expect(url.route).toBe('findings');
    expect(url.get('finding')).toBe('neu');
    expect(url.get('beleg')).toBeNull();
    expect(project.findings.draftFrom).toEqual({ unit_id: MSF, lines: [43, 46] });
    expect(project.findings.draftLabel).toBe('T2 msf · msfconsole -q · Zeilen 44 bis 47');
  });

  it('Zu Finding hinzufügen: Auswahl, Entscheid d.finding.evidence.add, Meldung', async () => {
    const { app, backend, project } = await open({ kind: 'unit', unit_id: MSF, lines: [43, 46] });
    const spy = vi.spyOn(backend, 'decide');
    await fireEvent.click(btn('Zu Finding hinzufügen'));
    await settle();
    const f1 = project.findings.list[0];
    expect(f1).toBeTruthy();
    const opt = screen.getByRole('button', { name: new RegExp(`^F${f1?.ordinal}`) });
    await fireEvent.click(opt);
    await until(() => spy.mock.calls.length === 1);
    const d = spy.mock.calls[0]?.[1] as DecisionInput[];
    expect(d[0]).toMatchObject({ kind: 'd.finding.evidence.add', payload: { finding_id: f1?.finding_id, unit_id: MSF, lines: [43, 46] } });
    await until(() => app.ui.notices.some((n) => n.text === `Beleg zu F${f1?.ordinal} hinzugefügt`));
    expect(app.ui.popover).toBeNull();
  });

  it('Als Beleg kopieren · Mac: Markdown mit Kopf und den markierten Zeilen', async () => {
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    await open({ kind: 'unit', unit_id: MSF, lines: [43, 46] });
    await fireEvent.click(btn('Als Beleg kopieren · Mac'));
    await until(() => writeText.mock.calls.length === 1);
    const text = (writeText.mock.calls[0] as unknown as [string])[0];
    expect(text.startsWith('**Beleg** T2 msf · msfconsole -q · Zeilen 44 bis 47\n')).toBe(true);
    expect(text).toContain('✓ geprüft');
    const body = text.split('```text\n')[1]?.split('\n```')[0]?.split('\n') ?? [];
    expect(body).toHaveLength(4);
    expect(body[0]?.startsWith('44  ')).toBe(true);
    expect(text.endsWith('```')).toBe(true);
    await until(() => !!panel().textContent?.includes('In der Zwischenablage des Macs'));
  });

  it('ohne Zwischenablage: markiertes Textfeld zum Kopieren von Hand', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    const { view } = await open({ kind: 'unit', unit_id: MSF, lines: [43, 46] });
    await fireEvent.click(btn('Als Beleg kopieren · Mac'));
    await until(() => !!view.container.querySelector('textarea.manual'));
    expect((view.container.querySelector('textarea.manual') as HTMLTextAreaElement).value).toContain('Zeilen 44 bis 47');
  });

  it('Ganzes Log: Download mit Dateiname ohne Zieldaten', async () => {
    const created: Blob[] = [];
    const createObjectURL = vi.fn((b: Blob) => {
      created.push(b);
      return 'blob:mock';
    });
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    let download = '';
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      download = this.download;
    });
    await open({ kind: 'unit', unit_id: MSF, lines: [43, 46] });
    await fireEvent.click(btn('Ganzes Log'));
    await until(() => click.mock.calls.length === 1);
    expect(download).toBe(logFileName(MSF));
    expect(download).toMatch(/^unit-[0-9a-f]{12}\.txt$/);
    expect(await created[0]?.text()).toContain('msf6 > use exploit/unix/ftp/vsftpd_234_backdoor');
  });
});

describe('Belegansicht: Hilfen', () => {
  it('evidenceMarkdown wählt einen anderen Zaun, wenn die Zeilen ``` enthalten, und zeigt Steuerzeichen', () => {
    const md = evidenceMarkdown({
      head: 'x',
      time: '16:00:00.000',
      context: 'Kali',
      chainOk: false,
      lines: [{ n: 9, text: '```\u001b[31m', ctrl: true, sgr: [], prompt_echo: false, concealed: false, overwritten: false, masked: [] }],
    });
    expect(md).toContain('~~~text');
    expect(md).toContain('<ESC>');
    expect(md).not.toContain('\u001b');
    expect(md).not.toContain('Hash-Kette');
  });

  it('logFileName ist stabil und hängt nur an der unit_id', () => {
    expect(logFileName('a')).toBe(logFileName('a'));
    expect(logFileName('a')).not.toBe(logFileName('b'));
    expect(logFileName('$(id)`whoami`')).toMatch(/^unit-[0-9a-f]{12}\.txt$/);
  });
});
