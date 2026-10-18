// Reine Hilfen des Verlaufs: Filter und Zeilen der Zeitachse, Ergebnis pro Befehl, Formular der
// Findings (Prüfung, Entscheide), Texte der Belegansicht. Besitzer: ui-verlauf.
import { describe, expect, it } from 'vitest';
import type { FindingDetail, TimelineItem } from '../../src/lib/api/types';
import { evidenceLabel, evidenceMarkdown, linesLabel, logFileName, refFor, stackText } from '../../src/lib/evidence/text';
import { buildDecisions, changedFields, checkId, cleanTitle, emptyForm, formFrom, isDirty, validate } from '../../src/lib/findings/form';
import { findingF1, timeline, unitView } from '../../src/lib/mock/data/history';
import { KALI_STAGE, T1, T2 } from '../../src/lib/mock/data/base';
import {
  canUndo,
  filterFromParams,
  filterToParams,
  isFiltered,
  mergeItems,
  newerFirst,
  NO_FILTER,
  resultText,
  rowKey,
  rowMatches,
  sameFilter,
  shortCommand,
  visibleRows,
} from '../../src/lib/timeline/model';

type Cmd = Extract<TimelineItem, { type: 'command' }>;
const items = timeline();
const cmd = (off: number) => items.find((x): x is Cmd => x.type === 'command' && x.cmd.cmd_id.endsWith(`@${off}`)) as Cmd;

describe('Zeitachse: Filter aus der URL', () => {
  it('liest Typen, Terminal und Host; unbekannte Typen und ungültige Kennungen fallen weg', () => {
    expect(filterFromParams(null, null, null)).toEqual(NO_FILTER);
    expect(filterFromParams('command,gap,bogus', T1, 'ip:default/192.168.56.101')).toEqual({
      types: ['command', 'gap'],
      terminal: T1,
      host: 'ip:default/192.168.56.101',
    });
    expect(filterFromParams('bogus', '<script>', null)).toEqual(NO_FILTER);
    // alle Typen = kein Filter
    expect(filterFromParams('command,segment,file,keystep,context,callback,decision,gap,project,input', null, null).types).toBeNull();
  });

  it('schreibt den Filter zurück und vergleicht ihn', () => {
    const f = filterFromParams('input,command', T2, null);
    expect(filterToParams(f)).toEqual({ typ: 'command,input', terminal: T2, hostf: null });
    expect(sameFilter(f, filterFromParams('command,input', T2, null))).toBe(true);
    expect(sameFilter(f, NO_FILTER)).toBe(false);
    expect(isFiltered(f)).toBe(true);
    expect(isFiltered(NO_FILTER)).toBe(false);
  });
});

describe('Zeitachse: Zeilen', () => {
  it('zeigt ohne Typfilter nur verdeckte Eingaben, mit Typ «Eingaben» alle', () => {
    const visibleInput: TimelineItem = {
      ...(items.find((x) => x.type === 'input') as Extract<TimelineItem, { type: 'input' }>),
      id: 'i:1',
    };
    const shown = { ...visibleInput, input: { ...(visibleInput as Extract<TimelineItem, { type: 'input' }>).input, hidden: false, text: 'id' } } as TimelineItem;
    const list = [...items, shown];
    expect(visibleRows(list, NO_FILTER).some((x) => x.id === 'i:1')).toBe(false);
    expect(visibleRows(list, NO_FILTER).some((x) => x.type === 'input' && x.input.hidden)).toBe(true);
    expect(visibleRows(list, filterFromParams('input', null, null)).some((x) => x.id === 'i:1')).toBe(true);
  });

  it('zeigt Dateien eines Befehls nur in seiner Unterzeile, mit Typ «Dateien» als eigene Zeile', () => {
    const owner = items.find((x): x is Cmd => x.type === 'command' && x.files.length > 0) as Cmd;
    expect(owner).toBeTruthy();
    const fileId = owner.files[0]?.unit_id;
    const fileRow: TimelineItem = {
      id: fileId ?? 'f:x', type: 'file', ts: owner.ts, ts_ns: owner.ts_ns, terminal_id: null, context_label: null, host_id: null, ctrl: false,
      terminal: null, unit_id: fileId ?? 'f:x', path: 'scans/ms2.xml', cmd_id: owner.cmd.cmd_id,
    } as TimelineItem;
    const loose = { ...fileRow, id: 'f:lose', unit_id: 'f:lose', cmd_id: null } as TimelineItem;
    const list = [...items.filter((x) => x.type !== 'file'), fileRow, loose];
    const all = visibleRows(list, NO_FILTER);
    expect(all.some((x) => x.id === fileRow.id)).toBe(false);
    expect(all.some((x) => x.id === 'f:lose')).toBe(true);
    expect(visibleRows(list, filterFromParams('file', null, null)).some((x) => x.id === fileRow.id)).toBe(true);
    expect(visibleRows(list, filterFromParams('file,command', null, null)).some((x) => x.id === fileRow.id)).toBe(false);
  });

  it('`zeile` trifft Befehle über id, cmd_id, cmd_ref und unit_id (Scope-Warnung, Host-Detail)', () => {
    const c = cmd(18432);
    expect(rowKey(c)).toBe(c.cmd.cmd_id);
    for (const z of [c.id, c.cmd.cmd_id, c.cmd.cmd_ref, c.unit_id]) expect(rowMatches(c, z)).toBe(true);
    expect(rowMatches(c, null)).toBe(false);
    expect(rowMatches(c, 'k:1')).toBe(false);
    const gap = items.find((x) => x.type === 'gap') as TimelineItem;
    expect(rowKey(gap)).toBe(gap.id);
    expect(rowMatches(gap, gap.id)).toBe(true);
  });

  it('Ergebnis pro Befehl wie im Design (Screen 6)', () => {
    expect(resultText(cmd(18432))).toBe('1 Host, 23 Services · 141 Werte übernommen');
    expect(resultText(cmd(30720))).toBe('+1 Host · 15 Werte übernommen · 1 Widerspruch');
    expect(resultText(cmd(40960))).toBe('0 übernommen, +17 ausserhalb');
    // läuft und noch nichts übernommen: leer
    expect(resultText(cmd(1024))).toBe('');
  });

  it('Rückgängig nur bei Befehlen mit übernommenen Werten, nicht misstraut', () => {
    expect(canUndo(cmd(18432))).toBe(true);
    expect(canUndo(cmd(51200))).toBe(false);
    expect(canUndo(cmd(1024))).toBe(false);
    expect(canUndo(items.find((x) => x.type === 'gap') as TimelineItem)).toBe(false);
  });

  it('ordnet nach Shim-Zeit (Dezimalstrings über 2^53) und mischt neue Seiten ohne Doppel', () => {
    const a = { ...cmd(18432), ts_ns: '1792311832291904672' };
    const b = { ...cmd(30720), ts_ns: '1792311832291904673' };
    expect(newerFirst(a, b)).toBe(1);
    expect(newerFirst(b, a)).toBe(-1);
    const merged = mergeItems([a], [b, { ...a, adopted: 7 }]);
    expect(merged.map((x) => x.id)).toEqual([b.id, a.id]);
    expect((merged[1] as Cmd).adopted).toBe(7);
  });

  it('Kurzname «nmap 14:02» ohne lange Zieldaten', () => {
    expect(shortCommand('nmap -sV 192.168.56.101', '14:02')).toBe('nmap 14:02');
    expect(shortCommand(null, '14:02')).toBe('14:02');
    expect([...shortCommand('x'.repeat(100), '1')].length).toBeLessThan(30);
  });
});

describe('Findings: Formular', () => {
  const f1 = findingF1();

  it('prüft wie der Server: Titel, «final» nur mit Schwere, Textlänge', () => {
    expect(validate(emptyForm())).toEqual({ title: 'fd.err.title' });
    expect(validate({ ...emptyForm(), title: 'x', status: 'final' })).toEqual({ status: 'fd.err.finalNeedsSeverity' });
    expect(validate({ ...emptyForm(), title: 'x'.repeat(201) }).title).toBe('fd.err.titleLong');
    expect(validate({ ...emptyForm(), title: 'x', description: 'y'.repeat(20001) }).description).toBe('fd.err.textLong');
    expect(validate({ ...emptyForm(), title: 'x', status: 'final', severity: 'high' })).toEqual({});
    expect(cleanTitle('a\nb\r\nc')).toBe('a b c');
  });

  it('ATT&CK und CVE nur in fester Form, ohne Doppel, höchstens 20', () => {
    expect(checkId('attack', 't1190', [])).toBeNull();
    expect(checkId('attack', 'T1059.004', [])).toBeNull();
    expect(checkId('attack', 'T19', [])).toBe('fd.err.attack');
    expect(checkId('cve', 'cve-2011-2523', [])).toBeNull();
    expect(checkId('cve', 'CVE-2011-2523; rm -rf', [])).toBe('fd.err.cve');
    expect(checkId('cve', 'CVE-2011-2523', [{ id: 'CVE-2011-2523', supported: false }])).toBe('fd.err.dupe');
    const many = Array.from({ length: 20 }, (_, i) => ({ id: `T10${String(i).padStart(2, '0')}`, supported: false }));
    expect(checkId('attack', 'T1999', many)).toBe('fd.err.tooMany');
  });

  it('neu: ein d.finding.create mit Belegen und «angelegt aus», ohne leere Felder', () => {
    const form = { ...emptyForm(), title: ' Titel ', severity: 'high' as const, evidenceAdd: [{ ref: { unit_id: `${T2}@1024`, lines: [43, 46] as [number, number] }, label: 'x' }] };
    const d = buildDecisions(form, null, { unit_id: `${T2}@1024`, lines: [43, 46] });
    expect(d).toEqual([
      {
        kind: 'd.finding.create',
        payload: {
          title: 'Titel',
          status: 'draft',
          severity: 'high',
          evidence: [{ unit_id: `${T2}@1024`, lines: [43, 46] }],
          created_from: { unit_id: `${T2}@1024`, lines: [43, 46] },
        },
      },
    ]);
  });

  it('bestehend: nur geänderte Felder, Belege hinzufügen und entfernen in einer Anfrage', () => {
    const form = formFrom(f1);
    expect(isDirty(form, f1)).toBe(false);
    expect(buildDecisions(form, f1, null)).toEqual([]);
    form.title = 'Neu';
    form.cves = [{ id: 'CVE-2011-2523', supported: true }];
    form.evidenceRemove = ['ev:2b3c4d5e6f708192'];
    form.evidenceAdd = [{ ref: { claim_key: 'a'.repeat(64) }, label: 'x' }];
    expect(changedFields(form, f1)).toEqual({ title: 'Neu', cves: [{ id: 'CVE-2011-2523', supported: true }] });
    expect(buildDecisions(form, f1, null).map((x) => x.kind)).toEqual(['d.finding.update', 'd.finding.evidence.add', 'd.finding.evidence.remove']);
    expect(isDirty(form, f1)).toBe(true);
  });

  it('eine gesetzte Schwere lässt sich nicht entfernen (null wird nicht gesendet)', () => {
    const form = { ...formFrom(f1), severity: null };
    expect(changedFields(form, f1)).toEqual({});
  });
});

describe('Belegansicht: Texte', () => {
  const unit = unitView(`${T2}@1024`);

  it('Kontext als Zeile, Zeilen ab 1 gezählt, Beschriftung ohne Steuerzeichen', () => {
    expect(stackText(unit?.context ?? [])).toBe('Kali › 192.168.56.101 [msf] (auto)');
    expect(stackText([KALI_STAGE])).toBe('Kali');
    expect(linesLabel([43, 46])).toBe('Zeilen 44 bis 47');
    expect(linesLabel([5, 5])).toBe('Zeile 6');
    expect(evidenceLabel(unit, [43, 46])).toBe('T2 msf · msfconsole -q · Zeilen 44 bis 47');
    expect(evidenceLabel(null, null, 'a\u001bb')).toBe('a<ESC>b');
  });

  it('Bezug fürs Finding: Wert per claim_key, Einheit mit Zeilen', () => {
    expect(refFor({ kind: 'claim', claim_key: 'c'.repeat(64) }, [1, 2])).toEqual({ claim_key: 'c'.repeat(64) });
    expect(refFor({ kind: 'unit', unit_id: 'u', lines: null }, [3, 4])).toEqual({ unit_id: 'u', lines: [3, 4] });
    expect(refFor({ kind: 'unit', unit_id: 'u', lines: null }, null)).toEqual({ unit_id: 'u' });
  });

  it('«Als Beleg kopieren» als Markdown-Block mit Nummern, Steuerzeichen sichtbar, ohne Umbruch am Ende', () => {
    const md = evidenceMarkdown({
      head: 'T2 msf',
      time: '2026-10-08 16:45:12.384 CEST',
      context: 'Kali › 192.168.56.101 [msf] (auto)',
      chainOk: true,
      lines: [
        { n: 43, text: '[+] ok', ctrl: false, sgr: [], prompt_echo: false, concealed: false, overwritten: false, masked: [] },
        { n: 44, text: 'x\u001b[2Jy ```', ctrl: true, sgr: [], prompt_echo: false, concealed: false, overwritten: false, masked: [] },
      ],
    });
    expect(md.startsWith('**Beleg** T2 msf\n2026-10-08 16:45:12.384 CEST · Kali › 192.168.56.101 [msf] (auto) · Hash-Kette ✓ geprüft')).toBe(true);
    expect(md).toContain('44  [+] ok');
    expect(md).toContain('45  x<ESC>[2Jy');
    expect(md).toContain('~~~text');
    expect(md.endsWith('~~~')).toBe(true);
    expect(md).not.toContain('\u001b');
  });

  it('Dateiname für «Ganzes Log» nie aus Zieldaten', () => {
    const name = logFileName('u:<img src=x>@1');
    expect(name).toMatch(/^unit-[0-9a-f]{12}\.txt$/);
    expect(logFileName('a')).not.toBe(logFileName('b'));
  });
});

describe('Mock-Daten des Verlaufs', () => {
  it('jede Einheit der Zeitachse hat Kopf und Zeilen, F1 verweist auf vorhandene Belege', () => {
    for (const it of items) {
      if (it.type === 'command' || it.type === 'segment' || it.type === 'file') expect(unitView(it.unit_id)?.unit_id).toBe(it.unit_id);
    }
    const f: FindingDetail = findingF1();
    for (const e of f.evidence) expect(e.evidence_id).toMatch(/^ev:[0-9a-f]{16}$/);
  });
});
