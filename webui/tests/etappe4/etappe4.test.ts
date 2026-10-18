// Etappe 4 (ui): KI-Denkanstoss mit Zuständen, D3, E119 gruppierte Versionen, Screenshots und
// Blobs, Belegziel `s:`. Mock wie der Daemon (Entwürfe api-ki, api-export, api-screenshots,
// api-paket). Besitzer: ui.
import { cleanup, fireEvent, render, screen, within } from '@testing-library/svelte';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { aiButton, aiResultText, budgetText, needsBudgetConfirm, usd } from '../../src/lib/ai/view';
import type { AiJob, AiStatus, Suggestion } from '../../src/lib/api/types';
import { installKeymap, resetKeymapForTests } from '../../src/lib/keys/keymap';
import { HOSTILE_IMG } from '../../src/lib/mock/data/hostile';
import AiFoot from '../../src/lib/next/AiFoot.svelte';
import SuggestionItem from '../../src/lib/next/SuggestionItem.svelte';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import { isImageBlob } from '../../src/lib/stores/shots.svelte';
import { decodeEvidence, encodeEvidence, url } from '../../src/lib/url/state.svelte';
import { makeApp, settle, stopAll, until } from '../fundament/helpers';

beforeAll(() => {
  installKeymap(window);
});
afterEach(() => {
  cleanup();
  stopAll();
  resetKeymapForTests();
  url.go('karte', {}, { replace: true, keep: false });
});

async function project(scenario: Parameters<typeof makeApp>[0]) {
  const h = await makeApp(scenario);
  h.backend.aiStepMs = 5;
  const p = h.app.project as ProjectStore;
  await until(() => p.ai.status !== null && p.next.view !== null);
  return { ...h, project: p };
}

const status = (over: Partial<AiStatus> = {}): AiStatus => ({
  provider: 'cloud', model: 'test-model', ready: true, reason: null, reason_text: null,
  budget: { month: '2026-10', limit_usd: 10, used_usd: 1, pct: 10, level: 'ok' }, job: null, ...over,
});

describe('KI: Anzeige (ai/view)', () => {
  const opts = { offline: false, presentation: false, starting: false };

  it('Knopf aktiv nur, wenn eingerichtet; sonst Grund als fester Text', () => {
    expect(aiButton(status(), null, opts)).toEqual({ enabled: true, reason: null });
    expect(aiButton(status({ ready: false, reason: 'off' }), null, opts).reason).toContain('ariadne ai setup');
    expect(aiButton(status({ ready: false, reason: 'cloud_not_allowed' }), null, opts).reason).toContain('allow-cloud');
    expect(aiButton(status(), null, { ...opts, presentation: true }).reason).toContain('Präsentationsmodus');
    expect(aiButton(status(), null, { ...opts, offline: true }).enabled).toBe(false);
    expect(aiButton(null, null, opts).enabled).toBe(false);
    const running = { status: 'running' } as AiJob;
    expect(aiButton(status(), running, opts).reason).toContain('läuft schon');
  });

  it('Budget: Hinweis ab 80 %, voll ab 100 %; Bestätigung über 422 budget_confirm', () => {
    expect(budgetText(status({ budget: { month: 'x', limit_usd: 10, used_usd: 8.6, pct: 86, level: 'warn' } }))?.text).toMatch(/fast aufgebraucht: 86 %/);
    expect(budgetText(status({ budget: { month: 'x', limit_usd: 10, used_usd: 10, pct: 100, level: 'over' } }))?.level).toBe('over');
    expect(budgetText(status({ provider: 'off' }))).toBeNull();
    expect(needsBudgetConfirm([{ loc: ['body', 'confirm_budget'], type: 'budget_confirm' }])).toBe(true);
    expect(needsBudgetConfirm([{ type: 'missing' }])).toBe(false);
    expect(needsBudgetConfirm(null)).toBe(false);
    expect(usd(0.018)).toBe('0.018 USD');
  });

  it('Ergebnis: Anbieter weg (lokal), Ablehnung, keine neuen', () => {
    const base = { status: 'failed', error: 'unreachable', provider: 'local', created: 0 } as AiJob;
    expect(aiResultText(base)).toContain('Ollama auf 127.0.0.1');
    expect(aiResultText({ ...base, status: 'refused', error: null })).toContain('abgelehnt');
    expect(aiResultText({ ...base, status: 'done', error: null, created: 0 })).toBe('Keine neuen Denkanstösse');
    expect(aiResultText({ ...base, status: 'done', error: null, created: 2 })).toBe('2 neue KI-Denkanstösse');
  });

  it('Ergebnis: Modell fehlt, Überlast, TLS-Aufbruch (eigene Texte)', () => {
    const base = { status: 'failed', error: 'model', provider: 'local', created: 0 } as AiJob;
    expect(aiResultText(base)).toContain('ollama pull');
    expect(aiResultText({ ...base, provider: 'cloud' })).toContain('Modell-ID');
    expect(aiResultText({ ...base, error: 'overloaded' })).toContain('ausgelastet');
    expect(aiResultText({ ...base, provider: 'cloud', error: 'tls' })).toContain('ai check');
  });
});

describe('KI: Auftrag im Mock wie der Daemon', () => {
  it('eingerichtet: anfordern, Fortschritt mit Tokens und Maskierung, danach ein KI-Denkanstoss in /next', async () => {
    const { app, project: p, backend } = await project('ki');
    render(AiFoot, { props: { app, project: p } });
    const btn = screen.getByRole('button', { name: 'Denkanstoss anfordern (KI)' }) as HTMLButtonElement;
    expect(btn.disabled).toBe(false);
    const req = vi.spyOn(backend, 'aiRequest');
    await fireEvent.click(btn);
    expect(req).toHaveBeenCalledWith(p.pid, false);
    await until(() => p.ai.job?.status === 'done', 3000);
    await until(() => (p.next.view?.suggestions ?? []).some((s) => s.origin === 'ai'), 3000);
    await settle();
    expect(document.querySelector('[data-ai-phase="done"]')?.textContent).toContain('1 neuer KI-Denkanstoss');
    expect(p.ai.job?.masked).toBe(3);
  });

  it('läuft: «Lagebild wird gesendet» mit Tokens und Maskierung; zweiter Auftrag gesperrt', async () => {
    const { app, project: p } = await project('kirun');
    render(AiFoot, { props: { app, project: p } });
    await fireEvent.click(screen.getByRole('button', { name: 'Denkanstoss anfordern (KI)' }));
    await until(() => p.ai.job?.step === 'anfrage', 3000);
    await settle();
    const st = document.querySelector('[data-ai-phase="running"]') as HTMLElement;
    expect(st.textContent).toContain('Lagebild wird gesendet');
    expect(st.textContent).toMatch(/4.212 Tokens gesendet/);
    expect(st.textContent).toContain('3 Werte maskiert');
    expect((screen.getByRole('button', { name: /Denkanstoss anfordern/ }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('Budget voll: erst Rückfrage, dann mit confirm_budget', async () => {
    const { app, project: p, backend } = await project('kiover');
    render(AiFoot, { props: { app, project: p } });
    expect(document.querySelector('[data-ai-budget="over"]')?.textContent).toContain('Monatsbudget erreicht');
    const req = vi.spyOn(backend, 'aiRequest');
    await fireEvent.click(screen.getByRole('button', { name: 'Denkanstoss anfordern (KI)' }));
    await until(() => p.ai.confirm);
    const dlg = screen.getByRole('alertdialog');
    expect(dlg.textContent).toContain('Trotzdem senden?');
    await fireEvent.click(within(dlg).getByRole('button', { name: 'Trotzdem senden' }));
    expect(req).toHaveBeenLastCalledWith(p.pid, true);
    await until(() => p.ai.job !== null);
  });

  it('Ablehnung wörtlich nur als Text (kein HTML, Steuerzeichen sichtbar)', async () => {
    const { app, project: p } = await project('kirefuse');
    render(AiFoot, { props: { app, project: p } });
    await fireEvent.click(screen.getByRole('button', { name: 'Denkanstoss anfordern (KI)' }));
    await until(() => p.ai.job?.status === 'refused', 3000);
    await settle();
    const q = document.querySelector('[data-ai-refusal]') as HTMLElement;
    expect(q.textContent).toContain('<b>Kein HTML</b>');
    expect(q.querySelector('b')).toBeNull();
    expect(q.textContent).toContain('<U+202E>');
  });

  it('Anbieter weg, Injection-Verdacht, KI aus mit Grund', async () => {
    const gone = await project('kigone');
    const v1 = render(AiFoot, { props: { app: gone.app, project: gone.project } });
    await fireEvent.click(screen.getByRole('button', { name: 'Denkanstoss anfordern (KI)' }));
    await until(() => gone.project.ai.job?.status === 'failed', 3000);
    await settle();
    expect(document.querySelector('[data-ai-phase="failed"]')?.textContent).toContain('Ollama auf 127.0.0.1');
    v1.unmount();

    const inj = await project('kiinject');
    const v2 = render(AiFoot, { props: { app: inj.app, project: inj.project } });
    await fireEvent.click(screen.getByRole('button', { name: 'Denkanstoss anfordern (KI)' }));
    await until(() => inj.project.ai.job?.status === 'done', 3000);
    await settle();
    expect(document.querySelector('[data-ai-injection]')?.textContent).toContain('1 mit Injection-Verdacht');
    v2.unmount();

    const off = await project('normal');
    render(AiFoot, { props: { app: off.app, project: off.project } });
    expect((screen.getByRole('button', { name: /Denkanstoss anfordern/ }) as HTMLButtonElement).disabled).toBe(true);
    expect(document.querySelector('[data-ai-reason]')?.textContent).toContain('KI ist aus');
  });
});

describe('D3: KI-Denkanstoss in der Spalte', () => {
  it('Kennzeichen KI, Kriterien als Text, Bestätigt/Widerlegt/Verwerfen; Bestätigt schreibt done mit basis', async () => {
    const { app, project: p, backend } = await project('kiinject');
    await p.ai.request();
    await until(() => (p.next.view?.suggestions ?? []).some((s) => s.origin === 'ai'), 3000);
    const s = p.next.view?.suggestions.find((x) => x.origin === 'ai') as Suggestion;
    render(SuggestionItem, { props: { app, project: p, suggestion: s, selected: true } });
    const card = document.querySelector(`[data-suggestion-key="${s.suggestion_key}"]`) as HTMLElement;
    expect(card.textContent).toContain('KI');
    expect(card.textContent).toContain('bestätigt, wenn');
    expect(card.textContent).toContain('widerlegt, wenn');
    expect(card.textContent).toContain(HOSTILE_IMG);
    expect(card.querySelector('img')).toBeNull();
    expect(card.textContent).toContain('Injection-Verdacht');
    expect(within(card).queryByRole('button', { name: /^Erledigt/ })).toBeNull();
    within(card).getByRole('button', { name: /^Widerlegt/ });
    within(card).getByRole('button', { name: /^Verwerfen/ });
    const decide = vi.spyOn(backend, 'decide');
    await fireEvent.click(within(card).getByRole('button', { name: /^Bestätigt/ }));
    await settle();
    const d = decide.mock.calls[0]?.[1][0];
    expect(d?.kind).toBe('d.suggestion.done');
    expect(d?.payload).toMatchObject({ suggestion_key: s.suggestion_key, basis: s.basis, reason: 'bestätigt' });
  });
});

describe('E119: Versionen pro Host als Liste', () => {
  it('eine Zeile pro Dienst mit genau einer Vorlage; templates ausgeblendet', async () => {
    const { app, project: p } = await project('versions');
    const s = p.next.view?.suggestions.find((x) => x.rule_id === 'R-VERSION-RECHERCHE') as Suggestion;
    expect(s.items?.length).toBe(8);
    // Lernmodus (Standard): erst nach Stufe 3 erscheinen die Vorlagen
    for (let i = 0; i < 3; i++) p.next.revealStage(s.suggestion_key);
    render(SuggestionItem, { props: { app, project: p, suggestion: s, selected: true } });
    const list = document.querySelector('[data-items="8"]') as HTMLElement;
    expect(list.textContent).toContain('8 Dienste');
    expect(list.querySelectorAll('li').length).toBe(8);
    expect(list.textContent).toContain('vsftpd 2.3.4');
    expect(list.textContent).toContain('8180/tcp');
    // nur die Liste, nicht zusätzlich die ersten vier aus `templates`
    expect(document.body.textContent?.match(/searchsploit vsftpd 2\.3\.4/g)?.length).toBe(1);
  });
});

describe('Screenshots und Blobs', () => {
  it('Magic-Bytes: PNG ja, SVG und HTML nein', async () => {
    const png = new Blob([new Uint8Array([0x89, 0x50, 0x4e, 0x47, 13, 10, 26, 10, 0, 0, 0, 13])]);
    expect(await isImageBlob(png)).toBe('image/png');
    expect(await isImageBlob(new Blob(['<svg xmlns="http://www.w3.org/2000/svg"/>']))).toBeNull();
    expect(await isImageBlob(new Blob(['<html>']))).toBeNull();
  });

  it('Präsentationsmodus: kein Abruf der Bilder', async () => {
    const { project: p, backend } = await project('present');
    await until(() => p.shots.loaded);
    const blob = vi.spyOn(backend, 'blob');
    expect(p.shots.items.length).toBeGreaterThan(0);
    expect(p.shots.items.every((s) => s.window_title === null)).toBe(true);
    expect(await p.shots.image(p.shots.items[0]!.blob_id)).toBeNull();
    expect(blob).not.toHaveBeenCalled();
  });

  it('Belegziel s:<id> hin und zurück, ungültige abgelehnt', () => {
    expect(decodeEvidence(encodeEvidence({ kind: 'shot', id: 'abc-123' }))).toEqual({ kind: 'shot', id: 'abc-123' });
    expect(decodeEvidence('s:<img>')).toBeNull();
    expect(decodeEvidence('s:')).toBeNull();
  });
});
