// Karte und Host-Detail gegen den Mock: Graph und Positionen laden, nach Änderungen gebündelt
// nachladen, Positionen gebündelt speichern, Tabelle ab 200 Hosts und erst bei Bedarf laden, Palette
// «hosts»; Host-Detail mit 404 («nicht mehr da»), Nebel annehmen und verwerfen über candidate_claims,
// Arbeitsstand, Zugriff, Tags, Notiz, Schlüsselschritt als Entscheide. Besitzer: ui-karte.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { hostId } from '../../src/lib/mock/data/base';
import { search } from '../../src/lib/shell/palette';
import type { ProjectStore } from '../../src/lib/stores/project.svelte';
import { url } from '../../src/lib/url/state.svelte';
import { makeApp, stopAll, until } from '../fundament/helpers';

const H101 = hostId('192.168.56.101');
const H103 = hostId('192.168.56.103');

afterEach(() => {
  stopAll();
  vi.useRealTimers();
  url.go('karte', {}, { replace: true, keep: false });
});

async function ready(scenario: Parameters<typeof makeApp>[0] = 'normal') {
  const h = await makeApp(scenario);
  await until(() => h.app.project?.map.graph != null && h.app.project.map.positionsLoaded);
  return { ...h, project: h.app.project as ProjectStore };
}

describe('MapStore', () => {
  it('lädt Graph und Positionen; Hosts, Zeit des Ladens', async () => {
    const { project } = await ready();
    expect(project.map.hosts.map((h) => h.id)).toContain(H101);
    expect(project.map.host(H101)?.access).toBe('admin');
    expect(project.map.host('gibt-es-nicht')).toBeNull();
    expect(project.map.loadedAt).not.toBeNull();
    expect(project.map.tableOnly).toBe(false);
  });

  it('lädt nach Änderungen an Hosts gebündelt nach, nicht nach Findings', async () => {
    const { project, backend } = await ready();
    const spy = vi.spyOn(backend, 'graph');
    const cs = (entity: string) => ({ project_id: project.pid, from: 1, to: 2, reset: false, changes: [{ generation: 2, entity, entity_key: 'x', change: 'updated' as const }] });
    project.map.onChanges(cs('finding') as never);
    project.map.onChanges(cs('host') as never);
    project.map.onChanges(cs('keystep') as never);
    await new Promise((r) => setTimeout(r, 400));
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('Positionen: lokal sofort, auf dem Server gebündelt; ohne Einträge nichts', async () => {
    const { project, backend } = await ready();
    const spy = vi.spyOn(backend, 'savePositions');
    project.map.savePositions({ kali: { x: 1, y: 2 } });
    project.map.savePositions({ kali: { x: 3, y: 4 }, [H101]: { x: 5, y: 6 } });
    expect(project.map.positions.kali).toEqual({ x: 3, y: 4 });
    await until(() => spy.mock.calls.length > 0, 2000);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[1]).toEqual({ kali: { x: 3, y: 4 }, [H101]: { x: 5, y: 6 } });
    expect(backend.state.positions.positions).toEqual({ kali: { x: 3, y: 4 }, [H101]: { x: 5, y: 6 } });
  });

  it('ab 200 Hosts nur die Tabelle; Hosts und Services erst bei Bedarf, Konflikte zuerst', async () => {
    const { project, backend } = await ready('many');
    expect(project.map.tableOnly).toBe(true);
    const hosts = vi.spyOn(backend, 'hosts');
    const services = vi.spyOn(backend, 'services');
    expect(project.map.table.hosts).toBeNull();
    await project.map.table.ensure('hosts');
    expect(hosts).toHaveBeenCalledTimes(1);
    expect(services).not.toHaveBeenCalled();
    expect(project.map.table.sortedHosts.slice(0, 2).map((h) => h.label)).toEqual(['192.168.56.17', '192.168.56.203']);
    await project.map.table.ensure('hosts');
    expect(hosts).toHaveBeenCalledTimes(1);
    await project.map.table.ensure('services');
    expect(services).toHaveBeenCalledTimes(1);
  });

  it('Palette: Hosts und Services, öffnet das Host-Detail', async () => {
    await ready();
    const hits = search('vsftpd');
    expect(hits.some((h) => h.group === 'hosts' && h.label.includes(':21'))).toBe(true);
    const host = search('192.168.56.104').find((h) => h.id === `host:${hostId('192.168.56.104')}`);
    host?.run();
    expect(url.get('host')).toBe(hostId('192.168.56.104'));
  });
});

describe('HostStore', () => {
  it('öffnet das Detail; Kali hat keines; unbekannter Host ist «nicht mehr da»', async () => {
    const { project } = await ready();
    await project.host.open(H101);
    expect(project.host.detail?.id).toBe(H101);
    await project.host.open('kali');
    expect(project.host.detail).toBeNull();
    await project.host.open('ip:default/192.168.56.250');
    expect(project.host.gone).toBe(true);
    expect(project.host.detail).toBeNull();
  });

  it('Nebel annehmen färbt ein (candidate_claims), verwerfen lässt ihn verschwinden', async () => {
    const { project, backend } = await ready();
    await project.host.open(H103);
    const claims = project.host.detail?.candidate_claims ?? [];
    expect(claims.length).toBe(1);
    expect(await project.host.decideFog(true)).toBe(true);
    expect(backend.state.decisions.at(-1)).toMatchObject({ kind: 'd.claim.confirm', payload: { claim_key: claims[0] } });
    await until(() => project.map.host(H103)?.claim_state === 'confirmed', 3000);
    expect(project.map.graph?.summary.fog).toBe(0);
  });

  it('Arbeitsstand, Zugriff, Tags, Notiz und Schlüsselschritt sind Entscheide', async () => {
    const { project, backend } = await ready();
    await project.host.open(H101);
    const last = () => backend.state.decisions.at(-1);
    expect(await project.host.setWork('dead_end', '  nur RDP ')).toBe(true);
    expect(last()).toMatchObject({ kind: 'd.status.work', payload: { subject: H101, value: 'dead_end', reason: 'nur RDP' } });
    expect(await project.host.setAccess('user')).toBe(true);
    expect(last()).toMatchObject({ kind: 'd.status.access', payload: { subject: H101, value: 'user' } });
    expect(await project.host.addTag(' web ')).toBe(true);
    expect(last()).toMatchObject({ kind: 'd.tag.add', payload: { subject: H101, tag: 'web' } });
    expect(await project.host.addTag('x'.repeat(65))).toBe(false);
    expect(await project.host.removeTag('linux')).toBe(true);
    expect(last()).toMatchObject({ kind: 'd.tag.remove', payload: { tag: 'linux' } });
    expect(await project.host.setNote('**neu**')).toBe(true);
    expect(last()).toMatchObject({ kind: 'd.note.set', payload: { subject: H101, text: '**neu**' } });
    expect(await project.host.markStep('privesc', 'sudo -l')).toBe(true);
    expect(last()).toMatchObject({ kind: 'd.keystep.mark', payload: { step: 'privesc', host: H101, note: 'sudo -l' } });
    await until(() => project.map.host(H101)?.work === 'dead_end' && project.map.host(H101)?.tags.includes('web') === true, 3000);
  });

  it('ohne Verbindung wird nichts gesendet', async () => {
    const { app, project, backend } = await ready();
    await project.host.open(H101);
    const spy = vi.spyOn(backend, 'decide');
    app.offline = true;
    expect(await project.host.setWork('done')).toBe(false);
    expect(spy).not.toHaveBeenCalled();
  });
});
