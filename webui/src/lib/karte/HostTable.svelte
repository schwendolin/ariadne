<!--
  Host-Tabelle (Screen 12, E108, Briefing 5.1): ab 200 Hosts statt der Karte, darunter mit `t`
  umschaltbar. Umschalter Hosts, Services, Credentials (v0.2, gesperrt); Auswahl in der URL
  (`tabelle`). Hosts: Konflikte zuerst, dann Fortschritt, dann Adresse. Services nach Klasse
  filterbar («alle SMB»). `j k` wechseln, `↵` öffnet das Host-Detail in der Spalte. Lange Listen
  werden nur im sichtbaren Ausschnitt gezeichnet (Positionen per CSSOM). Zieldaten über Txt.
  Besitzer: ui-karte.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import type { HostSummary, ServiceClass, ServiceView } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import { registerKeys } from '../keys/keymap';
  import type { ProjectStore } from '../stores/project.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import Txt from '../ui/Txt.svelte';
  import { styleProps } from '../ui/actions';
  import { url } from '../url/state.svelte';
  import { hhmm } from '../util/time';
  import { conflictWhat, hostSymbol } from './model';

  let { project, selected = null, onopen }: { project: ProjectStore; selected?: string | null; onopen: (hostId: string) => void } = $props();

  const ROW = 37;
  const CLASSES: ServiceClass[] = ['web', 'smb', 'db', 'remote', 'file', 'mail', 'other'];
  const kind = $derived(url.get('tabelle') === 'services' ? 'services' : 'hosts');
  let cls = $state<ServiceClass | 'all'>('all');
  let cursor = $state(0);
  let viewport: HTMLDivElement | undefined = $state();
  let scrollTop = $state(0);
  let height = $state(600);

  const table = $derived(project.map.table);
  const g = $derived(project.map.graph);
  const hosts = $derived<HostSummary[]>(table.sortedHosts);
  const services = $derived<ServiceView[]>(
    [...(table.services ?? [])]
      .filter((s) => cls === 'all' || s.class === cls)
      .sort((a, b) => a.host_label.localeCompare(b.host_label, 'en', { numeric: true }) || a.port - b.port),
  );
  const count = $derived(kind === 'hosts' ? hosts.length : services.length);
  const start = $derived(Math.max(0, Math.floor(scrollTop / ROW) - 8));
  const end = $derived(Math.min(count, Math.ceil((scrollTop + height) / ROW) + 8));
  const indices = $derived(Array.from({ length: Math.max(0, end - start) }, (_, i) => start + i));
  const firstVisible = $derived(count === 0 ? 0 : Math.min(count, Math.floor(scrollTop / ROW) + 1));
  const lastVisible = $derived(Math.min(count, Math.floor((scrollTop + height) / ROW)));
  const loading = $derived(kind === 'hosts' ? table.hosts === null : table.services === null);
  const tk = (key: string, p?: Record<string, string | number>) => t(key as MessageKey, p);

  $effect(() => {
    void table.ensure(kind);
  });

  // Auswahl aus der URL übernehmen (Rückkehr aus dem Detail)
  $effect(() => {
    if (kind !== 'hosts' || !selected) return;
    const i = hosts.findIndex((h) => h.id === selected);
    if (i >= 0) cursor = i;
  });

  function summary(): string {
    if (!g) return '';
    const s = g.summary;
    return `${t('lage.stand', { time: hhmm(g.as_of ?? project.map.loadedAt) })} · ${t('lage.hosts', { n: s.hosts })} · ${t('lage.access', { n: s.with_access })}`;
  }

  function knowledge(k: HostSummary['knowledge'], fog: boolean): string {
    return fog ? t('karte.fog') : t(`host.knowledge.${k}` as MessageKey);
  }

  function scrollToCursor(): void {
    if (!viewport) return;
    const top = cursor * ROW;
    if (top < viewport.scrollTop) viewport.scrollTop = top;
    else if (top + ROW > viewport.scrollTop + viewport.clientHeight) viewport.scrollTop = top + ROW - viewport.clientHeight;
    scrollTop = viewport.scrollTop;
  }

  function moveCursor(delta: number): void {
    if (count === 0) return;
    cursor = Math.max(0, Math.min(count - 1, cursor + delta));
    scrollToCursor();
  }

  function hostAt(i: number): string | null {
    return kind === 'hosts' ? (hosts[i]?.id ?? null) : (services[i]?.host_id ?? null);
  }

  function openAt(i: number): void {
    cursor = i;
    const id = hostAt(i);
    if (id) onopen(id);
  }

  onMount(() =>
    registerKeys([
      { keys: ['j'], help: 'help.k.lists', run: () => moveCursor(1) },
      { keys: ['k'], run: () => moveCursor(-1) },
      {
        keys: ['Enter'],
        when: () => !(document.activeElement instanceof HTMLButtonElement || document.activeElement instanceof HTMLAnchorElement),
        run: () => openAt(cursor),
      },
    ]),
  );

  function setKind(v: 'hosts' | 'services' | 'credentials'): void {
    if (v === 'credentials') return;
    cursor = 0;
    if (viewport) viewport.scrollTop = 0;
    scrollTop = 0;
    url.set({ tabelle: v === 'hosts' ? null : v });
  }
</script>

<div class="table-view" aria-label={t('table.label')}>
  <div class="bar">
    <span class="sum">{summary()}</span>
    {#if kind === 'services'}
      <span class="classes" role="group" aria-label={t('table.classLabel')}>
        <button type="button" class="chip" aria-pressed={cls === 'all'} onclick={() => (cls = 'all')}>{t('table.classAll')}</button>
        {#each CLASSES as c (c)}
          <button type="button" class="chip" aria-pressed={cls === c} onclick={() => (cls = c)}>{c}</button>
        {/each}
      </span>
    {/if}
    <span class="switch">
      <Segmented
        label={t('table.kind')}
        value={kind}
        onchange={setKind}
        options={[
          { value: 'hosts', label: t('table.hosts') },
          { value: 'services', label: t('table.services') },
          { value: 'credentials', label: t('table.credentials'), disabled: true },
        ]}
      />
    </span>
  </div>
  {#if kind === 'hosts'}
    <div class="row head hosts" aria-hidden="true">
      <span></span><span>{t('table.col.host')} ▾</span><span>{t('table.col.knowledge')}</span><span>{t('table.col.services')}</span><span>{t('table.col.hint')}</span>
    </div>
  {:else}
    <div class="row head svcs" aria-hidden="true">
      <span>{t('table.col.port')}</span><span>{t('table.col.host')}</span><span>{t('table.col.name')}</span><span>{t('table.col.product')}</span><span>{t('table.col.state')}</span>
    </div>
  {/if}
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <div class="body" bind:this={viewport} bind:clientHeight={height} onscroll={() => (scrollTop = viewport?.scrollTop ?? 0)} tabindex="0" role="list" aria-label={t('table.label')}>
    {#if loading}
      <p class="empty">{t('table.loading')}</p>
    {:else if count === 0}
      <p class="empty">{kind === 'hosts' ? t('table.empty') : t('table.emptyServices')}</p>
    {:else}
      <div class="spacer" use:styleProps={{ '--h': count * ROW }}>
        {#each indices as i (i)}
          {#if kind === 'hosts'}
            {@const h = hosts[i]}
            {#if h}
              <div role="listitem" class="ri" use:styleProps={{ '--top': i * ROW }}><button
                type="button"
                class="row hosts"
                class:cursor={i === cursor}
                class:sel={h.id === selected}
                data-host-id={h.id}
                onclick={() => openAt(i)}
              >
                <span class="sym s-{h.claim_state === 'candidate' ? 'fog' : h.access}" aria-hidden="true">{hostSymbol(h)}</span>
                <span class="mono"><Txt value={h.label} mono ctrl={h.ctrl} max={40} /></span>
                <span class="muted">{knowledge(h.knowledge, h.claim_state === 'candidate')}</span>
                <span class="mono ports">{(h.ports ?? []).join(' · ')}</span>
                <span class="hint">
                  {#if h.conflicts > 0}{t('table.conflict', { what: conflictWhat(h, tk) ?? '' }).replace(/: $/, '')}{:else if h.work === 'dead_end'}{t('karte.deadEnd')}{#if h.work_reason}{' · '}<Txt value={h.work_reason} max={40} />{/if}{/if}
                </span>
              </button></div>
            {/if}
          {:else}
            {@const s = services[i]}
            {#if s}
              <div role="listitem" class="ri" use:styleProps={{ '--top': i * ROW }}><button
                type="button"
                class="row svcs"
                class:cursor={i === cursor}
                data-service-id={s.service_id}
                onclick={() => openAt(i)}
              >
                <span class="mono muted">{s.port}/{s.proto}</span>
                <span class="mono"><Txt value={s.host_label} mono max={40} /></span>
                <span class="mono"><Txt value={s.name ?? ''} mono max={24} /></span>
                <span class="mono"><Txt value={[s.product, s.version].filter(Boolean).join(' ')} mono ctrl={s.ctrl} max={60} /></span>
                <span class="muted">{s.state ?? ''}{#if s.conflicts > 0}<span class="warn"> · !</span>{/if}</span>
              </button></div>
            {/if}
          {/if}
        {/each}
      </div>
    {/if}
  </div>
  <div class="foot">{count > 0 ? t('table.footer', { from: firstVisible, to: lastVisible, n: count }) : t('table.footerEmpty')}</div>
</div>

<style>
  .table-view {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    font-size: var(--fs-m);
    background: var(--bg);
  }
  .bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 20px;
    border-bottom: var(--lw-1) solid var(--line);
  }
  .sum {
    color: var(--muted);
    white-space: nowrap;
  }
  .switch {
    margin-left: auto;
  }
  .classes {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }
  .chip {
    padding: 2px 8px;
    border-radius: var(--r-pill);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    font-size: var(--fs-xs);
    font-family: var(--font-mono);
    color: var(--muted);
    cursor: pointer;
  }
  .chip[aria-pressed='true'] {
    background: var(--fg);
    border-color: var(--fg);
    color: var(--bg);
  }
  .row {
    display: grid;
    gap: 12px;
    align-items: center;
    padding: 7px 20px;
    width: 100%;
    text-align: left;
  }
  .row.hosts {
    grid-template-columns: 44px 170px 160px 120px minmax(0, 1fr);
  }
  .row.svcs {
    grid-template-columns: 90px 170px 120px minmax(0, 1fr) 110px;
  }
  .head {
    padding-top: 8px;
    padding-bottom: 8px;
    color: var(--faint);
    font-size: var(--fs-xs);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border-bottom: var(--lw-1) solid var(--line);
  }
  .body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    position: relative;
  }
  .spacer {
    position: relative;
    height: calc(var(--h, 0) * 1px);
  }
  .ri {
    position: absolute;
    left: 0;
    right: 0;
    top: calc(var(--top, 0) * 1px);
  }
  button.row {
    height: 37px;
    border: none;
    border-bottom: var(--lw-1) solid var(--surface-2);
    background: transparent;
    color: var(--fg);
    font: inherit;
    cursor: pointer;
  }
  button.row:hover {
    background: var(--rec-bg);
  }
  .cursor {
    box-shadow: inset 2px 0 0 var(--focus);
    background: var(--surface);
  }
  .sel {
    background: var(--surface-2);
  }
  .sym {
    width: 22px;
    height: 22px;
    border-radius: 5px;
    border: var(--lw-node) solid var(--line-strong);
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 700;
  }
  .s-admin {
    background: var(--access-root);
    border-color: var(--access-root);
    color: var(--bg);
  }
  .s-user {
    background: var(--access-user);
    border-color: var(--access-user);
    color: var(--bg);
  }
  .s-fog {
    border-style: dotted;
    border-color: var(--fog);
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ports {
    color: var(--fg-2);
  }
  .muted {
    color: var(--muted);
  }
  .hint {
    color: var(--attention);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .warn {
    color: var(--attention);
  }
  .empty {
    padding: 20px;
    color: var(--muted);
  }
  .foot {
    padding: 10px 20px;
    border-top: var(--lw-1) solid var(--line);
    color: var(--faint);
    font-size: var(--fs-s);
  }
</style>
