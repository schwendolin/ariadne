<!--
  Zeitachse (Screen 6, Briefing 5.5, BEHAVIOR «Zeitachse»): Filter Typ, Terminal, Host (in der URL:
  typ, terminal, hostf); Lokalzeit mit «UTC zeigen» (utc); Warteliste als eingeklappter Streifen
  oben; Zeilen neuestes oben (TimelineRow) mit Rückgängig inline (UndoInline), «Ältere laden»,
  am Ende «Projektstart 13:58». Gewählte Zeile in der URL (zeile, bei Befehlen die cmd_id).
  Tastatur: j k wählen, ↵ öffnet den Beleg, u macht den gewählten Befehl rückgängig, Esc bricht
  Rückgängig ab; nur solange keine Tafel offen ist. Live-Daten ohne Springen: der Store lädt im
  Hintergrund nach, die Liste behält Auswahl und Scrollposition (Scroll-Anker des Browsers).
  Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import type { HostNode, TimelineItem, TimelineType } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import { registerKeys } from '../keys/keymap';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Popover from '../ui/Popover.svelte';
  import Txt from '../ui/Txt.svelte';
  import { encodeEvidence, url } from '../url/state.svelte';
  import { errorText } from '../util/errors';
  import { termName } from '../util/format';
  import { hhmm, zoneName } from '../util/time';
  import {
    ALL_TYPES,
    canUndo,
    evidenceOf,
    filterFromParams,
    filterToParams,
    isFiltered,
    rowKey,
    rowMatches,
    type TimelineFilter,
  } from './model';
  import PendingStrip from './PendingStrip.svelte';
  import TimelineRow from './TimelineRow.svelte';
  import UndoInline from './UndoInline.svelte';

  let { app, project }: { app: AppState; project: ProjectStore } = $props();

  const store = $derived(project.timeline);
  const rows = $derived(store.rows);
  const zeile = $derived(url.get('zeile'));
  const utc = $derived(url.get('utc') === '1');
  const selIndex = $derived(rows.findIndex((r) => rowMatches(r, zeile)));
  const filter = $derived(store.filter);
  const undo = $derived(store.undo);
  const hosts = $derived(
    ((project.map.graph?.nodes.filter((n) => n.kind === 'host') ?? []) as HostNode[]).slice().sort((a, b) => a.label.localeCompare(b.label, 'de-CH', { numeric: true })),
  );
  const terms = $derived(project.terminals.all.filter((x) => x.term.state !== 'held'));
  const startedAt = $derived(project.info?.created_at ?? project.info?.started_at ?? null);

  /** Serverzeit jetzt (ms): «läuft noch» und Fristen hängen an der Uhr des Daemons */
  let clock = $state(Date.now());
  const now = $derived.by(() => {
    const st = app.status?.server_time ? Date.parse(app.status.server_time) : NaN;
    return Number.isNaN(st) || app.lastGoodAt === null ? clock : st + (clock - app.lastGoodAt);
  });

  let listEl: HTMLOListElement | undefined = $state();
  let scrolledFor: string | null = null;

  // URL -> Filter
  $effect(() => {
    const f = filterFromParams(url.get('typ'), url.get('terminal'), url.get('hostf'));
    untrack(() => store.setFilter(f));
  });

  // Sprung auf `zeile` (Scope-Warnung, Host-Detail, Palette): ältere Seiten nachladen, einmal zeigen
  $effect(() => {
    const z = zeile;
    if (!z || !store.loaded || scrolledFor === z) return;
    void store.ensureRow(z).then(async (ok) => {
      if (!ok || url.get('zeile') !== z) return;
      scrolledFor = z;
      await tick();
      const el = rowEl(z);
      el?.scrollIntoView?.({ block: 'center' });
      el?.focus({ preventScroll: true });
    });
  });

  /** Zeile im DOM nach TimelineItem.id (ohne Selektor aus Daten) */
  function byId(id: string): HTMLElement | null {
    if (!listEl) return null;
    for (const el of listEl.querySelectorAll<HTMLElement>('li[data-row]')) if (el.dataset.row === id) return el;
    return null;
  }

  function rowEl(z: string | null): HTMLElement | null {
    const it = rows.find((r) => rowMatches(r, z));
    return it ? byId(it.id) : null;
  }

  async function select(i: number, focus = false): Promise<void> {
    const it = rows[i];
    if (!it) return;
    const key = rowKey(it);
    scrolledFor = key;
    if (store.undo && store.undo.rowId !== it.id && store.undo.phase !== 'busy' && store.undo.phase !== 'trusting') store.cancelUndo();
    if (url.get('zeile') !== key) url.set({ zeile: key });
    if (focus) {
      await tick();
      const el = byId(it.id);
      el?.focus({ preventScroll: true });
      el?.scrollIntoView?.({ block: 'nearest' });
    }
  }

  function move(delta: 1 | -1): void {
    if (rows.length === 0) return;
    const i = selIndex < 0 ? 0 : Math.max(0, Math.min(rows.length - 1, selIndex + delta));
    void select(i, true);
  }

  function openEvidence(it: TimelineItem | undefined): boolean {
    if (!it) return false;
    const target = evidenceOf(it);
    if (!target) return false;
    url.set({ beleg: encodeEvidence(target) }, { push: true });
    return true;
  }

  function startUndo(it: TimelineItem | undefined): boolean {
    if (!it || !canUndo(it) || app.offline) return false;
    void select(rows.indexOf(it));
    store.askUndo(it);
    return true;
  }

  function closeUndo(): void {
    const id = store.undo?.rowId ?? null;
    store.cancelUndo();
    if (id) byId(id)?.focus({ preventScroll: true });
  }

  function active(): boolean {
    return url.route === 'zeitachse' && !url.get('beleg') && !url.get('tafel');
  }

  onMount(() => {
    const tm = setInterval(() => (clock = Date.now()), 30_000);
    const off = registerKeys([
      { keys: ['j', 'ArrowDown'], help: 'help.k.lists', when: active, run: () => move(1) },
      { keys: ['k', 'ArrowUp'], when: active, run: () => move(-1) },
      { keys: ['Enter'], when: active, run: () => openEvidence(rows[selIndex]) },
      { keys: ['u'], help: 'help.k.decide', when: active, run: () => startUndo(rows[selIndex]) },
      {
        keys: ['Escape'],
        allowInInput: true,
        when: () => active() && !!store.undo && store.undo.phase !== 'busy',
        run: () => closeUndo(),
      },
    ]);
    return () => {
      clearInterval(tm);
      off();
    };
  });

  // ------------------------------------------------------------------ Filter
  function setFilter(f: TimelineFilter): void {
    const p = filterToParams(f);
    url.set({ typ: p.typ, terminal: p.terminal, hostf: p.hostf, zeile: null });
  }

  function toggleType(ty: TimelineType): void {
    const cur = new Set(filter.types ?? ALL_TYPES);
    if (cur.has(ty)) cur.delete(ty);
    else cur.add(ty);
    const list = ALL_TYPES.filter((x) => cur.has(x));
    setFilter({ ...filter, types: list.length === 0 || list.length === ALL_TYPES.length ? null : list });
  }

  const typeLabel = $derived(filter.types ? t('tl.filter.typesN', { n: filter.types.length }) : t('tl.filter.types'));
  const termLabel = $derived.by(() => {
    if (!filter.terminal) return t('tl.filter.terminals');
    const x = terms.find((r) => r.term.terminal_id === filter.terminal)?.term;
    return x ? termName(x) : filter.terminal.slice(-8);
  });
  const hostLabel = $derived(filter.host ? (hosts.find((h) => h.id === filter.host)?.label ?? filter.host) : t('tl.filter.hosts'));

  const POP_TYPE = 'tl-types';
  const POP_TERM = 'tl-terms';
  const POP_HOST = 'tl-hosts';
</script>

<section class="tl" aria-label={t('tl.title')}>
  <div class="filters">
    <span class="pop">
      <button type="button" class="fbtn" class:on={!!filter.types} aria-haspopup="dialog" aria-expanded={app.ui.popover === POP_TYPE} onclick={() => app.ui.togglePopover(POP_TYPE)}
        >{typeLabel} ▾</button
      >
      <Popover open={app.ui.popover === POP_TYPE} onclose={() => app.ui.closePopover(POP_TYPE)} label={t('tl.filter.typeLabel')}>
        <div class="menu">
          {#each ALL_TYPES as ty (ty)}
            <label class="opt">
              <input type="checkbox" checked={!filter.types || filter.types.includes(ty)} onchange={() => toggleType(ty)} />
              {t(`tl.type.${ty}` as MessageKey)}
            </label>
          {/each}
          <button type="button" class="reset" onclick={() => setFilter({ ...filter, types: null })}>{t('tl.filter.reset')}</button>
        </div>
      </Popover>
    </span>
    <span class="pop">
      <button type="button" class="fbtn" class:on={!!filter.terminal} aria-haspopup="dialog" aria-expanded={app.ui.popover === POP_TERM} onclick={() => app.ui.togglePopover(POP_TERM)}
        ><Txt value={termLabel} max={40} flag={false} /> ▾</button
      >
      <Popover open={app.ui.popover === POP_TERM} onclose={() => app.ui.closePopover(POP_TERM)} label={t('tl.filter.termLabel')}>
        <div class="menu" role="radiogroup" aria-label={t('tl.filter.termLabel')}>
          <label class="opt"><input type="radio" name="tl-term" checked={!filter.terminal} onchange={() => setFilter({ ...filter, terminal: null })} />{t('tl.filter.terminals')}</label>
          {#each terms as r (r.term.terminal_id)}
            <label class="opt">
              <input type="radio" name="tl-term" checked={filter.terminal === r.term.terminal_id} onchange={() => setFilter({ ...filter, terminal: r.term.terminal_id })} />
              <Txt value={termName(r.term)} max={40} />
            </label>
          {/each}
        </div>
      </Popover>
    </span>
    <span class="pop">
      <button type="button" class="fbtn" class:on={!!filter.host} aria-haspopup="dialog" aria-expanded={app.ui.popover === POP_HOST} onclick={() => app.ui.togglePopover(POP_HOST)}
        ><Txt value={hostLabel} max={40} flag={false} /> ▾</button
      >
      <Popover open={app.ui.popover === POP_HOST} onclose={() => app.ui.closePopover(POP_HOST)} label={t('tl.filter.hostLabel')}>
        <div class="menu" role="radiogroup" aria-label={t('tl.filter.hostLabel')}>
          <label class="opt"><input type="radio" name="tl-host" checked={!filter.host} onchange={() => setFilter({ ...filter, host: null })} />{t('tl.filter.hosts')}</label>
          {#each hosts as h (h.id)}
            <label class="opt">
              <input type="radio" name="tl-host" checked={filter.host === h.id} onchange={() => setFilter({ ...filter, host: h.id })} />
              <Txt value={h.label} mono max={48} ctrl={h.ctrl} />
            </label>
          {/each}
          {#if hosts.length === 0}<span class="none">{t('tl.filter.noHosts')}</span>{/if}
        </div>
      </Popover>
    </span>
    <span class="zone">
      {utc ? t('tl.zoneUtc') : t('tl.zone', { zone: zoneName() })} ·
      <button type="button" class="utc" aria-pressed={utc} onclick={() => url.set({ utc: utc ? null : '1' })}>{utc ? t('tl.showLocal') : t('tl.showUtc')}</button>
    </span>
  </div>

  <PendingStrip {project} />

  <div class="scroll">
    {#if store.error}
      <p class="error-box" role="alert">{errorText(store.error, 'tl.loadFailed')}</p>
    {/if}
    {#if store.loaded && rows.length === 0 && !store.error}
      <p class="empty">{isFiltered(filter) ? t('tl.emptyFilter') : t('tl.empty')}</p>
    {/if}
    <ol class="rows" bind:this={listEl} aria-label={t('tl.listLabel')}>
      {#each rows as it, i (it.id)}
        <TimelineRow
          {app}
          {project}
          item={it}
          selected={i === selIndex}
          {utc}
          {now}
          onselect={() => void select(i)}
          onopen={() => openEvidence(it)}
          onundo={() => startUndo(it)}
          below={undo && undo.rowId === it.id ? belowUndo : undefined}
        />
      {/each}
    </ol>
    {#snippet belowUndo()}
      {@const it = rows.find((r) => r.id === undo?.rowId)}
      {#if undo && it}<UndoInline {store} {undo} item={it} offline={app.offline} onclose={closeUndo} />{/if}
    {/snippet}
    {#if store.nextCursor}
      <button type="button" class="more" disabled={store.loadingMore} onclick={() => void store.loadMore()}>{store.loadingMore ? t('tl.moreBusy') : t('tl.more')}</button>
    {:else if store.loaded && rows.length > 0 && startedAt && !isFiltered(filter)}
      <p class="start">{t('tl.projectStart', { time: hhmm(startedAt, { utc }) })}</p>
    {/if}
  </div>
</section>

<style>
  .tl {
    height: 100%;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .filters {
    display: flex;
    gap: var(--sp-2);
    align-items: center;
    padding: var(--sp-4) var(--sp-8) 10px;
    border-bottom: var(--lw-1) solid var(--line);
    flex: none;
  }
  .pop {
    position: relative;
  }
  .fbtn {
    padding: 5px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    cursor: pointer;
    max-width: 260px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .fbtn.on {
    border-color: var(--focus);
  }
  .menu {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 4px;
    max-height: 50vh;
    overflow: auto;
  }
  .opt {
    display: flex;
    gap: var(--sp-2);
    align-items: center;
    padding: 6px 8px;
    border-radius: 6px;
    cursor: pointer;
  }
  .opt:hover {
    background: var(--surface-3);
  }
  .reset {
    margin-top: 4px;
    border: none;
    background: none;
    color: var(--muted);
    text-align: left;
    padding: 6px 8px;
    cursor: pointer;
  }
  .none {
    color: var(--muted);
    padding: 6px 8px;
  }
  .zone {
    margin-left: auto;
    color: var(--faint);
    font-size: var(--fs-s);
  }
  .utc {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    cursor: pointer;
    font-size: var(--fs-s);
  }
  .utc:hover {
    color: var(--fg);
  }
  .scroll {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: 6px 20px;
  }
  .rows {
    margin: 0;
    padding: 0;
  }
  .empty {
    margin: var(--sp-3) 12px;
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--line);
    padding: var(--sp-3) 14px;
    color: var(--muted);
    max-width: 420px;
  }
  .error-box {
    margin: var(--sp-3) 12px;
    border-radius: var(--r-card);
    border: var(--lw-1) solid var(--error);
    padding: var(--sp-3) 14px;
    max-width: 560px;
  }
  .more {
    margin: var(--sp-3) 12px;
    padding: 6px 12px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    cursor: pointer;
  }
  .start {
    padding: 14px 12px;
    margin: 0;
    color: var(--faint);
    font-size: var(--fs-s);
  }
</style>
