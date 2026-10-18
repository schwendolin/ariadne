<!--
  Befehlspalette ⌘K (Briefing 4.3, Screen 10): sucht in den geladenen Daten über die Quellen der
  Bereiche (palette.ts: Hosts und Services, Als Nächstes, Befehle, Aktionen), höchstens 40 Treffer,
  gruppiert. Volltext im Rohlog nur auf Wunsch: der letzte Eintrag «Im Rohlog suchen: «q»» ruft
  GET /search (Secrets maskiert) und zeigt die Fundstellen; ↵ öffnet den Beleg. Treffer aus
  Zieldaten nur über Txt. Pfeile wählen, ↵ führt aus, Esc schliesst (Fokus zurück).
  Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { SearchResult } from '../api/types';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Txt from '../ui/Txt.svelte';
  import { encodeEvidence, url } from '../url/state.svelte';
  import { errorText, isAbort } from '../util/errors';
  import { hhmm } from '../util/time';
  import { GROUP_LABEL, search, type PaletteItem } from './palette';

  let { app, onclose }: { app: AppState; onclose: () => void } = $props();
  const LOG_ID = 'log:search';
  const LOG_MAX = 12;

  let query = $state('');
  let index = $state(0);
  let logFor = $state<string | null>(null);
  let logHits = $state.raw<SearchResult | null>(null);
  let logBusy = $state(false);
  let logError = $state<string | null>(null);
  let listEl: HTMLElement | undefined = $state();

  const q = $derived(query.trim());
  const canLog = $derived(!!app.project && q.length >= 2 && q.length <= 200 && !app.offline);

  const results = $derived.by<PaletteItem[]>(() => {
    const local = search(q);
    if (!canLog) return local;
    const out = [...local];
    if (logFor === q && logHits) {
      for (const [i, h] of logHits.items.slice(0, LOG_MAX).entries()) {
        out.push({
          id: `log:${i}:${h.unit_id}:${h.line}`,
          group: 'log',
          label: h.text,
          mono: true,
          hint: `${h.context_label || '–'} · ${hhmm(h.ts)}`,
          keywords: '',
          run: () => url.set({ beleg: encodeEvidence({ kind: 'unit', unit_id: h.unit_id, lines: [h.line, h.line] }) }, { push: true }),
        });
      }
    } else {
      out.push({ id: LOG_ID, group: 'log', label: t('palette.searchLog', { q }), keywords: '', run: () => void searchLog() });
    }
    return out;
  });

  $effect(() => {
    // Auswahl im sichtbaren Bereich halten
    const el = listEl?.querySelector<HTMLElement>(`[data-index="${index}"]`);
    if (typeof el?.scrollIntoView === 'function') el.scrollIntoView({ block: 'nearest' });
  });

  async function searchLog(): Promise<void> {
    const p = app.project;
    if (!p || !canLog) return;
    const term = q;
    logBusy = true;
    logError = null;
    try {
      const res = await p.backend.search(p.pid, term, 50, p.signal);
      if (query.trim() !== term) return;
      logFor = term;
      logHits = res;
      const first = search(term).length;
      index = res.items.length > 0 ? first : Math.max(0, first - 1);
    } catch (e) {
      if (!isAbort(e)) logError = errorText(e);
    } finally {
      logBusy = false;
    }
  }

  function run(item: PaletteItem | undefined): void {
    if (!item) return;
    if (item.id === LOG_ID) {
      void searchLog();
      return;
    }
    onclose();
    item.run();
  }

  function oninput(): void {
    index = 0;
    logError = null;
  }

  const keys = [
    { keys: ['ArrowDown'], allowInInput: true, run: () => void (index = Math.min(results.length - 1, index + 1)) },
    { keys: ['ArrowUp'], allowInInput: true, run: () => void (index = Math.max(0, index - 1)) },
    { keys: ['Enter'], allowInInput: true, run: () => run(results[index]) },
  ];
</script>

<Dialog title={t('palette.title')} {onclose} {keys} size="l" position="top" bare>
  <div class="head">
    <input
      class="q"
      bind:value={query}
      {oninput}
      placeholder={t('palette.placeholder')}
      aria-label={t('palette.title')}
      aria-controls="palette-list"
      aria-activedescendant={results[index] ? `palette-opt-${index}` : undefined}
      role="combobox"
      aria-expanded="true"
      autocomplete="off"
      spellcheck="false"
      maxlength="200"
      data-autofocus
    />
  </div>
  {#if results.length === 0}
    <p class="empty">{q ? t('palette.empty', { q }) : t('palette.placeholder')}</p>
  {:else}
    <ul id="palette-list" role="listbox" tabindex="-1" aria-label={t('palette.title')} bind:this={listEl}>
      {#each results as item, i (item.id)}
        {#if i === 0 || results[i - 1]?.group !== item.group}<li class="group" role="presentation">{t(GROUP_LABEL[item.group])}</li>{/if}
        <li role="option" id="palette-opt-{i}" aria-selected={i === index} data-index={i}>
          <button type="button" tabindex="-1" class:active={i === index} onclick={() => run(item)} onmouseenter={() => (index = i)}>
            <span class="label"><Txt value={item.label} mono={item.mono ?? false} max={90} /></span>
            {#if item.id === LOG_ID && logBusy}<span class="hint">{t('palette.searchLogBusy')}</span>
            {:else if item.hint}<span class="hint" class:mono={item.hint.length <= 3}><Txt value={item.hint} max={40} flag={false} /></span>{/if}
          </button>
        </li>
      {/each}
    </ul>
  {/if}
  {#if logFor === q && logHits && logHits.items.length === 0}<p class="note">{t('palette.searchLogNone')}</p>{/if}
  {#if logFor === q && logHits && (logHits.truncated || logHits.items.length > LOG_MAX)}<p class="note">{t('palette.searchLogMore')}</p>{/if}
  {#if logError}<p class="note error" role="alert">{logError}</p>{/if}
  <p class="foot">{t('palette.hint')}</p>
</Dialog>

<style>
  .head {
    padding: 14px var(--sp-4);
    border-bottom: var(--lw-1) solid var(--line);
  }
  .q {
    width: 100%;
    padding: 0;
    border: none;
    background: transparent;
    font-size: var(--fs-l);
    color: var(--fg);
  }
  .q:focus,
  .q:focus-visible {
    outline: none;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 6px;
    max-height: 52vh;
    overflow: auto;
  }
  .group {
    padding: var(--sp-2) 10px var(--sp-1);
    font-size: 11.5px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--faint);
  }
  li button {
    width: 100%;
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: var(--sp-3);
    padding: var(--sp-2) 10px;
    border: none;
    border-radius: var(--r-btn);
    background: none;
    text-align: left;
    cursor: pointer;
    color: var(--fg);
  }
  li button.active {
    background: var(--line);
  }
  .label {
    min-width: 0;
  }
  .hint {
    flex: none;
    color: var(--muted);
    font-size: var(--fs-xs);
    white-space: nowrap;
  }
  .hint.mono {
    font-family: var(--font-mono);
  }
  .empty,
  .note {
    margin: 0;
    padding: var(--sp-3) var(--sp-4);
    color: var(--muted);
  }
  .note {
    padding-top: 0;
    font-size: var(--fs-s);
  }
  .error {
    color: var(--error);
  }
  .foot {
    margin: 0;
    padding: var(--sp-2) var(--sp-4);
    border-top: var(--lw-1) solid var(--line);
    color: var(--faint);
    font-size: var(--fs-xs);
    font-family: var(--font-mono);
  }
</style>
