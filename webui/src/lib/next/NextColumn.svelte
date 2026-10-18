<!--
  Spalte «Als Nächstes» (SCREENS 1a, Ruhezustand, E105, E110, BEHAVIOR «Spalte»):
  - Kopf mit stiller Summe («21 Werte ausserhalb des Scopes, 2 Erwähnungen»).
  - Gruppe «Klären (n)» vor «Denkanstösse (n)»; immer genau ein Eintrag gewählt und aufgeklappt
    (`?sel=`). Erledigte bleiben gedämpft an ihrem Platz, mit «Rückgängig»; im Ruhezustand steht
    der Cursor auf dem ersten Denkanstoss.
  - Tastatur: `j k` wechseln, `↵` Beleg, `a` übernehmen/zusammenführen/annehmen, `x` verwerfen bzw.
    getrennt lassen, `e` ändern bzw. anderer Host, `u` rückgängig, `n` nächster Denkanstoss.
  - Fuss: «Denkanstoss anfordern (KI)» gesperrt mit Grund (kommt mit v0.1-KI) und Tastenhinweis.
  Besitzer: ui-karte.
-->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { t } from '../i18n';
  import { registerKeys } from '../keys/keymap';
  import { focusInZone, pageKeysActive } from '../keys/page';
  import { attrValue, ipShortener } from '../karte/model';
  import type { AppState } from '../stores/app.svelte';
  import type { Row } from '../stores/next.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Button from '../ui/Button.svelte';
  import { url } from '../url/state.svelte';
  import ClarifyItem from './ClarifyItem.svelte';
  import DoneRow from './DoneRow.svelte';
  import SuggestionItem from './SuggestionItem.svelte';

  let { app, project }: { app: AppState; project: ProjectStore } = $props();
  const next = $derived(project.next);
  const v = $derived(next.view);
  const clarifyRows = $derived(next.rowsOf('clarify'));
  const suggestionRows = $derived(next.rowsOf('suggestion'));
  const selectedKey = $derived(next.selectedKey);
  const selectedRow = $derived(next.selectedRow);
  const openClarify = $derived(v?.clarify.length ?? 0);
  const openSuggestions = $derived(v?.suggestions.length ?? 0);
  const short = $derived(ipShortener((project.map.graph?.nodes ?? []).filter((n) => n.kind === 'segment').map((n) => ({ label: n.label }))));
  let body: HTMLDivElement | undefined = $state();

  const quiet = $derived.by(() => {
    const q = v?.quiet;
    if (!q) return '';
    const parts: string[] = [];
    if (q.out_of_scope > 0) parts.push(t('next.quiet.out', { n: q.out_of_scope }));
    if (q.mentions > 0) parts.push(t('next.quiet.mentions', { n: q.mentions }));
    return parts.join(', ');
  });

  const keysLine = $derived.by(() => {
    const parts = [t('next.keys.move')];
    const r = selectedRow;
    if (r?.type === 'clarify') {
      if (r.item.kind === 'ctx_suggestion') parts.push(t('next.keys.accept'));
      else if (r.item.kind === 'merge_suggestion') parts.push(t('next.keys.merge'));
      else if (r.item.kind === 'decide_value') parts.push(t('next.keys.confirm'));
    }
    if ((r?.type === 'clarify' || r?.type === 'suggestion') && hasEvidence(r)) parts.push(t('next.keys.evidence'));
    parts.push(t('next.keys.help'));
    return parts.join(' · ');
  });

  function hasEvidence(r: Row): boolean {
    if (r.type === 'suggestion') return r.s.evidence.length > 0;
    if (r.type === 'clarify') return r.item.kind !== 'merge_suggestion' && r.item.kind !== 'orphan_decision';
    return false;
  }

  // Gewählten Eintrag sichtbar halten (ohne den Fokus zu verschieben)
  $effect(() => {
    const key = selectedKey;
    void tick().then(() => {
      if (!key || !body) return;
      const el = body.querySelector<HTMLElement>(`[data-item-key="${attrValue(key)}"], [data-suggestion-key="${attrValue(key)}"], [data-done-key="${attrValue(key)}"]`);
      el?.scrollIntoView?.({ block: 'nearest' });
    });
  });

  function onButton(): boolean {
    const el = document.activeElement;
    return el instanceof HTMLButtonElement || el instanceof HTMLAnchorElement || el instanceof HTMLInputElement || el instanceof HTMLSelectElement;
  }

  function primary(): boolean {
    const r = next.selectedRow;
    if (!r) return false;
    if (r.type === 'suggestion') return false;
    if (r.type !== 'clarify') return false;
    const it = r.item;
    if (it.kind === 'ctx_suggestion') void next.acceptContext(it);
    else if (it.kind === 'merge_suggestion') void next.merge(it, true);
    else if (it.kind === 'decide_value') void next.decideValue(it, 'confirm');
    else return false;
    return true;
  }

  function reject(): boolean {
    const r = next.selectedRow;
    if (r?.type === 'suggestion') {
      void next.suggestionDismiss(r.s);
      return true;
    }
    if (r?.type !== 'clarify') return false;
    const it = r.item;
    if (it.kind === 'merge_suggestion') void next.merge(it, false);
    else if (it.kind === 'decide_value') void next.decideValue(it, 'reject');
    else return false;
    return true;
  }

  function edit(): boolean {
    const r = next.selectedRow;
    if (r?.type !== 'clarify') return false;
    if (r.item.kind === 'ctx_suggestion' || r.item.kind === 'ctx_unknown') {
      next.openContextDialog(r.item);
      return true;
    }
    if (r.item.kind === 'decide_value') {
      next.requestEdit();
      return true;
    }
    return false;
  }

  function undo(): boolean {
    const r = next.selectedRow;
    const entry = r?.type === 'done' && r.entry.decisionId ? r.entry : next.lastUndoable;
    if (!entry) return false;
    void next.undo(entry);
    return true;
  }

  // Korrektur A2: nur ohne offene Tafel. A8: Ist die Host-Tabelle sichtbar, gehören j k ↵ ihr,
  // ausser der Fokus liegt in der Spalte (feste Zuständigkeit statt Einhängereihenfolge).
  const page = () => pageKeysActive('karte');
  const tableShown = () => project.map.tableOnly || url.get('ansicht') === 'tabelle';
  const listKeys = () => page() && (!tableShown() || focusInZone('next'));
  onMount(() =>
    registerKeys([
      { keys: ['j'], help: 'help.k.lists', when: listKeys, run: () => next.move(1) },
      { keys: ['k'], when: listKeys, run: () => next.move(-1) },
      { keys: ['Enter'], when: () => listKeys() && !onButton(), run: () => next.openEvidence() },
      { keys: ['a'], help: 'help.k.decide', when: () => page() && !app.offline, run: primary },
      { keys: ['x'], when: () => page() && !app.offline, run: reject },
      { keys: ['e'], when: () => page() && !app.offline, run: edit },
      { keys: ['u'], when: () => page() && !app.offline, run: undo },
      { keys: ['n'], help: 'help.k.nextSuggestion', when: page, run: () => next.nextSuggestion() },
    ]),
  );
</script>

<section class="next" aria-label={t('next.label')} data-keyzone="next">
  <header class="head">
    <h2>{t('next.title')}</h2>
    {#if app.offline}<p class="quiet">{t('state.offline.column')}</p>{:else if quiet}<p class="quiet">{quiet}</p>{/if}
  </header>
  <div class="body" bind:this={body}>
    {#if app.offline}
      <!-- SCREENS 9 «Keine Verbindung»: keine Einträge, bis die Verbindung zurück ist -->
    {:else if !v && next.error}
      <p class="error" role="alert">{t('next.error')}</p>
    {:else if !v}
      <p class="muted">{t('next.loading')}</p>
    {:else}
      <div class="group-head">
        <span>{t('next.clarify')}</span>
        {#if openClarify > 0}<span class="n">{openClarify}</span>{:else if clarifyRows.length > 0}<span class="word">{t('next.done')}</span>{/if}
      </div>
      {#if clarifyRows.length === 0}
        <p class="nothing">{t('next.nothing')}</p>
      {/if}
      <div class="rows">
        {#each clarifyRows as r (r.key)}
          {#if r.type === 'clarify'}
            <ClarifyItem {app} {project} item={r.item} selected={r.key === selectedKey} {short} />
          {:else if r.type === 'done'}
            <DoneRow {app} {project} entry={r.entry} selected={r.key === selectedKey} {short} />
          {/if}
        {/each}
      </div>
      {#if v.confirm.length > 0}
        <div class="group-head"><span>{t('next.confirm')}</span><span class="n">{v.confirm.length}</span></div>
      {/if}
      <div class="group-head sug">
        <span>{t('next.suggestions')}</span>
        {#if openSuggestions > 0}<span class="n">{openSuggestions}</span>{:else if suggestionRows.length > 0}<span class="word">{t('next.done')}</span>{/if}
      </div>
      {#if !v.suggestions_available}
        <p class="nothing">{t('next.suggestionsLater')}</p>
      {:else if suggestionRows.length === 0}
        <p class="nothing">{t('next.noSuggestions')}</p>
      {/if}
      <div class="rows">
        {#each suggestionRows as r (r.key)}
          {#if r.type === 'suggestion'}
            <SuggestionItem {app} {project} suggestion={r.s} selected={r.key === selectedKey} {short} />
          {:else if r.type === 'done'}
            <DoneRow {app} {project} entry={r.entry} selected={r.key === selectedKey} {short} />
          {/if}
        {/each}
      </div>
    {/if}
  </div>
  {#if !app.offline}
    <!-- Korrektur D12: ohne Verbindung keine Fusszeile (keine Einträge, Aktionen gesperrt) -->
    <footer class="foot">
      <Button disabled reason={t('next.askAiDisabled')}>{t('next.askAi')}</Button>
      <span class="keys">{keysLine}</span>
    </footer>
  {/if}
</section>

<style>
  .next {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    font-size: var(--fs-m);
  }
  .head {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 18px 20px 12px;
  }
  h2 {
    margin: 0;
    font-size: var(--fs-l);
    font-weight: 600;
  }
  .quiet {
    margin: 0;
    font-size: var(--fs-s);
    color: var(--muted);
  }
  .body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: 0 12px 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  /* Korrektur D5: Zeilen ohne Abstand (Raster 34 px wie im Design), Abstand nur um die Karte */
  .rows {
    display: flex;
    flex-direction: column;
    gap: 0;
  }
  .rows :global(.card) {
    margin: 4px 0 6px;
    line-height: 1.3;
  }
  .group-head {
    display: flex;
    justify-content: space-between;
    padding: 8px 8px 2px;
    color: var(--muted);
    font-size: var(--fs-xs);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .group-head.sug {
    padding-top: 14px;
  }
  .n {
    font-family: var(--font-mono);
  }
  .word {
    text-transform: none;
    letter-spacing: 0;
  }
  .nothing,
  .muted {
    margin: 0;
    padding: 6px 8px;
    color: var(--muted);
  }
  .error {
    margin: 0;
    padding: 6px 8px;
    color: var(--error);
  }
  .foot {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 14px 20px 16px;
    border-top: var(--lw-1) solid var(--line);
  }
  .foot :global(.btn) {
    justify-content: center;
    padding: 9px 12px;
    font-size: 13px;
  }
  .keys {
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--faint);
  }
</style>
