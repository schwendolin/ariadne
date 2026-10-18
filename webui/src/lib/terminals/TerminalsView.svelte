<!--
  Reiter Terminals (SCREENS 5, Briefing 5.4): Spaltenköpfe Terminal, Aufnahme, Kontext und letzter
  Befehl; eine Zeile pro Terminal (TerminalRow), held als gestrichelte Zeile, geschlossene bleiben
  gedämpft stehen; Hinweis auf die Tasten im Terminal. Tastatur (BEHAVIOR): j k wählen, ↵ und e
  Kontext setzen, a Vorschlag übernehmen; nur solange keine Tafel offen ist. Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { t } from '../i18n';
  import { registerKeys } from '../keys/keymap';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import { url } from '../url/state.svelte';
  import TerminalRow from './TerminalRow.svelte';

  let { app, project }: { app: AppState; project: ProjectStore } = $props();

  const store = $derived(project.terminals);
  const rows = $derived(store.all);
  let sel = $state(0);
  let listEl: HTMLUListElement | undefined = $state();
  const rowRefs: Record<string, { accept: () => Promise<void>; openContext: () => void }> = {};

  const current = $derived(rows[Math.min(sel, Math.max(0, rows.length - 1))] ?? null);

  function active(): boolean {
    return url.route === 'terminals' && !url.get('beleg') && !url.get('tafel') && !app.offline;
  }

  async function move(delta: 1 | -1): Promise<void> {
    if (rows.length === 0) return;
    sel = Math.max(0, Math.min(rows.length - 1, sel + delta));
    await tick();
    const id = rows[sel]?.term.terminal_id;
    const el = id ? Array.from(listEl?.querySelectorAll<HTMLElement>('li[data-terminal]') ?? []).find((x) => x.dataset.terminal === id) : null;
    el?.focus({ preventScroll: true });
    el?.scrollIntoView?.({ block: 'nearest' });
  }

  function withCurrent(fn: (ref: { accept: () => Promise<void>; openContext: () => void }) => void): boolean {
    const c = current;
    if (!c || c.closed || c.term.state === 'held') return false;
    const ref = rowRefs[c.term.terminal_id];
    if (!ref) return false;
    fn(ref);
    return true;
  }

  onMount(() =>
    registerKeys([
      { keys: ['j', 'ArrowDown'], help: 'help.k.lists', when: active, run: () => void move(1) },
      { keys: ['k', 'ArrowUp'], when: active, run: () => void move(-1) },
      { keys: ['Enter', 'e'], when: active, run: () => withCurrent((r) => r.openContext()) },
      {
        keys: ['a'],
        when: () => active() && !!current?.term.suggestion,
        run: () => withCurrent((r) => void r.accept()),
      },
    ]),
  );
</script>

<section class="terms" aria-label={t('term.title')}>
  <div class="cols" aria-hidden="true">
    <span>{t('term.col.terminal')}</span><span>{t('term.col.rec')}</span><span>{t('term.col.context')}</span><span></span>
  </div>
  {#if store.loaded && rows.length === 0}
    <div class="empty">
      <strong>{t('term.empty')}</strong>
      <p>{t('term.emptyHint')}</p>
    </div>
  {/if}
  <ul class="list" bind:this={listEl} aria-label={t('term.listLabel')}>
    {#each rows as r, i (r.term.terminal_id)}
      <TerminalRow
        bind:this={rowRefs[r.term.terminal_id]}
        {app}
        {project}
        term={r.term}
        closed={r.closed}
        selected={i === sel}
        onselect={() => (sel = i)}
      />
    {/each}
  </ul>
  <p class="hint">
    {t('term.hint')} <code>F12 h</code> {t('term.hint.host')} · <code>F12 b</code> {t('term.hint.back')} · <code>F12 r</code>
    {t('term.hint.pause')}
  </p>
</section>

<style>
  .terms {
    height: 100%;
    overflow: auto;
    padding: var(--sp-8) 48px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .cols,
  .list {
    max-width: 1180px;
    width: 100%;
  }
  .cols {
    display: grid;
    grid-template-columns: 150px 150px minmax(0, 1fr) 270px;
    gap: var(--sp-4);
    padding: 0 var(--sp-5);
    color: var(--faint);
    font-size: var(--fs-xs);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .list {
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .empty {
    max-width: 1180px;
    padding: 28px var(--sp-5);
    border: var(--lw-1) solid var(--line);
    border-radius: var(--r-card);
  }
  .empty p {
    margin: 6px 0 0;
    color: var(--muted);
  }
  .hint {
    margin: 0;
    padding: 4px var(--sp-5);
    color: var(--faint);
    font-size: var(--fs-s);
  }
  .hint code {
    font-family: var(--font-mono);
  }
</style>
