<!--
  Einstellungen als Tafel wie der Beleg (Screen 11, E112): Darstellung (System, Hell, Dunkel),
  Dichte, Lernmodus, KI, Profil, eigene Secrets (nur verdeckt mit Zahl, nie Werte, nie über HTTP),
  Projekt mit Scope. Theme, Dichte und Lernmodus speichert der Server (PUT /ui/prefs); die Anzeige
  folgt sofort, bei Fehler zurück mit Meldung. Kein Browser-Speicher.
  Abschnitt Scope (E129): Ziele, Ausschlüsse und Zeitfenster aus `GET /scope`; «Entfernen …» pro
  Eintrag und «Ausschliessen …» öffnen den Bestätigungsdialog; im Profil customer nur Anzeige mit
  Hinweis auf `ariadne scope`. Einträge als Text (Txt). Besitzer: ui-fundament, Scope: ui.
  E131: Zustandszeile offen/geschlossen, «Scope öffnen …» bzw. «Scope schliessen …» (Dialog mit
  dry_run), «Hinzufügen …»; bei offenem Scope ohne Einschlüsse steht «offen» statt «keine».
  Im Profil customer kein Knopf.
-->
<script lang="ts">
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import Panel from '../ui/Panel.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import Toggle from '../ui/Toggle.svelte';
  import Txt from '../ui/Txt.svelte';
  import type { ScopeWindow } from '../api/types';
  import { url } from '../url/state.svelte';
  import { scopeOpen } from '../scope/open';

  let { app }: { app: AppState } = $props();
  const p = $derived(app.prefs.prefs);
  const s = $derived(app.status);
  const info = $derived(app.project?.info ?? null);
  const own = $derived(s?.operator?.own_secrets);
  const disabled = $derived(app.offline);
  const scopeStore = $derived(app.project?.scope ?? null);
  const sv = $derived(scopeStore?.view ?? null);
  const include = $derived(sv?.include ?? info?.scope.include ?? []);
  const exclude = $derived(sv?.exclude ?? info?.scope.exclude ?? []);
  const windows = $derived(sv?.windows ?? []);
  const editable = $derived(!!scopeStore && scopeStore.editable && !!app.project);
  const editReason = $derived(app.offline ? t('err.network') : null);
  const open = $derived(scopeOpen(app));

  function windowText(w: ScopeWindow): string {
    return [w.days, w.from && w.to ? `${w.from}–${w.to}` : (w.from ?? w.to), w.tz].filter(Boolean).join(' ');
  }

  function removeEntry(entry: string, list: 'include' | 'exclude'): void {
    app.ui.openDialog({ kind: 'scope-edit', op: 'remove', entry, list });
  }

  function excludeEntry(): void {
    app.ui.openDialog({ kind: 'scope-edit', op: 'exclude' });
  }

  function addEntry(): void {
    app.ui.openDialog({ kind: 'scope-edit', op: 'add' });
  }

  function toggleOpen(): void {
    app.ui.openDialog({ kind: 'scope-open', op: open ? 'close' : 'open' });
  }

  function aiText(): string {
    if (!s || s.llm.mode === 'off') return t('settings.ai.off');
    return t('settings.ai.value', {
      mode: s.llm.mode === 'cloud' ? t('rec.ai.cloud') : t('rec.ai.local'),
      limit: s.llm.budget?.month_limit_usd ?? 0,
      used: (s.llm.budget?.month_used_usd ?? 0).toFixed(2),
    });
  }
</script>

<Panel title={t('settings.title')} onclose={() => url.set({ tafel: null })}>
  <dl class="grid">
    <dt id="set-theme">{t('settings.theme')}</dt>
    <dd>
      <Segmented
        label={t('settings.theme')}
        value={p.theme}
        {disabled}
        options={[
          { value: 'system', label: t('settings.theme.system') },
          { value: 'light', label: t('settings.theme.light') },
          { value: 'dark', label: t('settings.theme.dark') },
        ]}
        onchange={(v) => void app.prefs.set({ theme: v })}
      />
    </dd>
    <dt>{t('settings.density')}</dt>
    <dd>
      <Segmented
        label={t('settings.density')}
        value={p.density}
        {disabled}
        options={[
          { value: 'comfortable', label: t('settings.density.comfortable') },
          { value: 'compact', label: t('settings.density.compact') },
        ]}
        onchange={(v) => void app.prefs.set({ density: v })}
      />
    </dd>
    <dt>{t('settings.learning')}</dt>
    <dd>
      <Toggle
        label={t('settings.learning')}
        checked={p.learning}
        {disabled}
        text={p.learning ? t('settings.learning.on') : t('settings.learning.off')}
        onchange={(v) => void app.prefs.set({ learning: v })}
      />
    </dd>
    <dt>{t('settings.ai')}</dt>
    <dd>{aiText()}</dd>
    <dt>{t('settings.profile')}</dt>
    <dd>{s?.project?.profile ?? '–'} <span class="faint">· {t('settings.profile.hint')}</span></dd>
    <dt>{t('settings.ownSecrets')}</dt>
    <dd data-testid="own-secrets">
      <span class="mono">{t('secret.mask')}</span>
      {#if typeof own === 'number'}
        <span class="faint">· {t('settings.ownSecrets.value', { n: own })}</span>
      {:else if own === null || s?.operator?.unlocked === false}
        <span class="faint">· {t('settings.ownSecrets.locked')}</span>
      {/if}
    </dd>
    <dt>{t('settings.project')}</dt>
    <dd>
      {#if info}<span class="mono">{info.slug}</span>{:else}–{/if}
      <span class="faint">· {t('settings.project.hint')}</span>
    </dd>
  </dl>
  {#if app.project}
    <section class="scope" aria-labelledby="set-scope" data-testid="settings-scope">
      <h3 id="set-scope">{t('scope.view.title')}</h3>
      <div class="state" class:open data-testid="scope-state">
        <span>{open ? t('scope.state.open') : t('scope.state.closed')}</span>
        {#if editable}<button type="button" class="small" disabled={!!editReason} title={editReason ?? undefined} onclick={toggleOpen}>{open ? t('scope.close.button') : t('scope.open.button')}</button>{/if}
      </div>
      <h4>{t('scope.view.include')}</h4>
      {#if include.length === 0}<p class="none">{open ? t('scope.view.open') : t('scope.view.empty')}</p>{/if}
      <ul>
        {#each include as e, i (`${i}:${e}`)}
          <li>
            <span class="mono entry"><Txt value={e} mono max={120} /></span>
            {#if editable}<button type="button" class="small" disabled={!!editReason} title={editReason ?? undefined} onclick={() => removeEntry(e, 'include')}>{t('scope.edit.removeButton')}</button>{/if}
          </li>
        {/each}
      </ul>
      <h4>{t('scope.view.exclude')}</h4>
      {#if exclude.length === 0}<p class="none">{t('scope.view.empty')}</p>{/if}
      <ul>
        {#each exclude as e, i (`${i}:${e}`)}
          <li>
            <span class="mono entry"><Txt value={e} mono max={120} /></span>
            {#if editable}<button type="button" class="small" disabled={!!editReason} title={editReason ?? undefined} onclick={() => removeEntry(e, 'exclude')}>{t('scope.edit.removeButton')}</button>{/if}
          </li>
        {/each}
      </ul>
      {#if editable}
        <div class="adds">
          <button type="button" class="small add" disabled={!!editReason} title={editReason ?? undefined} onclick={addEntry}>{t('scope.edit.addButton')}</button>
          <button type="button" class="small add" disabled={!!editReason} title={editReason ?? undefined} onclick={excludeEntry}>{t('scope.edit.excludeButton')}</button>
        </div>
      {/if}
      <h4>{t('scope.view.windows')}</h4>
      {#if windows.length === 0}
        <p class="none">{t('scope.view.windowsNone')}</p>
      {:else}
        <ul>{#each windows as w, i (i)}<li><span class="mono entry"><Txt value={windowText(w)} mono max={120} /></span></li>{/each}</ul>
      {/if}
      {#if editable}
        <p class="faint hint">{t('scope.view.hint')}</p>
      {:else}
        <p class="hint">{t('scope.view.hintCustomer')} <code>{t('scope.view.cli')}</code></p>
      {/if}
    </section>
  {/if}
</Panel>

<style>
  .grid {
    display: grid;
    grid-template-columns: 130px minmax(0, 1fr);
    gap: 14px var(--sp-4);
    align-items: center;
    margin: 0;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    min-width: 0;
  }
  .faint {
    color: var(--faint);
  }
  .mono {
    font-family: var(--font-mono);
  }
  .scope {
    margin-top: var(--sp-5);
    padding-top: var(--sp-3);
    border-top: var(--lw-1) solid var(--line);
  }
  .scope h3 {
    margin: 0 0 var(--sp-2);
    font-size: var(--fs-m);
    font-weight: 600;
  }
  .scope h4 {
    margin: var(--sp-3) 0 var(--sp-1);
    font-size: 11.5px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-weight: 400;
    color: var(--faint);
  }
  .scope ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .scope li {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    min-width: 0;
  }
  .entry {
    flex: 1;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .none {
    margin: 0;
    color: var(--muted);
  }
  .small {
    flex: none;
    padding: 4px 9px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    font-size: var(--fs-xs);
    cursor: pointer;
  }
  .small:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .adds {
    display: flex;
    gap: var(--sp-2);
    flex-wrap: wrap;
    margin-top: var(--sp-2);
  }
  .state {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-2);
    flex-wrap: wrap;
    padding: 8px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line);
  }
  .state.open {
    border-color: var(--attention);
    color: var(--attention);
  }
  .state.open .small {
    color: var(--fg);
  }
  .hint {
    margin: var(--sp-3) 0 0;
    font-size: var(--fs-xs);
  }
  .hint code {
    font-family: var(--font-mono);
  }
</style>
