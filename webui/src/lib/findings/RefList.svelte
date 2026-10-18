<!--
  ATT&CK- bzw. CVE-Einträge eines Findings (Screen 8, web-api.md 18.5): Text in fester Form
  (T1190, T1059.004; CVE-2011-2523), je Eintrag «Hypothese, ohne eigenen Beleg», solange er nicht
  als belegt markiert ist und das Finding keinen gültigen Beleg hat. Eingabe mit Enter oder
  «Hinzufügen», Prüfung wie der Server. Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { t } from '../i18n';
  import { checkId, normId, type RefEntry } from './form';

  let {
    kind,
    label,
    entries,
    hypothesis,
    onchange,
    disabled = false,
  }: {
    kind: 'attack' | 'cve';
    label: string;
    entries: RefEntry[];
    /** gilt der Eintrag als Hypothese? */
    hypothesis: (e: RefEntry) => boolean;
    onchange: (next: RefEntry[]) => void;
    disabled?: boolean;
  } = $props();

  let value = $state('');
  let error = $state<string | null>(null);
  const id = $derived(`fd-${kind}`);

  function add(): void {
    if (!value.trim()) return;
    const err = checkId(kind, value, entries);
    if (err) {
      error = t(err);
      return;
    }
    onchange([...entries, { id: normId(value), supported: false }]);
    value = '';
    error = null;
  }

  function key(e: KeyboardEvent): void {
    if (e.key === 'Enter') {
      e.preventDefault();
      add();
    }
  }
</script>

<div class="field">
  <label for={id}>{label}</label>
  <div class="box" class:invalid={!!error}>
    {#each entries as e (e.id)}
      <div class="entry">
        <span class="mono id">{e.id}</span>
        <span class="spacer"></span>
        {#if hypothesis(e)}<span class="hyp">{t('fd.f.hypothesis')}</span>{/if}
        <label class="sup" title={t('fd.f.supportedHint')}>
          <input
            type="checkbox"
            checked={e.supported}
            {disabled}
            aria-label={`${e.id}: ${t('fd.f.markSupported')}`}
            onchange={() => onchange(entries.map((x) => (x.id === e.id ? { ...x, supported: !x.supported } : x)))}
          />
          {t('fd.f.supported')}
        </label>
        <button type="button" class="x" {disabled} aria-label={t('fd.f.removeId', { id: e.id })} onclick={() => onchange(entries.filter((x) => x.id !== e.id))}>×</button>
      </div>
    {/each}
    <div class="add">
      <input
        {id}
        class="mono"
        bind:value
        placeholder={kind === 'attack' ? t('fd.f.attackPlaceholder') : t('fd.f.cvePlaceholder')}
        autocomplete="off"
        spellcheck="false"
        maxlength="20"
        {disabled}
        onkeydown={key}
        oninput={() => (error = null)}
      />
      {#if value.trim()}<button type="button" class="addbtn" {disabled} onclick={add}>{t('fd.f.addId')}</button>{/if}
    </div>
  </div>
  {#if error}<p class="err" role="alert">{error}</p>{/if}
</div>

<style>
  .field {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }
  label {
    color: var(--muted);
    font-size: var(--fs-s);
  }
  .box {
    border-radius: 7px;
    border: var(--lw-1) solid var(--line-strong);
    background: var(--surface);
    display: flex;
    flex-direction: column;
  }
  .box.invalid {
    border-color: var(--error);
  }
  .entry {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: 8px 12px;
    border-bottom: var(--lw-1) solid var(--line);
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
  }
  .id {
    white-space: nowrap;
  }
  .spacer {
    flex: 1;
  }
  .hyp {
    color: var(--attention);
    font-size: var(--fs-xs);
    text-align: right;
  }
  .sup {
    flex: none;
    display: inline-flex;
    gap: 4px;
    align-items: center;
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .x {
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    padding: 0 2px;
  }
  .add {
    display: flex;
    align-items: center;
  }
  .add input {
    flex: 1;
    border: none;
    background: transparent;
    color: var(--fg);
    padding: 9px 12px;
    min-width: 0;
  }
  .add input:focus {
    outline: none;
  }
  .add input::placeholder {
    font-family: var(--font-ui);
  }
  .box:focus-within {
    border-color: var(--focus);
  }
  .addbtn {
    margin-right: 8px;
    padding: 3px 9px;
    border-radius: 5px;
    border: var(--lw-1) solid var(--line-strong);
    background: transparent;
    color: var(--fg);
    font-size: var(--fs-xs);
    cursor: pointer;
  }
  .err {
    margin: 0;
    color: var(--error);
    font-size: var(--fs-xs);
  }
</style>
