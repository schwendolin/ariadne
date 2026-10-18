<!--
  Eingabefeld mit Label und Fehlertext unter dem Feld (Anmeldung, Kontext, Findings). Einzeltasten
  der Seite wirken hier nicht (keymap). Besitzer: ui-fundament.
-->
<script lang="ts">
  let {
    label,
    value = $bindable(''),
    placeholder = '',
    error = null,
    mono = false,
    multiline = false,
    rows = 4,
    maxlength = undefined,
    autofocus = false,
    id,
    oninput,
  }: {
    label: string;
    value?: string;
    placeholder?: string;
    error?: string | null;
    mono?: boolean;
    multiline?: boolean;
    rows?: number;
    maxlength?: number | undefined;
    autofocus?: boolean;
    id: string;
    oninput?: (v: string) => void;
  } = $props();
</script>

<div class="field">
  <label for={id}>{label}</label>
  {#if multiline}
    <textarea {id} class:mono class:invalid={!!error} {rows} {placeholder} {maxlength} bind:value oninput={() => oninput?.(value)} data-autofocus={autofocus ? '' : undefined}></textarea>
  {:else}
    <input {id} class:mono class:invalid={!!error} {placeholder} {maxlength} bind:value oninput={() => oninput?.(value)} autocomplete="off" spellcheck="false" data-autofocus={autofocus ? '' : undefined} />
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</div>

<style>
  .field {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  label {
    font-size: var(--fs-s);
    color: var(--muted);
  }
  input,
  textarea {
    padding: 8px 12px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: var(--surface);
    color: var(--fg);
  }
  .mono {
    font-family: var(--font-mono);
    letter-spacing: 0.04em;
  }
  .invalid {
    border-color: var(--error);
  }
  .error {
    margin: 0;
    color: var(--error);
    font-size: var(--fs-s);
  }
</style>
