<!--
  Schalter (Lernmodus; Screen 11): 34 x 20, an gefüllt mit --fg. role="switch", der Text daneben
  nennt den Zustand. Besitzer: ui-fundament.
-->
<script lang="ts">
  let {
    checked,
    onchange,
    label,
    text = '',
    disabled = false,
  }: { checked: boolean; onchange: (v: boolean) => void; label: string; text?: string; disabled?: boolean } = $props();
</script>

<span class="toggle">
  <button type="button" role="switch" aria-checked={checked} aria-label={label} {disabled} onclick={() => onchange(!checked)}>
    <span class="knob"></span>
  </button>
  {#if text}<span class="text">{text}</span>{/if}
</span>

<style>
  .toggle {
    display: inline-flex;
    align-items: center;
    gap: 10px;
  }
  button {
    flex: none;
    width: 34px;
    height: 20px;
    border-radius: var(--r-pill);
    border: none;
    background: var(--line-strong);
    padding: 3px;
    cursor: pointer;
    display: inline-flex;
    justify-content: flex-start;
  }
  button[aria-checked='true'] {
    background: var(--fg);
    justify-content: flex-end;
  }
  button:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .knob {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: var(--bg);
  }
</style>
