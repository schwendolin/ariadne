<!--
  Segment-Umschalter (Theme, Dichte, Schwere, Status, Tabelle Hosts/Services; Screen 11): Rand
  --line-strong, gewählt gefüllt mit --fg. Tastatur: Pfeile innerhalb der Gruppe (radiogroup), der
  Fokus folgt der Wahl. Besitzer: ui-fundament.
-->
<script lang="ts" generics="T extends string">
  let {
    options,
    value,
    onchange,
    label,
    disabled = false,
  }: {
    options: { value: T; label: string; disabled?: boolean }[];
    value: T | null;
    onchange: (v: T) => void;
    label: string;
    disabled?: boolean;
  } = $props();

  function key(e: KeyboardEvent, i: number): void {
    const dir = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
    if (!dir) return;
    e.preventDefault();
    const n = options.length;
    for (let k = 1; k <= n; k++) {
      const o = options[(i + dir * k + n) % n];
      if (o && !o.disabled) {
        onchange(o.value);
        const group = (e.currentTarget as HTMLElement).parentElement;
        queueMicrotask(() => group?.querySelectorAll<HTMLButtonElement>('button')[(i + dir * k + n) % n]?.focus());
        break;
      }
    }
  }
</script>

<div class="seg" role="radiogroup" aria-label={label}>
  {#each options as o, i (o.value)}
    <button
      type="button"
      role="radio"
      aria-checked={value === o.value}
      tabindex={value === o.value || (value === null && i === 0) ? 0 : -1}
      disabled={disabled || o.disabled}
      onclick={() => onchange(o.value)}
      onkeydown={(e) => key(e, i)}>{o.label}</button
    >
  {/each}
</div>

<style>
  .seg {
    display: inline-flex;
    border: var(--lw-1) solid var(--line-strong);
    border-radius: 7px;
    overflow: hidden;
  }
  button {
    border: none;
    border-left: var(--lw-1) solid var(--line-strong);
    background: transparent;
    padding: 6px 10px;
    cursor: pointer;
    color: var(--fg);
    line-height: 1.2;
  }
  button:first-child {
    border-left: none;
  }
  button:hover:not(:disabled):not([aria-checked='true']) {
    background: var(--surface-3);
  }
  button[aria-checked='true'] {
    background: var(--fg);
    color: var(--bg);
    font-weight: 600;
  }
  button:focus-visible {
    outline-offset: -3px;
  }
  button:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
</style>
