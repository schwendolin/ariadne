<!--
  Phase eines Befehls für den Export (Briefing 5.12, Entwurf api-export): Auswahl der Phasen der
  Vorlage, «nach Regel» oder «korrigiert». Eine Änderung schreibt `POST /exports/phases` (Entscheid
  `d.unit.phase`, übersteht Reparse). Besitzer: ui.
-->
<script lang="ts">
  import type { PhaseCommand } from '../api/types';
  import { t } from '../i18n';

  let {
    entry,
    phases,
    cmdRef,
    disabled = false,
    onpick,
  }: { entry: PhaseCommand | null; phases: { key: string; label: string }[]; cmdRef: string; disabled?: boolean; onpick: (phase: string) => void } = $props();
</script>

<span class="phase" data-phase-of={cmdRef}>
  <label>
    <span class="sr-only">{t('tl.phase.select', { ref: cmdRef })}</span>
    <select value={entry?.phase ?? ''} {disabled} onchange={(e) => onpick((e.currentTarget as HTMLSelectElement).value)}>
      {#if !entry?.phase}<option value="" disabled>{t('tl.phase.none')}</option>{/if}
      {#each phases as p (p.key)}
        <option value={p.key}>{p.label}</option>
      {/each}
    </select>
  </label>
  <span class="src" class:none={!entry?.phase}>
    {#if !entry || entry.source === 'none'}{t('tl.phase.none')}{:else if entry.source === 'decision'}{t('tl.phase.decision')}{:else}{t('tl.phase.rule')}{/if}
  </span>
</span>

<style>
  .phase {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 2px 0 4px 124px;
    font-size: var(--fs-s);
  }
  select {
    padding: 3px 6px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: var(--surface);
    color: var(--fg);
    font: inherit;
  }
  .src {
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .src.none {
    color: var(--attention);
  }
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
</style>
