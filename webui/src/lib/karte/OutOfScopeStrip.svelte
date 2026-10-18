<!--
  Schraffierter Streifen am rechten Kartenrand «Out of Scope · N» (A 7.5, Screen 10). Ein Klick
  öffnet das Popover mit Wert, Urteil, Quelle und Hinweis pro Kennung («ausserhalb · nmap 15:20 ·
  gleiche MAC wie .101»). Feindliche Werte immer als Text (Txt), Punycode zusätzlich, nie als Link
  oder Bild. Ein Eintrag mit Quelle öffnet die Belegansicht. «Scope erweitern» gibt es in v0.1 nur
  im Terminal. Besitzer: ui-karte.
-->
<script lang="ts">
  import type { OosItem } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Popover from '../ui/Popover.svelte';
  import Txt from '../ui/Txt.svelte';
  import { encodeEvidence, url } from '../url/state.svelte';
  import { hhmm } from '../util/time';
  import { ipShortener } from './model';

  let { app, project }: { app: AppState; project: ProjectStore } = $props();
  const ID = 'oos';
  const oos = $derived(project.map.graph?.oos ?? { total: 0, items: [] });
  const open = $derived(app.ui.popover === ID);
  const short = $derived(ipShortener((project.map.graph?.nodes ?? []).filter((n) => n.kind === 'segment').map((n) => ({ label: n.label }))));

  function hostLabel(id: string | null | undefined): string | null {
    if (!id) return null;
    return project.map.host(id)?.label ?? null;
  }

  /** Untertitel: Urteil · Quelle · Hinweis (feste Texte; Werte über Txt in `values`) */
  function details(it: OosItem): { text: string; value: string | null }[] {
    const out: { text: string; value: string | null }[] = [];
    out.push({ text: t(`oos.verdict.${it.verdict}` as MessageKey), value: null });
    if (it.rule) out.push({ text: t('oos.rule', { rule: '' }).trim(), value: it.rule });
    const src = it.source ?? null;
    if (src) {
      const tool = (src.title.split(/\s+/)[0] ?? '').slice(0, 40);
      out.push({ text: '', value: `${tool} ${hhmm(src.ts)}`.trim() });
    }
    if (it.note === 'same_mac') {
      const rel = hostLabel(it.related);
      out.push(rel ? { text: t('oos.note.same_mac', { host: '' }).trim(), value: short(rel) } : { text: t('oos.note.sameMacPlain'), value: null });
    } else if (it.note === 'forged_callback') {
      out.push({ text: t('oos.note.forged_callback'), value: null });
    }
    if (it.mentions > 1) out.push({ text: t('oos.mentions', { n: it.mentions }), value: null });
    return out;
  }

  function evidence(it: OosItem): string | null {
    const unit = it.source?.unit_id ?? it.first_unit;
    return unit ? encodeEvidence({ kind: 'unit', unit_id: unit, lines: null }) : null;
  }

  function openEvidence(it: OosItem): void {
    const ev = evidence(it);
    if (!ev) return;
    app.ui.closePopover(ID);
    url.set({ beleg: ev }, { push: true });
  }
</script>

{#if oos.total > 0}
  <div class="strip">
    <button type="button" class="handle" aria-expanded={open} aria-haspopup="dialog" onclick={() => app.ui.togglePopover(ID)}>
      <span class="label">{t('oos.strip', { n: oos.total })}</span>
    </button>
    <Popover {open} onclose={() => app.ui.closePopover(ID)} label={t('oos.title')} placement="left" wide>
      <div class="list">
        {#each oos.items as it (it.identifier)}
          {@const ev = evidence(it)}
          {#snippet body()}
            <span class="value"><Txt value={it.label} mono ctrl={it.ctrl} max={90} />{#if it.punycode}<span class="puny"> <Txt value={it.punycode} mono max={90} /></span>{/if}</span>
            <span class="sub">
              {#each details(it) as d, i (i)}{#if i > 0}<span aria-hidden="true">{' · '}</span>{/if}{d.text}{#if d.value}{d.text ? ' ' : ''}<Txt value={d.value} max={60} />{/if}{/each}
            </span>
          {/snippet}
          {#if ev}
            <button type="button" class="item" onclick={() => openEvidence(it)}>{@render body()}</button>
          {:else}
            <div class="item">{@render body()}</div>
          {/if}
        {/each}
        {#if oos.total > oos.items.length}<p class="more">{t('oos.more', { n: oos.total - oos.items.length })}</p>{/if}
        <p class="hint">{t('oos.hint')}</p>
      </div>
    </Popover>
  </div>
{/if}

<style>
  .strip {
    position: absolute;
    top: 0;
    right: 0;
    bottom: 0;
    width: 38px;
    z-index: 3;
    border-left: var(--lw-1) solid var(--line);
    background: repeating-linear-gradient(135deg, var(--out-of-scope) 0 5px, var(--map) 5px 11px);
  }
  .strip:hover {
    background: var(--surface-2);
  }
  .handle {
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    border: none;
    background: transparent;
    cursor: pointer;
    padding: 0;
  }
  .label {
    writing-mode: vertical-rl;
    transform: rotate(180deg);
    background: var(--map);
    padding: 8px 2px;
    font-size: var(--fs-s);
    letter-spacing: 0.02em;
    color: var(--muted);
  }
  .strip :global(.popover) {
    top: 50%;
    transform: translateY(-50%);
    max-height: 80vh;
    overflow: auto;
  }
  .list {
    display: flex;
    flex-direction: column;
  }
  .item {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 10px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: var(--fg);
    text-align: left;
    font: inherit;
  }
  button.item {
    cursor: pointer;
  }
  button.item:hover {
    background: var(--surface-3);
  }
  .value {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
    overflow-wrap: anywhere;
  }
  .puny {
    color: var(--muted);
  }
  .sub {
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .more {
    margin: 0;
    padding: 6px 10px;
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .hint {
    margin: 0;
    padding: 8px 10px;
    color: var(--faint);
    font-size: var(--fs-xs);
    border-top: var(--lw-1) solid var(--line);
  }
</style>
