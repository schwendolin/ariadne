<!--
  «Betroffen» eines Findings (Screen 8): Kennungen als Chips («192.168.56.101:21 ftp»), entfernen
  mit ×, «+ Host oder Service» öffnet ein Popover mit Suche über die Hosts der Karte und die
  Services (GET /services, beim ersten Öffnen). Höchstens 50 Einträge. Labels sind Zieldaten (Txt).
  Besitzer: ui-verlauf.
-->
<script lang="ts">
  import { tick } from 'svelte';
  import type { HostNode, ServiceView } from '../api/types';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import type { ProjectStore } from '../stores/project.svelte';
  import Popover from '../ui/Popover.svelte';
  import Txt from '../ui/Txt.svelte';
  import { isAbort } from '../util/errors';
  import { AFFECTED_MAX, type AffectedEntry } from './form';

  let {
    app,
    project,
    entries,
    onchange,
    disabled = false,
  }: { app: AppState; project: ProjectStore; entries: AffectedEntry[]; onchange: (next: AffectedEntry[]) => void; disabled?: boolean } = $props();

  const POP = 'fd-affected';
  let q = $state('');
  let services = $state.raw<ServiceView[] | null>(null);
  const open = $derived(app.ui.popover === POP);

  const options = $derived.by(() => {
    const chosen = new Set(entries.map((e) => e.subject));
    const hosts = ((project.map.graph?.nodes.filter((n) => n.kind === 'host') ?? []) as HostNode[]).map((h) => ({
      subject: h.id,
      label: h.label,
      ctrl: h.ctrl,
    }));
    const svcs = (services ?? []).map((s) => ({
      subject: s.service_id,
      label: `${s.host_label}:${s.port}${s.name ? ` ${s.name}` : ''}`,
      ctrl: s.ctrl,
    }));
    const needle = q.trim().toLowerCase();
    return [...hosts, ...svcs].filter((o) => !chosen.has(o.subject) && (!needle || o.label.toLowerCase().includes(needle))).slice(0, 40);
  });

  async function toggle(): Promise<void> {
    app.ui.togglePopover(POP);
    await tick();
    if (app.ui.popover === POP) document.getElementById('fd-affected-q')?.focus();
    if (services === null) {
      try {
        services = await project.backend.services(project.pid, {}, project.signal);
      } catch (e) {
        if (!isAbort(e)) services = [];
      }
    }
  }

  function add(o: AffectedEntry): void {
    if (entries.length >= AFFECTED_MAX) return;
    onchange([...entries, o]);
    q = '';
  }
</script>

<div class="chips">
  {#each entries as e (e.subject)}
    <span class="chip">
      <Txt value={e.label} mono max={60} ctrl={e.ctrl} />
      <button type="button" class="x" {disabled} aria-label={t('fd.f.removeAffected', { label: e.label })} onclick={() => onchange(entries.filter((x) => x.subject !== e.subject))}>×</button>
    </span>
  {/each}
  <span class="pop">
    <button type="button" class="add" disabled={disabled || entries.length >= AFFECTED_MAX} aria-haspopup="dialog" aria-expanded={open} onclick={() => void toggle()}>{t('fd.f.addAffected')}</button>
    <Popover {open} onclose={() => app.ui.closePopover(POP)} label={t('fd.f.affected')} wide>
      <div class="menu">
        <label class="sr-only" for="fd-affected-q">{t('fd.f.affectedFilter')}</label>
        <input id="fd-affected-q" bind:value={q} placeholder={t('fd.f.affectedFilter')} autocomplete="off" spellcheck="false" />
        <div class="opts">
          {#each options as o (o.subject)}
            <button type="button" class="opt" onclick={() => add(o)}><Txt value={o.label} mono max={60} ctrl={o.ctrl} /></button>
          {/each}
          {#if options.length === 0}<span class="none">{t('fd.f.affectedNone')}</span>{/if}
        </div>
      </div>
    </Popover>
  </span>
</div>

<style>
  .chips {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    align-items: center;
  }
  .chip {
    display: inline-flex;
    gap: 6px;
    align-items: center;
    padding: 4px 10px;
    border-radius: var(--r-pill);
    border: var(--lw-1) solid var(--line-strong);
    font-size: var(--fs-s);
  }
  .x {
    border: none;
    background: none;
    color: var(--muted);
    cursor: pointer;
    padding: 0;
  }
  .pop {
    position: relative;
  }
  .add {
    padding: 4px 10px;
    border-radius: var(--r-pill);
    border: var(--lw-1) dashed var(--line-strong);
    background: transparent;
    color: var(--muted);
    cursor: pointer;
  }
  .add:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }
  .menu {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 4px;
  }
  .menu input {
    padding: 7px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line-strong);
    background: var(--bg);
    color: var(--fg);
  }
  .opts {
    display: flex;
    flex-direction: column;
    max-height: 40vh;
    overflow: auto;
  }
  .opt {
    text-align: left;
    padding: 7px 9px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--fg);
    cursor: pointer;
  }
  .opt:hover {
    background: var(--surface-3);
  }
  .none {
    color: var(--muted);
    padding: 7px 9px;
  }
</style>
