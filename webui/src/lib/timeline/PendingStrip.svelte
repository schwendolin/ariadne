<!--
  Warteliste als eingeklappter Streifen oben in der Zeitachse (E114, Screen 6 und 10, Briefing 5.8):
  «3 Dateien nicht übernommen · neueste 16:49»; aufgeklappt Pfad (Zieldaten, nur Text), Grund,
  Grösse, Zeit bzw. «gehört vermutlich zu nmap 15:10». Übernehmen geht in v0.1 nur im Terminal mit
  `ariadne import ‹pfad›`: der Befehl lässt sich kopieren (Ziel Mac), aber nur, wenn der Pfad keine
  Shell-Sonderzeichen enthält (E68); sonst steht nur der Hinweis da. Leer: «Keine Dateien in der
  Warteliste». Besitzer: ui-verlauf.
-->
<script lang="ts">
  import type { PendingFile } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import type { ProjectStore } from '../stores/project.svelte';
  import CopyButton from '../ui/CopyButton.svelte';
  import Txt from '../ui/Txt.svelte';
  import { errorText } from '../util/errors';
  import { bytes } from '../util/format';
  import { hhmm } from '../util/time';
  import { shortCommand } from './model';

  let { project }: { project: ProjectStore } = $props();
  const SEP = ' · ';

  const REASONS = new Set(['outside_workspace', 'symlink', 'hardlink', 'owner', 'not_regular', 'other_fs', 'path', 'too_large']);
  /** Pfad ohne Shell-Sonderzeichen, Leerraum, Steuerzeichen und `..` (Vorlagen-Regel E68) */
  const SAFE_PATH = /^(~\/)?[A-Za-z0-9._/+-]{1,255}$/;

  let open = $state(false);
  const data = $derived(project.timeline.pending);
  const files = $derived(data?.files ?? []);
  const newest = $derived(files.reduce<string | null>((m, f) => (m === null || f.ts > m ? f.ts : m), null));
  const failed = $derived(project.timeline.pendingError);

  function reason(f: PendingFile): string {
    return t((REASONS.has(f.reason) ? `pending.reason.${f.reason}` : 'pending.reason.other') as MessageKey);
  }

  function owner(f: PendingFile): string | null {
    const c = project.timeline.findByCmd(f.cmd_id);
    return c ? shortCommand(c.cmd.text, hhmm(c.ts)) : null;
  }

  function safe(path: string): boolean {
    return SAFE_PATH.test(path) && !path.split('/').includes('..');
  }
</script>

<div class="pending" class:open>
  {#if failed && !data}
    <div class="strip static"><strong>{t('pending.strip')}</strong><span class="muted">{errorText(failed, 'pending.failed')}</span></div>
  {:else if files.length === 0}
    <div class="strip static"><strong>{t('pending.strip')}</strong><span class="muted">{t('pending.empty')}</span></div>
  {:else}
    <button type="button" class="strip" aria-expanded={open} aria-controls="pending-list" onclick={() => (open = !open)}>
      <strong>{t('pending.strip')}</strong>
      <span class="muted">{t('pending.summary', { n: files.length, time: hhmm(newest) })}</span>
      <span class="caret" aria-hidden="true">{open ? '▴' : '▾'}</span>
      <span class="sr-only">{t('pending.toggle')}</span>
    </button>
    {#if open}
      <ul class="list" id="pending-list">
        {#each files as f, i (`${f.path}#${i}`)}
          {@const by = owner(f)}
          <li class="file">
            <span class="path"><Txt value={f.path} mono max={120} ctrl={f.ctrl} /></span>
            <span class="meta">
              {#if by}{t('pending.belongsTo', { cmd: by })}{:else}{reason(f)}{/if}{#if f.size !== null}{SEP}{bytes(f.size)}{/if}{#if !by}{SEP}{hhmm(f.ts)}{/if}
            </span>
            {#if safe(f.path)}
              <span class="copy"><CopyButton target="mac" text={`ariadne import ${f.path}`} label={t('pending.copyCmd')} /></span>
            {:else}
              <span class="meta warn">{t('pending.unsafePath')}</span>
            {/if}
          </li>
        {/each}
        {#if data?.truncated}<li class="file muted">{t('pending.truncated')}</li>{/if}
        <li class="hint">{t('pending.hint')} <code>{t('pending.hintCmd')}</code></li>
      </ul>
    {/if}
  {/if}
</div>

<style>
  .pending {
    margin: 10px 32px 0;
    border-radius: 8px;
    border: var(--lw-1) solid var(--line);
    flex: none;
  }
  .strip {
    width: 100%;
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: 9px 14px;
    border: none;
    background: transparent;
    color: var(--fg);
    border-radius: 8px;
    text-align: left;
    cursor: pointer;
  }
  .strip:hover:not(.static) {
    background: var(--rec-bg);
  }
  .static {
    cursor: default;
  }
  .caret {
    margin-left: auto;
    color: var(--muted);
    font-size: 10px;
  }
  .muted {
    color: var(--muted);
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 6px;
    border-top: var(--lw-1) solid var(--line);
    background: var(--surface-2);
    border-radius: 0 0 8px 8px;
    max-height: 40vh;
    overflow: auto;
  }
  .file {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 3px var(--sp-3);
    padding: 10px 12px;
  }
  .file + .file {
    border-top: var(--lw-1) solid var(--line);
  }
  .path {
    font-size: var(--fs-s);
    min-width: 0;
  }
  .meta {
    grid-column: 1;
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .warn {
    color: var(--attention);
  }
  .copy {
    grid-column: 2;
    grid-row: 1 / span 2;
    align-self: center;
  }
  .hint {
    padding: 10px 12px;
    border-top: var(--lw-1) solid var(--line);
    color: var(--faint);
    font-size: var(--fs-xs);
  }
  code {
    font-family: var(--font-mono);
  }
</style>
