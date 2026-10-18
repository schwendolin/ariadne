<!--
  Befehlsvorlage eines Denkanstosses (E68, Briefing 9.5, Screen 4 D2). Die Vorlage kommt fertig vom
  Server (typisierte Platzhalter, Kontext-Encoder); die UI baut nie selbst einen Befehl.
  - `rendered`: Befehl in Mono, Zieldaten gepunktet unterstrichen, «Kopieren · Mac» (ohne
    Zeilenumbruch am Ende).
  - sonst: «Enthält Shell-Sonderzeichen. Keine fertige Vorlage.» (Grund aus `blocked_reason`) und nur
    die Einzelwerte, jeder einzeln kopierbar («Mac»).
  Nie ein Ausführen-Knopf (E10). Besitzer: ui-karte.
-->
<script lang="ts">
  import type { CommandTemplate } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import CopyButton from '../ui/CopyButton.svelte';
  import TargetText from '../ui/TargetText.svelte';
  import Txt from '../ui/Txt.svelte';

  let { template, showLabel = false, title = null }: { template: CommandTemplate; showLabel?: boolean; title?: string | null } = $props();
  const blocked = $derived(t(`sug.blocked.${template.blocked_reason ?? 'shell_meta'}` as MessageKey));
</script>

{#if template.rendered && template.command}
  <div class="tpl-wrap" data-template-id={template.template_id}>
    {#if showLabel}<span class="label"><Txt value={template.label} max={60} /></span>{/if}
    <div class="tpl">
      <code><TargetText parts={template.parts} mono /></code>
      <CopyButton target="mac" text={template.command} />
    </div>
  </div>
{:else}
  <div class="blocked" data-template-id={template.template_id} data-blocked={template.blocked_reason ?? ''}>
    {#if title}<span class="title"><Txt value={title} max={120} /></span>{/if}
    <p class="warn">! {blocked}</p>
    <div class="vals">
      {#each template.values as v (v.slot)}
        <span class="lbl"><Txt value={v.label} max={30} /></span>
        <code class="val" class:unsafe={!v.safe} title={v.safe ? undefined : t('sug.valueUnsafe')}><Txt value={v.value} mono ctrl={v.ctrl} target={v.target} max={80} /></code>
        <CopyButton target="mac" text={v.value} short />
      {/each}
    </div>
  </div>
{/if}

<style>
  .tpl-wrap {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .label {
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .tpl {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: 8px 8px 8px 10px;
    border-radius: 7px;
    background: var(--bg);
    border: var(--lw-1) solid var(--line);
  }
  code {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--fg);
    overflow-wrap: anywhere;
  }
  .blocked {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .title {
    font-size: 14.5px;
    font-weight: 600;
  }
  .warn {
    margin: 0;
    font-size: var(--fs-xs);
    font-weight: 600;
    color: var(--attention);
  }
  .vals {
    display: grid;
    grid-template-columns: 62px minmax(0, 1fr) auto;
    gap: 6px 8px;
    align-items: center;
    font-size: var(--fs-s);
  }
  .lbl {
    color: var(--muted);
  }
  .val {
    font-size: var(--fs-s);
    justify-self: start;
  }
</style>
