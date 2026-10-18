<!--
  Services im Host-Detail (SCREENS 3, Briefing 5.3): Port, Dienst, Produkt und Version, Zustand
  ausser «open»; vom Ziel angebotene Titel mit «! Injection-Verdacht · vom Ziel angeboten».
  Zuerst 8 Zeilen (verdächtige immer dabei), «N weitere» klappt auf. Verlauf, wenn ein genauerer
  oder neuerer Wert einen alten abgelöst hat («445 Samba 3.X - 4.X → 3.0.20-Debian», E45).
  Besitzer: ui-karte.
-->
<script lang="ts">
  import { COMMA, DOT } from '../karte/sep';
  import type { ServiceView } from '../api/types';
  import { t } from '../i18n';
  import Txt from '../ui/Txt.svelte';

  let { services }: { services: ServiceView[] } = $props();
  const FIRST = 8;
  let all = $state(false);

  const sorted = $derived([...services].sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto)));
  const shown = $derived.by(() => {
    if (all || sorted.length <= FIRST) return sorted;
    const head = sorted.slice(0, FIRST);
    for (const s of sorted.slice(FIRST)) {
      if (!s.suspect) continue;
      // verdächtige Titel nie verstecken: ersetzt die letzte unauffällige Zeile
      const i = head.map((h) => h.suspect).lastIndexOf(false);
      if (i >= 0) head.splice(i, 1);
      head.push(s);
    }
    return head.sort((a, b) => a.port - b.port);
  });
  const hidden = $derived(sorted.length - shown.length);
  const history = $derived(
    sorted.flatMap((s) =>
      s.history.map((h) => ({ port: s.port, old: h.value, now: currentOf(s, h.predicate), key: `${s.service_id}:${h.claim_key}` })),
    ),
  );

  function currentOf(s: ServiceView, pred: ServiceView['history'][number]['predicate']): string {
    if (pred === 'service.state') return s.state ?? '';
    if (pred === 'service.version') return s.version ?? '';
    if (pred === 'service.product') return s.product ?? '';
    return s.name ?? '';
  }

  function product(s: ServiceView): string {
    return [s.product, s.version].filter(Boolean).join(' ');
  }
</script>

<div class="svc" role="table" aria-label={t('host.services')}>
  {#each shown as s (s.service_id)}
    <div class="row" class:suspect={s.suspect} role="row" data-service-id={s.service_id}>
      <span class="port" role="cell">{s.port}{s.proto === 'udp' ? '/udp' : ''}</span>
      <span class="name" role="cell"><Txt value={s.name ?? ''} mono max={20} /></span>
      <span class="prod" role="cell">
        <span class:muted={s.state !== null && s.state !== 'open'}><Txt value={product(s)} mono ctrl={s.ctrl} max={60} />{#if s.state && s.state !== 'open'}{product(s) ? ' · ' : ''}{t(`host.state.${s.state}`)}{/if}</span>
        {#if s.banner}<span class="banner"><Txt value={s.banner} mono max={70} /></span>{/if}
        {#if s.suspect}<span class="flag">{t('host.injection')}</span>{:else if s.from_target && s.banner}<span class="from">{t('host.fromTarget')}</span>{/if}
      </span>
    </div>
  {/each}
</div>
{#if hidden > 0 || history.length > 0 || all}
  <p class="more">
    {#if hidden > 0}<button type="button" class="link" onclick={() => (all = true)}>{t('host.servicesMore', { n: hidden })}</button>{:else if all && sorted.length > FIRST}<button
        type="button"
        class="link"
        onclick={() => (all = false)}>{t('host.servicesLess')}</button
      >{/if}
    {#if history.length > 0}
      {#if hidden > 0 || all}<span aria-hidden="true">{DOT}</span>{/if}{t('host.history', { items: '' })}{#each history as h, i (h.key)}{#if i > 0}{COMMA}{/if}{h.port} <Txt value={h.old} max={40} /> → <Txt value={h.now} max={40} />{/each}
    {/if}
  </p>
{/if}

<style>
  .svc {
    display: flex;
    flex-direction: column;
    gap: 1px;
    padding: 0 12px;
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
  }
  .row {
    display: grid;
    grid-template-columns: 44px 84px minmax(0, 1fr);
    border-radius: 6px;
  }
  .row > span {
    padding: 5px 0;
    min-width: 0;
  }
  .port {
    padding-left: 8px !important;
    color: var(--muted);
  }
  .prod {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding-right: 8px !important;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .prod > span {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .suspect {
    background: var(--surface-3);
  }
  .muted {
    color: var(--muted);
  }
  .banner {
    color: var(--fg-2);
  }
  .flag {
    font-family: var(--font-ui);
    font-size: 11px;
    font-weight: 600;
    color: var(--attention);
  }
  .from {
    font-family: var(--font-ui);
    font-size: 11px;
    color: var(--muted);
  }
  .more {
    margin: 0;
    padding: 6px 20px 12px;
    font-size: var(--fs-s);
    color: var(--muted);
  }
  .link {
    padding: 0;
    border: none;
    background: none;
    font: inherit;
    color: var(--muted);
    cursor: pointer;
  }
  .link:hover {
    color: var(--fg);
  }
</style>
