<!--
  Karte eines Hosts bzw. von Kali als HTML über dem Cytoscape-Canvas (SCREENS 1a, A 7.5, E108).
  - Host: Symbol (# root, $ user, ⊘ Sackgasse), Adresse in Mono, genau ein Hinweis («23 Services»,
    «im Nebel», «Sackgasse · nur RDP», «! Konflikt: Dienstname 445»); beim Hineinzoomen bis 6 Ports.
  - Füllung nach Zugriff, gepunkteter Rand im Nebel, Auswahlring 2 px --focus, verknüpfter Host mit
    gestricheltem Ring in --attention und der Nummer des Eintrags («K2»), Puls bei «Neu seit».
  - Ein echter Knopf (Tab, Enter); Zieldaten nur über Txt, nie als HTML oder Link.
  Besitzer: ui-karte.
-->
<script lang="ts">
  import type { GraphLayer } from '../api/types';
  import { t, type MessageKey } from '../i18n';
  import Txt from '../ui/Txt.svelte';
  import { pulse } from '../util/motion';
  import { hostHint, hostSymbol, zoomPorts, type CardModel } from './model';

  let {
    card,
    layers,
    selected = false,
    linked = null,
    zoomed = false,
    pulseToken = 0,
    pulsing = false,
    onselect,
  }: {
    card: CardModel;
    layers: Set<GraphLayer>;
    selected?: boolean;
    /** Nummer des gewählten Eintrags («K2»), wenn er diesen Host betrifft */
    linked?: string | null;
    /** Zoom gross genug für Ports */
    zoomed?: boolean;
    pulseToken?: number;
    pulsing?: boolean;
    onselect: (id: string) => void;
  } = $props();

  const tk = (key: string, p?: Record<string, string | number>) => t(key as MessageKey, p);
  const host = $derived(card.host);
  const hint = $derived(host ? hostHint(host, layers, tk) : null);
  const symbol = $derived(host ? hostSymbol(host) : '');
  const ports = $derived(host && zoomed && layers.has('services') && hint?.kind === 'services' ? zoomPorts(host) : []);
  const kaliAddr = $derived(card.kali?.addresses ?? []);
  const access = $derived(host?.claim_state === 'candidate' ? 'fog' : (host?.access ?? 'none'));
  const aria = $derived.by(() => {
    if (card.kind === 'kali') return `${t('karte.kali')} ${kaliAddr.join(', ')}`;
    if (!host || !hint) return '';
    const parts = [hint.text + (hint.value ? ` · ${hint.value}` : '')];
    if (host.access === 'admin') parts.push(t('karte.access.admin'));
    else if (host.access === 'user') parts.push(t('karte.access.user'));
    if (selected) parts.push(t('karte.selected'));
    if (linked) parts.push(t('karte.linked', { item: linked }));
    return t('karte.cardAria', { label: host.label, hint: parts.filter(Boolean).join(', ') });
  });
</script>

<div class="wrap" class:selected class:linked={!!linked} use:pulse={{ token: pulseToken, active: pulsing }}>
  {#if card.kind === 'kali'}
    <button type="button" class="card kali" data-host-id="kali" data-map-card aria-label={aria} aria-pressed={selected} onclick={() => onselect('kali')}>
      <span class="name">{t('karte.kali')}</span>
      {#if kaliAddr[0]}<span class="addr"><Txt value={kaliAddr[0]} mono max={40} />{#if kaliAddr.length > 1}<span class="more"> +{kaliAddr.length - 1}</span>{/if}</span>{/if}
    </button>
  {:else if host && hint}
    <button
      type="button"
      class="card a-{access}"
      class:dead={hint.kind === 'dead'}
      data-host-id={host.id}
      data-map-card
      aria-label={aria}
      aria-pressed={selected}
      onclick={() => onselect(host.id)}
    >
      {#if symbol}<span class="sym" aria-hidden="true">{symbol}</span>{/if}
      <span class="text">
        <span class="ip"><Txt value={host.label} mono ctrl={host.ctrl} max={40} /></span>
        {#if hint.kind !== 'none'}
          <span class="hint h-{hint.kind}">{hint.text}{#if hint.value}{hint.kind === 'conflict' ? ': ' : ' · '}<Txt value={hint.value} max={40} />{/if}</span>
        {/if}
        {#if ports.length}<span class="ports">{ports.join(' · ')}</span>{/if}
      </span>
    </button>
  {/if}
  {#if linked}
    <span class="ring ring-linked" aria-hidden="true"></span>
    <span class="ring-label" aria-hidden="true">{linked}</span>
  {/if}
  {#if selected}<span class="ring ring-sel" aria-hidden="true"></span>{/if}
</div>

<style>
  .wrap {
    position: relative;
    border-radius: var(--r-card);
  }
  .card {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    width: 214px;
    min-height: 66px;
    padding: 8px 12px;
    border-radius: var(--r-card);
    border: var(--lw-node) solid var(--line-strong);
    background: color-mix(in srgb, var(--surface) 40%, var(--surface-2));
    color: var(--fg);
    text-align: left;
    cursor: pointer;
    font: inherit;
  }
  .card:hover {
    border-color: var(--muted);
  }
  .card:focus-visible {
    outline: var(--lw-focus) solid var(--focus);
    outline-offset: 3px;
  }
  .kali {
    flex-direction: column;
    align-items: flex-start;
    justify-content: center;
    gap: 2px;
    width: auto;
    min-width: 120px;
    min-height: 64px;
    padding: 0 14px;
    white-space: nowrap;
    background: var(--surface-2);
    border-color: var(--line-hover);
  }
  .kali .name {
    font-weight: 600;
    font-size: 14px;
  }
  .kali .addr {
    font-size: 11.5px;
    color: var(--muted);
  }
  .more {
    color: var(--faint);
  }
  .a-admin {
    background: var(--access-root-bg);
    border-color: var(--access-root);
  }
  .a-admin:hover {
    background: color-mix(in srgb, var(--access-root-bg) 82%, var(--access-root));
    border-color: var(--access-root);
  }
  .a-user {
    background: var(--access-user-bg);
    border-color: var(--access-user);
  }
  .a-user:hover {
    background: color-mix(in srgb, var(--access-user-bg) 82%, var(--access-user));
    border-color: var(--access-user);
  }
  .a-fog {
    width: 190px;
    min-height: 56px;
    padding: 6px 14px;
    background: transparent;
    border-style: dotted;
    border-color: var(--fog);
  }
  .a-fog:hover {
    border-color: var(--muted);
  }
  .sym {
    width: 30px;
    height: 30px;
    flex: none;
    border-radius: 7px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 16px;
    background: var(--access-root);
    color: var(--bg);
  }
  .a-user .sym {
    background: var(--access-user);
  }
  .dead .sym {
    background: transparent;
    border: var(--lw-node) solid var(--line-hover);
    color: var(--muted);
    font-family: var(--font-ui);
    font-weight: 400;
    font-size: 15px;
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .ip {
    font-size: var(--fs-m);
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .a-fog .ip {
    font-size: 13px;
    font-weight: 400;
    color: var(--muted);
  }
  .dead .ip {
    font-weight: 400;
    color: var(--fg-2);
  }
  .hint {
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .a-admin .h-services {
    color: color-mix(in srgb, var(--access-root) 85%, var(--fg));
  }
  .a-user .h-services {
    color: color-mix(in srgb, var(--access-user) 85%, var(--fg));
  }
  .h-fog {
    color: var(--faint);
  }
  .h-conflict {
    color: var(--attention);
  }
  .ports {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted);
  }
  .ring {
    position: absolute;
    pointer-events: none;
    box-sizing: border-box;
  }
  .ring-sel {
    inset: -6px;
    border-radius: 13px;
    border: var(--lw-focus) solid var(--focus);
  }
  .ring-linked {
    inset: -7px;
    border-radius: 14px;
    border: var(--lw-focus) dashed var(--attention);
  }
  .selected .ring-linked {
    inset: -10px;
    border-radius: 16px;
  }
  .ring-label {
    position: absolute;
    right: 28px;
    bottom: -14px;
    padding: 0 4px;
    font-size: 11.5px;
    line-height: 1.2;
    color: var(--attention);
    background: var(--map);
    pointer-events: none;
  }
</style>
