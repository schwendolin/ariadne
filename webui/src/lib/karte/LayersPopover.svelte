<!--
  «Ebenen und Legende» unten links (SCREENS 1a, Briefing 5.1): Ebenen Topologie (immer), Services,
  Faden, Out of Scope, Nebel; Platz für «Credentials» (v0.2, gesperrt). Die Auswahl steht in der URL
  (`ebenen`), nie im Browser-Speicher. Darunter die Legende der Kartenzeichen (nie nur Farbe: jedes
  Zeichen hat Text). Besitzer: ui-karte.
-->
<script lang="ts">
  import type { GraphLayer } from '../api/types';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import Popover from '../ui/Popover.svelte';
  import { url } from '../url/state.svelte';
  import { layersParam, TOGGLE_LAYERS } from './model';

  let { app, layers }: { app: AppState; layers: Set<GraphLayer> } = $props();
  const ID = 'layers';
  const open = $derived(app.ui.popover === ID);
  const NAMES: Record<Exclude<GraphLayer, 'topology'>, 'layers.services' | 'layers.thread' | 'layers.oos' | 'layers.fog'> = {
    services: 'layers.services',
    thread: 'layers.thread',
    oos: 'layers.oos',
    fog: 'layers.fog',
  };

  function toggle(l: GraphLayer): void {
    const next = new Set(layers);
    if (next.has(l)) next.delete(l);
    else next.add(l);
    url.set({ ebenen: layersParam(next) });
  }
</script>

<div class="layers">
  <button type="button" class="btn" aria-expanded={open} aria-haspopup="dialog" onclick={() => app.ui.togglePopover(ID)}>{t('layers.button')}</button>
  <Popover {open} onclose={() => app.ui.closePopover(ID)} label={t('layers.button')} placement="above">
    <div class="pop">
      <h3>{t('layers.title')}</h3>
      <ul class="toggles">
        <li>
          <label class="row disabled"><input type="checkbox" checked disabled /> {t('layers.topology')} <span class="note">{t('layers.topologyAlways')}</span></label>
        </li>
        {#each TOGGLE_LAYERS as l (l)}
          <li>
            <label class="row"><input type="checkbox" checked={layers.has(l)} onchange={() => toggle(l)} data-layer={l} /> {t(NAMES[l])}</label>
          </li>
        {/each}
        <li>
          <label class="row disabled" title={t('table.credentialsLater')}><input type="checkbox" disabled /> {t('layers.credentials')} <span class="note">{t('layers.later')}</span></label>
        </li>
      </ul>
      <h3>{t('layers.legend')}</h3>
      <ul class="legend">
        <li><span class="sw sw-root" aria-hidden="true">#</span>{t('layers.lg.root')}</li>
        <li><span class="sw sw-user" aria-hidden="true">$</span>{t('layers.lg.user')}</li>
        <li><span class="sw sw-none" aria-hidden="true"></span>{t('layers.lg.none')}</li>
        <li><span class="sw sw-fog" aria-hidden="true"></span>{t('layers.lg.fog')}</li>
        <li><span class="sw sw-dead" aria-hidden="true">⊘</span>{t('layers.lg.dead')}</li>
        <li><span class="sw-line" aria-hidden="true"><span class="sw-num">1</span></span>{t('layers.lg.thread')}</li>
        <li><span class="sw sw-linked" aria-hidden="true"></span>{t('layers.lg.linked')}</li>
        <li><span class="sw sw-sel" aria-hidden="true"></span>{t('layers.lg.selected')}</li>
        <li><span class="sw sw-seg" aria-hidden="true"></span>{t('layers.lg.segment')}</li>
      </ul>
      <p class="keys">{t('layers.keys')}</p>
    </div>
  </Popover>
</div>

<style>
  .layers {
    position: absolute;
    left: 16px;
    bottom: 14px;
    z-index: 3;
  }
  .btn {
    padding: 5px 10px;
    border-radius: var(--r-btn);
    border: var(--lw-1) solid var(--line);
    background: var(--rec-bg);
    font-size: var(--fs-s);
    color: var(--muted);
    cursor: pointer;
  }
  .btn:hover {
    color: var(--fg);
  }
  .pop {
    padding: 6px 10px 8px;
    min-width: 280px;
  }
  h3 {
    margin: 6px 0 4px;
    font-size: var(--fs-xs);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--muted);
    font-weight: 500;
  }
  ul {
    list-style: none;
    margin: 0 0 6px;
    padding: 0;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 0;
    cursor: pointer;
  }
  .row.disabled {
    cursor: default;
    color: var(--muted);
  }
  .note {
    margin-left: auto;
    font-size: var(--fs-xs);
    color: var(--faint);
  }
  input[type='checkbox'] {
    accent-color: var(--fg);
    margin: 0;
  }
  .legend li {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 3px 0;
    font-size: var(--fs-s);
  }
  .sw {
    width: 26px;
    height: 16px;
    flex: none;
    border-radius: 4px;
    border: var(--lw-node) solid var(--line-strong);
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .sw-root {
    background: var(--access-root);
    border-color: var(--access-root);
    color: var(--bg);
  }
  .sw-user {
    background: var(--access-user);
    border-color: var(--access-user);
    color: var(--bg);
  }
  .sw-none {
    background: var(--surface-2);
  }
  .sw-fog {
    border-style: dotted;
    border-color: var(--fog);
  }
  .sw-dead {
    color: var(--muted);
    font-weight: 400;
    font-family: var(--font-ui);
  }
  .sw-linked {
    border: var(--lw-focus) dashed var(--attention);
  }
  .sw-sel {
    border: var(--lw-focus) solid var(--focus);
  }
  .sw-seg {
    border: var(--lw-node) dashed var(--segment-line);
  }
  .sw-line {
    width: 26px;
    height: 16px;
    flex: none;
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(var(--thread), var(--thread)) center / 100% 3px no-repeat;
  }
  .sw-num {
    width: 15px;
    height: 15px;
    border-radius: 50%;
    background: var(--thread);
    color: var(--bg);
    font-size: 10px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .keys {
    margin: 4px 0 0;
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--faint);
  }
</style>
