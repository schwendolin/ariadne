<!--
  «Erste Schritte» im leeren Projekt (SCREENS 9 «Leeres Projekt», Briefing 4.1 «Checkliste»): steht
  in der Spalte statt «Als Nächstes», solange es noch keine Hosts gibt. Projekt gestartet (erledigt),
  nmap mit -oA (Befehl zum Kopieren · Mac), Schlüsselschritt mit F12 k, am Ende export, stop und
  backup. Nur feste Texte und der Slug/Scope des Projekts; nichts wird ausgeführt.
  Props: `slug`, `scope` (scope.include). Einbau durch ui-karte in die Spalte. Besitzer: ui-fundament.
-->
<script lang="ts">
  import { t } from '../i18n';
  import CommandLine from '../ui/CommandLine.svelte';

  let { slug, scope = [] }: { slug: string; scope?: string[] } = $props();
  const startCmd = $derived(t('state.first.startCmd', { slug, scope: scope.join(',') || '‹ziel›' }));
  const nmapCmd = $derived(t('state.first.nmap.cmd', { slug }));
</script>

<section class="first" aria-labelledby="first-title">
  <h2 id="first-title">{t('state.first.title')}</h2>
  <ol>
    <li class="done">
      <span class="n" aria-hidden="true">✓</span>
      <span>{t('state.first.started')} <code>{startCmd}</code></span>
    </li>
    <li>
      <span class="row"><span class="n">2</span><span>{t('state.first.nmap.pre')} <code>-oA</code>{t('state.first.nmap.post')}</span></span>
      <div class="cmd"><CommandLine command={nmapCmd} short size="s" /></div>
    </li>
    <li>
      <span class="n">3</span>
      <span>{t('state.first.keystep')} <code>F12 k</code></span>
    </li>
    <li>
      <span class="n">4</span>
      <span>{t('state.first.end.pre')} <code>ariadne export</code>, <code>ariadne stop</code> {t('state.first.end.and')} <code>ariadne backup</code></span>
    </li>
  </ol>
</section>

<style>
  .first {
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 18px var(--sp-5);
  }
  h2 {
    margin: 0;
    font-size: var(--fs-l);
    font-weight: 600;
  }
  ol {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  li {
    display: flex;
    gap: 10px;
  }
  li:nth-child(2) {
    flex-direction: column;
    gap: 6px;
  }
  .row {
    display: flex;
    gap: 10px;
  }
  .n {
    flex: none;
    width: 12px;
    color: var(--muted);
  }
  .done {
    color: var(--faint);
  }
  .done .n {
    color: var(--faint);
  }
  code {
    font-family: var(--font-mono);
    font-size: var(--fs-s);
    overflow-wrap: anywhere;
  }
  .cmd {
    margin-left: 22px;
  }
</style>
