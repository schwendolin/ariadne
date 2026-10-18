<!--
  App-Gerüst (SCREENS «Grundlayout», 9, 10, 11). Besitzer: ui-fundament.

  - Zustände: Laden, Anmeldung, kein Projekt, gesperrt, Projekt; keine Verbindung als
    gedämpfte Ansicht mit gesperrten Aktionen (Klasse `offline-dim`, AppState.offline). Nicht mehr
    `inert` (Korrektur A11): Ein Eingabefeld behält Fokus und Getipptes, der Stand bleibt für
    Bildschirmleser lesbar; Klicks auf Knöpfe und Links und das Absenden von Formularen sperrt
    `blockOffline` an einer Stelle (Speichern bleibt gesperrt).
  - Kopfzeile immer (ausser bei der Anmeldung); Reiter Karte, Terminals, Zeitachse, Findings.
  - Höchstens ein Dialog (UiStore.dialog), höchstens eine Tafel (URL `beleg` oder `tafel`); die
    Scope-Warnung steht als erster Eintrag in «Als Nächstes» (E120), nicht mehr als Karte.
  - Belegansicht eines Screenshots (`beleg=s:<id>`) als eigene Tafel (ShotPanel).
  - Globale Kürzel: ⌘K Palette, ? Hilfe, 1 bis 4 Reiter, ⇧P Präsentationsmodus (nur mit Fokus
    ausserhalb von Eingabefeldern), Esc schliesst Tafel bzw. Detail (in den Komponenten).
  - Palette: Quelle «actions» (Reiter, Präsentation, Darstellung, Einstellungen, Scope, Hilfe,
    Abmelden); der Rohlog läuft in der Palette selbst (GET /search auf Wunsch).
  - Favicon mit Punkt und Tab-Titel «ms2 · 2 zu klären».
  - Bei Projektwechsel baut `{#key}` alle Ansichten neu auf (E70).
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import EvidencePanel from './lib/evidence/EvidencePanel.svelte';
  import ExportDialog from './lib/dialogs/ExportDialog.svelte';
  import ScreenshotDialog from './lib/dialogs/ScreenshotDialog.svelte';
  import FindingsView from './lib/findings/FindingsView.svelte';
  import { t } from './lib/i18n';
  import KarteView from './lib/karte/KarteView.svelte';
  import CommandPalette from './lib/shell/CommandPalette.svelte';
  import Header from './lib/shell/Header.svelte';
  import HelpDialog from './lib/shell/HelpDialog.svelte';
  import LoginView from './lib/shell/LoginView.svelte';
  import { installGlobal } from './lib/shell/global';
  import ScopeViewDialog from './lib/shell/ScopeViewDialog.svelte';
  import ScopeAddDialog from './lib/scope/ScopeAddDialog.svelte';
  import ScopeEditDialog from './lib/scope/ScopeEditDialog.svelte';
  import ScopeOpenDialog from './lib/scope/ScopeOpenDialog.svelte';
  import SettingsPanel from './lib/shell/SettingsPanel.svelte';
  import ShotPanel from './lib/shots/ShotPanel.svelte';
  import StateView from './lib/shell/StateView.svelte';
  import type { AppState } from './lib/stores/app.svelte';
  import ContextDialog from './lib/terminals/ContextDialog.svelte';
  import TerminalsView from './lib/terminals/TerminalsView.svelte';
  import TimelineView from './lib/timeline/TimelineView.svelte';
  import Notices from './lib/ui/Notices.svelte';
  import { url } from './lib/url/state.svelte';
  import { applyTabState } from './lib/util/favicon';

  let { app }: { app: AppState } = $props();

  const phase = $derived(app.phase);
  const project = $derived(app.project);
  const route = $derived(url.route);
  const dialog = $derived(app.ui.dialog);
  const evidence = $derived(url.evidence());
  const settingsOpen = $derived(url.get('tafel') === 'einstellungen');

  $effect(() => {
    applyTabState(document, project?.slug ?? null, project?.next.open ?? 0);
  });

  onMount(() => installGlobal(app));

  const ACTION = 'button, a[href], [role="button"], [role="link"], summary, input[type="checkbox"], input[type="radio"], input[type="submit"], select';

  /** Ohne Verbindung: Aktionen in der Ansicht sperren (Fokus und Eingaben bleiben), Korrektur A11. */
  function blockOffline(e: Event): void {
    if (!app.offline) return;
    const el = e.target instanceof Element ? e.target.closest(ACTION) : null;
    if (e.type === 'submit' || (el && !el.closest('[data-offline-ok]'))) {
      e.preventDefault();
      e.stopPropagation();
    }
  }
</script>

{#if phase === 'boot'}
  <p class="boot">{t('app.loading')}</p>
{:else if phase === 'login'}
  <LoginView {app} />
{:else}
  <div class="shell">
    <a class="skip" href="#main">{t('app.skip')}</a>
    <Header {app} />
    <main
      id="main"
      tabindex="-1"
      class:offline-dim={app.offline}
      aria-busy={app.offline ? 'true' : undefined}
      onclickcapture={blockOffline}
      onsubmitcapture={blockOffline}
      onchangecapture={blockOffline}
    >
      {#if phase === 'project' && project}
        {#key project.pid}
          {#if route === 'karte'}
            <KarteView {app} {project} />
          {:else if route === 'terminals'}
            <TerminalsView {app} {project} />
          {:else if route === 'zeitachse'}
            <TimelineView {app} {project} />
          {:else if route === 'findings'}
            <FindingsView {app} {project} />
          {/if}
          {#if evidence?.kind === 'shot'}
            <ShotPanel {app} {project} id={evidence.id} />
          {:else if evidence}
            <EvidencePanel {app} {project} target={evidence} />
          {/if}
        {/key}
      {:else}
        <StateView {app} />
      {/if}
      {#if settingsOpen}
        <SettingsPanel {app} />
      {/if}
    </main>
  </div>
{/if}

{#if dialog?.kind === 'palette'}
  <CommandPalette {app} onclose={() => app.ui.closeDialog()} />
{:else if dialog?.kind === 'help'}
  <HelpDialog onclose={() => app.ui.closeDialog()} />
{:else if dialog?.kind === 'scope-view'}
  <ScopeViewDialog {app} onclose={() => app.ui.closeDialog()} />
{:else if dialog?.kind === 'export' && project}
  <ExportDialog {app} {project} onclose={() => app.ui.closeDialog()} />
{:else if dialog?.kind === 'screenshot' && project}
  <ScreenshotDialog {app} {project} onclose={() => app.ui.closeDialog()} />
{:else if dialog?.kind === 'scope-add' && project}
  <ScopeAddDialog {app} {project} req={dialog} onclose={() => app.ui.closeDialog()} />
{:else if dialog?.kind === 'scope-edit' && project}
  <ScopeEditDialog {app} {project} op={dialog.op} entry={dialog.entry} list={dialog.list} onclose={() => app.ui.closeDialog()} />
{:else if dialog?.kind === 'scope-open' && project}
  <ScopeOpenDialog {app} {project} op={dialog.op} onclose={() => app.ui.closeDialog()} />
{:else if dialog?.kind === 'context' && project}
  <ContextDialog {app} {project} terminalId={dialog.terminalId} itemKey={dialog.itemKey} fromOff={dialog.fromOff} onclose={() => app.ui.closeDialog()} />
{/if}

<Notices ui={app.ui} />

<style>
  .boot {
    padding: var(--sp-6);
    color: var(--muted);
  }
  .shell {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .skip {
    position: absolute;
    left: -9999px;
  }
  .skip:focus {
    left: 8px;
    top: 8px;
    z-index: 100;
    padding: 6px 10px;
    background: var(--surface);
  }
  main {
    position: relative;
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }
  main:focus {
    outline: none;
  }
</style>
