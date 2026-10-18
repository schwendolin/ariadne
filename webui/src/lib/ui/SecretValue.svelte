<!--
  Verdeckter Wert (E99, E104, Briefing 9.4): «••••••••» ohne Längenangabe, optional mit Typhinweis
  («Passwort»). Aufdecken nur einzeln per Klick, nur im Profil lab und nie im Präsentationsmodus;
  der aufgedeckte Wert lebt nur in dieser Komponente und verschwindet beim Verdecken, beim
  Präsentationsmodus und beim Abbau. «In die Kali» kopiert ohne Anzeige. Nie in die Zwischenablage
  des Browsers, nie in Titel, Meldungen oder Konsole. Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { Backend } from '../api/backend';
  import type { Profile, SecretRef } from '../api/types';
  import { t } from '../i18n';
  import { errorText } from '../util/errors';
  import CopyButton from './CopyButton.svelte';
  import Txt from './Txt.svelte';

  let {
    secret,
    pid,
    backend,
    presentation,
    profile,
    hint = null,
    copy = true,
  }: {
    secret: SecretRef;
    pid: string;
    backend: Backend;
    presentation: boolean;
    profile: Profile | null;
    hint?: string | null;
    copy?: boolean;
  } = $props();

  let value = $state<string | null>(null);
  let error = $state<string | null>(null);
  const canReveal = $derived(!presentation && profile === 'lab');

  $effect(() => {
    if (presentation) value = null;
  });

  async function reveal(): Promise<void> {
    if (!canReveal) return;
    error = null;
    try {
      value = (await backend.reveal(pid, secret)).value;
    } catch (e) {
      error = errorText(e);
    }
  }
</script>

<span class="secret">
  {#if value === null}
    <span class="mask" aria-label={hint ?? t('secret.mask')}>{t('secret.mask')}</span>{#if hint}<span class="hint">({hint})</span>{/if}
    <button type="button" class="link" disabled={!canReveal} title={canReveal ? undefined : t('secret.revealBlocked')} onclick={reveal}>{t('secret.reveal')}</button>
  {:else}
    <span class="value"><Txt {value} mono max={0} /></span>
    <button type="button" class="link" onclick={() => (value = null)}>{t('secret.hide')}</button>
  {/if}
  {#if copy}
    <CopyButton target="kali" {secret} {pid} {backend} {presentation} {profile} />
  {/if}
  {#if error}<span class="err" role="alert">{error}</span>{/if}
</span>

<style>
  .secret {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    flex-wrap: wrap;
  }
  .mask,
  .value {
    font-family: var(--font-mono);
  }
  .hint {
    color: var(--muted);
    font-size: var(--fs-xs);
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: var(--muted);
    cursor: pointer;
    font-size: var(--fs-s);
    text-decoration: underline dotted;
  }
  .link:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }
  .err {
    color: var(--error);
    font-size: var(--fs-xs);
  }
</style>
