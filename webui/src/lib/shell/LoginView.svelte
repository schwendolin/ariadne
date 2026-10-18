<!--
  Anmeldung (SCREENS 9, Briefing 4.1, A 7.2): ein Feld «Anmeldecode» (XXXX-XXXX), Hinweis, wo der
  Code herkommt, «Ariadne fragt hier nie nach Passphrasen». Fehler unter dem Feld:
    unauthorized   «Code unbekannt, abgelaufen oder schon benutzt.» (Rand --error)
    rate_limited   «Zu viele Versuche. Neuen Code im Terminal holen.» (Feld gesperrt, «gesperrt»)
    validation     «Eingabe ungültig.» (auch schon im Browser, ohne Anfrage)
    network        «Daemon nicht erreichbar.»
  Nie ein Passphrase-Feld (type=password), nie der Code in URL, Titel, Speicher oder Konsole; das
  Feld behält den falschen Code markiert (er ist danach wertlos). Nach einer beendeten Sitzung erscheint die Seite ohne
  Grund. Besitzer: ui-fundament.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { normalizeTypedCode } from '../api/auth';
  import { t, type MessageKey } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import LogoMark from '../ui/LogoMark.svelte';

  let { app }: { app: AppState } = $props();
  let code = $state('');
  let localError = $state<MessageKey | null>(null);
  let busy = $state(false);
  let input: HTMLInputElement | undefined = $state();

  const serverError = $derived<MessageKey | null>(
    app.loginError === 'unauthorized'
      ? 'login.err.unauthorized'
      : app.loginError === 'rate_limited'
        ? 'login.err.rate_limited'
        : app.loginError === 'validation'
          ? 'login.err.validation'
          : app.loginError === 'network' || app.loginError === 'timeout'
            ? 'login.err.network'
            : app.loginError
              ? 'login.err.internal'
              : null,
  );
  const error = $derived<MessageKey | null>(localError ?? serverError);
  const locked = $derived(app.loginError === 'rate_limited');

  async function submit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (busy || locked) return;
    localError = null;
    const c = normalizeTypedCode(code);
    if (!c) {
      localError = 'login.err.validation';
      return;
    }
    busy = true;
    const ok = await app.login(c);
    busy = false;
    if (!ok) queueMicrotask(() => input?.select());
  }

  function retry(): void {
    app.clearLoginError();
    localError = null;
    code = '';
    queueMicrotask(() => input?.focus());
  }

  function oninput(): void {
    if (localError) localError = null;
  }

  onMount(() => {
    if (!locked) input?.focus();
  });
</script>

<main class="login" id="main">
  <form class="box" onsubmit={submit} novalidate aria-label={t('login.title')}>
    <h1 class="brand"><LogoMark size={22} decorative /><span>{t('login.title')}</span></h1>
    <div class="field">
      <label for="login-code">{t('login.label')}</label>
      <input
        id="login-code"
        bind:this={input}
        class:invalid={!!error && !locked}
        bind:value={code}
        {oninput}
        type="text"
        inputmode="text"
        placeholder={locked ? t('login.locked') : t('login.placeholder')}
        autocomplete="one-time-code"
        autocapitalize="characters"
        spellcheck="false"
        maxlength="80"
        disabled={locked}
        aria-invalid={!!error}
        aria-describedby={error ? 'login-error' : undefined}
        data-autofocus
      />
      {#if error}<p id="login-error" class="error" role="alert">{t(error)}</p>{/if}
      {#if locked}<button type="button" class="retry" onclick={retry}>{t('login.retry')}</button>{/if}
    </div>
    <button type="submit" class="submit" disabled={busy || locked}>{busy ? t('login.busy') : t('login.submit')}</button>
    <div class="info">
      <p>
        {t('login.where.mac')} <code>ariadne-mac start</code> {t('login.where.or')} <code>ssh -t kali-sl code</code>{t('login.where.kali')}
        <code>ariadne ui</code>.
      </p>
      <p class="never">{t('login.never')}</p>
    </div>
  </form>
</main>

<style>
  .login {
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg);
    padding: var(--sp-4);
  }
  .box {
    width: 380px;
    max-width: 100%;
    display: flex;
    flex-direction: column;
    gap: 18px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 0;
    font-size: 22px;
    font-weight: 700;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  label {
    font-size: var(--fs-s);
    color: var(--muted);
  }
  input {
    padding: 11px 14px;
    border-radius: 8px;
    border: var(--lw-1) solid var(--line-strong);
    background: var(--surface);
    font-family: var(--font-mono);
    font-size: 16px;
    letter-spacing: 0.12em;
    color: var(--fg);
  }
  input::placeholder {
    color: var(--faint);
  }
  input:focus {
    outline: none;
    border-color: var(--focus);
  }
  input:focus-visible {
    outline: none;
  }
  input.invalid {
    border-color: var(--error);
  }
  input:disabled {
    cursor: not-allowed;
    background: transparent;
  }
  .error {
    margin: 0;
    color: var(--error);
    font-size: var(--fs-m);
  }
  .retry {
    align-self: flex-start;
    padding: 0;
    border: none;
    background: none;
    color: var(--muted);
    font-size: var(--fs-s);
    text-decoration: underline dotted;
    cursor: pointer;
  }
  .submit {
    padding: 10px 14px;
    border-radius: 7px;
    border: 0;
    background: var(--fg);
    color: var(--bg);
    font-weight: 600;
    font-size: 14px;
    line-height: 1;
    cursor: pointer;
  }
  .submit:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .info {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding-top: 6px;
    border-top: var(--lw-1) solid var(--line);
    color: var(--muted);
    font-size: var(--fs-s);
    line-height: 1.5;
  }
  .info p {
    margin: 0;
  }
  .info code {
    font-family: var(--font-mono);
    color: var(--fg-2);
  }
  .never {
    color: var(--fg);
  }
</style>
