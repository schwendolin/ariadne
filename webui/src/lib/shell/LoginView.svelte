<!--
  Anmeldung (SCREENS 9, Briefing 4.1, A 7.2): ein Feld «Anmeldecode» (XXXX-XXXX), Hinweis, wo der
  Code herkommt, «Ariadne fragt hier nie nach Passphrasen». Fehler unter dem Feld:
    unauthorized   «Code unbekannt, abgelaufen oder schon benutzt.» (Rand --error)
    rate_limited   «Zu viele Versuche. Neuen Code im Terminal holen.» (Feld gesperrt, «gesperrt»)
    validation     «Eingabe ungültig.» (auch schon im Browser, ohne Anfrage)
    network        «Daemon nicht erreichbar.»
  Nie ein Passphrase-Feld (type=password), nie der Code in URL, Titel, Speicher oder Konsole; das
  Feld behält den falschen Code markiert (er ist danach wertlos).
  Praxistest 1: Hinweis «Code im Terminal holen: ariadne ui --code (oder ariadne ui öffnet den
  Browser direkt)», Muster XXXXX-XXXXX (Tippcode: 10 Zeichen, sessions.format_typed). Sieht die
  Eingabe nach einer Passphrase aus (ohne Bindestrich, kein plausibler Code), steht darunter «Das
  ist der Einmal-Code aus dem Terminal, nicht die Passphrase», und sie geht nicht an den Server.
  Endete die Sitzung durch stop, lock, Projektwechsel oder Neustart, nennt die Seite den Grund
  (`app.endNotice`). Besitzer: ui-fundament, Praxistest: ui.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { looksLikePassphrase, normalizeTypedCode } from '../api/auth';
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
  const passNote = $derived(looksLikePassphrase(code) && localError !== 'login.passphrase');
  const ended = $derived.by<string | null>(() => {
    const n = app.endNotice;
    if (!n) return null;
    if ((n.reason === 'stop' || n.reason === 'idle') && n.slug) return t(n.reason === 'stop' ? 'login.ended.stop' : 'login.ended.idle', { slug: n.slug });
    if (n.reason === 'stop') return t('login.ended.stopPlain');
    if (n.reason === 'idle') return t('login.ended.idlePlain');
    return t(`login.ended.${n.reason}` as MessageKey);
  });
  const describedBy = $derived([error ? 'login-error' : null, passNote ? 'login-pass' : null, 'login-pattern'].filter(Boolean).join(' '));
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
    // Passphrase statt Code: nie an den Server schicken
    if (looksLikePassphrase(code)) {
      localError = 'login.passphrase';
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
    {#if ended}<p class="ended" role="status" data-testid="login-ended">{ended}</p>{/if}
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
        aria-describedby={describedBy}
        data-autofocus
      />
      <p id="login-pattern" class="pattern">{t('login.pattern')}</p>
      {#if error}<p id="login-error" class="error" role="alert">{t(error)}</p>{/if}
      {#if passNote}<p id="login-pass" class="pass" role="note">{t('login.passphrase')}</p>{/if}
      {#if locked}<button type="button" class="retry" onclick={retry}>{t('login.retry')}</button>{/if}
    </div>
    <button type="submit" class="submit" disabled={busy || locked}>{busy ? t('login.busy') : t('login.submit')}</button>
    <div class="info">
      <p class="where">
        {t('login.where.code')} <code>ariadne ui --code</code> ({t('login.where.orUi')} <code>ariadne ui</code>
        {t('login.where.direct')})
      </p>
      <p>
        {t('login.where.mac')} <code>ariadne-mac start</code> {t('login.where.or')} <code>ssh -t kali-sl code</code>
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
  .pattern {
    margin: 0;
    color: var(--faint);
    font-size: var(--fs-xs);
  }
  .pass {
    margin: 0;
    color: var(--attention);
    font-size: var(--fs-s);
  }
  .ended {
    margin: 0;
    padding: 10px 12px;
    border-radius: 8px;
    border: var(--lw-1) solid var(--line-strong);
    background: var(--surface-2);
    color: var(--fg);
    font-size: var(--fs-s);
    line-height: 1.45;
  }
  .where {
    color: var(--fg-2);
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
