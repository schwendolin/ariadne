<!--
  Anmeldung mit Einmalcode (Architektur 7.2). Normalerweise kommt der Code über
  `ariadne ui` als Fragment und dieses Formular erscheint gar nicht.
  Hier wird nie eine Passphrase verlangt: Entsperren geht nur im Terminal.
-->
<script lang="ts">
  import { normalizeTypedCode } from '../api/auth';
  import { t } from '../i18n';
  import type { AppState } from '../stores/app.svelte';
  import { codeText } from '../util/errors';

  let { app }: { app: AppState } = $props();
  let code = $state('');
  let invalid = $state(false);
  let busy = $state(false);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    const c = normalizeTypedCode(code);
    invalid = c === null;
    if (!c) return;
    busy = true;
    await app.login(c);
    busy = false;
  }
</script>

<main class="login">
  <form class="card stack" onsubmit={submit}>
    <h1>{t('login.title')}</h1>
    <p>{t('login.intro')}</p>
    <label class="stack">
      {t('login.code')}
      <input type="text" bind:value={code} autocomplete="off" spellcheck="false" autocapitalize="off" />
    </label>
    {#if invalid}<p class="error" role="alert">{t('login.invalid')}</p>{/if}
    {#if app.loginError}<p class="error" role="alert">{codeText(app.loginError)}</p>{/if}
    <button type="submit" class="primary" disabled={busy}>{t('login.submit')}</button>
    <p class="small muted">{t('login.noPassphrase')}</p>
  </form>
</main>

<style>
  .login {
    display: grid;
    place-items: center;
    min-height: 100%;
    padding: 16px;
  }
  form {
    width: min(420px, 100%);
  }
</style>
