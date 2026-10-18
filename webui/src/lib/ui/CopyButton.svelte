<!--
  Kopierknopf mit Ziel (E111, Briefing 9.5):
  - target="mac": Text in die Zwischenablage des Browsers («Kopieren · Mac»), nur Befehle,
    Einzelwerte, Belege. Nie ein Secret (dafür gibt es kein `text` aus Secrets).
  - target="kali": ein Secret über den Daemon in die Zwischenablage der Kali («In die Kali»),
    ohne Anzeige; gesperrt im Präsentationsmodus und ausserhalb des Profils lab.
  Ohne Browser-Zwischenablage zeigt der Knopf den Text markiert in einem schreibgeschützten Feld
  (nie bei Secrets). Besitzer: ui-fundament.
-->
<script lang="ts">
  import type { Backend } from '../api/backend';
  import type { Profile, SecretRef } from '../api/types';
  import { t } from '../i18n';
  import { copyText } from '../util/clipboard';
  import { errorText } from '../util/errors';

  type MacProps = { target: 'mac'; text: string; short?: boolean; label?: string };
  type KaliProps = {
    target: 'kali';
    secret: SecretRef;
    pid: string;
    backend: Backend;
    presentation: boolean;
    profile: Profile | null;
    label?: string;
  };
  let props: MacProps | KaliProps = $props();

  let phase = $state<'idle' | 'done' | 'error' | 'manual'>('idle');
  let message = $state('');
  let manual: HTMLTextAreaElement | undefined = $state();

  const blocked = $derived(
    props.target === 'kali'
      ? props.presentation
        ? t('copy.kali.presentation')
        : props.profile !== 'lab'
          ? t('copy.kali.profile')
          : null
      : null,
  );
  const text = $derived(props.label ?? (props.target === 'mac' ? (props.short ? t('copy.macShort') : t('copy.mac')) : t('copy.kali')));

  async function run(): Promise<void> {
    if (props.target === 'mac') {
      const ok = await copyText(props.text);
      phase = ok ? 'done' : 'manual';
      message = ok ? t('copy.done.mac') : t('copy.failed');
      if (!ok) queueMicrotask(() => manual?.select());
    } else {
      if (blocked) return;
      try {
        await props.backend.copyToKali(props.pid, props.secret);
        phase = 'done';
        message = t('copy.done.kali');
      } catch (e) {
        phase = 'error';
        message = errorText(e);
      }
    }
    if (phase === 'done') setTimeout(() => (phase = 'idle'), 2500);
  }
</script>

<span class="copy">
  <button type="button" class="btn" disabled={blocked !== null} title={blocked ?? undefined} onclick={run}>{text}</button>
  <span class="msg" class:error={phase === 'error'} role="status" aria-live="polite">{phase === 'idle' ? '' : message}</span>
  {#if phase === 'manual' && props.target === 'mac'}
    <textarea class="manual" readonly bind:this={manual} rows="1">{props.text}</textarea>
  {/if}
</span>

<style>
  .copy {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    flex-wrap: wrap;
    flex: none;
  }
  .btn {
    padding: 5px 9px;
    border-radius: 5px;
    border: var(--lw-1) solid var(--line-strong);
    background: var(--surface-2);
    color: var(--fg);
    font-size: var(--fs-xs);
    line-height: 1;
    cursor: pointer;
    white-space: nowrap;
  }
  .btn:hover:not(:disabled) {
    border-color: var(--line-hover);
  }
  .btn:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .msg {
    font-size: var(--fs-xs);
    color: var(--muted);
  }
  .msg:empty {
    display: none;
  }
  .error {
    color: var(--error);
  }
  .manual {
    width: 100%;
    font-family: var(--font-mono);
    font-size: var(--fs-s);
    background: var(--log-bg);
    border: var(--lw-1) solid var(--focus);
    border-radius: var(--r-badge);
    resize: none;
  }
</style>
