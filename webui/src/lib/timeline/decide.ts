/**
 * Entscheide mit Fehlertext für die Anzeige an Ort und Stelle (Screen 6 «Rückgängig nicht
 * gespeichert: Das Projekt ist gesperrt.», Screen 8 «Speichern fehlgeschlagen»). Besitzer: ui-verlauf.
 *
 * Geschrieben wird nur über `ctx.decide` (Vertrag 2.2: client_ref, Offline-Sperre, feste Texte je
 * Code). Mit `onError` gibt `ctx.decide` den Fehlertext (fester Text, nie Zieldaten) zurück statt
 * eine Meldung anzulegen; die Zeile bzw. das Formular zeigt ihn selbst. Ohne Verbindung wird
 * nichts gesendet.
 */
import type { DecisionInput, DecisionResponse } from '../api/types';
import { t, type MessageKey } from '../i18n';
import type { ProjectCtx } from '../stores/ctx';

export interface DecideOutcome {
  res: DecisionResponse | null;
  error: string | null;
}

export async function decideWithError(ctx: ProjectCtx, decisions: DecisionInput[], prefix: MessageKey): Promise<DecideOutcome> {
  if (ctx.app.offline) return { res: null, error: `${t(prefix)}: ${t('err.network')}` };
  let error: string | null = null;
  const res = await ctx.decide(decisions, { errorPrefix: prefix, onError: (text) => (error = text) });
  if (res) return { res, error: null };
  return { res: null, error: error ?? `${t(prefix)}: ${t('err.internal')}` };
}
