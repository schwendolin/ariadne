/**
 * Gemeinsame Schnittstellen der Stores (Vertrag v0.1-Oberfläche, Abschnitt 4). Besitzer: ui-fundament.
 *
 * - `AppApi`: was Projekt-Stores und Komponenten vom App-Zustand sehen dürfen.
 * - `ProjectCtx`: Kontext eines offenen Projekts. `signal` bricht bei Projektwechsel, Sperre und
 *   Abmelden alle Abrufe ab; danach wird der ganze ProjectStore verworfen (Projekte mischen sich
 *   nie, E70).
 * - `ProjectPart`: jeder Projekt-Store (Karte, Als Nächstes, Host, Terminals, Zeitachse, Beleg,
 *   Findings, Neu seit) setzt das um. Der ProjectStore ruft `load()` beim Öffnen und bei `reset`,
 *   `onChanges()` nach jedem `/changes`, `onEvent()` für jedes SSE-Ereignis und `dispose()` beim
 *   Verwerfen.
 */
import type { Backend } from '../api/backend';
import type { ChangeSet, DecisionInput, DecisionResponse, Profile, Status, StreamEvent } from '../api/types';
import type { MessageKey } from '../i18n';
import type { PrefsStore } from './prefs.svelte';
import type { UiStore } from './ui.svelte';

export interface AppApi {
  readonly backend: Backend;
  readonly status: Status | null;
  /** Präsentationsmodus (Status, per SSE bestätigt) */
  readonly presentation: boolean;
  readonly profile: Profile | null;
  /** keine Verbindung: Daten gedämpft, Aktionen gesperrt */
  readonly offline: boolean;
  readonly prefs: PrefsStore;
  readonly ui: UiStore;
}

export interface DecideOptions {
  /** Präfix der Fehlermeldung, Standard «Entscheid nicht gespeichert» */
  errorPrefix?: MessageKey;
  /** Fehler nicht als Meldung zeigen (der Aufrufer zeigt sie selbst) */
  silent?: boolean;
  /**
   * Fehlertext (fester Text je Code mit Präfix, nie Zieldaten) an den Aufrufer statt als Meldung,
   * etwa für die Anzeige in der Zeile oder im Formular. Schliesst `silent` ein.
   */
  onError?: (text: string) => void;
}

/** Ein Entscheid dieses Tabs (Korrektur A5: «anderer Tab» nur ohne eigenen Entscheid). */
export interface OwnDecision {
  /** Art des Entscheids (`d.conflict.resolve`) oder `ctx` für Kontext setzen */
  kind: string;
  payload: Record<string, unknown>;
  decisionId: string | null;
  /** Date.now() beim Erfolg */
  at: number;
}

export interface ProjectCtx {
  readonly pid: string;
  readonly slug: string;
  readonly backend: Backend;
  readonly signal: AbortSignal;
  readonly app: AppApi;
  /**
   * Schreibt Entscheide (POST /decisions) mit `client_ref`. Gibt das Ergebnis zurück oder `null`,
   * wenn es scheiterte; dann ist die Meldung schon gezeigt (ausser `silent`). Im Offline-Zustand
   * wird nichts gesendet.
   */
  decide(decisions: DecisionInput[], opts?: DecideOptions): Promise<DecisionResponse | null>;
  /** Merkt einen eigenen Schreibvorgang, der nicht über `decide` lief (Kontext setzen). */
  noteOwn(kind: string, payload: Record<string, unknown>, decisionId: string | null): void;
  /** Eigene Entscheide dieses Tabs aus den letzten `ms` Millisekunden (neueste zuletzt). */
  ownSince(ms: number): readonly OwnDecision[];
}

export interface ProjectPart {
  load(): Promise<void>;
  onChanges?(cs: ChangeSet): void;
  onEvent?(ev: StreamEvent): void;
  dispose(): void;
}

/** Zufällige `client_ref` (idempotente Wiederholung, web-api.md 12). */
export function clientRef(): string {
  const a = new Uint8Array(12);
  crypto.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}
