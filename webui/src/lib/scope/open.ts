/**
 * Offener Scope (E131) und Terminal-Hinweise. Besitzer: ui.
 *
 * - `scopeOpen`: `open` aus `GET /scope`, sonst `scope_open` aus dem Projekt bzw. dem Status
 *   (ältere Server ohne Feld: geschlossen). Die UI urteilt nie selbst über den Scope.
 * - `addCommand`: `ariadne scope add <eintrag> --not-customer` nur für Einträge aus einem engen
 *   Zeichensatz (Name, Wildcard, Adresse, Netz, Bereich), sonst mit «…»; Wildcards in Hochkommas.
 *   So landet nie ein Zieldatum mit Shell-Zeichen in einem kopierbaren Befehl.
 */
import type { AppState } from '../stores/app.svelte';

export function scopeOpen(app: AppState): boolean {
  const v = app.project?.scope.view;
  if (v && typeof v.open === 'boolean') return v.open;
  const info = app.project?.info;
  if (info && typeof info.scope_open === 'boolean') return info.scope_open;
  if (info && typeof info.scope.open === 'boolean') return info.scope.open;
  const s = app.status;
  return s?.scope_open === true || s?.project?.scope_open === true;
}

const SAFE = /^(\*\.)?[A-Za-z0-9][A-Za-z0-9.\-:/]{0,252}$/;

export function addCommand(entry: string | null | undefined): string {
  const e = (entry ?? '').trim();
  if (!e || !SAFE.test(e)) return 'ariadne scope add … --not-customer';
  return `ariadne scope add ${e.startsWith('*.') ? `'${e}'` : e} --not-customer`;
}
