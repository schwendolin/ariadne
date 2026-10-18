/**
 * Deutsche Texte für Terminals, Zeitachse, Warteliste, Belegansicht, Findings, Kontext-, Export-
 * und Screenshot-Dialog (Besitzer: ui-verlauf).
 * Präfixe: term, ctx, tl, pending, ev, fd, export, shot. Regeln wie in de.ts.
 */
export const deVerlauf = {
  'term.title': 'Terminals',
  'term.col.terminal': 'Terminal',
  'term.col.rec': 'Aufnahme',
  'term.col.context': 'Kontext und letzter Befehl',
  'term.empty': 'Noch keine Terminals',
  'term.closed': 'geschlossen',
  'term.hint': 'Im Terminal: F12 h Host setzen · F12 b Stufe zurück · F12 r Pause',

  'ctx.title': 'Kontext für {term}',
  'ctx.host': 'Host',
  'ctx.user': 'Benutzer',
  'ctx.from': 'Gilt ab',
  'ctx.set': 'Setzen',
  'ctx.hint': 'Im Terminal: F12 h',

  'tl.title': 'Zeitachse',
  'tl.empty': 'Noch keine Einträge',
  'tl.emptyFilter': 'Keine Einträge für diesen Filter',
  'tl.projectStart': 'Projektstart {time}',

  'pending.strip': 'Warteliste',
  'pending.summary': '{n} Datei nicht übernommen · neueste {time}|{n} Dateien nicht übernommen · neueste {time}',
  'pending.empty': 'Keine Dateien in der Warteliste',
  'pending.hint': 'Übernehmen im Terminal: ariadne import ‹pfad›',

  'ev.title': 'Beleg',
  'ev.close': 'Esc schliessen',
  'ev.asFinding': 'Als Finding',
  'ev.addToFinding': 'Zu Finding hinzufügen',
  'ev.copy': 'Als Beleg kopieren · Mac',
  'ev.fullLog': 'Ganzes Log',
  'ev.chainBroken': 'Hash-Kette verletzt',

  'fd.title': 'Findings',
  'fd.new': 'Neues Finding',
  'fd.empty': 'Noch keine Findings.',
  'fd.emptyHint': 'Findings entstehen aus Belegen.',

  'export.title': 'Bericht exportieren',
  'export.later': 'Der Export kommt in einer späteren Version. Bis dahin im Terminal: ariadne export.',

  'shot.title': 'Screenshot der Kali',
  'shot.later': 'Screenshots aus dem Dashboard kommen in einer späteren Version. Im Terminal: F12 s.',
} as const;
