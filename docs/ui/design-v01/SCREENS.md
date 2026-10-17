# Screens ARIADNE-Dashboard v0.1

Referenz 1440 x 900, fluid. Beispieldaten: Projekt `ms2`, Standbild 16:54 (Anhang A). Werte als Tokens aus `tokens.css`.

## Grundlayout (alle Projekt-Screens)

- **Kopfzeile** 52 px, `--bg`, Trenner `--line`. Links: Logo-Zeichen 20 px, Slug in Mono, Aufnahme-Knopf mit Popover, Zustands-Badges, Herkunft («über sshd» oder «lokal»). Mitte: Reiter Karte, Terminals, Zeitachse, Findings (aktiv mit 2 px Unterstrich `--fg`). Rechts: Suche mit `⌘K`, Menü `⋯`.
- Unter 1280 px Breite wird die Kopfzeile kompakt: Suche nur als `⌘K`, Aufnahmetext gekürzt («2 von 3 nehmen auf»). Die Herkunft bleibt immer sichtbar.
- **Karte** füllt den Rest, `--map`. Inhalt skaliert mit der Fläche (50 bis 140 %).
- **Spalte «Als Nächstes»** rechts: `flex: 0 0 27%`, min 320 px, max 480 px, `--surface`, Trenner links `--line`.

## 1a Hauptansicht (`Ariadne Runde 1.dc.html`, `#1a`)

- Lagebild oben links auf der Karte: «Stand 16:54 · 3 Hosts, 1 im Nebel · 1 mit Zugriff». Daneben die Marke `+3 seit 16:40` (Pill, Rand `--line-strong`).
- Karte: Subnetz 192.168.56.0/24 als gestrichelter Rahmen. Kali links. `.101` mit Zugriff root (Füllung `--access-root`, Symbol `#`, «23 Services»). `.103` im Nebel (gepunkteter Rand `--fog`). `.104` als Sackgasse (Symbol `⊘`, «Sackgasse · nur RDP»). Faden in `--thread`, 3 px, mit nummerierten Knoten 1 und 2. Verknüpfter Host (`.101` zu K2) mit gestricheltem Ring in `--attention`.
- Rechter Rand: schraffierter Streifen «Out of Scope · 4», öffnet ein Popover.
- Unten links: «Ebenen und Legende».
- Spalte: Kopf «Als Nächstes» und Satz zu den Werten ausserhalb des Scopes. Gruppe **Klären (2)**: K2 aufgeklappt (Vorschlag, Grund, Wirkt ab, Logauszug «Darum mehrdeutig», Knöpfe Übernehmen `a`, Anderer Host, Beleg `↵`), K3 einzeilig. Gruppe **Denkanstösse (3)**: einzeilig, Quelle «Regel» oder Badge «KI». Fuss: «Denkanstoss anfordern (KI)» und Tastenhinweis.
- Gewählter Eintrag: Fokusring 2 px `--focus`.

## 1a Ruhezustand

- Keine offenen Klärungen. Erledigte stehen gedämpft (`--faint`) mit ✓ und «Rückgängig».
- Der Cursor springt auf den ersten Denkanstoss und klappt ihn auf: Regel-ID, Titel, Beleg, Vorlage in Mono mit gepunktet unterstrichenen Zieldaten, «Kopieren · Mac», Erledigt und Verwerfen.

## 3 Host-Detail

- Ersetzt den Inhalt der Spalte. Kopf «← Als Nächstes» und `Esc`.
- `.101`: Symbol, IP, OS. Raster: Zugriff (mit Entscheid und «ändern»), Wissen, Arbeitsstand (Dropdown), Faden, Offen. Services-Tabelle (Port, Name, Version), feindlicher Titel bei 8180 mit «! Injection-Verdacht · vom Ziel angeboten». Tags, Notiz, Zeile mit Konten und Namen ausserhalb.
- `.103` im Nebel: Erklärung, Annehmen `a` und Verwerfen `x`, Kennung, Quelle, «Noch keine Services bekannt».
- Auf der Karte: Auswahlring 2 px `--focus`.

## 4 Einträge

- **K3 Zusammenführen:** zwei Kacheln (im Scope oder ausserhalb), Grund mit MAC-Adresse, Zusammenführen oder Getrennt lassen. Zustände danach: zusammengeführt mit Rückgängig `u`, verworfen (durchgestrichen), in einem anderen Tab entschieden.
- **D2 mit Vorlage:** Kopierknopf nennt das Ziel. Variante mit Shell-Sonderzeichen: keine fertige Vorlage, nur die Einzelwerte, jeder einzeln kopierbar.
- **D3 von der KI:** Badge KI, «bestätigt, wenn» und «widerlegt, wenn», Knöpfe Bestätigt, Widerlegt, Verwerfen. Zustand während der Anfrage mit Token-Zahl und Maskierung.
- **D1 im Lernmodus:** Stufen Frage, Richtung, Vorlage, jede erst auf Klick.

## 5 Aufnahmezustand

- Kopfzeile in den Varianten normal, waiting, pause, held, locked, noproject, offline, Präsentation.
- Popover der Aufnahme: Terminals mit Pause oder Fortsetzen, Projekt, Sitzung, Leerlauf, KI-Budget, Hinweis `F12 r`.
- Reiter Terminals: eine Zeile pro Terminal (Name und pts, Aufnahme, Kontext als Brotkrume, letzter Befehl, Aktionen). T3 mit offenem Kontext `?` und «Vorschlag übernehmen». held als gestrichelte Zeile.

## 6 Zeitachse (`Ariadne Runde 2.dc.html`, `#6`)

- Filter: Typ, Terminal, Host. Lokalzeit CEST, «UTC zeigen».
- Warteliste als eingeklappter Streifen oben.
- Zeilen, neuestes oben: Zeit, Terminal, Ereignis, Ergebnis, Aktion. Typen: Befehl, Callback, Lücke (schraffiert), Schlüsselschritt (Faden-Nummer), Entscheid, Remote-Segment, Rückgängig, misstraut (durchgestrichen, «Wieder vertrauen»), KI-Anfrage, Scope-Warnung.
- Rückgängig inline mit optionalem Grund. Rückmeldung «18 verworfen, 0 geschwächt».

## 7 Belegansicht

- Tafel von rechts, 52 % Breite (620 bis 860 px), Karte dahinter gedimmt.
- Kopf mit Quelle und Zeit. Raster: Befehl, Kontext, Zeit auf ms genau, Quelle, Hash-Kette. Log mit Zeilennummern, markierter Bereich in `--focus`-Ton. Knöpfe Als Finding, Zu Finding hinzufügen, Als Beleg kopieren · Mac, Ganzes Log.
- Varianten: Datei mit SHA-256, KI-Zitat wörtlich, Präsentationsmodus mit verdeckten Secrets, Hash-Kette verletzt (Rand `--error`, nicht wegklickbar).

## 8 Findings

- Liste links (32 %), Formular rechts: Titel, Schwere (5 Stufen, setzt nur der Mensch), Status (Entwurf, final), Betroffen, Beschreibung, Massnahme, ATT&CK, CVE (Hypothese ohne eigenen Beleg markiert), Belege, Speichern.
- Leer: «Noch keine Findings. Findings entstehen aus Belegen.»

## 9 Anmeldung und Zustände

- Anmeldung: Feld Anmeldecode `XXXX-XXXX`, Hinweis, wo der Code herkommt, «Ariadne fragt hier nie nach Passphrasen». Fehler: unbekannt oder abgelaufen, zu viele Versuche, Eingabe ungültig.
- Kein Projekt, gesperrt (kein Passphrase-Feld), keine Verbindung (Inhalt gedimmt, Aktionen gesperrt), leeres Projekt mit Checkliste «Erste Schritte».

## 10 Dialoge und Popover

Kontext setzen, Befehlspalette `⌘K`, Scope-Warnung, Out of Scope mit feindlichen Werten (immer als Text), Screenshot mit Countdown, Export (cys, htb), Warteliste aufgeklappt, Hilfe `?`.

## 11 Menü und Einstellungen

Menü hinter `⋯`. Einstellungen als Tafel: Darstellung (System, Hell, Dunkel), Dichte, Lernmodus, KI, Profil, eigene Secrets, Projekt.

## 12 Host-Tabelle

Ab 200 Hosts statt der Karte. Umschalter Hosts, Services, Credentials (v0.2). Konflikte zuerst. Spalte «Als Nächstes» bleibt.

## Hell (`Ariadne Hell.dc.html`)

1a Hauptansicht, Ruhezustand, Host-Detail und Zeitachse mit den hellen Tokens. Alle anderen Screens verwenden dieselben Tokens.
