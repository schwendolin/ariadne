# Handoff: ARIADNE-Dashboard v0.1

Stand 2026-10-17. Ergebnis der Design-Session zum Briefing «Ariadne-Dashboard: Funktionen und Inhalte» (Stand 2026-10-15). Gewählt ist die Richtung **1a «Spalte bleibt»**, das Logo ist **2c «Graph-A, alle Knoten gefüllt»**.

## Überblick

ARIADNE ist ein Flugschreiber für Pentests in Kali. Das Dashboard ist die Web-Oberfläche dazu, gebaut in **Svelte**, Karte mit **Cytoscape.js** plus HTML-Overlay für die Host-Karten. Es liest alle Daten und schreibt nur Entscheide. Es führt nie Befehle gegen Ziele aus.

## Über die Design-Dateien

Die Dateien in diesem Ordner sind **Design-Referenzen in HTML**, keine Produktionsvorlage. Sie zeigen Aussehen, Inhalte und Zustände mit den Beispieldaten aus Anhang A (Projekt `ms2`, Standbild 16:54). Aufgabe ist, sie im Svelte-Rohbau nachzubauen.

Wichtig für den Bau:

- Die Referenzen nutzen **Inline-Styles**. Im Produkt gilt die strenge CSP: **keine Inline-Styles**. Alle Werte gehören in CSS-Variablen (`tokens.css`) und Klassen.
- Die `.dc.html`-Dateien laufen mit `support.js` im Browser. Öffnen genügt, kein Build.
- Zieldaten erscheinen in den Referenzen als Text. Im Produkt gilt Briefing Abschnitt 9: nie HTML, nie klickbare Links, Steuerzeichen sichtbar machen.

## Fidelity

**High-Fidelity** für Farben, Typografie, Abstände, Inhalte und Zustände. Die Kartenlage (Positionen der Knoten) ist illustrativ. Im Produkt kommt das Layout aus Cytoscape und den gespeicherten Positionen.

## Dateien

| Datei | Inhalt |
|---|---|
| `Ariadne Runde 1.dc.html` | Abschnitt 0 fluide Breite (Presets 3440 bis 1000 px, ziehbar). Richtungen 1a, 1b, 1c mit Hauptansicht und Ruhezustand. **Massgeblich ist 1a.** Host-Detail, Einträge, Aufnahmezustand, Reiter Terminals |
| `Ariadne Runde 2.dc.html` | 6 Zeitachse mit Warteliste, 7 Belegansicht, 8 Findings, 9 Anmeldung und Zustände, 10 Dialoge und Popover, 11 Menü und Einstellungen, 12 Host-Tabelle, 13 Tokens |
| `Ariadne Hell.dc.html` | 1a, Host-Detail und Zeitachse im hellen Modus |
| `Ariadne Logo.dc.html` | Logo-Runden. Gewählt: 2c |
| `AriadneKopfzeile.dc.html`, `AriadneKopfzeileHell.dc.html` | Kopfzeile, Prop `variant`: normal, pause, waiting, held, locked, noproject, offline. Props `tab`, `origin`, `present` |
| `AriadneKarte.dc.html`, `AriadneKarteHell.dc.html` | Karte, Props `selected`, `linked`, `showNew`, `pulse`. Skaliert den Inhalt per ResizeObserver |
| `tokens.css` | alle Tokens als CSS-Variablen, hell und dunkel |
| `assets/ariadne-mark.svg` | Logo-Zeichen, folgt hell und dunkel |
| `assets/ariadne-favicon-klaeren.svg` | Favicon mit Zustandspunkt «etwas zu klären» |
| `SCREENS.md` | jeder Screen im Detail |
| `BEHAVIOR.md` | Interaktionen, Live-Verhalten, Tastatur, Zustand |

## Entscheide dieser Session (fürs Entscheidungsprotokoll)

Antworten auf Briefing 13.1:

1. **Rückkehr und Ruhezustand:** Richtung 1a. Die Spalte «Als Nächstes» bleibt immer da. Im Ruhezustand stehen erledigte Klärungen gedämpft, der Cursor springt auf den ersten Denkanstoss und klappt ihn auf. «Karte mindestens 70 %» gilt weiter (Spalte 27 %).
2. **Neu seit:** Der Server merkt sich den Zeitpunkt, an dem der Tab unsichtbar wird (`visibilitychange`). Kein Knopf «Gesehen». Anzeige als Marke `+N seit HH:MM` im Lagebild, ein Klick lässt das Neue einmal pulsieren.
3. **Kopfzeile:** Herkunft der Sitzung immer sichtbar, Profil nur im Popover der Aufnahme. Keine Zahlen von Klärungen oder Denkanstössen in der Kopfzeile (E87). Pause im Popover und im Reiter Terminals, 10 min.
4. **Karte und Tastatur:** Host-Karten als HTML-Overlay, mit `Tab` erreichbar, Pfeiltasten springen zum nächstgelegenen Host. Services als Zahl. Host-Tabelle ab 200 Hosts, darunter mit `t` umschaltbar.
5. **Farben:** Architektur 7.5 übernommen. **Keine Profilfarbe** (E87 geht vor A 7.4).
6. **auto, Rückgängig, Bestätigen:** «auto» ist unauffällig, nur als Wort im Detail und in Brotkrumen. Rückgängig pro Befehl als Knopf in der Zeitachsenzeile (Hover, Fokus, `u`). **«Bestätigen» entfällt im Profil lab**, kommt mit customer (v0.3) zurück.
7. **Kopierziel:** Jeder Kopierknopf nennt das Ziel: «Kopieren · Mac» (Browser-Zwischenablage) oder «in die Kali» (Secrets, über den Daemon, ohne Anzeigen).
8. **Einstellungen ohne Browser-Speicher:** Theme, Dichte, Lernmodus auf dem Server. Reiter, Ebenen und Auswahl in der URL.
9. **Schriften:** nur Systemschriften (`-apple-system, system-ui` und `ui-monospace, SF Mono, Menlo`).
10. **Findings v0.1:** Formular im Reiter und «Als Finding» aus dem Beleg führen ins selbe Formular. Schwere 5 Stufen (Kritisch, Hoch, Mittel, Tief, Info), Status 2 Stufen (Entwurf, final).

Weitere Festlegungen:

- **Warteliste:** eingeklappter Streifen oben in der Zeitachse («3 Dateien nicht übernommen»). Übernehmen in v0.1 nur mit `ariadne import`.
- **Belegansicht:** Tafel von rechts über Karte und Spalte, 52 % Breite (620 bis 860 px), immer nur eine offen.
- **Fehlerfarbe:** eigenes Rosa `--error`, damit Rot allein für den Faden bleibt.
- **Präsentationsmodus:** Taste `Shift+P` (nur mit Fokus ausserhalb von Eingabefeldern). In der Webkonsole auf Kollision testen.

Änderungen an bisherigen Entscheiden:

- **E86:** unverändert übernommen.
- **E87:** bestätigt. Die Kopfzeile hat zusätzlich das Logo-Zeichen (ein Element).
- **E88:** im Profil lab ohne Wirkung, weil «Bestätigen» dort entfällt.
- **E99:** unverändert.
- **Architektur 7.5:** übernommen. Ergänzt: Sackgasse als Symbol `⊘` und Text auf der Host-Karte, verknüpfter Host mit gestricheltem Ring in `--attention`.

## Logo

Zeichen: gleichseitiges Dreieck aus drei gefüllten Knoten, offene Basis, dazu eine Kante vom Knoten unten rechts zur Mitte des linken Schenkels. viewBox `0 0 32 32`, Knoten bei (16, 6.5), (5, 25.55), (27, 25.55), Radius 3.4 bis 3.6 (siehe `assets/ariadne-mark.svg`), Kantenstärke 3, runde Enden. Die Diagonale endet bei (10.5, 16.03). Immer einfarbig in `--fg`.

Schriftzug: `ARIADNE` in Versalien, Systemschrift, Gewicht 650, Laufweite 0.08em.

Einsatz: Favicon (16 und 32 px, mit Zustandspunkt in `--attention`, wenn etwas zu klären ist), Kopfzeile (20 px, vor dem Slug), Anmeldeseite, exportierter Bericht. CLI-Banner `ARIADNE 0.1`.

## Tokens

Siehe `tokens.css`. Kurzfassung:

| Token | hell | dunkel | Verwendung |
|---|---|---|---|
| `--bg` | #f4f5f7 | #111418 | Fenster |
| `--map` | #eef0f3 | #121519 | Kartenfläche |
| `--surface` | #ffffff | #15191e | Spalte, Tafeln |
| `--surface-2` | #f0f2f5 | #1d2228 | aufgeklappter Eintrag, Popover, Dialog |
| `--fg` | #1a1e24 | #e5e8ec | Text, Primärknopf |
| `--fg-2` | #3a414b | #c4cad2 | Fliesstext, Logzeilen |
| `--muted` | #5a6370 | #9aa3ae | Labels |
| `--faint` | #6b7480 | #6b7480 | Hinweise, erledigt |
| `--line` | #dde1e7 | #2a3038 | Trennlinien |
| `--line-strong` | #c4cad2 | #3a414b | Ränder von Knöpfen und Feldern |
| `--focus` | #1f5fbf | #7aa7ff | Fokus, Auswahl, markierter Logbereich |
| `--access-user` | #0b7fa3 | #6cc3e0 | Zugriff `$` |
| `--access-root` | #6a45c9 | #b59cf5 | Zugriff `#` |
| `--thread` | #b42318 | #f0675c | Faden, einziges kräftiges Rot |
| `--attention` | #a15c00 | #e8b14a | Handlungsbedarf, Pause, held, Warnung |
| `--error` | #c0264b | #ef7d95 | Fehler |
| `--fog` | #9aa3ae | #5a6370 | Nebel, gepunkteter Rand |
| `--out-of-scope` | #e3e7ec | #191d23 | Schraffur am Kartenrand |

Abstände 4, 8, 12, 16, 20, 24, 32. Radien 4 (Badge), 6 (Knopf), 10 (Karte), 12 (Dialog), 999 (Tag). Linien 1 (Trenner), 1.5 (Knoten), 2 (Fokus), 3 (Faden). Schriftgrössen 12, 12.5, 13.5, 15, 20.

## Assets

Keine Bilder. Logo als SVG in `assets/`. Screenshot-Vorschauen in der Zeitachse sind Platzhalter.
