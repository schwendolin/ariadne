# Verhalten ARIADNE-Dashboard v0.1

## Live-Daten

- Änderungen kommen per Server-Push. Neue Werte landen ohne Klick auf der Karte, nur Klärungen brauchen den Menschen.
- **Neu seit:** Beim `visibilitychange` auf hidden meldet der Client den Zeitpunkt an den Server. Bei der Rückkehr zeigt das Lagebild `+N seit HH:MM`. Ein Klick lässt die neuen Elemente einmal pulsieren (900 ms). Der Wert übersteht Neuladen.
- Eine Entscheidung aus einem anderen Tab schliesst den Eintrag hier mit «In einem anderen Tab entschieden».

## Spalte «Als Nächstes»

- Reihenfolge: Klären vor Denkanstössen. Es ist immer genau ein Eintrag gewählt und aufgeklappt.
- Ist eine Klärung erledigt, springt der Cursor zur nächsten. Gibt es keine mehr, springt er zum ersten Denkanstoss (Ruhezustand).
- Erledigte bleiben bis zum nächsten Wechsel ins Dashboard gedämpft stehen, mit Rückgängig.
- Klick auf einen Host (Karte oder Text) öffnet das Host-Detail in der Spalte. `Esc` kehrt zurück, der Fokus geht auf den Host.

## Karte

- Host-Karten sind HTML-Elemente über dem Cytoscape-Canvas, mit `Tab` erreichbar. Pfeiltasten springen zum nächstgelegenen Host in dieser Richtung. `+ − 0` zoomen und passen ein.
- Positionen speichert der Server.
- Der Faden verbindet die Schlüsselschritte in zeitlicher Reihenfolge.

## Zeitachse

- `j k` wechseln, `↵` öffnet den Beleg, `u` macht den gewählten Befehl rückgängig (inline, mit optionalem Grund).
- Rückgängig verwirft nur Werte mit genau dieser Quelle. Werte mit weiteren Quellen verlieren nur diese. Die Zeile bleibt als «misstraut».

## Belegansicht

- Es ist immer nur eine Tafel offen. `Esc` schliesst sie, der Fokus geht zurück zum Auslöser.
- Hash-Kette verletzt: Die Meldung lässt sich nicht schliessen. Kopieren und Finding sind gesperrt.

## Kopieren

- «Kopieren · Mac» schreibt in die Zwischenablage des Browsers.
- Secrets gehen nie in den Browser. «In die Kali» läuft über den Daemon, ohne Anzeige.
- Im Präsentationsmodus kopiert «Als Beleg kopieren» maskiert.

## Tastatur

| Taste | Wirkung |
|---|---|
| `⌘K` | Palette |
| `1` bis `4` | Reiter |
| `j k ↵` | Liste, Zeitachse, Terminals |
| `a x e u` | annehmen, verwerfen, ändern, rückgängig |
| `t` | Karte oder Host-Tabelle |
| `n` | nächster Denkanstoss |
| `⇧P` | Präsentationsmodus |
| `?` | Hilfe |
| `Esc` | Tafel oder Detail schliessen |

Einzeltasten wirken nur mit Fokus ausserhalb von Eingabefeldern. In Dialogen bleibt der Fokus gefangen, Einzeltasten sind dort aus.

## Zustand

- Auf dem Server: Theme, Dichte, Lernmodus, «Neu seit», Kartenpositionen.
- In der URL: Reiter, Ebenen, Auswahl, offene Tafel.
- Kein `localStorage`, kein `sessionStorage`.

## Breite

- Spalte 27 %, 320 bis 480 px. Die Karte skaliert ihren Inhalt mit (ResizeObserver).
- Kopfzeile kompakt unter 1280 px.
- Unter etwa 1000 px gibt es keinen eigenen Entwurf, nur diesen Rückfall.

## Bewegung

Einblenden 180 ms ease-out, Tafel 160 ms von rechts, Puls einmal 900 ms. Bei `prefers-reduced-motion` ist alles aus, statt des Pulses steht 2 s lang ein statischer Ring.

## Favicon

Standardzeichen. Gibt es offene Klärungen, kommt ein Punkt in `--attention` dazu, und der Tab-Titel lautet `ms2 · 2 zu klären`.
