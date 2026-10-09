# Ariadne: Fragenkatalog Web-Oberfläche

> Brainstorming zur Web-Oberfläche, Stand 2026-10-09. Jede Frage hat Optionen und eine Empfehlung. Grundlage sind die [Architektur, Abschnitt 7](architektur.md#7-web-oberfläche-und-karte) und deine bisherigen Antworten. Ein klickbarer Prototyp mit Beispieldaten zeigt die empfohlene Richtung.
>
> **So antworten:** «Empfehlungen passen, ausser B2: C, F4: B».

## A. Gesamtbild

### A1 Hauptlayout

- **A) Cockpit:** Die Karte bleibt im Zentrum, Inbox, Details und Belege öffnen sich als Schubladen daneben.
- **B) Seiten:** Jede Ansicht (Karte, Inbox, Terminals ...) füllt den ganzen Bildschirm.
- **C) Fest geteilt:** Karte links, Inbox oder Detail rechts, immer beide sichtbar.
- **D) Dashboard:** Kacheln mit Zahlen, die Karte ist eine Kachel unter vielen.

**Empfehlung: A.** Der Überblick ist dein Kernproblem, also darf die Karte nie verschwinden. In einer VM mit 1366x768 ist eine feste Zweiteilung zu eng, Schubladen nutzen den Platz besser.

### A2 Was zeigt die UI beim Öffnen?

- **A)** immer die Karte
- **B)** die Inbox
- **C)** ein Lagebild mit Zahlen
- **D)** die zuletzt geöffnete Ansicht

**Empfehlung: D**, beim allerersten Start die Karte mit der Checkliste «REC an, nmap mit `-oA`, Foothold mit F12 k markieren».

### A3 Informationsdichte

- **A) kompakt:** viel auf einmal, kleine Abstände
- **B) komfortabel:** luftig, weniger pro Bildschirm
- **C) umschaltbar**

**Empfehlung: C mit Standard kompakt.** Das VM-Fenster ist klein, und im Pentest willst du viel gleichzeitig sehen.

### A4 Farbschema

- **A)** immer dunkel
- **B)** immer hell
- **C)** folgt dem System
- **D)** folgt dem System, mit Umschalter

**Empfehlung: D.** Dunkel als «Nachtkarte» (tiefes Tintenblau, kein reines Schwarz), hell als «Vermessungskarte». In beiden ist der Faden das einzige kräftige Rot.

### A5 Sprache der Oberfläche

- **A)** Deutsch mit englischen Fachbegriffen (Credential, Foothold, Finding)
- **B)** durchgehend Englisch
- **C)** umschaltbar

**Empfehlung: A.** Die Texte laufen ab Tag 1 über ein Übersetzungsmodul, Englisch lässt sich später ergänzen.

### A6 Wie öffnet sich die UI?

- **A)** `ariadne ui` öffnet ein eigenes Firefox-Fenster mit eigenem, gehärtetem Profil
- **B)** als Tab in deinem normalen Browser
- **C)** als eigene Desktop-App

**Empfehlung: A.** Dein Testbrowser läuft über Burp und besucht feindliche Seiten. Die UI mit allen Credentials gehört nicht in dasselbe Profil.

## B. Karte

### B1 Standardebene

- **A)** Topologie (Hosts nach Netz)
- **B)** Faden (chronologischer Angriffspfad)
- **C)** Services
- **D)** zuletzt genutzte

**Empfehlung: A, mit dem Faden immer eingeblendet.** Topologie gibt die Orientierung, der Faden zeigt den Weg.

### B2 Anordnung der Hosts

- **A) organisch:** ein Kräfte-Layout ordnet die Hosts selbst an
- **B) hierarchisch:** Kali links, je Pivot-Stufe eine Spalte weiter rechts
- **C) Labyrinth-Ringe:** Kali in der Mitte, direkt erreichbare Netze im ersten Ring, Netze hinter einem Pivot im zweiten
- **D) Raster:** nach Subnetz sortiert

**Empfehlung: C.** Die Ringe zeigen auf einen Blick, wie tief du drin bist, und passen zum Bild des Labyrinths. Bestehende Hosts behalten ihren Platz, neue kommen dazu. **Unsicher:** Die Umsetzung ist aufwendiger als A. Im Prototyp lässt sich vergleichen, was sich besser anfühlt.

### B3 Wie stark wird ausgemalt?

- **A) dezent:** Farbe nur bei Zugriff
- **B) stufenweise:** Nebel, dann grau, entsättigt, Farbe
- **C) Heatmap** nach Fortschritt

**Empfehlung: B.** Genau das ist dein «Bild langsam ausmalen». Jede Stufe hat einen klaren Auslöser (erwähnt, gescannt, Versionen bekannt, Zugriff).

### B4 Unbestätigte Werte auf der Karte

- **A)** sofort als Nebel (grau, gepunktet)
- **B)** erst nach Bestätigung
- **C)** nur in einer zuschaltbaren Vorschau

**Empfehlung: A.** Sonst bleibt die Karte nach dem ersten nmap leer, bis die Inbox abgearbeitet ist.

### B5 Services darstellen

- **A)** als Badges am Host (z. B. «Web 2, SMB 1»)
- **B)** als eigene Knoten rund um den Host
- **C)** je nach Grösse: Knoten bei wenigen Hosts, Badges bei vielen

**Empfehlung: C.** Bei einer einzelnen Box willst du die Dienste direkt sehen, bei 10 Hosts wird es mit Knoten unübersichtlich.

### B6 Credentials auf der Karte

- **A)** eigene Ebene: Schlüssel-Symbol an jedem Dienst, auf dem ein Credential gilt
- **B)** nur in Tabelle und Matrix
- **C)** Kanten «Credential gilt auf Host X»

**Empfehlung: A, dazu die Matrix ab v0.2.** Credential-Reuse ist der häufigste Weg zum nächsten Host und soll auf der Karte auffallen.

### B7 Faden

- **A)** rote Linie über die Karte mit nummerierten Schritten
- **B)** eigene Ansicht, chronologisch von links nach rechts
- **C)** beides

**Empfehlung: C.** In v0.1 die Linie, ab v0.2 die eigene Ansicht. Diese wird auch das Gerüst für dein Writeup.

### B8 Neue Funde während der Arbeit

- **A)** Elemente blenden ein, pulsieren einmal, dazu ein Zähler «+3 seit 14:02»
- **B)** nur ein Zähler, die Karte bleibt ruhig bis zum Klick
- **C)** Popup-Meldungen

**Empfehlung: A.** Bestehende Elemente bewegen sich dabei nie, sonst verlierst du die Orientierung.

### B9 Session abspielen

- **A) früh (v0.2):** ein Regler, der die Karte zu jedem Zeitpunkt zeigt und die Session Schritt für Schritt abspielt
- **B) später (v0.4)**
- **C) nie**

**Empfehlung: A in einer einfachen Version**, Schritt für Schritt entlang der Schlüsselschritte. Das Datenmodell kann das (Rohdaten bleiben erhalten). Es hilft beim Writeup und beim Lernen. Der Prototyp zeigt die Idee.

## C. Inbox und Bestätigen

### C1 Wo bestätigst du Werte?

- **A)** nur in der Inbox
- **B)** auch direkt auf der Karte und im Host-Detail
- **C)** zusätzlich überall per Tastatur

**Empfehlung: B und C.**

### C2 Granularität

- **A)** jeder Wert einzeln
- **B)** pro Gruppe (ein Befehl, z. B. «nmap 14:02: 1 Host, 21 Services»), mit Ausnahmen
- **C)** pro Host

**Empfehlung: B.** Ein nmap-Lauf ist eine Einheit. Verdächtige Werte (ausserhalb des Scopes, wenig Konfidenz, vom Ziel angeboten) zeigt die Gruppe separat an.

### C3 Werte ausserhalb des Scopes

- **A)** nur als gesammelter Hinweis
- **B)** ausblenden
- **C)** eigene Gruppe mit der Frage «Scope erweitern?»

**Empfehlung: C im Lab.** Bei Kundenprojekten (ab v0.3) gilt A, und den Scope erweitert nur eine bewusste Aktion mit Bestätigung.

### C4 Hinweis auf neue Inbox-Einträge

- **A)** Zahl in der Kopfzeile
- **B)** zusätzlich Desktop-Benachrichtigung
- **C)** Ton

**Empfehlung: A.** Benachrichtigungen schaltest du nach einem Tag ab.

## D. Terminals und Kontext

### D1 Terminal-Ansicht

- **A)** Liste mit Name, Status, letztem Befehl und Kontext als Brotkrumen («Kali › 10.10.10.3 (www-data) › mysql»)
- **B)** Kacheln mit den letzten Zeilen live
- **C)** volles Live-Terminal in der UI

**Empfehlung: A, B optional.** C kommt erst später, weil ein Terminal-Renderer im Browser eine eigene Angriffsfläche ist.

### D2 Kontext in der UI setzen

- **A)** Auswahlliste bekannter Hosts
- **B)** Freitext mit Vorschlägen
- **C)** Host auf der Karte anklicken und «diesem Terminal zuordnen» wählen

**Empfehlung: B und C.** Vorschläge kommen aus Listener-Meldungen und `hostname`/`whoami`.

### D3 Kontext rückwirkend korrigieren

- **A)** einen Bereich in der Zeitachse markieren und einem Host zuweisen
- **B)** nur ab jetzt
- **C)** pro Befehl oder Segment

**Empfehlung: C in v0.1, A später.** Der häufigste Fall: Du hast vergessen, F12 h zu drücken, und willst die letzten Ausgaben dem richtigen Host zuordnen.

## E. Belege und Rohlog

### E1 Belegansicht

- **A)** Ausschnitt mit ein paar Zeilen Kontext
- **B)** das ganze Log mit Sprung zur Stelle
- **C)** beides

**Empfehlung: C.**

### E2 Farben im Log

- **A)** Originalfarben
- **B)** dezent, nur Hervorhebungen (z. B. die roten und gelben Zeilen von linpeas)
- **C)** keine Farben

**Empfehlung: B, Originalfarben per Schalter.**

### E3 Format beim Kopieren eines Belegs

- **A)** Markdown-Codeblock mit Befehl, Zeit, Host und Ausschnitt
- **B)** nur der Text
- **C)** als Bild

**Empfehlung: A.** Passt direkt in Writeup und Bericht.

## F. Denkanstösse und KI

### F1 Wo erscheinen Denkanstösse?

- **A)** eigene Ansicht
- **B)** Leiste neben der Karte
- **C)** im Host-Detail, passend zum Host

**Empfehlung: C und A**, dazu eine Zahl in der Kopfzeile.

### F2 Lernmodus

- **A)** an: zuerst eine Frage, dann eine Richtung, zuletzt der Befehl
- **B)** aus: direkt der Befehl
- **C)** pro Denkanstoss wählbar

**Empfehlung: A, mit einem Knopf «alle Stufen zeigen».** Du willst lernen, nicht nur abarbeiten.

### F3 Wann kommt ein KI-Denkanstoss?

- **A)** nur auf Knopfdruck
- **B)** auf Knopfdruck, dazu ein dezenter Hinweis bei Stillstand (z. B. 20 Minuten ohne neuen Fund)
- **C)** automatisch nach jedem Fund

**Empfehlung: B.** Der Hinweis löst keinen KI-Aufruf aus, er hebt nur den Knopf hervor.

### F4 Chat mit der KI («Frag Ariadne»)

- **A)** kein Chat, nur die strukturierten Funktionen (Denkanstoss, Zusammenfassung)
- **B)** ein Chat-Fenster mit Zugriff auf den Projektstand
- **C)** Fragen an die Karte, die die KI in eine sichtbare Abfrage übersetzt (z. B. «welche Credentials habe ich auf 10.10.10.3 noch nicht probiert?»)

**Empfehlung: C ab v0.2, B frühestens später.** Ein freier Chat liest Zieldaten und ist damit anfällig für Prompt-Injection. Ausserdem verleitet er zum Autopiloten.

## G. Notizen, Findings, Export

### G1 Notizen

- **A)** pro Host und Service
- **B)** ein Projekt-Notizbuch
- **C)** beides

**Empfehlung: C.**

### G2 Findings

- **A)** einfaches Formular: Titel, Schweregrad, betroffene Hosts, Belege, Massnahme
- **B)** dazu Vorlagen (CYS-Schema, MITRE ATT&CK)
- **C)** erst später

**Empfehlung: A in v0.1, B in v0.2.**

### G3 Export

- **A)** ein Knopf «Writeup erzeugen» mit Wahl der Vorlage (cys, htb)
- **B)** Vorschau in der UI vor dem Export
- **C)** beides

**Empfehlung: C.** Der Export landet im Projektordner.

## H. Bedienung

### H1 Tastatur

- **A)** alles per Tastatur, mit Befehlspalette (`Ctrl+K`)
- **B)** nur die wichtigsten Kürzel
- **C)** vor allem Maus

**Empfehlung: A.** Pentester leben auf der Tastatur.

### H2 Präsentationsmodus (Secrets maskieren)

- **A)** manuell per Knopf
- **B)** automatisch beim Export
- **C)** immer an, einzeln aufdecken

**Empfehlung: A im Lab.** Im Kundenprofil gilt später C.

### H3 Mehrere Projekte

- **A)** genau ein aktives Projekt
- **B)** mehrere als Tabs, die übrigen nur lesbar

**Empfehlung: A.** Die strikte Trennung der Projekte ist dir wichtig.

## I. Darstellung

### I1 Farbsehschwäche

- **A)** Farbe immer zusammen mit Symbol und Form
- **B)** zusätzlich eine wählbare Palette
- **C)** nur Farben

**Empfehlung: A, B später.** Rund 8 % der Männer sehen Rot und Grün schlecht.

### I2 Bewegung

- **A)** sichtbare Animationen beim Ausmalen
- **B)** ganz ruhig
- **C)** einstellbar

**Empfehlung: C mit dezenter Animation als Standard.** «Weniger Bewegung» im System wird respektiert.
