# Entscheidungsprotokoll

> Hält fest, was entschieden wurde, warum, und wer entschieden hat. Ariadne entsteht mit KI-Unterstützung (Claude). Für die Diplomarbeit muss erkennbar sein, welche Entscheide vom Nutzer stammen und welche die KI vorgeschlagen oder übernommen hat.

**Quelle**

- **Nutzer:** direkt so beantwortet oder verlangt.
- **an KI delegiert:** der Nutzer hat ausdrücklich gesagt «du entscheidest».
- **KI-Vorschlag:** von der KI vorgeschlagen, vom Nutzer noch nicht ausdrücklich bestätigt.
- **Nutzer + KI:** Anforderung vom Nutzer, technische Umsetzung von der KI.

**Status:** fest, vorläufig (gilt, bis jemand widerspricht) oder offen.

Bezüge zeigen auf den [Fragenkatalog](fragenkatalog.md) (z. B. F2.3) und die [Lösungsarchitektur](architektur.md) (z. B. A3.6).

## Rahmen

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E01 | 2026-10-08 | Zuerst Schule und Labs, danach professionelle Aufträge. Kundenaufträge sind vorerst fiktiv | so geplant | Nutzer | fest | F1.1 |
| E02 | 2026-10-08 | Kernproblem: Überblick verlieren bei vielen Infos, dazu fehlende Denkanstösse | so erlebt | Nutzer | fest | F1.2 |
| E03 | 2026-10-08 | Vorerst Einzelnutzer. Datenmodell trägt trotzdem eine Operator-ID | Teamarbeit später ohne Neubau möglich | Nutzer + KI | fest | F1.3, A5.2 |
| E04 | 2026-10-08 | Leitgefühl: schnell eine erste Übersicht, dann das Bild langsam ausmalen | so gewünscht | Nutzer | fest | F1.4, A7.5 |
| E05 | 2026-10-08 | Privates Projekt, geplant als Diplomprojekt, Vorgehen nach HERMES 2022 | so geplant | Nutzer | fest | VISION |
| E06 | 2026-10-08 | Entwicklung allein und KI-unterstützt, ca. 20 Stunden pro Woche | so geplant | Nutzer | vorläufig: «Kai» als «KI» gelesen | VISION |
| E07 | 2026-10-08 | Keine Zertifizierung geplant, daher kein Prüfungsmodus | so geplant | Nutzer | fest | F8.4 |
| E08 | 2026-10-08 | Repo privat, Lizenz später | so gewünscht | Nutzer | fest | F10.3 |

## Grundsätze

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E10 | 2026-10-08 | Ariadne beobachtet, dokumentiert und schlägt vor, führt aber nie Befehle gegen Ziele aus | Kontrolle bleibt beim Pentester, keine Lockouts oder Scope-Verletzungen durch das Tool | Nutzer | fest | F7.3 |
| E11 | 2026-10-08 | Einzige Ausnahme zu E10: Webseiten-Screenshot auf ausdrücklichen Klick, über einen Proxy, der den Scope erzwingt, nur GET | Nutzer will, dass Ariadne Screenshots selbst macht; automatische Webshots würden E10 verletzen | Nutzer + KI | vorläufig | F3.4, A4.4 |
| E12 | 2026-10-08 | Jeder Fakt hat eine Quelle bis zur Zeile bzw. Bildregion | Belegbarkeit im Bericht | Nutzer | fest | F5.5, A5.5 |
| E13 | 2026-10-08 | Zieldaten gelten überall als feindlich, ein Encoder pro Senke | Ergebnis des Security-Reviews: grösste Angriffsfläche sind die Rückkanäle zum Operator | KI-Vorschlag | vorläufig | A9 |

## Erfassung

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E20 | 2026-10-08 | Rohlog dauerhaft speichern, unveränderlich, verschlüsselt | Beweis und spätere Neuauswertung | Nutzer | fest | F2.1 |
| E21 | 2026-10-08 | Erfassung über einen eigenen PTY-Wrapper um jede Shell, unabhängig von Terminal und Multiplexer. tmux optional | Nutzer arbeitet mit dem Kali-Standard ohne tmux, Ariadne muss mit anderen Setups kompatibel sein | Nutzer + KI | fest | F2.2, A3 |
| E22 | 2026-10-08 | Record-Knopf: solange REC an ist, nimmt Ariadne alles auf. Umschalten per Web-UI, CLI und Hotkey | so gewünscht | Nutzer | fest | F2.3, A3.6 |
| E23 | 2026-10-08 | Host-Kontext als Stapel pro Terminal, gesetzt per Hotkey `Ctrl-]` und Web-UI; Automatik nur für Session-Start und Rückkehr | Remote-Shells nehmen keine lokalen Befehle an, der Shim sitzt davor | Nutzer + KI | vorläufig: Tastaturlayout offen | F2.4, A3.5 |
| E24 | 2026-10-08 | Parallele Terminals: getrennte Ströme und Kontexte, eine Zeitachse, ein Graph | Kontexte dürfen sich nicht mischen | an KI delegiert | fest | F2.5 |
| E25 | 2026-10-08 | Grosse Outputs: alles speichern und durchsuchbar, verdichtet in vier Stufen (Rohstrom, Mentions, Hinweise, Karte) | Nutzer: alle Infos relevant; Karte muss lesbar bleiben | Nutzer + KI | fest | F2.6, A5.11 |
| E26 | 2026-10-08 | Gespeichert wird nur der Output, nie Tastendrücke. Ab v0.2 vergleicht der Shim die Eingabe mit dem Echo und speichert nur ein Bestätigungs-Flag | Datensparsamkeit; Schutz vor gefälschten Remote-Befehlen | KI-Vorschlag | vorläufig | A5.13 |
| E27 | 2026-10-08 | Marker zählen nur mit gültiger Nonce und passender Vordergrund-Prozessgruppe | Ziele können Marker fälschen | KI-Vorschlag | vorläufig | A3.3 |
| E28 | 2026-10-08 | Terminals werden beim ersten REC an ein Projekt gebunden | strikte Projekttrennung | Nutzer + KI | fest | F8.1, A3.6 |

## Quellen

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E30 | 2026-10-08 | Dateien: alles Mögliche, Projektordner automatisch überwacht | so gewünscht | Nutzer | fest | F3.1, F3.2 |
| E31 | 2026-10-08 | Projektordner `~/ariadne/<slug>/` mit Klartext-Arbeitsbereich und verschlüsseltem `.vault/` | Tools schreiben Klartext, Ariadne-Daten bleiben verschlüsselt | KI-Vorschlag | vorläufig | A4.1 |
| E32 | 2026-10-08 | Screenshots macht Ariadne selbst; Inhalt soll verstanden werden (OCR ab v0.2, Vision ab v0.3) | so gewünscht; gestaffelt wegen Aufwand und Datenschutz | Nutzer + KI | fest | F3.3, F3.4 |
| E33 | 2026-10-08 | Weitere Quellen (Burp, Browser, Zwischenablage, PCAP) gestaffelt ab v0.2 | so gewünscht; Datenschutz pro Quelle | Nutzer + KI | fest | F3.5, A4.5 |

## Auswertung und Karte

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E40 | 2026-10-08 | Alle Wertearten (Netz, Zugänge, Angriffsflächen, AD), gestaffelt nach Version | so gewünscht | Nutzer | fest | F4.1 |
| E41 | 2026-10-08 | Extraktion hybrid: Parser zuerst, Regex-Netz, LLM nur mit wörtlichem Beleg | so gewünscht; Schutz vor Halluzinationen | Nutzer + KI | fest | F4.2, A6.3 |
| E42 | 2026-10-08 | Neue Werte als Vorschlag in die Inbox, Automodus pro Projekt umschaltbar | so gewünscht | Nutzer | fest | F4.4 |
| E43 | 2026-10-08 | Kandidaten im Scope erscheinen sofort als Nebel auf der Karte | sonst bleibt die Karte bis zur Bestätigung leer, das widerspricht E04 | KI-Vorschlag | vorläufig | A5.7 |
| E44 | 2026-10-08 | Live-nahe und nachträgliche Auswertung über dieselbe Pipeline | so gewünscht | Nutzer | fest | F4.5 |
| E45 | 2026-10-08 | Widersprüche werden erkannt und nie automatisch aufgelöst | so gewünscht | Nutzer + KI | fest | F4.6 |
| E46 | 2026-10-08 | Karte als Kombination aller Ebenen mit Umschalten | so gewünscht | Nutzer | fest | F5.1 |
| E47 | 2026-10-08 | Drei Status-Achsen: Wissen, Zugriff, Arbeitsstand | Zugriff und Arbeitsstand sind verschiedene Fragen | Nutzer + KI | fest | F5.2, A5.9 |
| E48 | 2026-10-08 | Tunnel und Segmente im Datenmodell ab Tag 1 | Pivots sonst falsch zugeordnet | Nutzer + KI | fest | F5.3 |
| E49 | 2026-10-08 | Scope gehört zur konkreten Kennung, nicht zur Entität; keine DNS-Auflösung von Zielnamen | Ziele können Kennungen fälschen; DNS erreicht Zielinfrastruktur | KI-Vorschlag | vorläufig | A5.8 |
| E50 | 2026-10-08 | Zuerst bis ca. 10 Hosts, Datenmodell skaliert weiter | so gewünscht | Nutzer | fest | F5.6 |

## Oberfläche, KI und Bericht

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E60 | 2026-10-08 | Web-Oberfläche als Hauptoberfläche, ohne speziellen Zweitbildschirm-Modus | so gewünscht | Nutzer | fest | F6.1, F6.2 |
| E61 | 2026-10-08 | Fragen an die Karte über eine DSL; KI übersetzt Fragen, Ausführung erst nach Klick | so gewünscht; nachprüfbar | Nutzer + KI | fest | F6.3 |
| E62 | 2026-10-08 | Bericht als Markdown, mit Vorlage nach dem Schema des Moduls Cybersecurity | so gewünscht; Schulabgabe | Nutzer + KI | fest | F6.4, A8.7 |
| E63 | 2026-10-08 | Notizen, Tags und Status als Entscheide | so gewünscht | Nutzer | fest | F6.5 |
| E64 | 2026-10-08 | Vorschläge aus Regeln und KI kombiniert, mit Lernmodus | so gewünscht; Lernwert im Studium | Nutzer + KI | fest | F7.1, F7.2 |
| E65 | 2026-10-08 | LLM lokal (Ollama) und Cloud (Claude) umschaltbar pro Projekt, über ein einziges Gateway | so gewünscht | Nutzer + KI | fest | F4.3, A6.2 |
| E66 | 2026-10-08 | Cloud-Standardmodell `claude-opus-5-5`; günstigere Modelle nur auf Wunsch | Qualität vor Kosten, Budget begrenzt | KI-Vorschlag | offen: Budget | A6.2 |
| E67 | 2026-10-08 | Scope-Warnung: v0.1 nach dem Befehlsstart, ab v0.2 vor dem Ausführen | so gewünscht; gestaffelt | Nutzer + KI | fest | F7.4 |
| E68 | 2026-10-08 | Befehlsvorlagen nur mit typisierten Platzhaltern und Kontext-Encodern | aus Zieldaten gefüllte Befehle sind sonst ein Weg zur Codeausführung auf Kali | KI-Vorschlag | vorläufig | A6.1 |

## Sicherheit und Daten

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E70 | 2026-10-08 | Projekte strikt getrennt | so gewünscht | Nutzer | fest | F8.1 |
| E71 | 2026-10-08 | Verschlüsselung at rest ab v0.1 (SQLCipher, age), keine eigene Kryptografie | so gewünscht; Nachrüsten wäre teuer | Nutzer + KI | fest | F8.2, A8.4 |
| E72 | 2026-10-08 | Eigene Secrets: ein Redaktor im Daemon, längenerhaltend, nur exakte Treffer der eigenen Liste | Nutzer: wichtig; generische Muster würden Funde vernichten | Nutzer + KI | fest | F8.3, A8.5 |
| E73 | 2026-10-08 | Profile lab und customer; lab mit Leitplanken gegen versehentliche Kundendaten | Kundenprofil erst ab v0.3, Risiko eines echten Auftrags im lab-Projekt | KI-Vorschlag | vorläufig | A8.1 |
| E74 | 2026-10-08 | Entsperren nur per CLI, nie in der Web-UI | Port-Squatting würde Phishing der Passphrase erlauben | KI-Vorschlag | vorläufig | A7.2 |
| E75 | 2026-10-08 | Parser und Bildverarbeitung laufen in Worker-Prozessen ohne Schlüssel | wer Schlüssel hält, parst nicht | KI-Vorschlag | vorläufig | A9.3 |
| E76 | 2026-10-08 | Hash-Kette über alle Felder mit gesalzenen Commitments; externer Anker ab v0.3 | Beweiswert gegenüber Dritten | KI-Vorschlag | vorläufig | A5.2 |

## Technik

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E80 | 2026-10-08 | Python für Shim, Daemon, Parser und Gateway; TypeScript mit Svelte 5 für die Web-UI; Cytoscape.js für die Karte | Pentest-Ökosystem und Parser in Python, gutes Claude-SDK, kleine UI-Laufzeit | an KI delegiert | fest | F9.1, A7.1 |
| E81 | 2026-10-08 | Kali als Referenz, offline lauffähig | so gewünscht | Nutzer | fest | F9.2 |
| E82 | 2026-10-08 | Drei SQLCipher-Datenbanken pro Projekt (`journal`, `derived`, `state`) plus age-Blobs | Journal unveränderlich, Auswertung austauschbar, Betriebszustand ausserhalb der Kette | an KI delegiert | fest | F9.3, A5.1 |
| E83 | 2026-10-08 | Plugin-System für Parser, nur aus einer Allowlist, im Worker | so gewünscht; Lieferkette | Nutzer + KI | fest | F9.4 |
| E84 | 2026-10-08 | Installation per pipx (Paket `ariadne-recon`, Befehl `ariadne`), später Offline-Bundle | Kali blockiert systemweites pip; `ariadne` ist auf PyPI belegt | an KI delegiert | fest | F9.5, A8.8 |
| E85 | 2026-10-08 | Ein Event- und Entscheid-Katalog in `events.py` als einzige Quelle | Review fand drei widersprüchliche Namensräume | KI-Vorschlag | vorläufig | A5.3 |

## Offen

| ID | Frage | Wer | Bezug |
|---|---|---|---|
| O01 | Rahmen der Diplomarbeit: Start, Dauer, Abgabe, welche Version ist Gegenstand | Nutzer, Schule | VISION |
| O02 | Regeln der Schule zum KI-Einsatz in der Diplomarbeit | Nutzer, Schule | VISION |
| O03 | Hotkey-Präfix bei Schweizer Tastaturlayout | Nutzer | E23 |
| O04 | Hardware und Umgebung (VM oder nativ, Desktop, RAM, GPU, zweiter Rechner) | Nutzer | A13 |
| O05 | Monatsbudget für Claude im Profil lab | Nutzer | E66 |
| O06 | Obsidian-Export direkt in den synchronisierten Vault (nur lab)? | Nutzer | A8.7 |
| O07 | Tools nach nmap und verfügbares Testmaterial | Nutzer | A5.6 |
| O08 | Sprache der UI | Nutzer | A14 |
| O09 | Passwortmanager unter Kali | Nutzer | A4.5 |
