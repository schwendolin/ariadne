# Entscheidungsprotokoll

> Hält fest, was entschieden wurde, warum, und wer entschieden hat. Ariadne entsteht mit KI-Unterstützung (Claude). Das Protokoll macht sichtbar, welche Entscheide vom Nutzer stammen und welche die KI vorgeschlagen oder übernommen hat.

**Quelle**

- **Nutzer:** direkt so beantwortet oder verlangt.
- **an KI delegiert:** der Nutzer hat ausdrücklich gesagt «du entscheidest».
- **KI-Vorschlag:** von der KI vorgeschlagen, vom Nutzer noch nicht ausdrücklich bestätigt.
- **Nutzer + KI:** Anforderung vom Nutzer, technische Umsetzung von der KI.

**Status:** fest, vorläufig (gilt, bis jemand widerspricht), offen oder aufgehoben. Geänderte Entscheide behalten ihre ID; das Datum der Änderung und der alte Stand stehen in der Zeile.

Bezüge zeigen auf den [Fragenkatalog](fragenkatalog.md) (z. B. F2.3) und die [Lösungsarchitektur](architektur.md) (z. B. A3.6). «TW» meint die Fragen im [Konzept Terminal und Web](konzept-terminal-und-web.md) (Abschnitt 7), «FZ» die Fragen im [Konzept Fernzugriff](konzept-fernzugriff.md) (Abschnitt 9), beide beantwortet am 2026-10-15.

## Rahmen

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E01 | 2026-10-08 | Zuerst Schule und Labs, danach professionelle Aufträge. Kundenaufträge sind vorerst fiktiv | so geplant | Nutzer | fest | F1.1 |
| E02 | 2026-10-08 | Kernproblem: Überblick verlieren bei vielen Infos, dazu fehlende Denkanstösse | so erlebt | Nutzer | fest | F1.2 |
| E03 | 2026-10-08 | Vorerst Einzelnutzer. Datenmodell trägt trotzdem eine Operator-ID | Teamarbeit später ohne Neubau möglich | Nutzer + KI | fest | F1.3, A5.2 |
| E04 | 2026-10-08 | Leitgefühl: schnell eine erste Übersicht, dann das Bild langsam ausmalen | so gewünscht | Nutzer | fest | F1.4, A7.5 |
| E05 | 2026-10-09 | Privates Projekt, keine Diplomarbeit, Start sofort | so entschieden | Nutzer | fest | VISION |
| E06 | 2026-10-08 | Entwicklung allein und KI-unterstützt, ca. 20 Stunden pro Woche | so geplant | Nutzer | fest | VISION |
| E09 | 2026-10-09, geändert 2026-10-15 | Zielumgebung: Kali als entfernte VM im SmartLearn-Netz der gibb (VMware vSphere, laut Netzplan 1 vCPU, 4 GB RAM), bedient über die Webkonsole im Browser des Macs. Die Kali kommt ins Internet, Tailscale ist von der Schule erlaubt | Korrektur und Antworten des Nutzers vom 2026-10-14 und 2026-10-15; vorher «Kali in einer VM mit eher knapper Leistung» | Nutzer | fest | VISION, FZ 1 |
| E07 | 2026-10-08 | Keine Zertifizierung geplant, daher kein Prüfungsmodus | so geplant | Nutzer | fest | F8.4 |
| E08 | 2026-10-08 | Repo privat, Lizenz später | so gewünscht | Nutzer | fest | F10.3 |

## Grundsätze

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E10 | 2026-10-08, ergänzt 2026-10-15 | Ariadne beobachtet, dokumentiert und schlägt vor, führt aber nie Befehle gegen Ziele aus. Seit 2026-10-15 ohne Ausnahme (E11 aufgehoben) | Kontrolle bleibt beim Pentester, keine Lockouts oder Scope-Verletzungen durch das Tool | Nutzer | fest | F7.3, TW 7 |
| E11 | 2026-10-08, aufgehoben 2026-10-15 | Aufgehoben: Ariadne macht keine Webseiten-Screenshots selbst. Bilder von Webseiten kommen ab v0.3 aus der Firefox-Erweiterung (Tab-Screenshot). Vorher: Webshot auf Klick über einen Scope-Proxy als einzige Ausnahme zu E10 | der Browser-Recorder (E33) liefert die Seiten ohne eigenen Verkehr | Nutzer | aufgehoben | F3.4, A4.4, TW 7 |
| E12 | 2026-10-08 | Jeder Fakt hat eine Quelle bis zur Zeile bzw. Bildregion | Belegbarkeit im Bericht | Nutzer | fest | F5.5, A5.5 |
| E13 | 2026-10-08 | Zieldaten gelten überall als feindlich, ein Encoder pro Senke | Ergebnis des Security-Reviews: grösste Angriffsfläche sind die Rückkanäle zum Operator | KI-Vorschlag | vorläufig | A9 |

## Erfassung

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E20 | 2026-10-08 | Rohlog dauerhaft speichern, unveränderlich, verschlüsselt | Beweis und spätere Neuauswertung | Nutzer | fest | F2.1 |
| E21 | 2026-10-08 | Erfassung über einen eigenen PTY-Wrapper um jede Shell, unabhängig von Terminal und Multiplexer. tmux optional | Nutzer arbeitet mit dem Kali-Standard ohne tmux, Ariadne muss mit anderen Setups kompatibel sein | Nutzer + KI | fest | F2.2, A3 |
| E22 | 2026-10-08, geändert 2026-10-15 | Aufnahme läuft immer, solange ein Projekt aktiv ist, in allen Terminals, auch parallel. `F12 r` pausiert ein Terminal für 10 Minuten. Das Projekt endet mit `ariadne stop` oder nach 12 Stunden ohne Ausgabe. Vorher: REC-Knopf, nach einem Neustart aus | Nutzer: «wenn einmal eingerichtet immer alle Terminalfenster aufnehmen» | Nutzer | fest | F2.3, A3.6, TW 1 |
| E23 | 2026-10-08, ergänzt 2026-10-15 | Host-Kontext als Stapel pro Terminal, gesetzt per Hotkey und Web-UI; Automatik für Session-Start, Rückkehr und neu für den ersten Callback einer Reverse Shell: Liegt seine IP im Scope und ist sie nicht Loopback, setzt Ariadne den Host selbst, sichtbar als «auto». `F12 h` überschreibt und wirkt rückwirkend | Remote-Shells nehmen keine lokalen Befehle an, der Shim sitzt davor; `F12 h` braucht es dann nur noch bei Pivots, NAT und Port-Forwards | Nutzer + KI | fest | F2.4, A3.5, TW 5 |
| E29 | 2026-10-09 | Hotkey-Präfix `F12` statt `Ctrl-]`, konfigurierbar | Nutzer wollte eine andere Taste; F12 ist auf dem Schweizer Layout einfach erreichbar und selten belegt | Nutzer + KI | vorläufig | A3.4 |
| E24 | 2026-10-08 | Parallele Terminals: getrennte Ströme und Kontexte, eine Zeitachse, ein Graph | Kontexte dürfen sich nicht mischen | an KI delegiert | fest | F2.5 |
| E25 | 2026-10-08 | Grosse Outputs: alles speichern und durchsuchbar, verdichtet in vier Stufen (Rohstrom, Mentions, Hinweise, Karte) | Nutzer: alle Infos relevant; Karte muss lesbar bleiben | Nutzer + KI | fest | F2.6, A5.11 |
| E26 | 2026-10-08, geändert 2026-10-15 | Ariadne speichert Ein- und Ausgaben vollständig mit Zeitstempel, auch alles Getippte in Remote-Shells und Passwörter ohne Echo. Der Shim vergleicht die Eingabe mit dem Echo und markiert bestätigte Befehle. Vorher: nur Output, nie Tastendrücke | Nutzer will eine lückenlose Zeitachse; das Journal ist verschlüsselt (E71), gefiltert wird an den Ausgängen (E72) | Nutzer | fest | A5.13, TW 4 |
| E27 | 2026-10-08 | Marker zählen nur mit gültiger Nonce und passender Vordergrund-Prozessgruppe | Ziele können Marker fälschen | KI-Vorschlag | vorläufig | A3.3 |
| E28 | 2026-10-08, geändert 2026-10-15 | Offene Terminals wechseln beim Projektwechsel ins neue Projekt, sobald dort wieder die lokale Kali-Shell läuft; eine laufende Remote-Sitzung bleibt bis dahin beim alten Projekt. Vorher: gebundene Terminals pausieren, bis ihr altes Projekt wieder aktiv ist | einfache Bedienung bei strikter Projekttrennung (E70) | Nutzer + KI | fest | F8.1, A3.6, TW 1 |
| E95 | 2026-10-15 | Ohne aktives Projekt hält Ariadne die letzten 15 Minuten pro Terminal nur im Arbeitsspeicher. `ariadne start` fragt, ob sie ins Projekt übernommen werden | nichts geht verloren, wenn man das Starten vergisst, und nichts liegt unverschlüsselt auf der Platte | Nutzer + KI | fest | TW 2 |
| E96 | 2026-10-15 | Massgeblich ist die Zeit, die der Shim beim Lesen misst (Wanduhr in Nanosekunden plus monotone Uhr); sortiert wird nach der monotonen Uhr. Die Empfangszeit im Daemon dient nur noch als Kontrolle | die Empfangszeit lag bis zu 250 ms daneben; Nutzer will «haargenaue» Zeitstempel, realistisch etwa 1 ms | Nutzer + KI | fest | TW 2.2 |
| E101 | 2026-10-15 | `ariadne unlock` bei aktivem Projekt öffnet dieses Projekt wie `ariadne start` ohne Projektnamen; die Aufnahme läuft sofort weiter. Das gilt auch vom Mac aus per `ssh -t kali-sl unlock` | ein Schritt statt zwei nach einem Neustart der VM | Nutzer | fest | E74, E22 |
| E102 | 2026-10-15 | Stürzt der Daemon ab oder startet er neu, während ein Projekt aktiv ist, übernimmt `ariadne start` bzw. `unlock` die gepufferte Ausgabe seit dem Ausfall ohne Rückfrage. Nur der Vorlauf ohne Projekt (E95) wird weiter erfragt. *Auslegung 2026-10-18 (Korrektur F3):* ohne Rückfrage nur in das Projekt, das beim Ausfall aktiv war; startet `start` ein anderes, gilt der Puffer dort wie Vorlauf (Frage, und nur was an kein Projekt gebunden war, E70) | das Projekt war aktiv, die Aufnahme hätte ohnehin laufen sollen | Nutzer | fest | E22, E95 |
| E103 | 2026-10-15 | `ariadne lock` sperrt nur den Tresor, das Projekt bleibt aktiv; bis zum nächsten `start` oder `unlock` wird nichts gespeichert (nur Puffer im RAM). `ariadne stop` beendet das Projekt | Sperren in einer Pause soll das Projekt nicht beenden | Nutzer | fest | E22, E74 |
| E104 | 2026-10-15 | Eingaben ohne Echo (Passwortabfragen von sudo, ssh, su, mysql; erkannt am Terminalmodus und am fehlenden Echo in der Ausgabe) werden vollständig gespeichert, aber in CLI und Dashboard verdeckt angezeigt; ein Klick zeigt sie | vollständige Daten (E26) ohne Passwörter offen auf dem Bildschirm | Nutzer | fest | E26, E99 |

## Quellen

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E30 | 2026-10-08 | Dateien: alles Mögliche, Projektordner automatisch überwacht | so gewünscht | Nutzer | fest | F3.1, F3.2 |
| E31 | 2026-10-08 | Projektordner `~/ariadne/<slug>/` mit Klartext-Arbeitsbereich und verschlüsseltem `.vault/` | Tools schreiben Klartext, Ariadne-Daten bleiben verschlüsselt | KI-Vorschlag | vorläufig | A4.1 |
| E32 | 2026-10-08 | Screenshots macht Ariadne selbst; Inhalt soll verstanden werden (OCR ab v0.2, Vision ab v0.3) | so gewünscht; gestaffelt wegen Aufwand und Datenschutz | Nutzer + KI | fest | F3.3, F3.4 |
| E33 | 2026-10-08, geändert 2026-10-15 | Browser: Aufzeichnungs-Proxy mit eigenem Testbrowser pro Projekt (`ariadne browser`) in v0.2, HAR- und Burp-Import als Rückfall, Firefox-Erweiterung in v0.3. Zwischenablage und PCAP wie geplant gestaffelt. Vorher: Burp und HAR v0.2, Browser-Verlauf v0.3, Erweiterung später | der Proxy liefert exakte Grenzen, Ziel-IP und Bodies ohne Code im Browser | Nutzer + KI | fest | F3.5, A4.5, TW 7 |
| E97 | 2026-10-15 | Der Browser-Recorder speichert Anfragen, Antworten und Formulare vollständig: nichts geschwärzt, nichts maskiert, auch keine Ziel-Passwörter | Nutzer will vollständige Daten; Schutz über Verschlüsselung (E71) und Filter an den Ausgängen (E72) | Nutzer | fest | TW 8 |

## Auswertung und Karte

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E40 | 2026-10-08 | Alle Wertearten (Netz, Zugänge, Angriffsflächen, AD), gestaffelt nach Version | so gewünscht | Nutzer | fest | F4.1 |
| E41 | 2026-10-08 | Extraktion hybrid: Parser zuerst, Regex-Netz, LLM nur mit wörtlichem Beleg | so gewünscht; Schutz vor Halluzinationen | Nutzer + KI | fest | F4.2, A6.3 |
| E42 | 2026-10-08, geändert 2026-10-15 | Drei-Spuren-Regel als Standard im Profil lab. «automatisch»: Werte anerkannter Parser im Scope gehen direkt auf die Karte, markiert als «auto», pro Befehl rückgängig (`d.unit.distrust`). «still»: heuristische Werte, Werte ausserhalb des Scopes, Mentions als Nebel oder Zähler. «entscheiden»: KI- und OCR-Werte, echte Widersprüche, unklarer Kontext, angebotene Credentials. Eigene Adressen von Kali werden nie Host. Jeder Entscheid des Nutzers geht vor. Vorher: alles als Vorschlag in die Inbox, Automodus pro Projekt | ein nmap-Lauf auf Metasploitable2 ergab 86 Inbox-Einträge, mit der Regel noch einen | Nutzer + KI | fest | F4.4, TW 5 |
| E43 | 2026-10-08 | Kandidaten im Scope erscheinen sofort als Nebel auf der Karte | sonst bleibt die Karte bis zur Bestätigung leer, das widerspricht E04 | KI-Vorschlag | vorläufig | A5.7 |
| E44 | 2026-10-08 | Live-nahe und nachträgliche Auswertung über dieselbe Pipeline | so gewünscht | Nutzer | fest | F4.5 |
| E45 | 2026-10-08, präzisiert 2026-10-15 | Widersprüche werden erkannt und nie automatisch aufgelöst. Eine genauere Version (Präzisierung) und ein neuerer Zustand gelten nicht als Widerspruch; der Verlauf bleibt sichtbar | so gewünscht | Nutzer + KI | fest | F4.6, TW 5 |
| E46 | 2026-10-08 | Karte als Kombination aller Ebenen mit Umschalten | so gewünscht | Nutzer | fest | F5.1 |
| E47 | 2026-10-08 | Drei Status-Achsen: Wissen, Zugriff, Arbeitsstand | Zugriff und Arbeitsstand sind verschiedene Fragen | Nutzer + KI | fest | F5.2, A5.9 |
| E48 | 2026-10-08 | Tunnel und Segmente im Datenmodell ab Tag 1 | Pivots sonst falsch zugeordnet | Nutzer + KI | fest | F5.3 |
| E49 | 2026-10-08, ergänzt 2026-10-15 | Scope gehört zur konkreten Kennung, nicht zur Entität; keine DNS-Auflösung von Zielnamen. Einzige Ausnahme: Der Browser-Recorder löst die Namen auf, die der Testbrowser selbst anfragt, und baut die Verbindungen auf. Er gilt als passiv, weil er nur weiterleitet, was der Browser schickt | Ziele können Kennungen fälschen; DNS erreicht Zielinfrastruktur; der Recorder erzeugt keinen eigenen Verkehr | Nutzer + KI | fest | A5.8, TW 7 |
| E50 | 2026-10-08 | Zuerst bis ca. 10 Hosts, Datenmodell skaliert weiter | so gewünscht | Nutzer | fest | F5.6 |

## Oberfläche, KI und Bericht

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E60 | 2026-10-08, ergänzt 2026-10-15 | Web-Oberfläche als Hauptoberfläche, ohne speziellen Zweitbildschirm-Modus. Ein Browser auf dem Mac über die SSH-Weiterleitung ist eine normale Sitzung derselben UI; die UI zeigt nur die Herkunft der Sitzung. Das Dashboard läuft als volles Fenster, der Nutzer wechselt zwischen Webkonsole und Dashboard | so gewünscht | Nutzer | fest | F6.1, F6.2, FZ |
| E61 | 2026-10-08 | Fragen an die Karte über eine DSL; KI übersetzt Fragen, Ausführung erst nach Klick | so gewünscht; nachprüfbar | Nutzer + KI | fest | F6.3 |
| E62 | 2026-10-08 | Bericht als Markdown, mit Vorlage nach dem Schema des Moduls Cybersecurity | so gewünscht; Schulabgabe | Nutzer + KI | fest | F6.4, A8.7 |
| E63 | 2026-10-08 | Notizen, Tags und Status als Entscheide | so gewünscht | Nutzer | fest | F6.5 |
| E64 | 2026-10-08 | Vorschläge aus Regeln und KI kombiniert, mit Lernmodus | so gewünscht; Lernwert im Studium | Nutzer + KI | fest | F7.1, F7.2 |
| E65 | 2026-10-08 | LLM lokal (Ollama) und Cloud (Claude) umschaltbar pro Projekt, über ein einziges Gateway | so gewünscht | Nutzer + KI | fest | F4.3, A6.2 |
| E66 | 2026-10-09 | KI über die Claude API als Standard, Modell `claude-opus-5-5`; konfigurierbares Monatslimit (Standard 20 USD) nur als Schutz gegen Fehlbedienung | Nutzer: Budget egal, mit API; lokale Modelle sind in der VM zu schwach | Nutzer + KI | fest | A6.2 |
| E98 | 2026-10-15 | Die KI liest unbekannte Ausgaben im Profil lab automatisch, aber nur Ausgaben von einem Ziel mit Signalwörtern (user, pass, key, admin), die kein Parser vollständig erkannt hat. Bekannte Secrets werden vorher ersetzt. In SmartLearn erst, wenn die Schule Lab-Daten in der Cloud erlaubt und die Prüfliste keinen TLS-Aufbruch zeigt. Im Profil customer nur auf Klick und nur lokal | bezahlbar (etwa 1 bis 3 Rappen pro Befehl) und ohne alles wegzuschicken | Nutzer + KI | fest | E41, E65, TW 6 |
| E58 | 2026-10-09 | Kein Export in einen Obsidian-Vault; Export bleibt im Projektordner | so gewünscht | Nutzer | fest | A8.7 |
| E69 | 2026-10-09 | Parser-Reihenfolge nach Verbreitung im Lab, Tests mit nachgestellten Outputs, bis echte vorliegen | kein Testmaterial zur Hand | Nutzer + KI | fest | A5.6 |
| E67 | 2026-10-08 | Scope-Warnung: v0.1 nach dem Befehlsstart, ab v0.2 vor dem Ausführen | so gewünscht; gestaffelt | Nutzer + KI | fest | F7.4 |
| E68 | 2026-10-08 | Befehlsvorlagen nur mit typisierten Platzhaltern und Kontext-Encodern | aus Zieldaten gefüllte Befehle sind sonst ein Weg zur Codeausführung auf Kali | KI-Vorschlag | vorläufig | A6.1 |
| E86 | 2026-10-10 | Layout «Karte und Arbeitsliste»: links die Karte, rechts eine Spalte «Als Nächstes» (Klären, Bestätigen, Denkanstösse), die bei Auswahl eines Hosts dessen Detail zeigt; Terminals, Zeitachse und Findings als Reiter. Ersetzt das Cockpit mit Schubladen (UI A1) | Nutzer fand den ersten Prototyp «sehr überladen und unübersichtlich»; von zwei ruhigen Varianten gewählt. Referenz: [Prototyp](ui/prototyp-karte-liste.html) | Nutzer | fest | UI A1, A7.4 |
| E87 | 2026-10-10, bestätigt 2026-10-17 | Gestaltungsregel «Ruhe zuerst»: im Startzustand höchstens etwa 25 Bedienelemente, Karte mindestens 70 % der Fläche, jede Zahl nur einmal, Farbe nur für Zugriff, Faden und Handlungsbedarf, Konfidenz und Scope nur als Ausnahme, Host-Karten mit einem Hinweis und mehr erst bei Hover, Auswahl oder Zoom | aus dem Feedback zum ersten Prototyp abgeleitet und an beiden Varianten gemessen; in der Design-Session bestätigt, die Kopfzeile hat zusätzlich das Logo-Zeichen | Nutzer + KI | fest | UI A3, A7.5 |
| E88 | 2026-10-10, ergänzt 2026-10-17 | Sammelbestätigung nimmt nur Werte im Scope, ohne KI-Werte und ohne niedrige Konfidenz; Konflikte, Merges und Kontexte immer einzeln. Im Profil lab ohne Wirkung, weil der Abschnitt «Bestätigen» dort entfällt (E110) | ein UI-Review fand, dass «Alle annehmen» sonst feindliche und KI-Werte mitnimmt | KI-Vorschlag | vorläufig | UI C2, web-api.md |
| E105 | 2026-10-17 | Richtung 1a «Spalte bleibt»: Die Spalte «Als Nächstes» ist immer da (27 %, 320 bis 480 px), die Karte bleibt bei mindestens 70 %. Ruhezustand: erledigte Klärungen gedämpft mit Rückgängig, der Cursor springt auf den ersten Denkanstoss und klappt ihn auf. Referenz: [Design v0.1](ui/design-v01/README.md) | nichts springt beim Wechsel aus der Webkonsole | Nutzer | fest | Briefing 13.1 Frage 1, E86 |
| E106 | 2026-10-17 | «Neu seit»: Der Client meldet beim Unsichtbarwerden des Tabs den Zeitpunkt an den Server; bei der Rückkehr zeigt das Lagebild «+N seit HH:MM», ein Klick lässt das Neue einmal pulsieren. Kein Knopf «Gesehen» | der Nutzer wechselt zwischen Webkonsole und Dashboard | Nutzer | fest | Briefing 13.1 Frage 2 |
| E107 | 2026-10-17 | Kopfzeile: Logo-Zeichen, Slug, Aufnahme mit Popover, Ausnahme-Badges, Herkunft der Sitzung immer sichtbar; Profil nur im Popover; keine Zahlen von Klärungen oder Denkanstössen. Pause pro Terminal im Popover und im Reiter Terminals, 10 min | E87 «jede Zahl nur einmal» | Nutzer | fest | Briefing 13.1 Frage 3 |
| E108 | 2026-10-17 | Karte: Host-Karten als HTML-Overlay über Cytoscape, mit Tab erreichbar, Pfeiltasten zum nächsten Host; Services als Zahl; Host-Tabelle ab 200 Hosts, darunter mit `t` umschaltbar | Tastaturbedienung und Lesbarkeit | Nutzer | fest | Briefing 13.1 Frage 4 |
| E109 | 2026-10-17 | Farben nach Architektur 7.5, keine Profilfarbe (E87 geht vor A 7.4). Eigene Fehlerfarbe (Rosa), damit Rot nur für den Faden steht. Sackgasse als Symbol ⊘ mit Text, verknüpfter Host mit gestricheltem Ring in der Farbe für Handlungsbedarf. Tokens in `docs/ui/design-v01/tokens.css` | Ruhe zuerst | Nutzer | fest | Briefing 13.1 Frage 5, A 7.5 |
| E110 | 2026-10-17 | «auto» ist unauffällig (nur als Wort im Detail und in Brotkrumen). Rückgängig pro Befehl als Knopf in der Zeitachse (Hover, Fokus, `u`). Der Abschnitt «Bestätigen» entfällt im Profil lab und kommt mit customer (v0.3) zurück | im Lab ist «Bestätigen» immer leer (E42) | Nutzer | fest | Briefing 13.1 Frage 6 |
| E111 | 2026-10-17 | Jeder Kopierknopf nennt sein Ziel: «Kopieren · Mac» (Zwischenablage des Browsers) oder «in die Kali» (Secrets, über den Daemon, ohne Anzeige) | Secrets nie in den Browser | Nutzer | fest | Briefing 13.1 Frage 7, E99 |
| E112 | 2026-10-17 | Kein Browser-Speicher: Theme, Dichte, Lernmodus und «Neu seit» auf dem Server; Reiter, Ebenen, Auswahl und offene Tafel in der URL. Nur Systemschriften, keine Schriftdateien | strenge CSP, offline, nichts im Browser | Nutzer | fest | Briefing 13.1 Fragen 8 und 9 |
| E113 | 2026-10-17 | Findings kommen schon in v0.1: Formular im Reiter Findings und «Als Finding» aus der Belegansicht führen ins selbe Formular. Schwere in 5 Stufen (Kritisch, Hoch, Mittel, Tief, Info), nur vom Menschen gesetzt; Status Entwurf oder final | Bericht braucht Findings | Nutzer | fest | Briefing 13.1 Frage 10, E62 |
| E114 | 2026-10-17 | Weitere Festlegungen der Design-Session: Warteliste als eingeklappter Streifen oben in der Zeitachse (Übernehmen in v0.1 nur mit `ariadne import`); Belegansicht als Tafel von rechts (52 %, 620 bis 860 px), immer nur eine; Präsentationsmodus mit `Shift+P`; Logo 2c (Dreieck aus drei Knoten mit Kante) und Schriftzug ARIADNE; Favicon mit Punkt, wenn etwas zu klären ist | Ergebnis der Design-Session | Nutzer | fest | [Design v0.1](ui/design-v01/README.md) |

## Sicherheit und Daten

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E70 | 2026-10-08 | Projekte strikt getrennt | so gewünscht | Nutzer | fest | F8.1 |
| E71 | 2026-10-08 | Verschlüsselung at rest ab v0.1 (SQLCipher, age), keine eigene Kryptografie | so gewünscht; Nachrüsten wäre teuer | Nutzer + KI | fest | F8.2, A8.4 |
| E72 | 2026-10-08, geändert 2026-10-15 | Eigene Secrets: Das Journal speichert alles ungeschwärzt, nur verschlüsselt (E71). Der Redaktor ersetzt eigene Secrets erst an den Ausgängen: vor der KI, beim Export und im Bericht. Weiterhin nur exakte Treffer der eigenen Liste, längenerhaltend. Vorher: Schwärzen im Daemon vor dem Speichern | Nutzer will vollständige Daten überall | Nutzer | fest | F8.3, A8.5, TW 8 |
| E73 | 2026-10-08, ergänzt 2026-10-15 | Profile lab und customer; lab mit Leitplanken gegen versehentliche Kundendaten. In SmartLearn nur Profil lab, nie Kundendaten; customer schaltet den Fernzugriff standardmässig aus | Kundenprofil erst ab v0.3, Risiko eines echten Auftrags im lab-Projekt; die Plattform der Schule sieht Konsole und Disk | KI-Vorschlag | vorläufig | A8.1, FZ 8 |
| E74 | 2026-10-08, ergänzt 2026-10-15 | Entsperren nur per CLI, nie in der Web-UI. Die Passphrase kommt einmal in `ariadne start`; vom Mac aus per `ssh -t kali-sl unlock` über den eingeschränkten Schlüssel (E94), damit sie nicht über die Webkonsole läuft | Port-Squatting würde Phishing der Passphrase erlauben; Erweiterungen im Konsolen-Browser sehen Tasten | Nutzer + KI | fest | A7.2, TW 3, FZ |
| E75 | 2026-10-08 | Parser und Bildverarbeitung laufen in Worker-Prozessen ohne Schlüssel | wer Schlüssel hält, parst nicht | KI-Vorschlag | vorläufig | A9.3 |
| E76 | 2026-10-08 | Hash-Kette über alle Felder mit gesalzenen Commitments; externer Anker ab v0.3 | Beweiswert gegenüber Dritten | KI-Vorschlag | vorläufig | A5.2 |
| E99 | 2026-10-15 | Die UI zeigt eigene Secrets und Secret-Werte standardmässig verdeckt (`••••••••`); ein Klick zeigt sie einzeln | das Dashboard läuft in einem normalen Browser mit Erweiterungen (E93) | KI-Vorschlag | vorläufig | E72, FZ 3 |

## Fernzugriff

| ID | Datum | Entscheid | Begründung | Quelle | Status | Bezug |
|---|---|---|---|---|---|---|
| E89 | 2026-10-15 | Fernzugriff nur per SSH-Portweiterleitung auf denselben Port. Der Daemon lauscht nur auf Loopback und erzwingt das beim Start (fail-closed); kein eigener Netzport, keine öffentlichen Tunnel-Dienste, keine Host-Ausnahmen | ein Sicherheitsmodell für alle Wege | Nutzer + KI | fest | FZ 2, R1 bis R3 |
| E90 | 2026-10-15 | Zugangsweg B: Tailscale nur als Transport für SSH vom Mac zur Kali. Die Schule erlaubt Tailscale (Nutzer hat gefragt). Weg E, das Dashboard im Browser der Kali, bleibt Rückfall | kein eigener Server zu pflegen, Inhalte Ende-zu-Ende verschlüsselt | Nutzer | fest | FZ 1, FZ 2 |
| E91 | 2026-10-15 | `ariadne backup` und `restore` in v0.1 (vorgezogen aus v0.2). Sicherung nach jeder Session, mit age an Empfänger ausserhalb der VM verschlüsselt, mit Weg B direkt auf den Mac; Operator-Tresor immer dabei; Recovery-Schlüssel ausserhalb der VM und nie als Datei | die Schule kann die VM jederzeit zurücksetzen | Nutzer + KI | fest | FZ 6, A8.9 |
| E92 | 2026-10-15 | Anmeldungen im Dashboard gelten höchstens 12 Stunden und enden zusätzlich bei `lock`, `project close`, Neustart des Daemons und mit dem Tunnel. Tokens nur als Hash gespeichert und an den Peer-Prozess gebunden; `ariadne ui --sessions` zeigt die Herkunft | vergessene und gestohlene Sitzungen | Nutzer + KI | fest | FZ 4, R6 bis R8 |
| E93 | 2026-10-15 | Auf dem Mac öffnest du das Dashboard im normalen Browser; kein eigenes Insel-Profil. Schutz bleibt in der UI: strenge CSP, keine Fremdressourcen, Präsentationsmodus, verdeckte Secrets (E99) | so gewünscht; Restrisiko: Erweiterungen mit Zugriff auf alle Seiten können das Dashboard lesen | Nutzer | fest | FZ 3 |
| E94 | 2026-10-15 | Der SSH-Schlüssel des Macs öffnet nur das Dashboard: Forced Command `ariadne remote serve`, Weiterleitung nur zu `127.0.0.1:7330`, keine Shell. Hostkeys der Kali selbst neu erzeugt, `StrictHostKeyChecking yes` | Schadsoftware auf dem Mac, geklonte Hostkeys eines Mastersets | Nutzer + KI | fest | FZ 5, R11 |
| E100 | 2026-10-15 | Der ganze Fernzugriff kommt in v0.1: Loopback-Pflicht, Middleware, Sitzungen, `remote check`, `remote serve`, Einrichtungsskript für die Kali, Mac-Helfer und E2E-Test über einen echten Tunnel | Nutzer will das Dashboard von Anfang an neben der Webkonsole auf dem Mac | Nutzer | fest | FZ 7 |
| E115 | 2026-10-17 | Startdatei und Fetch-Metadaten: Die Startdatei aus `ariadne ui` bzw. `ariadne-mac start` liegt unter `file://` und ist für den Browser eine fremde Herkunft. Ein `GET` der SPA-Shell (`/`, `/index.html`, Routen ohne Dateiendung) als Navigation (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`) darf darum auch mit `Sec-Fetch-Site: cross-site` oder `same-site` laden; liefert die App dafür etwas anderes als die Shell, wird daraus 403. Für Assets, API, Sitzung und jede andere Anfrage gilt R12 unverändert (`same-origin` oder `none`) | ohne die Ausnahme lädt das Dashboard nach der Startdatei nie (403); die Shell enthält keine Daten, Rahmen, COOP und alle API-Regeln bleiben. Restrisiko: eine fremde Seite kann die Shell mit einem falschen Code öffnen und so höchstens Fehlversuche auslösen (Sperre bis zum nächsten `ariadne ui`) | KI-Vorschlag (Integration Bau v0.1-Server) | vorläufig | R12, E93, FZ 4.2, web-api.md 1.1 |

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
| O07 | Echte Outputs aus Metasploitable2 als Testmaterial | Nutzer, sobald vorhanden | A10.2 |
| O08 | Sprache der UI (Standard: Deutsch mit englischen Fachbegriffen) | Nutzer | A14 |
| O09 | Passwortmanager unter Kali (ab v0.3 relevant) | Nutzer | A4.5 |
| O10 | Erlaubnis der Schule für Tailscale schriftlich ablegen (Mail oder Ticket) und klären, was in Prüfungen gilt | Nutzer | E90, FZ 3.5 |

Erledigt am 2026-10-09: Diplomarbeit (keine), KI-Regeln der Schule (entfällt), Hotkey (E29), Umgebung (E09), Budget (E66), Obsidian (E58), Tools (E69).

Erledigt am 2026-10-15: alle Fragen aus den Konzepten Terminal und Web (TW 1 bis 8) und Fernzugriff (FZ 1 bis 7), siehe E09 bis E104. Erledigt am 2026-10-17: die zehn Fragen aus dem Dashboard-Briefing (Abschnitt 13.1), siehe E105 bis E114.
