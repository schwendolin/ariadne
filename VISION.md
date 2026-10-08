# Ariadne: Vision

> Stand 2026-10-08, Entwurf. Erarbeitet im Dialog mit KI-Unterstützung (Claude) auf Basis der Antworten im [Fragenkatalog](docs/fragenkatalog.md). Die einzelnen Entscheide und wer sie getroffen hat, stehen im [Entscheidungsprotokoll](docs/entscheide.md). Die technische Umsetzung beschreibt die [Lösungsarchitektur](docs/architektur.md).

## Kurzfassung

Ariadne ist der **Flugschreiber und Kartograf** eines Pentests unter Linux. Auf Knopfdruck zeichnet es auf, was in den Terminals, im Projektordner und auf dem Bildschirm passiert. Es liest daraus Hosts, Services, Zugänge und Schwachstellenhinweise aus und malt Schritt für Schritt eine Karte der Zielumgebung. Der Faden auf der Karte zeigt jederzeit, auf welchem Weg man wohin gekommen ist. Zu jedem Fakt lässt sich die Stelle zeigen, aus der er stammt.

Ariadne beobachtet, dokumentiert und gibt Denkanstösse. Es greift nie selbst an.

## Problem

Drei Dinge gehen in einem Pentest regelmässig schief:

1. **Man verliert den Überblick.** Nach ein paar Scans, Shells und Passwörtern liegen die Informationen verstreut in Terminals, Dateien und im eigenen Kopf. Was schon geprüft wurde, was offen ist und welches Passwort wo funktioniert, weiss man nach ein paar Stunden nicht mehr sicher.
2. **Man steckt fest.** Oft fehlt nicht das Wissen, sondern der Anstoss, einen vergessenen Schritt doch noch zu machen: ein Full-Port-Scan, ein UDP-Scan, neue Credentials gegen alle bekannten Dienste.
3. **Die Belege fehlen am Ende.** Beim Schreiben des Berichts muss man den genauen Befehl, den Output und den Zeitpunkt aus History und Screenshots zusammensuchen. Wie man auf den ersten Host gekommen ist, lässt sich dann oft nur noch ungefähr rekonstruieren.

## Zielbild

Nach den ersten Minuten steht eine grobe Übersicht: Der Scope zeichnet die Umrisse, der erste nmap-Lauf setzt graue Hosts in den Nebel. Mit jedem Scan, jeder Shell und jedem Passwort füllt sich das Bild. Grau wird zu Farbe, Unbekanntes zu Bekanntem. Eine kräftige Linie, der Faden, verbindet die Schlüsselschritte von Kali bis zum letzten Host.

Am Ende einer Lab-Session liegt ein Markdown-Bericht bereit: Übersicht, Angriffspfad, Writeup-Gerüst nach dem Phasenschema des Moduls Cybersecurity und Belege mit Befehl, Ausschnitt, Zeitpunkt und Screenshot.

Ein typischer Ablauf:

1. `ariadne project new lame --target 10.10.10.3` legt das Projekt an.
2. Klick auf REC in der Web-Oberfläche. Ab jetzt nimmt Ariadne alle Terminals auf.
3. `nmap -sV -oA scans/lame 10.10.10.3` füllt die Karte mit Ports und Versionen.
4. Der Denkanstoss «Unauthentisierten Zugriff auf FTP prüfen» erscheint, mit Begründung und Beleg.
5. In der Reverse Shell drückt man `Ctrl-]` und `h` und setzt den Host. Ab dann stimmt der Kontext, und die `/etc/passwd` landet beim richtigen Host.
6. `Ctrl-]` und `k` markiert den Foothold als Schlüsselschritt. Der Faden wächst.
7. Am Ende erzeugt `ariadne export` das Writeup-Gerüst mit allen Belegen.

## Für wen und in welchem Rahmen

| Thema | Festlegung |
|---|---|
| Nutzer | eine Person, Student HF Informatik (Cybersecurity), arbeitet hauptberuflich in der IT |
| Einsatz | zuerst Schule und Labs (Metasploitable2, Übungsboxen bis ca. 10 Hosts), danach professionelle Aufträge. Kundenaufträge sind vorerst fiktiv |
| Plattform | Kali Linux im Standard-Setup (zsh, QTerminal, Xfce), offline lauffähig, kompatibel mit anderen Shells und Terminals |
| Projektform | privates Projekt, geplant als Diplomprojekt an der HF, Vorgehen nach HERMES 2022 |
| Entwicklung | allein, KI-unterstützt, ca. 20 Stunden pro Woche |
| Zertifizierungen | keine geplant, daher kein Prüfungsmodus |

## Grundsätze

1. **Beobachten, nicht handeln.** Ariadne schickt keine Pakete an Ziele und löst keine Zielnamen per DNS auf. Die einzige Ausnahme ist ein Webseiten-Screenshot auf ausdrücklichen Klick, nach Scope-Prüfung und über einen Proxy, der den Scope erzwingt.
2. **Jeder Fakt hat eine Quelle.** Ein Klick auf einen Wert zeigt den Befehl, den Output-Ausschnitt, die Datei oder die Bildregion, aus der er stammt.
3. **Rohdaten sind unveränderlich.** Was aufgenommen wurde, bleibt dauerhaft und verschlüsselt gespeichert. Auswertungen lassen sich jederzeit neu berechnen, deine Entscheide überstehen das.
4. **Die Aufnahme steuerst du.** Ein REC-Knopf schaltet die Aufnahme für alle Terminals ein und aus. Der Zustand ist immer sichtbar.
5. **Vorschlag vor Automatik.** Neue Werte landen in einer Inbox und auf der Karte als Nebel. Bestätigen färbt ein. Ein Automodus ist pro Projekt zuschaltbar.
6. **KI als Denkpartner, nicht als Autopilot.** Denkanstösse kommen aus festen Regeln und aus einem Sprachmodell, immer begründet, gekennzeichnet und mit Belegen. Ein Lernmodus gibt zuerst eine Frage, dann eine Richtung, erst zuletzt einen Befehl.
7. **Zieldaten sind feindlich.** Alles, was ein Ziel beeinflussen kann, wird so behandelt, als hätte ein Angreifer es geschrieben: Output, Banner, Hostnamen, Dateien, Bilder und KI-Texte darüber.
8. **Local-first.** Ariadne läuft ohne Internet. Daten gehen nur an einen Cloud-Dienst, wenn das Projekt es erlaubt.
9. **Die Shell geht nie kaputt.** Fällt Ariadne aus, arbeitet das Terminal normal weiter, nur ohne Aufnahme.
10. **Ein Fakt ist kein Finding.** «Port 445 offen» sammelt Ariadne. «SMB-Signing fehlt, Relay möglich» ist ein Urteil des Pentesters.

## Was Ariadne kann

**Aufnehmen.** Ein kleiner Wrapper um jede Shell nimmt den Output aller Terminals auf, unabhängig von Terminal-Programm und Multiplexer. Shell-Integrationen für zsh und bash (später fish) liefern Befehlsgrenzen, Exit-Codes und Arbeitsordner. Dazu kommen der überwachte Projektordner, Screenshots, später auch Burp-Exporte, Zwischenablage, Browser-Verlauf und PCAPs.

**Kontext kennen.** Ariadne führt pro Terminal einen Stapel, zum Beispiel `Kali › web01 (www-data) › mysql`. Startet eine Remote-Session, steht der Kontext zuerst auf «unbekannt». Mit einem Tastenkürzel setzt du den Host, auch mitten in evil-winrm oder einer Reverse Shell.

**Verstehen.** Parser lesen die Ausgaben bekannter Tools, bevorzugt ihre strukturierten Dateien wie nmap-XML. Ein Regex-Netz fängt IPs, Hashes, URLs und CVEs aus beliebigem Text. Ein Sprachmodell ergänzt, darf aber nur Werte liefern, die wörtlich im Rohtext stehen.

**Karte zeigen.** Die Web-Oberfläche zeigt eine Karte mit umschaltbaren Ebenen: Topologie, Services, Credentials, Angriffspfad, später Web-Struktur und Active Directory. Dazu kommen Tabellen, eine Credential-Matrix, eine Zeitachse, die Inbox und die Belegansicht.

**Denkanstösse geben.** Regeln erkennen offene Prüfziele («SMB offen, Shares noch nicht aufgelistet»). Auf Knopfdruck erstellt ein Sprachmodell aus einem kompakten Lagebild weitere Anstösse. Ariadne führt nichts davon aus.

**Belegen und berichten.** Der Export erzeugt Markdown: Übersicht, Angriffspfad, Writeup-Gerüst, Hosts und Belege. Eine Vorlage folgt dem Schema aus dem Modul Cybersecurity (Reconnaissance, Scanning/Enumeration, Exploitation, Post-Exploitation, Reporting) mit MITRE-ATT&CK-IDs, Schweregraden und Massnahmen.

**Schützen.** Projekte sind strikt getrennt und verschlüsselt. Eigene Secrets (sudo-Passwort, API-Keys) werden vor dem Speichern geschwärzt. Eine Hash-Kette macht nachträgliche Änderungen am Rohlog erkennbar.

## Was Ariadne nicht ist

- **Kein Autopilot.** Kein automatisches Scannen, Sprayen oder Exploiten. PentestGPT ab v1.0 geht in diese Richtung, Ariadne bewusst nicht.
- **Kein Scanner und kein Exploit-Framework.** Ariadne liest die Ergebnisse von nmap, NetExec, Metasploit und Co., ersetzt sie aber nicht.
- **Kein Ersatz für BloodHound oder Burp.** Für tiefe AD-Pfadanalysen und Web-Tests bleiben die Spezialwerkzeuge. Ariadne importiert ihre Kernergebnisse.
- **Kein Report-Generator, der Findings bewertet.** Ariadne liefert die Belege. Bewerten und Formulieren bleibt Aufgabe des Pentesters.
- **Kein Team-Server** vorerst. Das Datenmodell trägt eine Operator-ID, damit Teamarbeit später möglich ist.
- **Kein Prüfungsmodus.** Er ist im aktuellen Rahmen nicht nötig.

## Roadmap

Jede Version ist für sich nutzbar. Ab v0.1 läuft jede Lab-Übung mit Ariadne, und was dabei stört, wird zum Backlog der nächsten Version. Details stehen in der [Lösungsarchitektur, Abschnitt 11](docs/architektur.md#11-roadmap).

| Version | Ziel | Kern |
|---|---|---|
| **v0.1** Flugschreiber mit erster Karte | Eine Metasploitable2- oder einfache HTB-Session lückenlos aufnehmen und als Writeup exportieren | Shell-Wrapper für zsh und bash, REC, Kontext per Tastenkürzel, verschlüsselte Ablage, nmap-Parser und Regex-Netz, Inbox, Web-Oberfläche mit Karte im Nebel, Belegansicht, Screenshots unter X11, Regeln und KI-Denkanstoss auf Knopfdruck, Markdown-Export |
| **v0.2** Bild ausmalen und verstehen | Ein Lab mit mehreren Hosts, Pivots und Credentials | typische Lab-Tools als Parser, linpeas, KI-Extraktion, lokale KI über Ollama, Credential-Matrix, Tunnel, Fragen an die Karte, OCR, Burp-Import, Offline-Paket |
| **v0.3** bereit für Kunden | Ein (fiktiver) Kundenauftrag nach professionellen Massstäben | Kundenprofil, verschlüsselter Arbeitsordner, Aktivitätsprotokoll-Export, Cleanup-Liste, Findings, Löschnachweis, Vision, Webseiten-Screenshots, PCAP, Active Directory |
| **v0.4+** Ausbau | Grosse Netze, Komfort, Langzeitpflege | semantischer Zoom, Zeitreise, Burp- und Browser-Erweiterung, Teamfunktionen |

## Erfolgskriterien

- **v0.1:** Eine vollständige Metasploitable2-Session ist mit REC aufgenommen. Jeder Fakt auf der Karte führt zu seiner Quelle, der Faden zeigt Foothold und Root, und der Export taugt ohne Nacharbeit als Gerüst für einen Lab-Bericht.
- **Kein Klartext-Leck:** Ein Canary-Test findet nach dem Schliessen eines Projekts keinen markierten Testwert im Klartext, weder im Home noch in Logs, Coredumps oder Exporten.
- **Robustheit:** Ein feindliches Test-Ziel (präparierte Hostnamen, Escape-Sequenzen, gefälschte Marker, XSS-Strings) bringt weder Shell, Daemon noch Web-Oberfläche dazu, etwas Unerwünschtes zu tun.
- **Nutzung:** Ab v0.1 läuft jede Lab-Übung mit Ariadne. Sinkt die Nutzung, ist das ein Signal für das Backlog, nicht für mehr Funktionen.

## Rahmen Diplomarbeit

Als Diplomprojekt folgt Ariadne HERMES 2022. Die bisherigen Dokumente gehören in die Phasen Initialisierung und Konzept:

| HERMES-Phase | Ergebnis | Stand |
|---|---|---|
| Initialisierung | Projektauftrag, Stakeholderanalyse, Grobplanung | Projektauftrag fehlt noch; Vision und Roadmap dienen als Grundlage |
| Konzept | Lösungsarchitektur, Anforderungskatalog, Risikoanalyse | [Lösungsarchitektur](docs/architektur.md) als Entwurf, Anforderungen in Vision und [Entscheidungsprotokoll](docs/entscheide.md), Risiken in der Architektur (Abschnitte 9 und 12); eine Risikomatrix 5x5 fehlt noch |
| Realisierung | Detailkonzept, Testprotokoll, Implementierungsplan | ab v0.1 |
| Einführung | Abnahme, Betriebsdokumentation | Einsatz im Lab |
| Abschluss | Abschlussbericht, Lessons Learned | offen |

**KI-Einsatz:** Konzept und Code entstehen mit KI-Unterstützung. Damit das für die Diplomarbeit sauber bleibt, gilt:

- Die Regeln der Schule zum KI-Einsatz werden vor dem offiziellen Start geklärt.
- Das [Entscheidungsprotokoll](docs/entscheide.md) hält fest, welche Entscheide vom Nutzer stammen, welche an die KI delegiert wurden und welche nur ein Vorschlag sind.
- Texte, die als eigene Leistung abgegeben werden (Reflexion, Fazit, Begründungen), schreibt der Nutzer selbst.

## Offene Punkte

Diese Punkte kann nur der Nutzer klären:

1. **Rahmen der Diplomarbeit:** Start, Dauer, Abgabeform. Welche Version soll Gegenstand der Arbeit sein?
2. **KI-Regeln der Schule** für die Diplomarbeit.
3. **Tastaturlayout:** Auf dem Schweizer Layout liegt `]` auf AltGr. Bleibt `Ctrl-]` als Präfix, oder braucht es eine andere Taste?
4. **Hardware und Umgebung:** Kali als VM oder nativ? Welcher Desktop? RAM und GPU? Gibt es einen zweiten Rechner für Ollama? Davon hängen Screenshots und lokale KI ab.
5. **Claude-Budget:** Welches Monatslimit gilt im Lab (Vorschlag 20 USD)?
6. **Obsidian:** Darf Ariadne Lab-Writeups auf Wunsch direkt in den synchronisierten Vault schreiben, oder bleibt der Export immer im Projektordner?
7. **Testmaterial:** Welche Tools kommen nach nmap am häufigsten zum Einsatz? Gibt es echte Outputs aus Metasploitable2, die als Testfälle dienen können?
